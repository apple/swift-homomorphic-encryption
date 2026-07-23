// Copyright 2025-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

public import HomomorphicEncryption
import Foundation
import ModularArithmetic

extension SimplePirContext {
    @inlinable
    func generateSecretPolys() -> [PolyRq<Scalar, Coeff>] {
        (0..<chunksPerEntry).map { _ in
            var poly = PolyRq<Scalar, Coeff>.zero(context: extraContext)
            poly.randomizeTernary()
            return poly
        }
    }

    @inlinable
    func noiselessSample(aPolynomials: [PolyRq<Scalar, Eval>],
                         secretKeys: [PolyRq<Scalar, Coeff>]) async throws -> Array2d<Scalar>
    {
        var evalSecretKeys: [PolyRq<Scalar, Eval>] = try secretKeys.map { try $0.convertToEvalFormat() }
        defer {
            // important zeroize the secret keys after use
            for i in evalSecretKeys.indices {
                evalSecretKeys[i].data.zeroize()
            }
        }

        let matrixData = try evalSecretKeys.flatMap { evalSecretKey in
            // one row is aPolys multiplied with the same secret key and concatenated
            try aPolynomials.map { aPoly in
                try (aPoly * evalSecretKey).convertToCoeffFormat()
            }.collect().data.prefix(databaseColumns)
        }
        return Array2d<Scalar>(
            data: matrixData,
            rowCount: chunksPerEntry,
            columnCount: databaseColumns)
    }

    /// Returns a sample with added noise.
    /// - Parameters:
    ///   - aPolynomials: The encrypted a-polynomials.
    ///   - secretKeys: The secret keys to use for the sample.
    ///   - rng: The random number generator to use.
    @inlinable
    func encryptZero(
        aPolynomials: [PolyRq<Scalar, Eval>],
        secretKeys: [PolyRq<Scalar, Coeff>],
        using rng: inout some PseudoRandomNumberGenerator) async throws -> Array2d<Scalar>
    {
        var noiselessSample = try await noiselessSample(aPolynomials: aPolynomials, secretKeys: secretKeys)
        try modSwitch(&noiselessSample)
        var error = Array2d<Scalar>.zero(rowCount: 1, columnCount: databaseColumns * chunksPerEntry)
        defer {
            error.zeroize()
        }
        error.randomCenteredBinomialDistribution(
            standardDeviation: errorStdDev,
            mod: [1 << ciphertextModulusBits],
            using: &rng)
        error.columnCount = databaseColumns
        error.rowCount = chunksPerEntry

        error &= mask
        noiselessSample += error
        noiselessSample &= mask

        return noiselessSample
    }

    @inlinable
    func extractEntries(from data: Array2d<Scalar>, for index: Int) -> Array2d<Scalar> {
        let subIndices = (0..<chunksPerEntry).map { $0 + index * chunksPerEntry }
        let extractedData = subIndices.enumerated().flatMap { queryIndex, entryIndex in
            let indexInColumn = entryIndex % entriesPerColumn
            let offset = queryIndex * columnSize
            let indexStart = offset + indexInColumn * chunkSize
            let indiceRange = indexStart..<(indexStart + chunkSize)
            return data.data[indiceRange]
        }
        return Array2d(data: extractedData, rowCount: subIndices.count, columnCount: chunkSize)
    }
}

public struct SimplePirClient<Generator: QueryGenerator>: SimplePirProtocol {
    public typealias Scalar = Generator.Scalar

    @usableFromInline var queryGenerator: Generator
    public var context: SimplePirContext<Scalar> {
        queryGenerator.context
    }

    @inlinable
    public init(queryGenerator: Generator) async throws {
        self.queryGenerator = queryGenerator
    }

    @inlinable
    public func decrypt(responses: Responses,
                        with preparedResponses: PrecomputedQueries<Scalar>.WithPreparedResponse,
                        at index: Int) async throws -> [UInt8]
    {
        let results = preparedResponses.integrate(responses: responses, at: index)
        return try Array(
            CoefficientPacking.coefficientsToBytes(coeffs: results,
                                                   bitsPerCoeff: context.plaintextModulusBits)
                .prefix(context.entrySizeInBytes))
    }

    public func query(at index: Int) async throws -> PrecomputedQueries<Scalar>.WithQueryIndices {
        let withoutIndices = try await queryGenerator.nextPrecomputedQueries()
        return withoutIndices.add(index: index)
    }
}
