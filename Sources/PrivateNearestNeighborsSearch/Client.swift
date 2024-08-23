// Copyright 2024 Apple Inc. and the Swift Homomorphic Encryption project authors
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

import Algorithms
import Foundation
import HomomorphicEncryption

/// Private nearest neighbors client.
struct Client<Scheme: HeScheme> {
    /// Configuration.
    let config: ClientConfig<Scheme>

    /// One context per plaintext modulus.
    let contexts: [Context<Scheme>]

    /// Performs composition of the plaintext CRT responses.
    let crtComposer: CrtComposer<Scheme.Scalar>

    /// Context for the plaintext CRT moduli.
    let plaintextContext: PolyContext<Scheme.Scalar>

    var evaluationKeyConfiguration: HomomorphicEncryption.EvaluationKeyConfiguration {
        config.evaluationKeyConfig
    }

    /// Creates a new ``Client``.
    /// - Parameter config: Client configuration.
    /// - Throws: Error upon failure to create a new client.
    @inlinable
    init(config: ClientConfig<Scheme>) throws {
        guard config.distanceMetric == .cosineSimilarity else {
            throw PnnsError.wrongDistanceMetric(got: config.distanceMetric, expected: .cosineSimilarity)
        }
        self.config = config
        let extraEncryptionParams = try config.extraPlaintextModuli.map { plaintextModulus in
            try EncryptionParameters<Scheme>(
                polyDegree: config.encryptionParams.polyDegree,
                plaintextModulus: plaintextModulus,
                coefficientModuli: config.encryptionParams.coefficientModuli,
                errorStdDev: config.encryptionParams.errorStdDev,
                securityLevel: config.encryptionParams.securityLevel)
        }
        let encryptionParams = [config.encryptionParams] + extraEncryptionParams
        self.contexts = try encryptionParams.map { encryptionParams in
            try Context(encryptionParameters: encryptionParams)
        }
        self.plaintextContext = try PolyContext(
            degree: config.encryptionParams.polyDegree,
            moduli: config.plaintextModuli)
        self.crtComposer = try CrtComposer(polyContext: plaintextContext)
    }

    /// Generates a nearest neighbor search query.
    /// - Parameters:
    ///   - vectors: Vectors.
    ///   - secretKey: Secret key to encrypt with.
    /// - Returns: The query.
    /// - Throws: Error upon failure to generate the query.
    @inlinable
    func generateQuery(vectors: Array2d<Float>, using secretKey: SecretKey<Scheme>) throws -> Query<Scheme> {
        let scaledVectors: Array2d<Scheme.SignedScalar> = vectors.normalizedRows(norm: Array2d<Float>.Norm.Lp(p: 2.0))
            .scaled(by: Float(config.scalingFactor)).rounded()
        let dimensions = try MatrixDimensions(rowCount: vectors.rowCount, columnCount: vectors.columnCount)

        let matrices = try contexts.map { context in
            // For a single plaintext modulus, reduction isn't necessary
            let shouldReduce = contexts.count > 1
            let plaintextMatrix = try PlaintextMatrix(
                context: context,
                dimensions: dimensions,
                packing: config.queryPacking,
                signedValues: scaledVectors.data,
                reduce: shouldReduce)
            return try plaintextMatrix.encrypt(using: secretKey).convertToCoeffFormat()
        }
        return Query(ciphertextMatrices: matrices)
    }

    /// Decrypts a nearest neighbors search response.
    /// - Parameters:
    ///   - response: The response.
    ///   - secretKey: Secret key to decrypt with.
    /// - Returns: The distances from the query vectors to the database rows.
    /// - Throws: Error upon failure to decrypt the response.
    @inlinable
    func decrypt(response: Response<Scheme>, using secretKey: SecretKey<Scheme>) throws -> DatabaseDistances {
        guard let dimensions = response.ciphertextMatrices.first?.dimensions else {
            throw PnnsError.emptyCiphertextArray
        }
        let decoded: [[Scheme.Scalar]] = try response.ciphertextMatrices.map { ciphertextMatrix in
            try ciphertextMatrix.decrypt(using: secretKey).unpack()
        }
        // CRT-decomposed scores
        let values = Array2d<Scheme.Scalar>(data: decoded)
        // Plaintext CRT modulus must be < `UInt64.max`
        let composedDistances: [UInt64] = try crtComposer.compose(data: values)

        let modulus: UInt64 = plaintextContext.moduli.product()
        // Encrypted distances are scaled by config.scalingFactor^2, so we undo the scaling here.
        let distanceValues = composedDistances.map { unsigned in
            let signed = unsigned.remainderToCentered(modulus: modulus)
            return Float(signed) / (Float(config.scalingFactor) * Float(config.scalingFactor))
        }

        let distances = Array2d(
            data: distanceValues,
            rowCount: dimensions.rowCount,
            columnCount: dimensions.columnCount)
        return DatabaseDistances(
            distances: distances,
            entryIds: response.entryIds,
            entryMetadatas: response.entryMetadatas)
    }

    /// Generates an ``EvaluationKey`` for use in nearest neighbors search.
    /// - Parameter secretKey: Secret key used to generate the evaluation key.
    /// - Returns: The evaluation key.
    /// - Throws: Error upon failure to generate the evaluation key.
    /// - Warning: Uses the first context to generate the evaluation key. So either the HE scheme should generate
    /// evaluation keys independent of the plaintext modulus (as in BFV), or there should be just one plaintext modulus.
    @inlinable
    func generateEvaluationKey(using secretKey: SecretKey<Scheme>) throws -> EvaluationKey<Scheme> {
        try contexts[0].generateEvaluationKey(configuration: evaluationKeyConfiguration, using: secretKey)
    }
}

extension Array2d where T == Float {
    /// A mapping from vectors to non-negative real numbers.
    @usableFromInline
    enum Norm {
        case Lp(p: Float) // sum_i (|x_i|^p)^{1/p}
    }

    /// Normalizes each row in the matrix.
    @inlinable
    func normalizedRows(norm: Norm) -> Array2d<Float> {
        switch norm {
        case let Norm.Lp(p):
            let normalizedValues = data.chunks(ofCount: columnCount).flatMap { row in
                let sumOfPowers = row.map { pow($0, p) }.reduce(0, +)
                let norm = pow(sumOfPowers, 1 / p)
                return row.map { value in
                    if sumOfPowers.isZero {
                        Float.zero
                    } else {
                        value / norm
                    }
                }
            }
            return Array2d<Float>(
                data: normalizedValues,
                rowCount: rowCount,
                columnCount: columnCount)
        }
    }

    /// Returns the matrix where each entry is rounded to the closest integer.
    @inlinable
    func rounded<V: FixedWidthInteger & SignedInteger>() -> Array2d<V> {
        Array2d<V>(
            data: data.map { value in V(value.rounded()) },
            rowCount: rowCount,
            columnCount: columnCount)
    }

    /// Returns the matrix where each entry has been multiplied by a scaling factor.
    /// - Parameter scalingFactor: The factor to multiply each entry by.
    /// - Returns: The scaled matrix.
    @inlinable
    func scaled(by scalingFactor: Float) -> Array2d<Float> {
        Array2d<Float>(
            data: data.map { value in value * scalingFactor },
            rowCount: rowCount,
            columnCount: columnCount)
    }
}
