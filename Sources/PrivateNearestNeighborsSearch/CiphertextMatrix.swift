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

import HomomorphicEncryption

/// Stores a matrix of scalars as ciphertexts.
struct CiphertextMatrix<Scheme: HeScheme, Format: PolyFormat>: Equatable, Sendable {
    typealias Packing = PlaintextMatrixPacking
    typealias Dimensions = MatrixDimensions

    /// Dimensions of the scalars.
    @usableFromInline let dimensions: Dimensions

    /// Dimensions of the scalar matrix in a SIMD-encoded plaintext.
    @usableFromInline let simdDimensions: SimdEncodingDimensions

    /// Plaintext packing with which the data is stored.
    @usableFromInline let packing: Packing

    /// Encrypted data.
    @usableFromInline let ciphertexts: [Ciphertext<Scheme, Format>]

    /// The parameter context.
    @usableFromInline var context: Context<Scheme> {
        precondition(!ciphertexts.isEmpty, "Ciphertext array cannot be empty")
        return ciphertexts[0].context
    }

    /// Number of rows in SIMD-encoded plaintext.
    @usableFromInline var simdRowCount: Int { simdDimensions.rowCount }

    /// Number of columns SIMD-encoded plaintext.
    @usableFromInline var simdColumnCount: Int { simdDimensions.columnCount }

    /// Number of data values stored in the ciphertexts matrix.
    @usableFromInline var count: Int { dimensions.count }

    /// Number of rows in the stored data.
    @usableFromInline var rowCount: Int { dimensions.rowCount }

    /// Number of columns in the stored data.
    @usableFromInline var columnCount: Int { dimensions.columnCount }

    /// Creates a new ciphertexts matrix.
    /// - Parameters:
    ///   - dimensions: Ciphertext matrix dimensions
    ///   - packing: The packing with which the data is stored
    ///   - ciphertexts: ciphertexts encrypting the data; must not be empty.
    /// - Throws: Error upon failure to initialize the ciphertext matrix.
    @inlinable
    init(dimensions: Dimensions, packing: Packing, ciphertexts: [Ciphertext<Scheme, Format>]) throws {
        guard let context = ciphertexts.first?.context else {
            throw PnnsError.emptyCiphertextArray
        }
        let encryptionParams = context.encryptionParameters
        guard let simdDimensions = encryptionParams.simdDimensions else {
            throw PnnsError.simdEncodingNotSupported(for: encryptionParams)
        }
        let expectedCiphertextCount = try PlaintextMatrix<Scheme, Format>.plaintextCount(
            encryptionParameters: encryptionParams,
            dimensions: dimensions,
            packing: packing)
        guard ciphertexts.count == expectedCiphertextCount else {
            throw PnnsError.wrongCiphertextCount(got: ciphertexts.count, expected: expectedCiphertextCount)
        }
        for ciphertext in ciphertexts {
            guard ciphertext.context == context else {
                throw PnnsError.wrongContext(got: ciphertext.context, expected: context)
            }
        }

        self.simdDimensions = simdDimensions
        self.dimensions = dimensions
        self.packing = packing
        self.ciphertexts = ciphertexts
    }

    @inlinable
    func decrypt(using secretKey: SecretKey<Scheme>) throws -> PlaintextMatrix<Scheme, Coeff> {
        let plaintexts = try ciphertexts.map { ciphertext in try ciphertext.decrypt(using: secretKey) }
        return try PlaintextMatrix(dimensions: dimensions, packing: packing, plaintexts: plaintexts)
    }
}

// MARK: format conversion

extension CiphertextMatrix {
    /// Converts the ciphertext matrix to ``Eval`` format.
    /// - Returns: The converted ciphertext matrix.
    /// - Throws: Error upon failure to convert the ciphertext matrix.
    @inlinable
    public func convertToEvalFormat() throws -> CiphertextMatrix<Scheme, Eval> {
        if Format.self == Eval.self {
            // swiftlint:disable:next force_cast
            return self as! CiphertextMatrix<Scheme, Eval>
        }
        let evalCiphertexts = try ciphertexts.map { ciphertext in try ciphertext.convertToEvalFormat() }
        return try CiphertextMatrix<Scheme, Eval>(
            dimensions: dimensions,
            packing: packing,
            ciphertexts: evalCiphertexts)
    }

    /// Converts the plaintext matrix to ``Coeff`` format.
    /// - Returns: The converted plaintext ciphertext.
    /// - Throws: Error upon failure to convert the ciphertext matrix.
    @inlinable
    public func convertToCoeffFormat() throws -> CiphertextMatrix<Scheme, Coeff> {
        if Format.self == Coeff.self {
            // swiftlint:disable:next force_cast
            return self as! CiphertextMatrix<Scheme, Coeff>
        }
        let coeffCiphertexts = try ciphertexts.map { ciphertexts in try ciphertexts.convertToCoeffFormat() }
        return try CiphertextMatrix<Scheme, Coeff>(
            dimensions: dimensions,
            packing: packing,
            ciphertexts: coeffCiphertexts)
    }
}
