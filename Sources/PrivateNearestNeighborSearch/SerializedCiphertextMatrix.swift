// Copyright 2024-2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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
public struct SerializedCiphertextMatrix<Scalar: ScalarType>: Equatable, Sendable {
    /// Dimensions of the matrix.
    public let dimensions: MatrixDimensions

    /// Packing with which the data is stored.
    public let packing: MatrixPacking

    /// Ciphertexts encrypting the scalars.
    public let ciphertexts: [SerializedCiphertext<Scalar>]

    /// Creates a new ``SerializedCiphertextMatrix``.
    /// - Parameters:
    ///   - dimensions: Ciphertext matrix dimensions.
    ///   - packing: The packing with which the data is stored.
    ///   - ciphertexts: Ciphertexts encrypting the data.
    /// - Throws: Error upon failure to initialize the serialized ciphertext matrix.
    @inlinable
    public init(
        dimensions: MatrixDimensions,
        packing: MatrixPacking,
        ciphertexts: [SerializedCiphertext<Scalar>]) throws
    {
        self.dimensions = dimensions
        self.packing = packing
        self.ciphertexts = ciphertexts
    }
}

extension CiphertextMatrix {
    /// Deserializes a serialized ciphertext matrix.
    /// - Parameters:
    ///   - serialized: Serialized ciphertext matrix.
    ///   - context: Context to associate with the ciphertext matrix.
    ///   - moduliCount: Number of moduli in each serialized ciphertext. If not set, deserialization will use the
    /// top-level ciphertext with all the moduli.
    /// - Throws: Error upon failure to deserialize the ciphertext matrix.
    @inlinable
    public init(
        deserialize serialized: SerializedCiphertextMatrix<Scalar>,
        context: Context<Scheme.Scalar>,
        moduliCount: Int? = nil) throws
    {
        let ciphertexts: [Ciphertext<Scheme, Format>] = try serialized.ciphertexts.map { serializedCiphertext in
            try Ciphertext(deserialize: serializedCiphertext, context: context, moduliCount: moduliCount)
        }
        try self.init(dimensions: serialized.dimensions, packing: serialized.packing, ciphertexts: ciphertexts)
    }

    /// Serializes the ciphertext matrix.
    /// - Parameter forDecryption: If true, serialization may use a more concise format, yielding ciphertexts which,
    /// once deserialized, are only compatible with decryption, and not any other HE operations.
    /// - Returns: The serialized ciphertext matrix.
    /// - Throws: Error upon failure to serialize.
    @inlinable
    public func serialize(forDecryption: Bool = false) throws -> SerializedCiphertextMatrix<Scalar> {
        try SerializedCiphertextMatrix(
            dimensions: dimensions,
            packing: packing,
            ciphertexts: ciphertexts.map { ciphertext in try ciphertext.serialize(forDecryption: forDecryption) })
    }
}
