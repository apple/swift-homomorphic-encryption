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

/// Stores a matrix of scalars as plaintexts.
public struct SerializedPlaintextMatrix: Equatable, Sendable {
    /// Dimensions of the matrix.
    public let dimensions: MatrixDimensions

    /// Packing with which the data is stored.
    public let packing: MatrixPacking

    /// Plaintexts encoding the scalars.
    public let plaintexts: [SerializedPlaintext]

    /// Creates a new ``SerializedPlaintextMatrix``.
    /// - Parameters:
    ///   - dimensions: Plaintext matrix dimensions.
    ///   - packing: The packing with which the data is stored.
    ///   - plaintexts: Plaintexts encoding the data.
    /// - Throws: Error upon failure to initialize the serialized plaintext matrix.
    @inlinable
    public init(
        dimensions: MatrixDimensions,
        packing: MatrixPacking,
        plaintexts: [SerializedPlaintext]) throws
    {
        self.dimensions = dimensions
        self.packing = packing
        self.plaintexts = plaintexts
    }
}

extension PlaintextMatrix {
    /// Serializes the plaintext matrix.
    @inlinable
    public func serialize() throws -> SerializedPlaintextMatrix {
        try SerializedPlaintextMatrix(
            dimensions: dimensions,
            packing: packing,
            plaintexts: plaintexts.map { plaintext in plaintext.serialize() })
    }
}
