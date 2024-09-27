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

/// A nearest neighbor search query.
public struct Query<Scheme: HeScheme>: Equatable, Sendable {
    /// Encrypted query; one matrix per plaintext CRT modulus.
    public let ciphertextMatrices: [CiphertextMatrix<Scheme, Coeff>]

    /// Creates a ``Query``.
    /// - Parameter ciphertextMatrices: Encrypted query.
    public init(ciphertextMatrices: [CiphertextMatrix<Scheme, Coeff>]) {
        self.ciphertextMatrices = ciphertextMatrices
    }
}

/// A nearest neighbor search response.
public struct Response<Scheme: HeScheme>: Sendable {
    /// Encrypted distances; one matrix per plaintext CRT modulus.
    public let ciphertextMatrices: [CiphertextMatrix<Scheme, Coeff>]
    /// The entry identifiers the server computed distances for.
    public let entryIds: [UInt64]
    /// Metadata for each entry the server computed distances for.
    public let entryMetadatas: [[UInt8]]

    /// Creates a new ``Response``.
    /// - Parameters:
    ///   - ciphertextMatrices: Encrypted distances; one matrix per plaintext CRT modulus.
    ///   - entryIds: An identifiers the server computed distances for.
    ///   - entryMetadatas: Metadata for each entry the server computed distances for.
    public init(
        ciphertextMatrices: [CiphertextMatrix<Scheme, Coeff>] = [],
        entryIds: [UInt64] = [],
        entryMetadatas: [[UInt8]] = [])
    {
        self.ciphertextMatrices = ciphertextMatrices
        self.entryIds = entryIds
        self.entryMetadatas = entryMetadatas
    }
}

/// Distances from one or more query vector to the database rows.
public struct DatabaseDistances: Sendable {
    /// Each row contains the distances from a database entry to each query vector.
    public let distances: Array2d<Float>
    /// Identifier for each entry in the database.
    public let entryIds: [UInt64]
    /// Metadata for each entry in the database.
    public let entryMetadatas: [[UInt8]]

    /// Creates a new ``DatabaseDistances``.
    /// - Parameters:
    ///   - distances: Each row contains the distances from a database entry to each query vector.
    ///   - entryIds: Identifier for each entry in the database
    ///   - entryMetadatas: Metadata for each entry in the database
    public init(
        distances: Array2d<Float> = Array2d(),
        entryIds: [UInt64] = [],
        entryMetadatas: [[UInt8]] = [])
    {
        self.distances = distances
        self.entryIds = entryIds
        self.entryMetadatas = entryMetadatas
    }
}

extension Response {
    /// Computes the noise budget of the response.
    ///
    /// The *noise budget* of the each ciphertext in the response decreases throughout HE operations. Once a
    /// ciphertext's noise budget is
    /// below
    /// `HeScheme/minNoiseBudget`, decryption may yield inaccurate plaintexts.
    /// - Parameters:
    ///   - secretKey: Secret key.
    ///   - variableTime: If `true`, indicates the secret key coefficients may be leaked through timing.
    /// - Returns: The noise budget.
    /// - Throws: Error upon failure to compute the noise budget.
    /// - Warning: Leaks `secretKey` through timing. Should be used for testing only.
    /// - Warning: The noise budget depends on the encrypted message, which is impractical to know apriori. So this
    /// function should be treated only as a rough proxy for correct decryption, rather than a source of truth.
    ///   See Section 2 of <https://eprint.iacr.org/2016/510.pdf> for more details.
    @inlinable
    public func noiseBudget(using secretKey: Scheme.SecretKey, variableTime: Bool) throws -> Double {
        try ciphertextMatrices.map { ciphertextMatrix in
            try ciphertextMatrix.noiseBudget(using: secretKey, variableTime: variableTime)
        }.min() ?? -Double.infinity
    }
}
