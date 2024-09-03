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

/// Private nearest neighbors server.
public struct Server<Scheme: HeScheme>: Sendable {
    /// The database.
    public let database: ProcessedDatabase<Scheme>

    /// Configuration.
    public var config: ServerConfig<Scheme> {
        database.serverConfig
    }

    /// Configuration needed for private nearest neighbors search..
    public var evaluationKeyConfig: EvaluationKeyConfig {
        config.clientConfig.evaluationKeyConfig
    }

    /// One context per plaintext modulus.
    public var contexts: [Context<Scheme>] {
        database.contexts
    }

    /// Creates a new ``Server``.
    /// - Parameter database: Processed database.
    /// - Throws: Error upon failure to create the server.
    @inlinable
    public init(database: ProcessedDatabase<Scheme>) throws {
        guard database.serverConfig.distanceMetric == .cosineSimilarity else {
            throw PnnsError.wrongDistanceMetric(got: database.serverConfig.distanceMetric, expected: .cosineSimilarity)
        }
        self.database = database
    }

    /// Compute the encrypted response to a query.
    /// - Parameters:
    ///   - query: Query.
    ///   - evaluationKey: Evaluation key to aid in the server computation.
    /// - Returns: The response.
    /// - Throws: Error upon failure to compute a response.
    @inlinable
    public func computeResponse(to query: Query<Scheme>,
                                using evaluationKey: EvaluationKey<Scheme>) throws -> Response<Scheme>
    {
        guard query.ciphertextMatrices.count == database.plaintextMatrices.count else {
            throw PnnsError.invalidQuery(reason: InvalidQueryReason.wrongCiphertextMatrixCount(
                got: query.ciphertextMatrices.count,
                expected: database.plaintextMatrices.count))
        }

        let responseMatrices = try zip(query.ciphertextMatrices, database.plaintextMatrices)
            .map { ciphertextMatrix, plaintextMatrix in
                // Client query has transposed dimensions
                // TODO: remove (and make CiphertextMatrix.dimensions `let` instead of `var)
                var ciphertextMatrix = ciphertextMatrix
                ciphertextMatrix.dimensions = try MatrixDimensions(
                    rowCount: ciphertextMatrix.columnCount,
                    columnCount: ciphertextMatrix.rowCount)
                var responseMatrix = try plaintextMatrix.mul(
                    ciphertextVector: ciphertextMatrix.convertToCanonicalFormat(),
                    using: evaluationKey)
                // Reduce response size by mod-switching to a single modulus.
                try responseMatrix.modSwitchDownToSingle()
                return try responseMatrix.convertToCoeffFormat()
            }

        return Response(
            ciphertextMatrices: responseMatrices,
            entryIds: database.entryIds,
            entryMetadatas: database.entryMetadatas)
    }
}
