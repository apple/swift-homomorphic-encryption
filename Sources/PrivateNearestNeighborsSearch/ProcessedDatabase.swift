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

public struct ProcessedDatabase<Scheme: HeScheme>: Equatable, Sendable {
    let contexts: [Context<Scheme>]

    /// The processed vectors in the database.
    public let plaintextMatrices: [PlaintextMatrix<Scheme, Eval>]

    /// Unique identifier for each database entry.
    public let entryIds: [UInt64]

    /// Metadata associated for each database entry.
    public let entryMetadatas: [[UInt8]]

    /// Server configuration.
    public let serverConfig: ServerConfig<Scheme>

    /// Serializes the processed database.
    /// - Returns: The serialized processed database.
    /// - Throws: Error upon failure to serialize.
    public func serialize() throws -> SerializedProcessedDatabase<Scheme> {
        try SerializedProcessedDatabase(
            plaintextMatrices: plaintextMatrices
                .map { matrix in try matrix.serialize() },
            entryIds: entryIds,
            entryMetadatas: entryMetadatas,
            serverConfig: serverConfig)
    }
}

extension Database {
    /// Processes the database for neareset neighbors computation.
    /// - Parameter config: Configuration to process with.
    /// - Returns: The processed database.
    /// - Throws: Error upon failure to process the database.
    public func process<Scheme: HeScheme>(with config: ServerConfig<Scheme>) throws -> ProcessedDatabase<Scheme> {
        guard config.distanceMetric == .cosineSimilarity else {
            throw PnnsError.wrongDistanceMetric(got: config.distanceMetric, expected: .cosineSimilarity)
        }
        let vectors = Array2d(data: rows.map { row in row.vector })
        let roundedVectors: Array2d<Scheme.SignedScalar> = vectors
            .normalizedRows(norm: .Lp(p: 2.0))
            .scaled(by: Float(config.clientConfig.scalingFactor)).rounded()

        let contexts = try config.encryptionParameters().map { encryptionParams in
            try Context(encryptionParameters: encryptionParams)
        }
        let plaintextMatrices: [PlaintextMatrix<Scheme, Eval>] = try contexts.map { context in
            // For a single plaintext modulus, reduction isn't necessary
            let shouldReduce = contexts.count > 1
            return try PlaintextMatrix(
                context: context,
                dimensions: MatrixDimensions(
                    rowCount: roundedVectors.rowCount,
                    columnCount: roundedVectors.columnCount),
                packing: config.databasePacking,
                signedValues: roundedVectors.data,
                reduce: shouldReduce).convertToEvalFormat()
        }

        return ProcessedDatabase(
            contexts: contexts,
            plaintextMatrices: plaintextMatrices,
            entryIds: rows.map { row in row.entryId },
            entryMetadatas: rows.map { row in row.entryMetadata },
            serverConfig: config)
    }
}

/// A serialized ``ProcessedDatabase``.
public struct SerializedProcessedDatabase<Scheme: HeScheme>: Equatable, Sendable {
    /// The processed vectors in the database.
    public let plaintextMatrices: [SerializedPlaintextMatrix]

    /// Unique identifier for each database entry.
    public let entryIds: [UInt64]

    /// Associated metadata for each database entry.
    public let entryMetadatas: [[UInt8]]

    /// Server configuration.
    public let serverConfig: ServerConfig<Scheme>

    /// Creates a new ``ProcessedDatabase``.
    /// - Parameters:
    ///   - plaintextMatrices: Plaintext matrices.
    ///   - entryIds: Unique identifier for each database entry.
    ///   - entryMetadatas: Associated metadata for each database entry.
    ///   - serverConfig: Server configuration.
    public init(
        plaintextMatrices: [SerializedPlaintextMatrix],
        entryIds: [UInt64],
        entryMetadatas: [[UInt8]],
        serverConfig: ServerConfig<Scheme>)
    {
        self.plaintextMatrices = plaintextMatrices
        self.entryIds = entryIds
        self.entryMetadatas = entryMetadatas
        self.serverConfig = serverConfig
    }
}
