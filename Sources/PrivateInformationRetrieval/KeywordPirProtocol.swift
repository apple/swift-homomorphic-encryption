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

import Foundation
import HomomorphicEncryption

/// Configuration for a ``KeywordDatabase``.
public struct KeywordPirConfig: Hashable, Codable, Sendable {
    /// Number of dimensions in the database.
    @usableFromInline let dimensionCount: Int

    /// Configuration for the cuckoo table.
    @usableFromInline let cuckooTableConfig: CuckooTableConfig

    /// Whether to enable the `uneven dimensions` optimization.
    @usableFromInline let unevenDimensions: Bool

    /// Strategy for ``EvaluationKey`` compression.
    @usableFromInline let keyCompression: PirKeyCompressionStrategy

    /// When set to true, entry size will be equal to ``CuckooTableConfig/maxSerializedBucketSize``.
    ///
    /// Otherwise the largest serialized bucket size is used instead.
    @usableFromInline let useMaxSerializedBucketSize: Bool

    /// Sharding function configuration.
    @usableFromInline let shardingFunction: ShardingFunction

    /// Keyword PIR parameters.
    public var parameter: KeywordPirParameter {
        KeywordPirParameter(hashFunctionCount: cuckooTableConfig.hashFunctionCount, shardingFunction: shardingFunction)
    }

    /// Initializes a ``KeywordPirConfig``.
    /// - Parameters:
    ///   - dimensionCount: Number of dimensions in the database.
    ///   - cuckooTableConfig: Cuckoo table configuration.
    ///   - unevenDimensions: Whether to enable the `uneven dimensions` optimization.
    ///   - keyCompression: Strategy for evaluation key compression.
    ///   - useMaxSerializedBucketSize: Enable this to set the entry size in index PIR layer to
    /// ``CuckooTableConfig/maxSerializedBucketSize``. When not enabled, the largest serialized bucket size is used
    /// instead.
    ///   - shardingFunction: The sharding function to use.
    /// - Throws: Error upon invalid arguments.
    public init(
        dimensionCount: Int,
        cuckooTableConfig: CuckooTableConfig,
        unevenDimensions: Bool,
        keyCompression: PirKeyCompressionStrategy,
        useMaxSerializedBucketSize: Bool = false,
        shardingFunction: ShardingFunction = .sha256) throws
    {
        let validDimensionsCount = [1, 2]
        guard validDimensionsCount.contains(dimensionCount) else {
            throw PirError.invalidDimensionCount(dimensionCount: dimensionCount, expected: validDimensionsCount)
        }
        guard cuckooTableConfig.multipleTables else {
            throw PirError.invalidCuckooConfig(config: cuckooTableConfig)
        }
        self.dimensionCount = dimensionCount
        self.cuckooTableConfig = cuckooTableConfig
        self.unevenDimensions = unevenDimensions
        self.keyCompression = keyCompression
        self.useMaxSerializedBucketSize = useMaxSerializedBucketSize
        self.shardingFunction = shardingFunction
    }
}

/// Parameters for a keyword PIR lookup.
///
/// Must be the same between client and server for a correct database lookup.
public struct KeywordPirParameter: Hashable, Codable, Sendable {
    /// Number of hash functions in the ``CuckooTableConfig``.
    public let hashFunctionCount: Int

    /// Sharding function used.
    public let shardingFunction: ShardingFunction

    /// Initializes a ``KeywordPirParameter``.
    /// - Parameters:
    ///   - hashFunctionCount: Number of hash functions in the ``CuckooTableConfig``.
    ///   - shardingFunction: Sharding function that was used for sharding.
    public init(hashFunctionCount: Int, shardingFunction: ShardingFunction = .sha256) {
        self.hashFunctionCount = hashFunctionCount
        self.shardingFunction = shardingFunction
    }
}

/// Protocol for a Keyword PIR lookup.
public protocol KeywordPirProtocol {
    /// Index PIR type backing the keyword PIR computation.
    associatedtype IndexPir: IndexPirProtocol
    /// Encrypted query type.
    typealias Query = IndexPir.Query
    /// Encrypted server response type.
    typealias Response = IndexPir.Response
    /// HE scheme used for PIR computation.
    typealias Scheme = IndexPir.Scheme

    /// Evaluation key configuration.
    ///
    /// This tells the client what to include in the evaluation key. Must be the same between client and server.
    var evaluationKeyConfig: EvaluationKeyConfig { get }
}

/// A server that can compute encrypted keyword PIR results.
///
/// The server computes the response to a keyword PIR query by transforming the database to an Index PIR database using
/// cuckoo hashing.
public final class KeywordPirServer<PirServer: IndexPirServer>: KeywordPirProtocol, Sendable {
    public typealias IndexPir = PirServer.IndexPir
    public typealias Query = IndexPir.Query
    public typealias Response = IndexPir.Response
    public typealias Scheme = IndexPir.Scheme

    @usableFromInline let indexPirServer: PirServer

    /// Index PIR parameters for the index PIR database.
    ///
    /// Must be the same between client and server.
    public var indexPirParameter: IndexPirParameter { indexPirServer.parameter }

    public var evaluationKeyConfig: EvaluationKeyConfig { indexPirServer.evaluationKeyConfig }

    /// Initializes a ``KeywordPirServer``.
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - processed: Processed database.
    /// - Throws: Error upon failure to initialize the server.
    public required init(context: Context<Scheme>,
                         processed: ProcessedDatabaseWithParameters<Scheme>) throws
    {
        if let keywordPirParameter = processed.keywordPirParameter {
            let subTableSize = processed.database.count / keywordPirParameter.hashFunctionCount
            let tables = stride(from: 0, to: processed.database.count, by: subTableSize).map { startIndex in
                PirServer
                    .Database(plaintexts: Array(processed.database.plaintexts[startIndex..<startIndex + subTableSize]))
            }
            self.indexPirServer = try PirServer(parameter: processed.pirParameter, context: context, databases: tables)
            return
        }
        self.indexPirServer = try PirServer(
            parameter: processed.pirParameter,
            context: context,
            databases: [processed.database])
    }

    /// Processes the database to prepare for PIR queries.
    ///
    /// This processing must be performed whenever the database changes.
    /// - Parameters:
    ///   - database: Collection of database entries.
    ///   - config: Keyword PIR configuration.
    ///   - context: Context for HE computation.
    ///   - onEvent: Function to call when a ``ProcessKeywordDatabase/ProcessShardEvent`` happens.
    /// - Returns: A processed database.
    /// - Throws: Error upon failure to process the database.
    @inlinable
    public static func process(database: some Collection<KeywordValuePair>,
                               config: KeywordPirConfig,
                               with context: Context<Scheme>,
                               onEvent: @escaping (ProcessKeywordDatabase.ProcessShardEvent) throws -> Void = { _ in })
        throws -> ProcessedDatabaseWithParameters<Scheme>
    {
        func onCuckooEvent(event: CuckooTable.Event) throws {
            try onEvent(ProcessKeywordDatabase.ProcessShardEvent.cuckooTableEvent(event))
        }

        let cuckooTableConfig = config.cuckooTableConfig
        let cuckooTable = try CuckooTable(config: cuckooTableConfig, database: database, onEvent: onCuckooEvent)
        let entryTable = try cuckooTable.serializeBuckets()
        let maxEntrySize: Int
        if config.useMaxSerializedBucketSize {
            maxEntrySize = cuckooTableConfig.maxSerializedBucketSize
        } else {
            switch cuckooTable.config.bucketCount {
            case .allowExpansion:
                guard let foundMaxEntrySize = entryTable.map(\.count).max() else {
                    throw PirError.emptyDatabase
                }
                maxEntrySize = foundMaxEntrySize
            case .fixedSize:
                maxEntrySize = cuckooTableConfig.maxSerializedBucketSize
            }
        }

        let indexPirConfig = try IndexPirConfig(
            entryCount: cuckooTable.bucketsPerTable,
            entrySizeInBytes: maxEntrySize,
            dimensionCount: config.dimensionCount,
            batchSize: cuckooTableConfig.hashFunctionCount,
            unevenDimensions: config.unevenDimensions,
            keyCompression: config.keyCompression)
        let indexPirParameter = PirServer.generateParameter(config: indexPirConfig, with: context)

        let processedDb = try PirServer.Database(plaintexts: stride(
            from: 0,
            to: entryTable.count,
            by: cuckooTable.bucketsPerTable).flatMap { startIndex in
            try PirServer.process(
                database: entryTable[startIndex..<startIndex + cuckooTable.bucketsPerTable],
                with: context,
                using: indexPirParameter).plaintexts
        })
        let evaluationKeyConfig = indexPirParameter.evaluationKeyConfig

        return ProcessedDatabaseWithParameters(
            database: processedDb,
            algorithm: PirServer.IndexPir.algorithm,
            evaluationKeyConfig: evaluationKeyConfig,
            pirParameter: indexPirParameter,
            keywordPirParameter: config.parameter)
    }

    /// Compute the encrypted response to a query lookup.
    /// - Parameters:
    ///   - query: Encrypted query.
    ///   - evaluationKey: Evaluation key to aid in the server computation.
    /// - Returns: The encrypted response.
    /// - Throws: Error upon failure to compute a response.
    @inlinable
    public func computeResponse(to query: Query,
                                using evaluationKey: EvaluationKey<Scheme>) throws -> Response
    {
        try indexPirServer.computeResponse(to: query, using: evaluationKey)
    }
}

/// Client which can perform keyword PIR requests.
public final class KeywordPirClient<PirClient: IndexPirClient>: KeywordPirProtocol, Sendable {
    /// Index PIR type backing the keyword PIR computation.
    public typealias IndexPir = PirClient.IndexPir

    /// Encrypted query type.
    public typealias Query = IndexPir.Query

    /// Encrypted server response type.
    public typealias Response = IndexPir.Response

    /// HE scheme used for PIR computation.
    public typealias Scheme = IndexPir.Scheme

    let keywordParameter: KeywordPirParameter
    let indexPirClient: PirClient

    /// Index PIR parameters for the index PIR database.
    ///
    /// Must be the same between client and server.
    var indexPirParameter: IndexPirParameter { indexPirClient.parameter }

    public var evaluationKeyConfig: EvaluationKeyConfig { indexPirClient.evaluationKeyConfig }

    /// Initializes a ``KeywordPirClient``.
    /// - Parameters:
    ///   - keywordParameter: Keyword PIR parameters.
    ///   - pirParameter: Index PIR parameters for the transformed keyword to index database.
    ///   - context: Context for HE computation.
    public required init(
        keywordParameter: KeywordPirParameter,
        pirParameter: IndexPirParameter,
        context: Context<IndexPir.Scheme>)
    {
        self.keywordParameter = keywordParameter
        self.indexPirClient = PirClient(parameter: pirParameter, context: context)
    }

    /// Generates an encrypted query.
    /// - Parameters:
    ///   - keyword: Keyword whose associated value to lookup.
    ///   - secretKey: Secret key used for the query.
    /// - Returns: An encrypted query.
    /// - Throws: Error upon failure to generate a query.
    public func generateQuery(at keyword: [UInt8],
                              using secretKey: SecretKey<Scheme>) throws -> Query
    {
        let indices = HashKeyword.hashIndices(
            keyword: keyword,
            bucketCount: indexPirClient.parameter.entryCount,
            hashFunctionCount: keywordParameter.hashFunctionCount)
        return try indexPirClient.generateQuery(at: indices, using: secretKey)
    }

    /// Decrypts an encrypted response.
    /// - Parameters:
    ///   - response: Encrypted response from a PIR query.
    ///   - keyword: Keyword which was queried.
    ///   - secretKey: Secret key used for decryption.
    /// - Returns: The value associated with the keyword, or `nil` if no associated value was found.
    /// - Throws: Error upon failure to decrypt.
    public func decrypt(response: Response, at keyword: [UInt8],
                        using secretKey: SecretKey<Scheme>) throws -> [UInt8]?
    {
        let indices = HashKeyword.hashIndices(
            keyword: keyword,
            bucketCount: indexPirClient.parameter.entryCount,
            hashFunctionCount: keywordParameter.hashFunctionCount)
        let hash = HashKeyword.hash(keyword: keyword)
        let serializedBuckets = try indexPirClient.decrypt(response: response, at: indices, using: secretKey)
        for serializedBucket in serializedBuckets {
            let bucket = try HashBucket(deserialize: serializedBucket)
            if let value = bucket.find(hash: hash) {
                return value
            }
        }
        return nil
    }

    /// Generates an `EvaluationKey` for use in server-side PIR computation.
    /// - Parameter secretKey: Secret key used to generate the evaluation key.
    /// - Returns: An `EvaluationKey` for use in sever-side computation.
    /// - Throws: Error upon failure to generate an evaluation key.
    /// - Warning: The evaluation key is only valid for use with the given `secretKey`.
    public func generateEvaluationKey(using secretKey: SecretKey<Scheme>) throws -> EvaluationKey<Scheme> {
        try indexPirClient.generateEvaluationKey(using: secretKey)
    }

    /// Count the number of entries contained in a PIR response.
    /// - Parameters:
    ///   - response: PIR response.
    ///   - secretKey: The secret key to use for decrypting the response.
    /// - Returns: The number of entries that were contained in the response.
    /// - Throws: Error upon failure to decrypt.
    public func countEntriesInResponse(response: Response, using secretKey: SecretKey<Scheme>) throws -> Int {
        var entriesFound = 0
        let responses = try indexPirClient.decryptFull(response: response, using: secretKey)
        for bytes in responses {
            // scan for hashbuckets in the reply bytes
            //
            // note: that zero byte is a valid hashbucket with 0 entries and length one
            // so we will scan over the zero padding
            var offset = 0
            while let bucket = try? HashBucket(deserialize: Array(bytes[offset...])) {
                entriesFound += bucket.slots.count
                offset += bucket.serializedSize()
            }
        }
        return entriesFound
    }
}
