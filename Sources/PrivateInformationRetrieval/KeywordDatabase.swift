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

import Crypto
import Foundation
import HomomorphicEncryption

/// A keyword with an associated value.
public struct KeywordValuePair: Hashable, Codable {
    /// Keyword type.
    public typealias Keyword = [UInt8]
    /// Value type.
    public typealias Value = [UInt8]

    /// The keyword.
    public let keyword: Keyword
    /// The value.
    public let value: Value

    /// Initializes a ``KeywordValuePair``.
    /// - Parameters:
    ///   - keyword: Keyword.
    ///   - value: Value associated with the keyword.
    public init(keyword: Keyword, value: Value) {
        self.keyword = keyword
        self.value = value
    }
}

extension KeywordValuePair.Keyword {
    /// Returns the shard ID for the given shard count.
    /// - Parameters:
    ///  - shardCount: The shard count.
    /// - Returns: The shard identifier.
    @inlinable
    public func shardID(shardCount: Int) -> String {
        String(shardIndex(shardCount: shardCount))
    }

    /// Returns the shard index for the given shard count.
    /// - Parameter shardCount: The shard count.
    /// - Returns: The shard index.
    @inlinable
    public func shardIndex(shardCount: Int) -> Int {
        let digest = SHA256.hash(data: self)
        let truncatedHash = digest.withUnsafeBytes { buffer in
            buffer.load(as: UInt64.self)
        }
        return Int(truncatedHash % UInt64(shardCount))
    }
}

/// Different ways to divide a database into disjoint shards.
public enum Sharding: Hashable, Codable, Sendable {
    /// Divide database into as many shards as needed to average at least `entryCountPerShard` entries per shard.
    case entryCountPerShard(Int)
    /// Divide database into `shardCount` approximately equal-sized shards.
    case shardCount(Int)

    enum CodingKeys: String, CodingKey {
        case entryCountPerShard
        case shardCount
    }

    public init(from decoder: Decoder) throws {
        // Default codable conformance expects a json with "shardCount": { "shardCount": 10 }
        // Custom implementation expects a json with "shardCount": 10
        let container = try decoder.container(keyedBy: CodingKeys.self)
        var allKeys = ArraySlice(container.allKeys)
        guard let onlyKey = allKeys.popFirst(), allKeys.isEmpty else {
            throw DecodingError.typeMismatch(Sharding.self, DecodingError.Context(
                codingPath: container.codingPath,
                debugDescription: "Invalid number of keys found, expected one.",
                underlyingError: nil))
        }
        switch onlyKey {
        case .entryCountPerShard:
            self = try .entryCountPerShard(container.decode(Int.self, forKey: CodingKeys.entryCountPerShard))
        case .shardCount:
            self = try .shardCount(container.decode(Int.self, forKey: CodingKeys.shardCount))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .entryCountPerShard(entryCountPerShard):
            try container.encode(entryCountPerShard, forKey: CodingKeys.entryCountPerShard)
        case let .shardCount(shardCount):
            try container.encode(shardCount, forKey: CodingKeys.shardCount)
        }
    }
}

extension Sharding {
    /// Whether or not a sharding is valid.
    public var isValid: Bool {
        switch self {
        case let .shardCount(shardCount):
            guard shardCount >= 1 else {
                return false
            }
        case let .entryCountPerShard(entryCountPerShard):
            guard entryCountPerShard >= 1 else {
                return false
            }
        }
        return true
    }

    /// Initializes a new ``Sharding`` from a number of shards.
    /// - Parameter shardCount: Number of shards.
    public init?(shardCount: Int) {
        self = .shardCount(shardCount)
        guard isValid else {
            return nil
        }
    }

    /// Initializes a new ``Sharding`` from an entry count per shard.
    /// - Parameter entryCountPerShard: Average number of entries in a shard.
    public init?(entryCountPerShard: Int) {
        self = .entryCountPerShard(entryCountPerShard)
        guard isValid else {
            return nil
        }
    }

    /// Validates the sharding is valid.
    ///
    /// - Throws: Error upon invalid sharding.
    public func validate() throws {
        guard isValid else {
            throw PirError.invalidSharding(self)
        }
    }
}

/// A shard of a ``KeywordDatabase``.
public struct KeywordDatabaseShard: Hashable, Codable {
    /// Identifier for the shard.
    public let shardID: String
    /// Rows in the database.
    public var rows: [KeywordValuePair.Keyword: KeywordValuePair.Value]
    /// Whether or not the database is empty, i.e., has no rows.
    public var isEmpty: Bool {
        rows.isEmpty
    }

    /// Initializes a ``KeywordDatabaseShard``.
    /// - Parameters:
    ///   - shardID: Identifier for the database shard.
    ///   - rows: Rows in the database.
    @inlinable
    public init(
        shardID: String,
        rows: some Collection<(KeywordValuePair.Keyword, KeywordValuePair.Value)>)
    {
        self.shardID = shardID
        self.rows = [KeywordValuePair.Keyword: KeywordValuePair.Value](uniqueKeysWithValues: rows)
    }

    @inlinable
    subscript(_ keyword: KeywordValuePair.Keyword) -> KeywordValuePair.Value? {
        @inlinable
        get {
            rows[keyword]
        }

        @inlinable
        set {
            rows[keyword] = newValue
        }
    }
}

extension KeywordDatabaseShard: Collection {
    public typealias Index = [KeywordValuePair.Keyword: KeywordValuePair.Value].Index
    public typealias Element = KeywordValuePair

    public var startIndex: Index { rows.startIndex }

    public var endIndex: Index { rows.endIndex }

    public func index(after i: Index) -> Index {
        rows.index(after: i)
    }

    public subscript(index: Index) -> Iterator.Element {
        let row = rows[index]
        return KeywordValuePair(keyword: row.key, value: row.value)
    }
}

/// Configuration for a ``KeywordDatabase``.
public struct KeywordDatabaseConfig: Hashable, Codable {
    public let sharding: Sharding
    public let keywordPirConfig: KeywordPirConfig

    /// Initializes a ``KeywordDatabaseConfig``.
    /// - Parameters:
    ///   - sharding: Sharding to use for the database.
    ///   - keywordPirConfig: Keyword PIR configuration.
    public init(
        sharding: Sharding,
        keywordPirConfig: KeywordPirConfig)
    {
        self.sharding = sharding
        self.keywordPirConfig = keywordPirConfig
    }
}

/// Database of keyword-value pairs, divided into shards.
public struct KeywordDatabase {
    /// Shards of the database.
    ///
    /// Each keyword-value pair is in exactly one shard.
    public let shards: [String: KeywordDatabaseShard]

    /// Initializes a ``KeywordDatabase``.
    /// - Parameters:
    ///   - rows: Rows in the database.
    ///   - sharding: How to shard the database.
    /// - Throws: Error upon failure to initialize the database.
    public init(rows: some Collection<KeywordValuePair>, sharding: Sharding) throws {
        let shardCount = switch sharding {
        case let .shardCount(shardCount): shardCount
        case let .entryCountPerShard(entryCountPerShard):
            // Flooring divide ensures `entryCountPerShard` for privacy
            max(rows.count / entryCountPerShard, 1)
        }

        var shards: [String: KeywordDatabaseShard] = [:]
        for row in rows {
            let shardID = String(row.keyword.shardIndex(shardCount: shardCount))
            if let previousValue = shards[shardID, default: KeywordDatabaseShard(shardID: shardID, rows: [])].rows
                .updateValue(
                    row.value,
                    forKey: row.keyword)
            {
                throw PirError
                    .invalidDatabaseDuplicateKeyword(
                        keyword: row.keyword,
                        oldValue: previousValue,
                        newValue: row.value)
            }
        }

        self.shards = shards
    }
}

/// Utilities for processing a ``KeywordDatabase``.
public enum ProcessKeywordDatabase {
    /// Arguments for processing a keyword database.
    public struct Arguments<Scheme: HeScheme>: Codable {
        /// Database configuration.
        public let databaseConfig: KeywordDatabaseConfig
        /// Encryption parameters.
        public let encryptionParameters: EncryptionParameters<Scheme>
        /// PIR algorithm to process with.
        public let algorithm: PirAlgorithm
        /// Number of test queries per shard.
        public let trialsPerShard: Int

        /// Initializes ``ProcessKeywordDatabase/Arguments`` for database processing.
        /// - Parameters:
        ///   - databaseConfig: Database configuration.
        ///   - encryptionParameters: Encryption parameters.
        ///   - algorithm: PIR algorithm to process with.
        ///   - trialsPerShard: number of test queries per shard.
        ///  - Throws: Error upon invalid arguments
        public init(
            databaseConfig: KeywordDatabaseConfig,
            encryptionParameters: EncryptionParameters<Scheme>,
            algorithm: PirAlgorithm,
            trialsPerShard: Int) throws
        {
            guard trialsPerShard >= 0 else {
                throw PirError.validationError("trialsPerShard \(trialsPerShard) must be > 0")
            }
            guard algorithm == .mulPir else {
                throw PirError.invalidPirAlgorithm(algorithm)
            }
            self.databaseConfig = databaseConfig
            self.encryptionParameters = encryptionParameters
            self.algorithm = algorithm
            self.trialsPerShard = trialsPerShard
        }
    }

    /// Validation results for a single shard.
    public struct ShardValidationResult<Scheme: HeScheme> {
        /// An evaluation key.
        public let evaluationKey: EvaluationKey<Scheme>
        /// A query.
        public let query: Query<Scheme>
        /// A response.
        public let response: Response<Scheme>
        /// Minimum noise budget over all responses.
        public let noiseBudget: Double
        /// Server runtimes.
        public let computeTimes: [Duration]

        /// Initializes a ``ShardValidationResult``.
        /// - Parameters:
        ///   - evaluationKey: Evaluation key
        ///   - query: Query.
        ///   - response: Response.
        ///   - noiseBudget: Noise budget of the response.
        ///   - computeTimes: Server runtimes.
        public init(
            evaluationKey: EvaluationKey<Scheme>,
            query: Query<Scheme>,
            response: Response<Scheme>,
            noiseBudget: Double,
            computeTimes: [Duration])
        {
            self.evaluationKey = evaluationKey
            self.response = response
            self.computeTimes = computeTimes
            self.query = query
            self.noiseBudget = noiseBudget
        }
    }

    /// A processed keyword database.
    public struct Processed<Scheme: HeScheme> {
        /// Evaluation key configuration.
        public let evaluationKeyConfiguration: EvaluationKeyConfiguration
        /// Maps each shardID to the associated database shard and PIR parameters.
        public let shards: [String: ProcessedDatabaseWithParameters<Scheme>]

        /// Initializes a processed keyword database.
        /// - Parameters:
        ///   - evaluationKeyConfiguration: Evaluation key configuration.
        ///   - shards: Database shards.
        @inlinable
        init(evaluationKeyConfiguration: EvaluationKeyConfiguration,
             shards: [String: ProcessedDatabaseWithParameters<Scheme>])
        {
            self.evaluationKeyConfiguration = evaluationKeyConfiguration
            self.shards = shards
        }
    }

    /// Processes a database shard.
    /// - Parameters:
    ///   - shard: Shard of a keyword database.
    ///   - arguments: Processing arguments.
    /// - Returns: The processed database.
    /// - Throws: Error upon failure to process the shard.
    @inlinable
    public static func processShard<Scheme: HeScheme>(shard: KeywordDatabaseShard,
                                                      with arguments: Arguments<Scheme>) throws
        -> ProcessedDatabaseWithParameters<Scheme>
    {
        let keywordConfig = arguments.databaseConfig.keywordPirConfig
        let context = try Context(encryptionParameters: arguments.encryptionParameters)
        guard arguments.algorithm == .mulPir else {
            throw PirError.invalidPirAlgorithm(arguments.algorithm)
        }
        return try KeywordPirServer<MulPirServer<Scheme>>.process(database: shard,
                                                                  config: keywordConfig,
                                                                  with: context)
    }

    /// Validates the correctness of processing on a shard.
    /// - Parameters:
    ///   - shard: Processed database shard.
    ///   - row: Keyword-value pair to validate in a PIR query.
    ///   - trials: How many PIR calls to validate. Must be > 0.
    ///   - context: Context for HE computation.
    /// - Returns: The shard validation results.
    /// - Throws: Error upon failure to validate the sharding.
    /// - seealso: ``ProcessKeywordDatabase/processShard(shard:with:)`` to process a shard before validation.
    @inlinable
    public static func validateShard<Scheme: HeScheme>(
        shard: ProcessedDatabaseWithParameters<Scheme>,
        row: KeywordValuePair,
        trials: Int,
        context: Context<Scheme>) throws -> ShardValidationResult<Scheme>
    {
        guard trials > 0 else {
            throw PirError.validationError("Invalid trialsPerShard: \(trials)")
        }
        guard let keywordPirParameter = shard.keywordPirParameter else {
            throw PirError.validationError("Shard missing keywordPirParameter")
        }

        let server = try KeywordPirServer<MulPirServer<Scheme>>(
            context: context,
            processed: shard)

        let client = KeywordPirClient<MulPirClient<Scheme>>(
            keywordParameter: keywordPirParameter,
            pirParameter: shard.pirParameter,
            context: context)
        var evaluationKey: EvaluationKey<Scheme>?
        var query: Query<Scheme>?
        var response = Response<Scheme>(ciphertexts: [[]])
        let clock = ContinuousClock()
        var minNoiseBudget = Double.infinity
        let computeTimes = try (0..<trials).map { trial in
            let secretKey = try Scheme.generateSecretKey(context: context)
            let trialEvaluationKey = try client.generateEvaluationKey(using: secretKey)
            let trialQuery = try client.generateQuery(at: row.keyword, using: secretKey)
            let computeTime = try clock.measure {
                response = try server.computeResponse(to: trialQuery, using: trialEvaluationKey)
            }
            let noiseBudget = try response.noiseBudget(using: secretKey, variableTime: true)
            minNoiseBudget = min(minNoiseBudget, noiseBudget)
            let decryptedResponse = try client.decrypt(
                response: response,
                at: row.keyword,
                using: secretKey)
            guard decryptedResponse == row.value else {
                let noiseBudget = try response.noiseBudget(using: secretKey, variableTime: true)
                guard noiseBudget >= Scheme.minNoiseBudget else {
                    throw PirError.validationError("Insufficient noise budget \(noiseBudget)")
                }
                throw PirError.validationError("Incorrect PIR response")
            }

            if trial == 0 {
                evaluationKey = trialEvaluationKey
                query = trialQuery
            }
            return computeTime
        }
        guard let evaluationKey, let query else {
            throw PirError.validationError("Empty evaluation key or query")
        }
        return ShardValidationResult(
            evaluationKey: evaluationKey,
            query: query,
            response: response,
            noiseBudget: minNoiseBudget,
            computeTimes: computeTimes)
    }

    /// Processes the database to prepare for PIR queries.
    /// - Parameters:
    ///   - rows: Rows in the database.
    ///   - arguments: Processing arguments.
    /// - Returns: The processed database.
    /// - Throws: Error upon failure to process the database.
    @inlinable
    public static func process<Scheme: HeScheme>(rows: some Collection<KeywordValuePair>,
                                                 with arguments: Arguments<Scheme>) throws -> Processed<Scheme>
    {
        var evaluationKeyConfiguration = EvaluationKeyConfiguration()
        let keywordConfig = arguments.databaseConfig.keywordPirConfig

        let context = try Context(encryptionParameters: arguments.encryptionParameters)
        let keywordDatabase = try KeywordDatabase(rows: rows, sharding: arguments.databaseConfig.sharding)

        var processedShards = [String: ProcessedDatabaseWithParameters<Scheme>]()
        for (shardID, shardedDatabase) in keywordDatabase.shards where !shardedDatabase.isEmpty {
            guard arguments.algorithm == .mulPir else {
                throw PirError.invalidPirAlgorithm(arguments.algorithm)
            }
            let processed = try KeywordPirServer<MulPirServer<Scheme>>.process(database: shardedDatabase,
                                                                               config: keywordConfig,
                                                                               with: context)
            evaluationKeyConfiguration = [
                evaluationKeyConfiguration,
                MulPir.evaluationKeyConfiguration(
                    parameter: processed.pirParameter,
                    encryptionParameters: arguments.encryptionParameters),
            ].union()

            processedShards[shardID] = processed
        }
        return Processed(
            evaluationKeyConfiguration: evaluationKeyConfiguration,
            shards: processedShards)
    }
}
