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

import _CryptoExtras
public import Crypto
public import Foundation
public import HomomorphicEncryption

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

/// Sharding function that determines the shard a keyword should be in.
public struct ShardingFunction: Hashable, Sendable {
    /// Internal enumeration with supported cases.
    @usableFromInline
    package enum Internal: Hashable, Sendable {
        case sha256
        case doubleMod(otherShardCount: Int)
    }

    /// SHA256 based sharding.
    ///
    /// The shard is determined by `truncate(SHA256(keyword)) % shardCount`.
    public static let sha256: Self = .init(.sha256)

    /// Internal representation.
    @usableFromInline package var function: Internal

    init(_ function: Internal) {
        self.function = function
    }

    /// Sharding is dependent on another usecase.
    ///
    /// The shard is determined by `(truncate(SHA256(keyword)) % otherShardCount) % shardCount`.
    /// - Parameter otherShardCount: Number of shards in the other usecase.
    /// - Returns: Sharding function that depends also on another usecase.
    public static func doubleMod(otherShardCount: Int) -> Self {
        .init(.doubleMod(otherShardCount: otherShardCount))
    }
}

extension ShardingFunction {
    /// Compute the shard index for keyword.
    /// - Parameters:
    ///   - keyword: The keyword.
    ///   - shardCount: Number of shards.
    /// - Returns: An index in the range `0..<shardCount`.
    @inlinable
    public func shardIndex(keyword: KeywordValuePair.Keyword, shardCount: Int) -> Int {
        switch function {
        case .sha256:
            return keyword.shardIndex(shardCount: shardCount)
        case let .doubleMod(otherShardCount):
            let otherShardIndex = keyword.shardIndex(shardCount: otherShardCount)
            return otherShardIndex % shardCount
        }
    }
}

// custom implementation
extension ShardingFunction: Codable {
    enum CodingKeys: String, CodingKey {
        case sha256
        case doubleMod
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        var allKeys = ArraySlice(container.allKeys)
        guard let onlyKey = allKeys.popFirst(), allKeys.isEmpty else {
            throw DecodingError.typeMismatch(
                Self.self,
                DecodingError.Context(
                    codingPath: container.codingPath,
                    debugDescription: "Invalid number of keys found, expected one."))
        }
        switch onlyKey {
        case .sha256:
            self = .sha256
        case .doubleMod:
            let otherShardCount = try container.decode(Int.self, forKey: .doubleMod)
            self = .doubleMod(otherShardCount: otherShardCount)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch function {
        case .sha256:
            try container.encodeNil(forKey: .sha256)
        case let .doubleMod(otherShardCount):
            try container.encode(otherShardCount, forKey: .doubleMod)
        }
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
public struct KeywordDatabaseShard: Hashable, Codable, Sendable {
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
public struct KeywordDatabaseConfig: Hashable, Codable, Sendable {
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
    ///   - shardingFunction: What function to use for sharding.
    ///   - symmetricPirConfig: Configuration for Symmetric PIR.
    /// - Throws: Error upon failure to initialize the database.
    public init(
        rows: some Collection<KeywordValuePair>,
        sharding: Sharding,
        shardingFunction: ShardingFunction = .sha256,
        symmetricPirConfig: SymmetricPirConfig? = nil) throws
    {
        let database = if let symmetricPirConfig {
            try KeywordDatabase.symmetricPIRProcess(database: rows, config: symmetricPirConfig)
                as any Collection<KeywordValuePair>
        } else {
            rows
        }
        let shardCount = switch sharding {
        case let .shardCount(shardCount): shardCount
        case let .entryCountPerShard(entryCountPerShard):
            // Flooring divide ensures `entryCountPerShard` for privacy
            max(rows.count / entryCountPerShard, 1)
        }

        var shards: [String: KeywordDatabaseShard] = [:]
        for row in database {
            let shardID = String(shardingFunction.shardIndex(keyword: row.keyword, shardCount: shardCount))
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
    public struct Arguments<Scalar: ScalarType>: Codable, Sendable {
        /// Database configuration.
        public let databaseConfig: KeywordDatabaseConfig
        /// Encryption parameters.
        public let encryptionParameters: EncryptionParameters<Scalar>
        /// PIR algorithm to process with.
        public let algorithm: PirAlgorithm
        /// Strategy for evaluation key compression.
        public let keyCompression: PirKeyCompressionStrategy
        /// Number of test queries per shard.
        public let trialsPerShard: Int
        /// Encryption key for Symmetric PIR.
        public let symmetricPirConfig: SymmetricPirConfig?

        /// Initializes ``ProcessKeywordDatabase/Arguments`` for database processing.
        /// - Parameters:
        ///   - databaseConfig: Database configuration.
        ///   - encryptionParameters: Encryption parameters.
        ///   - algorithm: PIR algorithm to process with.
        ///   - keyCompression: Strategy for evaluation key compression.
        ///   - trialsPerShard: Number of test queries per shard.
        ///   - symmetricPirConfig: Config for Symmetric PIR.
        ///  - Throws: Error upon invalid arguments
        public init(
            databaseConfig: KeywordDatabaseConfig,
            encryptionParameters: EncryptionParameters<Scalar>,
            algorithm: PirAlgorithm,
            keyCompression: PirKeyCompressionStrategy,
            trialsPerShard: Int,
            symmetricPirConfig: SymmetricPirConfig? = nil) throws
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
            self.keyCompression = keyCompression
            self.trialsPerShard = trialsPerShard
            self.symmetricPirConfig = symmetricPirConfig
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
        /// Number of entries per response.
        public let entryCountPerResponse: [Int]

        /// Initializes a ``ShardValidationResult``.
        /// - Parameters:
        ///   - evaluationKey: Evaluation key.
        ///   - query: Query.
        ///   - response: Response.
        ///   - noiseBudget: Noise budget of the response.
        ///   - computeTimes: Server runtime for each trial.
        ///   - entryCountPerResponse: Number of entries in a single PIR response.
        public init(
            evaluationKey: EvaluationKey<Scheme>,
            query: Query<Scheme>,
            response: Response<Scheme>,
            noiseBudget: Double,
            computeTimes: [Duration],
            entryCountPerResponse: [Int])
        {
            self.evaluationKey = evaluationKey
            self.query = query
            self.response = response
            self.noiseBudget = noiseBudget
            self.computeTimes = computeTimes
            self.entryCountPerResponse = entryCountPerResponse
        }
    }

    /// A processed keyword database.
    public struct Processed<Scheme: HeScheme> {
        /// Evaluation key configuration.
        public let evaluationKeyConfig: EvaluationKeyConfig
        /// Maps each shardID to the associated database shard and PIR parameters.
        public let shards: [String: ProcessedDatabaseWithParameters<Scheme>]

        /// Initializes a processed keyword database.
        /// - Parameters:
        ///   - evaluationKeyConfig: Evaluation key configuration.
        ///   - shards: Database shards.
        @inlinable
        init(evaluationKeyConfig: EvaluationKeyConfig,
             shards: [String: ProcessedDatabaseWithParameters<Scheme>])
        {
            self.evaluationKeyConfig = evaluationKeyConfig
            self.shards = shards
        }
    }

    /// Events happening during shard processing.
    public enum ProcessShardEvent {
        /// A ``CuckooTable`` event.
        case cuckooTableEvent(CuckooTable.Event)
    }

    /// Processes a database shard.
    /// - Parameters:
    ///   - shard: Shard of a keyword database.
    ///   - arguments: Processing arguments.
    ///   - _: Type for auxiliary functionalities used in PIR.
    ///   - onEvent: Function to call when a ``ProcessShardEvent`` happens.
    /// - Returns: The processed database.
    /// - Throws: Error upon failure to process the shard.
    @inlinable
    public static func processShard<PirUtil: PirUtilProtocol>(shard: KeywordDatabaseShard,
                                                              with arguments: Arguments<PirUtil.Scheme.Scalar>,
                                                              using _: PirUtil.Type,
                                                              onEvent: @escaping (ProcessShardEvent) throws
                                                                  -> Void = { _ in
                                                                  }) async throws
        -> ProcessedDatabaseWithParameters<PirUtil.Scheme>
    {
        let keywordConfig = arguments.databaseConfig.keywordPirConfig
        let context = try PirUtil.Scheme.Context(encryptionParameters: arguments.encryptionParameters)
        guard arguments.algorithm == .mulPir else {
            throw PirError.invalidPirAlgorithm(arguments.algorithm)
        }
        return try await KeywordPirServer<MulPirServer<PirUtil>>.process(database: shard,
                                                                         config: keywordConfig,
                                                                         with: context, onEvent: onEvent,
                                                                         symmetricPirConfig: arguments
                                                                             .symmetricPirConfig)
    }

    /// Validates the correctness of processing on a shard.
    /// - Parameters:
    ///   - shard: Processed database shard.
    ///   - row: Keyword-value pair to validate in a PIR query.
    ///   - trials: How many PIR calls to validate. Must be > 0.
    ///   - context: Context for HE computation.
    ///   - _: Type for auxiliary functionalities used in PIR.
    /// - Returns: The shard validation results.
    /// - Throws: Error upon failure to validate the sharding.
    /// - seealso: ``ProcessKeywordDatabase/processShard(shard:with:using:onEvent:)`` to process a shard before
    /// validation.
    @inlinable
    public static func validateShard<PirUtil: PirUtilProtocol>(
        shard: ProcessedDatabaseWithParameters<PirUtil.Scheme>,
        row: KeywordValuePair,
        trials: Int,
        context: PirUtil.Scheme.Context,
        using _: PirUtil.Type) async throws -> ShardValidationResult<PirUtil.Scheme>
    {
        guard trials > 0 else {
            throw PirError.validationError("Invalid trialsPerShard: \(trials)")
        }
        guard let keywordPirParameter = shard.keywordPirParameter else {
            throw PirError.validationError("Shard missing keywordPirParameter")
        }

        let server = try KeywordPirServer<MulPirServer<PirUtil>>(
            context: context,
            processed: shard)

        let client = KeywordPirClient<MulPirClient<PirUtil>>(
            keywordParameter: keywordPirParameter,
            pirParameter: shard.pirParameter,
            context: context)
        var evaluationKey: EvaluationKey<PirUtil.Scheme>?
        var query: Query<PirUtil.Scheme>?
        var response = Response<PirUtil.Scheme>(ciphertexts: [[]])
        let clock = ContinuousClock()
        var minNoiseBudget = Double.infinity
        var results: [(Duration, Int)] = Array(repeating: (.seconds(0), 0), count: trials)
        for trial in 0..<trials {
            let secretKey = try context.generateSecretKey()
            let trialEvaluationKey = try client.generateEvaluationKey(using: secretKey)
            let trialQuery = try client.generateQuery(at: row.keyword, using: secretKey)
            let computeTime = try await clock.measure {
                response = try await server.computeResponse(to: trialQuery, using: trialEvaluationKey)
            }
            let noiseBudget = try response.noiseBudget(using: secretKey, variableTime: true)
            minNoiseBudget = min(minNoiseBudget, noiseBudget)
            let decryptedResponse = try client.decrypt(
                response: response,
                at: row.keyword,
                using: secretKey)
            guard decryptedResponse == row.value else {
                let noiseBudget = try response.noiseBudget(using: secretKey, variableTime: true)
                guard noiseBudget >= PirUtil.Scheme.minNoiseBudget else {
                    throw PirError.validationError("Insufficient noise budget \(noiseBudget)")
                }
                throw PirError.validationError("Incorrect PIR response")
            }

            let entryCount = try client.countEntriesInResponse(response: response, using: secretKey)

            if trial == 0 {
                evaluationKey = trialEvaluationKey
                query = trialQuery
            }
            results[trial] = (computeTime, entryCount)
        }
        guard let evaluationKey, let query else {
            throw PirError.validationError("Empty evaluation key or query")
        }

        let computeTimes = results.map(\.0)
        let entryCounts = results.map(\.1)

        return ShardValidationResult(
            evaluationKey: evaluationKey,
            query: query,
            response: response,
            noiseBudget: minNoiseBudget,
            computeTimes: computeTimes,
            entryCountPerResponse: entryCounts)
    }

    /// Processes the database to prepare for PIR queries.
    /// - Parameters:
    ///   - rows: Rows in the database.
    ///   - arguments: Processing arguments.
    ///   - _: Type for auxiliary functionalities used in PIR.
    /// - Returns: The processed database.
    /// - Throws: Error upon failure to process the database.
    @inlinable
    public static func process<PirUtil: PirUtilProtocol>(
        rows: some Collection<KeywordValuePair>,
        with arguments: Arguments<PirUtil.Scheme.Scalar>,
        using _: PirUtil.Type) async throws -> Processed<PirUtil.Scheme>
    {
        var evaluationKeyConfig = EvaluationKeyConfig()
        let keywordConfig = arguments.databaseConfig.keywordPirConfig

        let context = try PirUtil.Scheme.Context(encryptionParameters: arguments.encryptionParameters)
        let keywordDatabase = try KeywordDatabase(
            rows: rows,
            sharding: arguments.databaseConfig.sharding,
            shardingFunction: keywordConfig.shardingFunction,
            symmetricPirConfig: arguments.symmetricPirConfig)
        var processedShards = [String: ProcessedDatabaseWithParameters<PirUtil.Scheme>]()
        for (shardID, shardedDatabase) in keywordDatabase.shards where !shardedDatabase.isEmpty {
            guard arguments.algorithm == .mulPir else {
                throw PirError.invalidPirAlgorithm(arguments.algorithm)
            }
            let processed = try await KeywordPirServer<MulPirServer<PirUtil>>.process(database: shardedDatabase,
                                                                                      config: keywordConfig,
                                                                                      with: context)
            evaluationKeyConfig = [evaluationKeyConfig, processed.pirParameter.evaluationKeyConfig]
                .union()

            processedShards[shardID] = processed
        }
        return Processed(
            evaluationKeyConfig: evaluationKeyConfig,
            shards: processedShards)
    }
}
