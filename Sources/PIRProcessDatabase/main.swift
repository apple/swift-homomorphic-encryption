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

import ApplicationProtobuf
import ArgumentParser
import Crypto
import Foundation
import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import Logging
import PrivateInformationRetrieval

/// The different table sizes that can be used for the PIR database.
enum TableSizeOption: Codable, Equatable, Hashable {
    /// An `allowExpansion` option allows the database to grow as needed.
    case allowExpansion(targetLoadFactor: Double?, expansionFactor: Double?)
    /// fixes size to `bucketCount` buckets per entry.
    case fixedSize(bucketCount: Int)

    /// The default target load factor for the PIR database.
    static let defaultTargetLoadFactor = 0.9
    /// The default expansion factor for the PIR database.
    static let defaultExpansionFactor = 1.1
}

/// The configuration for Symmetric PIR.
struct SymmetricPirArguments: Codable, Hashable {
    /// File path for key with which database will be encrypted.
    ///
    /// Also see ``outputDatabaseEncryptionKeyFilePath``.
    let databaseEncryptionKeyFilePath: String?
    /// Config type for Symmetric PIR.
    let configType: SymmetricPirConfigType?
    /// Path to write newly generated database encryption key.
    ///
    /// If this is specified, a new database encryption key will be generated and written to this path.
    /// This key will be used to encrypt the database for Symmetric PIR.
    /// Exactly one of ``outputDatabaseEncryptionKeyFilePath`` or ``databaseEncryptionKeyFilePath`` should be present.
    let outputDatabaseEncryptionKeyFilePath: String?

    /// Returns a parsed `SymmetricPirConfig` for given parameters.
    /// - Returns: Symmetric PIR config.
    func resolve() throws -> SymmetricPirConfig {
        if outputDatabaseEncryptionKeyFilePath != nil, databaseEncryptionKeyFilePath != nil {
            throw ValidationError(
                """
                Both `databaseEncryptionKeyFilePath` and `outputDatabaseEncryptionKeyFilePath` \
                can not be present in `symmetricPirArguments`.
                """)
        }
        let configType = configType ?? .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128
        if let databaseEncryptionKeyFilePath {
            do {
                let secretKeyString = try String(contentsOfFile: databaseEncryptionKeyFilePath, encoding: .utf8)
                guard let secretKey = Array(hexEncoded: secretKeyString) else {
                    throw PirError.invalidOPRFHexSecretKey
                }
                try configType.validateEncryptionKey(secretKey)
                return try SymmetricPirConfig(oprfSecretKey: Secret(value: secretKey), configType: configType)
            } catch {
                throw PirError.failedToLoadOPRFKey(underlyingError: "\(error)", filePath: databaseEncryptionKeyFilePath)
            }
        }
        if let outputDatabaseEncryptionKeyFilePath {
            switch configType {
            case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128:
                let secretKey = [UInt8](P384._VOPRF.PrivateKey().rawRepresentation)
                try secretKey.hexString.write(
                    toFile: outputDatabaseEncryptionKeyFilePath,
                    atomically: true,
                    encoding: .utf8)
                return try SymmetricPirConfig(
                    oprfSecretKey: Secret(value: secretKey), configType: .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128)
            }
        }
        throw ValidationError(
            """
            One of `databaseEncryptionKeyFilePath` or `outputDatabaseEncryptionKeyFilePath`\
            should be present in `symmetricPirArguments`.
            """)
    }
}

/// A struct representing the arguments for the `cuckooTable` command.
struct CuckooTableArguments: Codable, Equatable, Hashable {
    let hashFunctionCount: Int?
    let maxEvictionCount: Int?
    let maxSerializedBucketSize: Int?
    let bucketCount: TableSizeOption?
    let slotCount: Int?

    /// - Parameters:
    ///  - hashFunctionCount: The number of hashes to use in the cuckoo table.
    ///  - maxEvictionCount: The maximum number of evictions before re-making the cuckoo table.
    ///  - maxSerializedBucketSize: The maximum number of bytes per serialized bucket.
    ///  - bucketCount: The number of buckets.
    ///  - slotCount: Then number of slots in a bucket.
    init(hashFunctionCount: Int? = nil,
         maxEvictionCount: Int? = nil,
         maxSerializedBucketSize: Int? = nil,
         bucketCount: TableSizeOption? = nil,
         slotCount: Int? = nil)
    {
        self.hashFunctionCount = hashFunctionCount
        self.maxEvictionCount = maxEvictionCount
        self.maxSerializedBucketSize = maxSerializedBucketSize
        self.bucketCount = bucketCount
        self.slotCount = slotCount
    }

    /// Returns a `CuckooTableConfig` with the given parameters.
    /// - Parameter maxSerializedBucketSize: The maximum number of bytes per serialized bucket.
    /// - Returns: Cuckoo Table configuration.
    /// - Throws: Error upon failure to resolve the cuckoo table configuration.
    func resolve(maxSerializedBucketSize: Int) throws -> CuckooTableConfig {
        let bucketCount: CuckooTableConfig.BucketCountConfig = switch bucketCount {
        case let .allowExpansion(targetLoadFactor, expansionFactor):
            .allowExpansion(
                expansionFactor: expansionFactor ?? TableSizeOption.defaultExpansionFactor,
                targetLoadFactor: targetLoadFactor ?? TableSizeOption.defaultTargetLoadFactor)
        case let .fixedSize(bucketCount):
            .fixedSize(bucketCount: bucketCount)
        case nil:
            .allowExpansion(
                expansionFactor: TableSizeOption.defaultExpansionFactor,
                targetLoadFactor: TableSizeOption.defaultTargetLoadFactor)
        }

        let hashFunctionCount = hashFunctionCount ?? 2
        let maxEvictionCount = maxEvictionCount ?? 100
        if let slotCount {
            return try CuckooTableConfig(
                hashFunctionCount: hashFunctionCount,
                maxEvictionCount: maxEvictionCount,
                maxSerializedBucketSize: maxSerializedBucketSize,
                bucketCount: bucketCount,
                slotCount: slotCount)
        }
        return try CuckooTableConfig(
            hashFunctionCount: hashFunctionCount,
            maxEvictionCount: maxEvictionCount,
            maxSerializedBucketSize: maxSerializedBucketSize,
            bucketCount: bucketCount)
    }
}

extension String {
    /// Performs validation on proto file name.
    /// - Parameter descriptor: The proto file name to validate.
    /// - Throws: Error upon invalid file name.
    func validateProtoFilename(descriptor: String) throws {
        guard hasSuffix(".txtpb") || hasSuffix(".binpb") else {
            throw ValidationError("'\(descriptor)' must contain have extension '.txtpb' or '.binpb', found \(self)")
        }
    }
}

extension KeywordDatabase {
    /// Creates a new `KeywordDatabase` from a given path.
    /// - Parameters:
    ///   - path: The path to the `KeywordDatabase` file.
    ///   - sharding: The sharding strategy to use.
    /// - Throws: Error upon failure to initialize the database.
    init(from path: String, sharding: Sharding) throws {
        let database = try Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase(from: path)
        try self.init(rows: database.native(), sharding: sharding)
    }
}

/// A struct that represents the database processing arguments.
struct Arguments: Codable, Equatable, Hashable, Sendable {
    /// The default arguments.
    static let defaultArguments = Arguments(
        inputDatabase: "/path/to/input/database.txtpb",
        outputDatabase: "/path/to/output/database-SHARD_ID.bin",
        outputPirParameters: "path/to/output/pir-parameters-SHARD_ID.txtpb",
        rlweParameters: .n_4096_logq_27_28_28_logt_5,
        outputEvaluationKeyConfig: "/path/to/output/evaluation-key-config.txtpb")

    let inputDatabase: String
    let outputDatabase: String
    let outputPirParameters: String
    let rlweParameters: PredefinedRlweParameters
    let outputEvaluationKeyConfig: String?
    var sharding: Sharding?
    var shardingFunction: ShardingFunction?
    var cuckooTableArguments: CuckooTableArguments?
    var algorithm: PirAlgorithm?
    var keyCompression: PirKeyCompressionStrategy?
    // swiftlint:disable:next discouraged_optional_boolean
    var useMaxSerializedBucketSize: Bool?
    var symmetricPirArguments: SymmetricPirArguments?
    var trialsPerShard: Int?

    static func defaultJsonString() -> String {
        // swiftlint:disable:next force_try
        let resolved = try! defaultArguments.resolve(for: [], scheme: Bfv<UInt64>.self)
        let resolvedCuckooConfig = resolved.cuckooTableConfig
        let resolvedBucketCount = switch resolvedCuckooConfig.bucketCount {
        case let .allowExpansion(
            expansionFactor: expansionFactor,
            targetLoadFactor: targetLoadFactor):
            TableSizeOption
                .allowExpansion(
                    targetLoadFactor: targetLoadFactor,
                    expansionFactor: expansionFactor)
        case let .fixedSize(bucketCount: bucketCount):
            TableSizeOption.fixedSize(bucketCount: bucketCount)
        }
        let cuckooTableArguments = CuckooTableArguments(
            hashFunctionCount: resolvedCuckooConfig.hashFunctionCount,
            maxEvictionCount: resolvedCuckooConfig.maxEvictionCount,
            maxSerializedBucketSize: resolvedCuckooConfig.maxSerializedBucketSize,
            bucketCount: resolvedBucketCount)
        let defaultArguments = Arguments(
            inputDatabase: resolved.inputDatabase,
            outputDatabase: resolved.outputDatabase,
            outputPirParameters: resolved.outputPirParameters,
            rlweParameters: resolved.rlweParameters,
            outputEvaluationKeyConfig: resolved.outputEvaluationKeyConfig,
            sharding: resolved.sharding,
            shardingFunction: resolved.shardingFunction,
            cuckooTableArguments: cuckooTableArguments,
            algorithm: resolved.algorithm,
            keyCompression: PirKeyCompressionStrategy.noCompression,
            trialsPerShard: resolved.trialsPerShard)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // swiftlint:disable:next force_try
        let data = try! encoder.encode(defaultArguments)
        // swiftlint:disable:next optional_data_string_conversion
        return String(decoding: data, as: UTF8.self)
    }

    func resolve<Scheme: HeScheme>(for database: [KeywordValuePair],
                                   scheme _: Scheme.Type) throws -> ResolvedArguments
    {
        let cuckooTableArguments = cuckooTableArguments ?? CuckooTableArguments()
        let maxValueSize = database.map { row in row.value.count }.max() ?? 0
        let maxSerializedBucketSize = try cuckooTableArguments.maxSerializedBucketSize ?? {
            let bytesPerPlaintext = try EncryptionParameters<Scheme.Scalar>(from:
                rlweParameters).bytesPerPlaintext
            let singleBucketSize = HashBucket.serializedSize(singleValueSize: maxValueSize)
            return if singleBucketSize >= bytesPerPlaintext / 2 {
                singleBucketSize.nextMultiple(of: bytesPerPlaintext, variableTime: true)
            } else {
                bytesPerPlaintext / 2
            }
        }()
        guard maxSerializedBucketSize >= HashBucket.serializedSize(singleValueSize: maxValueSize) else {
            let requiredSize = HashBucket.serializedSize(singleValueSize: maxValueSize)
            throw ValidationError(
                """
                'maxSerializedBucketSize' must be at least as large as the maximum value size + hash bucket \
                serialization overhead. Maximum values size is \(maxValueSize) so 'maxSerializedBucketSize' \
                must be at least \(requiredSize).
                """)
        }
        let cuckooTableConfig = try cuckooTableArguments.resolve(maxSerializedBucketSize: maxSerializedBucketSize)

        return try ResolvedArguments(
            inputDatabase: inputDatabase,
            outputDatabase: outputDatabase,
            outputPirParameters: outputPirParameters,
            outputEvaluationKeyConfig: outputEvaluationKeyConfig,
            sharding: sharding ?? Sharding.shardCount(1),
            shardingFunction: shardingFunction ?? .sha256,
            cuckooTableConfig: cuckooTableConfig,
            rlweParameters: rlweParameters,
            algorithm: algorithm ?? .mulPir,
            keyCompression: keyCompression ?? .noCompression,
            useMaxSerializedBucketSize: useMaxSerializedBucketSize ?? false,
            symmetricPirConfig: symmetricPirArguments?.resolve(),
            trialsPerShard: trialsPerShard ?? 1)
    }
}

/// The resolved arguments for the database processing.
struct ResolvedArguments: CustomStringConvertible, Encodable {
    let inputDatabase: String
    let outputDatabase: String
    let outputPirParameters: String
    let outputEvaluationKeyConfig: String?
    let sharding: Sharding
    let shardingFunction: ShardingFunction
    let cuckooTableConfig: CuckooTableConfig
    let rlweParameters: PredefinedRlweParameters
    let algorithm: PirAlgorithm
    let keyCompression: PirKeyCompressionStrategy
    let useMaxSerializedBucketSize: Bool
    let symmetricPirConfig: SymmetricPirConfig?
    let trialsPerShard: Int

    var description: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // swiftlint:disable:next force_try
        let data = try! encoder.encode(self)
        // swiftlint:disable:next optional_data_string_conversion
        return String(decoding: data, as: UTF8.self)
    }

    /// - Parameters:
    ///  - inputDatabase: Path to the un-processed input database.
    ///  - outputDatabase: Path to save the output, processed database.
    ///  - outputPirParameters: Path to save the PIR parameters for each shard.
    ///  - outputEvaluationKeyConfig: Path to save each shard's evaluation key configuration.
    ///  - sharding: Sharding configuration.
    ///  - cuckooTableConfig: Cuckoo Table configuration.
    ///  - rlweParameters: RLWE parameters.
    ///  - algorithm: PIR algorithm.
    ///  - keyCompression: Evaluation key compression.
    ///  - symmetricPirConfig: Config for symmetric PIR.
    ///  - trialsPerShard: Number of test queries per shard.
    init(
        inputDatabase: String,
        outputDatabase: String,
        outputPirParameters: String,
        outputEvaluationKeyConfig: String?,
        sharding: Sharding,
        shardingFunction: ShardingFunction,
        cuckooTableConfig: CuckooTableConfig,
        rlweParameters: PredefinedRlweParameters,
        algorithm: PirAlgorithm,
        keyCompression: PirKeyCompressionStrategy,
        useMaxSerializedBucketSize: Bool,
        symmetricPirConfig: SymmetricPirConfig?,
        trialsPerShard: Int) throws
    {
        self.inputDatabase = inputDatabase
        self.outputDatabase = outputDatabase
        self.outputPirParameters = outputPirParameters
        self.outputEvaluationKeyConfig = outputEvaluationKeyConfig
        self.sharding = sharding
        self.shardingFunction = shardingFunction
        self.cuckooTableConfig = cuckooTableConfig
        self.rlweParameters = rlweParameters
        self.algorithm = algorithm
        self.keyCompression = keyCompression
        self.useMaxSerializedBucketSize = useMaxSerializedBucketSize
        self.symmetricPirConfig = symmetricPirConfig
        self.trialsPerShard = trialsPerShard

        try validate()
    }

    /// Performs the validation of the resolved arguments.
    func validate() throws {
        guard sharding == Sharding.shardCount(1) || outputPirParameters.contains("SHARD_ID") else {
            throw ValidationError("'outputPirParameters' must contain 'SHARD_ID', found \(outputPirParameters)")
        }
        guard sharding == Sharding.shardCount(1) || outputDatabase.contains("SHARD_ID") else {
            throw ValidationError("'outputPirDatabase' must contain 'SHARD_ID', found \(outputDatabase)")
        }
        guard algorithm == .mulPir else {
            throw ValidationError("'algorithm' must be 'mulPir', found \(algorithm)")
        }
    }
}

// This executable is used in tests, which breaks `swift test -c release` when used with `@main`.
// So we avoid using `@main` here.
struct ProcessDatabase: AsyncParsableCommand {
    static let configuration: CommandConfiguration = .init(
        commandName: "PIRProcessDatabase", version: Version.current.description)

    static let logger = Logger(label: "PIRProcessDatabase")

    @Argument(
        help: """
            Path to json configuration file.
            Default for \(Arguments.defaultArguments.rlweParameters):
            \(Arguments.defaultJsonString())
            """)
    var configFile: String

    @Flag(name: .customLong("parallel"),
          inversion: .prefixedNo,
          help: "Enables parallel processing.")
    var parallel = true

    /// Performs the processing on the given database.
    /// - Parameters:
    ///   - config: The configuration for the PIR processing.
    ///   - scheme: The HE scheme.
    /// - Throws: Error upon processing the database.
    @inlinable
    mutating func process<PirUtil: PirUtilProtocol>(config: Arguments, pirUtil _: PirUtil.Type) async throws {
        typealias Scalar = PirUtil.Scheme.Scalar
        let database: [KeywordValuePair] =
            try Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase(from: config.inputDatabase).native()

        let config = try config.resolve(for: database, scheme: PirUtil.Scheme.self)
        ProcessDatabase.logger.info("Processing database with configuration: \(config)")
        let keywordConfig = try KeywordPirConfig(dimensionCount: 2,
                                                 cuckooTableConfig: config.cuckooTableConfig,
                                                 unevenDimensions: true,
                                                 keyCompression: config.keyCompression,
                                                 useMaxSerializedBucketSize: config.useMaxSerializedBucketSize,
                                                 shardingFunction: config.shardingFunction,
                                                 symmetricPirClientConfig: config.symmetricPirConfig?.clientConfig())
        let databaseConfig = KeywordDatabaseConfig(
            sharding: config.sharding,
            keywordPirConfig: keywordConfig)

        let encryptionParameters = try EncryptionParameters<Scalar>(from: config.rlweParameters)
        let processArgs = try ProcessKeywordDatabase.Arguments<Scalar>(databaseConfig: databaseConfig,
                                                                       encryptionParameters: encryptionParameters,
                                                                       algorithm: config.algorithm,
                                                                       keyCompression: config.keyCompression,
                                                                       trialsPerShard: config.trialsPerShard,
                                                                       symmetricPirConfig: config.symmetricPirConfig)
        let context = try PirUtil.Scheme.Context(encryptionParameters: processArgs.encryptionParameters)

        let keywordDatabase = try KeywordDatabase(
            rows: database,
            sharding: processArgs.databaseConfig.sharding,
            shardingFunction: config.shardingFunction,
            symmetricPirConfig: processArgs.symmetricPirConfig)
        ProcessDatabase.logger.info("Sharded database into \(keywordDatabase.shards.count) shards")
        let shards = keywordDatabase.shards.sorted { $0.0.localizedStandardCompare($1.0) == .orderedAscending }
        var evaluationKeyConfig = EvaluationKeyConfig()

        if parallel {
            try await withThrowingTaskGroup { group in
                for (shardID, shard) in shards {
                    group.addTask { @Sendable [self] in
                        try await processShard(
                            shardID: shardID,
                            shard: shard,
                            config: config,
                            context: context,
                            processArgs: processArgs,
                            pirUtil: PirUtil.self)
                    }
                }

                for try await processedEvaluationKeyConfig in group {
                    evaluationKeyConfig = [evaluationKeyConfig, processedEvaluationKeyConfig].union()
                }
            }
        } else {
            for (shardID, shard) in shards {
                let processedEvaluationKeyConfig = try await processShard(
                    shardID: shardID,
                    shard: shard, config:
                    config, context: context,
                    processArgs: processArgs,
                    pirUtil: PirUtil.self)
                evaluationKeyConfig = [evaluationKeyConfig, processedEvaluationKeyConfig].union()
            }
        }

        if let evaluationKeyConfigFile = config.outputEvaluationKeyConfig {
            let protoEvaluationKeyConfig = try evaluationKeyConfig.proto(
                encryptionParameters: encryptionParameters,
                scheme: PirUtil.Scheme.self)
            try protoEvaluationKeyConfig.save(to: evaluationKeyConfigFile)
            ProcessDatabase.logger.info("Saved evaluation key configuration to \(evaluationKeyConfigFile)")
        }
    }

    // swiftlint:disable:next function_parameter_count
    private func processShard<PirUtil: PirUtilProtocol>(
        shardID: String,
        shard: KeywordDatabaseShard,
        config: ResolvedArguments,
        context: PirUtil.Scheme.Context,
        processArgs: ProcessKeywordDatabase.Arguments<PirUtil.Scheme.Scalar>,
        pirUtil _: PirUtil.Type) async throws -> EvaluationKeyConfig
    {
        var logger = ProcessDatabase.logger
        logger[metadataKey: "shardID"] = .string(shardID)

        func logEvent(event: ProcessKeywordDatabase.ProcessShardEvent) throws {
            switch event {
            case let .cuckooTableEvent(.createdTable(table)):
                let summary = try table.summarize()
                logger.info("Created cuckoo table \(summary)")
            case let .cuckooTableEvent(.expandingTable(table)):
                let summary = try table.summarize()
                logger.info("Expanding cuckoo table \(summary)")
            case let .cuckooTableEvent(.finishedExpandingTable(table)):
                let summary = try table.summarize()
                logger.info("Finished expanding cuckoo table \(summary)")
            case let .cuckooTableEvent(.insertedKeywordValuePair(index, _)):
                let reportingPercentage = 10
                let shardFraction = shard.rows.count / reportingPercentage
                if (index + 1).isMultiple(of: shardFraction) {
                    let percentage = Float(reportingPercentage * (index + 1)) / Float(shardFraction)
                    logger.info("Inserted \(index + 1) / \(shard.rows.count) keywords \(percentage)%")
                }
            }
        }

        logger.info("Processing shard with \(shard.rows.count) rows")
        let processed: ProcessedDatabaseWithParameters<PirUtil.Scheme> = try await ProcessKeywordDatabase.processShard(
            shard: shard,
            with: processArgs,
            using: PirUtil.self,
            onEvent: logEvent)

        if config.trialsPerShard > 0 {
            guard let row = shard.rows.first else {
                throw PirError.emptyDatabase
            }
            logger.info("Validating shard")
            let validationResults = try await ProcessKeywordDatabase
                .validateShard(shard: processed,
                               row: KeywordValuePair(keyword: row.key, value: row.value),
                               trials: config.trialsPerShard, context: context, using: PirUtil.self)
            let description = try validationResults.description()
            logger.info("ValidationResults \(description)")
        }

        let outputDatabaseFilename = config.outputDatabase.replacingOccurrences(
            of: "SHARD_ID",
            with: String(shardID))
        try processed.database.save(to: outputDatabaseFilename)
        logger.info("Saved shard to \(outputDatabaseFilename)")

        let shardPirParameters = try processed.proto(context: context)
        let outputParametersFilename = config.outputPirParameters.replacingOccurrences(
            of: "SHARD_ID",
            with: String(shardID))
        try shardPirParameters.save(to: outputParametersFilename)
        logger.info("Saved shard PIR parameters to \(outputParametersFilename)")

        return processed.evaluationKeyConfig
    }

    mutating func run() async throws {
        let configURL = URL(fileURLWithPath: configFile)
        let configData = try Data(contentsOf: configURL)
        let config = try JSONDecoder().decode(Arguments.self, from: configData)
        if config.rlweParameters.supportsScalar(UInt32.self) {
            try await process(config: config, pirUtil: PirUtil<Bfv<UInt32>>.self)
        } else {
            try await process(config: config, pirUtil: PirUtil<Bfv<UInt64>>.self)
        }
    }
}

extension ProcessKeywordDatabase.ShardValidationResult {
    /// Returns a description of processed database validation.
    func description() throws -> String {
        func sizeString(byteCount: Int, count: Int, label: String) -> String {
            let sizeKB = String(format: "%.01f", Double(byteCount) / 1000.0)
            return "\(sizeKB) KB (\(count) \(label))"
        }

        var descriptionDict = [String: String]()
        descriptionDict["query size"] = try sizeString(byteCount: query.size(), count: query.ciphertexts.count,
                                                       label: "ciphertexts")
        descriptionDict["evaluation key size"] = try sizeString(
            byteCount: evaluationKey.size(),
            count: evaluationKey.config.keyCount,
            label: "keys")
        descriptionDict["response size"] = try sizeString(byteCount: response.size(),
                                                          count: response.ciphertexts.flatMap(\.self).count,
                                                          label: "ciphertexts")
        descriptionDict["noise budget"] = String(format: "%.01f", noiseBudget)

        let runtimeString = computeTimes.sorted().map { runtime in
            String(format: "%.01f", runtime.milliseconds)
        }.joined(separator: ", ")
        descriptionDict["runtime (ms)"] = "[\(runtimeString)]"
        descriptionDict["entry count per response"] = "\(entryCountPerResponse)"

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // swiftlint:disable:next force_try
        let data = try! encoder.encode(descriptionDict)
        // swiftlint:disable:next optional_data_string_conversion
        let description = String(decoding: data, as: UTF8.self)
        return description.replacingOccurrences(of: "\"", with: "")
    }
}

extension Duration {
    var milliseconds: Double {
        Double(components.seconds) * 1e3 + Double(components.attoseconds) * 1e-15
    }
}

// workaround to call the async main, but without using a top-level `await` to not break `swift test -c release`.
let group = DispatchGroup()
group.enter()
let task = Task.detached(priority: .userInitiated) {
    defer { group.leave() }
    await ProcessDatabase.main()
}

group.wait()
