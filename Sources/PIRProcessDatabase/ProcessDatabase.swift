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

import ArgumentParser
import Foundation
import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import Logging
import PrivateInformationRetrieval
import PrivateInformationRetrievalProtobuf

/// Creates a new `KeywordDatabase` from a given path.
/// - Parameters:
///   - path: The path to the `KeywordDatabase` file.
///   - sharding: The sharding strategy to use.
extension KeywordDatabase {
    init(from path: String, sharding: Sharding) throws {
        let database = try Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase(from: path)
        try self.init(rows: database.native(), sharding: sharding)
    }
}

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

/// A struct representing the arguments for the `cuckooTable` command.
struct CuckooTableArguments: Codable, Equatable, Hashable {
    let hashFunctionCount: Int?
    let maxEvictionCount: Int?
    let maxSerializedBucketSize: Int?
    let bucketCount: TableSizeOption?

    /// - Parameters:
    ///  - hashFunctionCount: The number of hashes to use in the cuckoo table.
    ///  - maxEvictionCount: The maximum number of evictions before re-making the cuckoo table.
    ///  - maxSerializedBucketSize: The maximum number of bytes per serialized bucket.
    ///  - bucketCount: The number of buckets per entry.
    init(hashFunctionCount: Int? = nil,
         maxEvictionCount: Int? = nil,
         maxSerializedBucketSize: Int? = nil,
         bucketCount: TableSizeOption? = nil)
    {
        self.hashFunctionCount = hashFunctionCount
        self.maxEvictionCount = maxEvictionCount
        self.maxSerializedBucketSize = maxSerializedBucketSize
        self.bucketCount = bucketCount
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
    var cuckooTableArguments: CuckooTableArguments?
    var algorithm: PirAlgorithm?
    var keyCompression: PirKeyCompressionStrategy?
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
            cuckooTableArguments: cuckooTableArguments,
            algorithm: resolved.algorithm,
            keyCompression: PirKeyCompressionStrategy.noCompression,
            trialsPerShard: resolved.trialsPerShard)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // swiftlint:disable:next force_try
        let data = try! encoder.encode(defaultArguments)
        return String(decoding: data, as: UTF8.self)
    }

    func resolve<Scheme: HeScheme>(for database: [KeywordValuePair],
                                   scheme _: Scheme.Type) throws -> ResolvedArguments
    {
        let cuckooTableArguments = cuckooTableArguments ?? CuckooTableArguments()
        let maxValueSize = database.map { row in row.value.count }.max() ?? 0
        let maxSerializedBucketSize = try cuckooTableArguments.maxSerializedBucketSize ?? {
            let bytesPerPlaintext = try EncryptionParameters<Scheme>(from:
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
            cuckooTableConfig: cuckooTableConfig,
            rlweParameters: rlweParameters,
            algorithm: algorithm ?? .mulPir,
            keyCompression: keyCompression ?? .noCompression,
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
    let cuckooTableConfig: CuckooTableConfig
    let rlweParameters: PredefinedRlweParameters
    let algorithm: PirAlgorithm
    let keyCompression: PirKeyCompressionStrategy
    let trialsPerShard: Int

    var description: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // swiftlint:disable:next force_try
        let data = try! encoder.encode(self)
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
    ///  - keyCompression: ``EvaluationKey`` compression.
    ///  - trialsPerShard: Number of test queries per shard.
    init(
        inputDatabase: String,
        outputDatabase: String,
        outputPirParameters: String,
        outputEvaluationKeyConfig: String?,
        sharding: Sharding,
        cuckooTableConfig: CuckooTableConfig,
        rlweParameters: PredefinedRlweParameters,
        algorithm: PirAlgorithm,
        keyCompression: PirKeyCompressionStrategy,
        trialsPerShard: Int) throws
    {
        self.inputDatabase = inputDatabase
        self.outputDatabase = outputDatabase
        self.outputPirParameters = outputPirParameters
        self.outputEvaluationKeyConfig = outputEvaluationKeyConfig
        self.sharding = sharding
        self.cuckooTableConfig = cuckooTableConfig
        self.rlweParameters = rlweParameters
        self.algorithm = algorithm
        self.keyCompression = keyCompression
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

@main
struct ProcessDatabase: ParsableCommand {
    static let configuration: CommandConfiguration = .init(
        commandName: "PIRProcessDatabase")

    static let logger = Logger(label: "PIRProcessDatabase")

    @Argument(
        help: """
            Path to json configuration file.
            Default for \(Arguments.defaultArguments.rlweParameters):
            \(Arguments.defaultJsonString())
            """)
    var configFile: String

    /// Performs the processing on the given database.
    /// - Parameters:
    ///   - config: The configuration for the PIR processing.
    ///   - scheme: The HE scheme.
    /// - Throws: Error upon processing the database.
    @inlinable
    mutating func process<Scheme: HeScheme>(config: Arguments, scheme: Scheme.Type) throws {
        let database: [KeywordValuePair] =
            try Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase(from: config.inputDatabase).native()

        let config = try config.resolve(for: database, scheme: scheme)
        ProcessDatabase.logger.info("Processing database with configuration: \(config)")
        let keywordConfig = try KeywordPirConfig(dimensionCount: 2,
                                                 cuckooTableConfig: config.cuckooTableConfig,
                                                 unevenDimensions: true,
                                                 keyCompression: config.keyCompression)
        let databaseConfig = KeywordDatabaseConfig(
            sharding: config.sharding,
            keywordPirConfig: keywordConfig)

        let encryptionParameters = try EncryptionParameters<Scheme>(from: config.rlweParameters)
        let processArgs = try ProcessKeywordDatabase.Arguments<Scheme>(databaseConfig: databaseConfig,
                                                                       encryptionParameters: encryptionParameters,
                                                                       algorithm: config.algorithm,
                                                                       keyCompression: config.keyCompression,
                                                                       trialsPerShard: config.trialsPerShard)

        var evaluationKeyConfig = EvaluationKeyConfiguration()
        let context = try Context(encryptionParameters: processArgs.encryptionParameters)
        let keywordDatabase = try KeywordDatabase(rows: database, sharding: processArgs.databaseConfig.sharding)
        ProcessDatabase.logger
            .info("Sharded database into \(keywordDatabase.shards.count) shards")
        for (shardID, shard) in keywordDatabase.shards
            .sorted(by: { $0.0.localizedStandardCompare($1.0) == .orderedAscending })
        {
            ProcessDatabase.logger.info("Processing shard \(shardID)")
            let processed = try ProcessKeywordDatabase.processShard(shard: shard, with: processArgs)
            if config.trialsPerShard > 0 {
                guard let row = shard.rows.first else {
                    throw PirError.emptyDatabase
                }
                ProcessDatabase.logger.info("Validating shard \(shardID)")
                let validationResults = try ProcessKeywordDatabase
                    .validateShard(shard: processed,
                                   row: KeywordValuePair(keyword: row.key, value: row.value),
                                   trials: config.trialsPerShard, context: context)
                let description = try validationResults.description()
                ProcessDatabase.logger.info("ValidationResults \(description)")
            }

            let outputDatabaseFilename = config.outputDatabase.replacingOccurrences(
                of: "SHARD_ID",
                with: String(shardID))
            try processed.database.save(to: outputDatabaseFilename)
            ProcessDatabase.logger.info("Saved shard \(shardID) to \(outputDatabaseFilename)")

            let shardEvaluationKeyConfig = processed.evaluationKeyConfiguration
            evaluationKeyConfig = [evaluationKeyConfig, shardEvaluationKeyConfig].union()

            let shardPirParameters = try processed.proto(context: context)
            let outputParametersFilename = config.outputPirParameters.replacingOccurrences(
                of: "SHARD_ID",
                with: String(shardID))
            try shardPirParameters.save(to: outputParametersFilename)
            ProcessDatabase.logger.info("Saved shard \(shardID) PIR parameters to \(outputParametersFilename)")
        }

        if let evaluationKeyConfigFile = config.outputEvaluationKeyConfig {
            let protoEvaluationKeyConfig = try evaluationKeyConfig.proto(encryptionParameters: encryptionParameters)
            try protoEvaluationKeyConfig.save(to: evaluationKeyConfigFile)
            ProcessDatabase.logger.info("Saved evaluation key configuration to \(evaluationKeyConfigFile)")
        }
    }

    mutating func run() throws {
        let configURL = URL(fileURLWithPath: configFile)
        let configData = try Data(contentsOf: configURL)
        let config = try JSONDecoder().decode(Arguments.self, from: configData)
        if config.rlweParameters.supportsScalar(UInt32.self) {
            try process(config: config, scheme: Bfv<UInt32>.self)
        } else {
            try process(config: config, scheme: Bfv<UInt64>.self)
        }
    }
}

extension ProcessKeywordDatabase.ShardValidationResult {
    /// Returns a description of processed database validation.
    public func description() throws -> String {
        func sizeString(byteCount: Int, count: Int, label: String) -> String {
            let sizeKB = String(format: "%.01f", Double(byteCount) / 1000.0)
            return "\(sizeKB) KB (\(count) \(label))"
        }

        var descriptionDict = [String: String]()
        descriptionDict["query size"] = try sizeString(byteCount: query.size(), count: query.ciphertexts.count,
                                                       label: "ciphertexts")
        descriptionDict["evaluation key size"] = try sizeString(
            byteCount: query.size(),
            count: evaluationKey.configuration.keyCount,
            label: "keys"
        )
        descriptionDict["response size"] = try sizeString(byteCount: response.size(),
                                                          count: response.ciphertexts.count, label: "ciphertexts")
        descriptionDict["noise budget"] = String(format: "%.01f", noiseBudget)

        let runtimeString = computeTimes.sorted().map { runtime in
            String(format: "%.01f", runtime.milliseconds)
        }.joined(separator: ", ")
        descriptionDict["runtime (ms)"] = "[\(runtimeString)]"

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // swiftlint:disable:next force_try
        let data = try! encoder.encode(descriptionDict)
        let description = String(decoding: data, as: UTF8.self)
        return description.replacingOccurrences(of: "\"", with: "")
    }
}

extension Duration {
    var milliseconds: Double {
        Double(components.seconds) * 1e3 + Double(components.attoseconds) * 1e-15
    }
}
