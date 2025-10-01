// Copyright 2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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
import Benchmark
import Foundation
import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import PrivateInformationRetrieval

@usableFromInline nonisolated(unsafe) let pirBenchmarkConfiguration = Benchmark.Configuration(
    metrics: [
        .wallClock,
        .mallocCountTotal,
        .peakMemoryResident,
        .evaluationKeySize,
        .evaluationKeyCount,
        .querySize,
        .queryCiphertextCount,
        .responseSize,
        .responseCiphertextCount,
        .noiseBudget,
    ],
    maxDuration: .seconds(5))

func getDatabaseForTesting(
    numberOfEntries: Int,
    entrySizeInBytes: Int) -> [[UInt8]]
{
    (0..<numberOfEntries).map { _ in (0..<entrySizeInBytes)
        .map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
    }
}

/// Configuration for a PIR database.
public struct PirDatabaseConfig {
    /// Number of rows in the database.
    public let entryCount: Int
    /// Size of each entry in bytes.
    public let entrySizeInBytes: Int

    /// Creates a new ``DatabaseConfig``
    /// - Parameters:
    ///   - entryCount: Number of rows in the database.
    ///   - entrySize: Size of each entry in bytes.
    public init(entryCount: Int, entrySizeInBytes: Int) {
        self.entryCount = entryCount
        self.entrySizeInBytes = entrySizeInBytes
    }

    func generateDatabase() -> [[UInt8]] {
        (0..<entryCount).map { _ in (0..<entrySizeInBytes)
            .map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
        }
    }
}

/// Configuration for PIR benchmarks.
public struct PirBenchmarkConfig<Scalar: ScalarType> {
    /// Database configuration.
    public let databaseConfig: PirDatabaseConfig
    /// Encryption parameters configuration.
    public let encryptionConfig: EncryptionParametersConfig
    /// Benchmark configuration.
    public let benchmarkConfig: Benchmark.Configuration
    /// Keyword PIR configuration.
    public let keywordPirConfig: KeywordPirConfig
    /// Index PIR configuration.
    public let indexPirConfig: IndexPirConfig

    /// Creates a new ``PirBenchmarkConfig``
    /// - Parameters:
    ///   - databaseConfig: Database configuration.
    ///   - benchmarkConfig: Benchmark configuration.
    ///   - encryptionConfig: Encryption parameters configuration.
    public init(databaseConfig: PirDatabaseConfig = .init(entryCount: 1_000_000, entrySizeInBytes: 1),
                benchmarkConfig: Benchmark.Configuration = pirBenchmarkConfiguration,
                encryptionConfig: EncryptionParametersConfig = .defaultPir,
                keywordPirConfig: KeywordPirConfig? = nil) throws
    {
        self.databaseConfig = databaseConfig
        self.encryptionConfig = encryptionConfig
        self.benchmarkConfig = benchmarkConfig

        if let keywordPirConfig {
            self.keywordPirConfig = keywordPirConfig
        } else {
            let encryptionParams = try EncryptionParameters<Scalar>(from: encryptionConfig)
            let cuckooTableConfig = CuckooTableConfig
                .defaultKeywordPir(maxSerializedBucketSize: encryptionParams.bytesPerPlaintext)
            self.keywordPirConfig = try KeywordPirConfig(dimensionCount: 2, cuckooTableConfig: cuckooTableConfig,
                                                         unevenDimensions: true,
                                                         keyCompression: .hybridCompression)
        }
        self.indexPirConfig = try IndexPirConfig(
            entryCount: databaseConfig.entryCount,
            entrySizeInBytes: databaseConfig.entrySizeInBytes,
            dimensionCount: self.keywordPirConfig.dimensionCount,
            batchSize: 1,
            unevenDimensions: self.keywordPirConfig.unevenDimensions,
            keyCompression: self.keywordPirConfig.keyCompression)
    }
}

extension PrivateInformationRetrieval.Response {
    func scaledNoiseBudget(using secretKey: Scheme.SecretKey) throws -> Int {
        try Int(
            noiseBudget(using: secretKey, variableTime: true) * Double(
                noiseBudgetScale))
    }
}

struct ProcessBenchmarkContext<Server: IndexPirServer> {
    let database: [[UInt8]]
    let context: Context<Server.Scheme>
    let parameter: IndexPirParameter
    init(server _: Server.Type, pirConfig: IndexPirConfig,
         encryptionConfig: EncryptionParametersConfig) throws
    {
        let encryptParameter: EncryptionParameters<Server.Scheme.Scalar> =
            try EncryptionParameters(from: encryptionConfig)
        self.database = getDatabaseForTesting(
            numberOfEntries: pirConfig.entryCount,
            entrySizeInBytes: pirConfig.entrySizeInBytes)
        self.context = try Context(encryptionParameters: encryptParameter)
        self.parameter = Server.generateParameter(config: pirConfig, with: context)
    }
}

/// Pre-processing database benchmark.
public func pirProcessBenchmark<Scheme: HeScheme>(
    _: Scheme.Type,
    // swiftlint:disable:next force_try
    config: PirBenchmarkConfig<Scheme.Scalar> = try! .init()) -> () -> Void
{
    {
        let databaseConfig = config.databaseConfig
        let benchmarkName = [
            "Process",
            String(describing: Scheme.self),
            config.encryptionConfig.description,
            "entryCount=\(databaseConfig.entryCount)",
            "entrySize=\(databaseConfig.entrySizeInBytes)",
            "keyCompression=\(config.keywordPirConfig.keyCompression)",
        ].joined(separator: "/")
        // swiftlint:disable closure_parameter_position
        Benchmark(benchmarkName, configuration: config.benchmarkConfig) { (
            benchmark,
            benchmarkContext: ProcessBenchmarkContext<MulPirServer<Scheme>>) in
            for _ in benchmark.scaledIterations {
                try blackHole(
                    MulPirServer<Scheme>.process(
                        database: benchmarkContext.database,
                        with: benchmarkContext.context,
                        using: benchmarkContext.parameter))
            }
        } setup: {
            try ProcessBenchmarkContext(
                server: MulPirServer<Scheme>.self,
                pirConfig: config.indexPirConfig,
                encryptionConfig: config.encryptionConfig)
        }
        // swiftlint:enable closure_parameter_position
    }
}

struct IndexPirBenchmarkContext<Server: IndexPirServer, Client: IndexPirClient>
    where Server.Scheme == Client.Scheme
{
    let processedDatabase: Server.Database
    let server: Server
    let client: Client
    let secretKey: SecretKey<Client.Scheme>
    let evaluationKey: Server.Scheme.EvaluationKey
    let query: Client.Query
    let evaluationKeySize: Int
    let evaluationKeyCount: Int
    let querySize: Int
    let queryCiphertextCount: Int
    let responseSize: Int
    let responseCiphertextCount: Int
    let noiseBudget: Int

    init(
        server _: Server.Type,
        client _: Client.Type,
        pirConfig: IndexPirConfig,
        encryptionConfig: EncryptionParametersConfig) throws
    {
        let encryptParameter: EncryptionParameters<Server.Scheme.Scalar> =
            try EncryptionParameters(from: encryptionConfig)
        let context = try Context<Server.Scheme>(encryptionParameters: encryptParameter)
        let indexPirParameters = Server.generateParameter(config: pirConfig, with: context)
        let database = getDatabaseForTesting(
            numberOfEntries: pirConfig.entryCount,
            entrySizeInBytes: pirConfig.entrySizeInBytes)
        self.processedDatabase = try Server.process(database: database, with: context, using: indexPirParameters)

        self.server = try Server(parameter: indexPirParameters, context: context, database: processedDatabase)
        self.client = Client(parameter: indexPirParameters, context: context)
        self.secretKey = try context.generateSecretKey()
        self.evaluationKey = try client.generateEvaluationKey(using: secretKey)
        self.query = try client.generateQuery(at: [0], using: secretKey)

        // Validate correctness
        let queryIndex = Int.random(in: 0..<pirConfig.entryCount)
        let query = try client.generateQuery(at: [queryIndex], using: secretKey)
        let response = try server.computeResponse(to: query, using: evaluationKey)
        let decryptedResponse = try client.decrypt(response: response, at: queryIndex, using: secretKey)
        guard decryptedResponse == database[queryIndex] else {
            fatalError("Incorrect PIR response")
        }

        self.evaluationKeySize = try evaluationKey.size()
        self.evaluationKeyCount = evaluationKey.config.keyCount
        self.querySize = try query.size()
        self.queryCiphertextCount = query.ciphertexts.count
        self.responseSize = try response.size()
        self.responseCiphertextCount = response.ciphertexts.count
        self.noiseBudget = try response.scaledNoiseBudget(using: secretKey)
    }
}

/// IndexPIR benchmark.
public func indexPirBenchmark<Scheme: HeScheme>(
    _: Scheme.Type,
    // swiftlint:disable:next force_try
    config: PirBenchmarkConfig<Scheme.Scalar> = try! .init()) -> () -> Void
{
    {
        let benchmarkName = [
            "IndexPir",
            String(describing: Scheme.self),
            config.encryptionConfig.description,
            "entryCount=\(config.databaseConfig.entryCount)",
            "entrySize=\(config.databaseConfig.entrySizeInBytes)",
            "keyCompression=\(config.indexPirConfig.keyCompression)",
        ].joined(separator: "/")
        // swiftlint:disable closure_parameter_position
        Benchmark(benchmarkName, configuration: config.benchmarkConfig) { (
            benchmark,
            benchmarkContext: IndexPirBenchmarkContext<MulPirServer<Scheme>, MulPirClient<Scheme>>) in
            for _ in benchmark.scaledIterations {
                try blackHole(benchmarkContext.server.computeResponse(to: benchmarkContext.query,
                                                                      using: benchmarkContext
                                                                          .evaluationKey))
            }
            benchmark.measurement(.evaluationKeySize, benchmarkContext.evaluationKeySize)
            benchmark.measurement(.evaluationKeyCount, benchmarkContext.evaluationKeyCount)
            benchmark.measurement(.querySize, benchmarkContext.querySize)
            benchmark.measurement(.queryCiphertextCount, benchmarkContext.queryCiphertextCount)
            benchmark.measurement(.responseSize, benchmarkContext.responseSize)
            benchmark.measurement(.responseCiphertextCount, benchmarkContext.responseCiphertextCount)
            benchmark.measurement(.noiseBudget, benchmarkContext.noiseBudget)
        }
        // swiftlint:enable closure_parameter_position
        setup: {
            try IndexPirBenchmarkContext(
                server: MulPirServer<Scheme>.self,
                client: MulPirClient<Scheme>.self,
                pirConfig: config.indexPirConfig,
                encryptionConfig: config.encryptionConfig)
        }
    }
}

struct KeywordPirBenchmarkContext<IndexServer: IndexPirServer, IndexClient: IndexPirClient>
    where IndexServer.Scheme == IndexClient.Scheme
{
    typealias Server = KeywordPirServer<IndexServer>
    typealias Client = KeywordPirClient<IndexClient>
    let server: Server
    let client: Client
    let secretKey: SecretKey<Client.Scheme>
    let evaluationKey: Server.Scheme.EvaluationKey
    let query: Client.Query
    let evaluationKeySize: Int
    let evaluationKeyCount: Int
    let querySize: Int
    let queryCiphertextCount: Int
    let responseSize: Int
    let responseCiphertextCount: Int
    let noiseBudget: Int

    init(config: PirBenchmarkConfig<Server.Scheme.Scalar>) async throws {
        let encryptParameter: EncryptionParameters<Server.Scheme.Scalar> =
            try EncryptionParameters(from: config.encryptionConfig)
        let context = try Context<Server.Scheme>(encryptionParameters: encryptParameter)
        let rows = (0..<config.databaseConfig.entryCount).map { index in KeywordValuePair(
            keyword: [UInt8](String(index).utf8),
            value: (0..<config.databaseConfig.entrySizeInBytes).map { _ in UInt8.random(in: 0..<UInt8.max) })
        }
        let entryCount = config.databaseConfig.entryCount

        func logEvent(event: ProcessKeywordDatabase.ProcessShardEvent) throws {
            switch event {
            case let .cuckooTableEvent(CuckooTable.Event.createdTable(table)):
                let summary = try table.summarize()
                print("Created cuckoo table \(summary)")
            case let .cuckooTableEvent(.expandingTable(table)):
                let summary = try table.summarize()
                print("Expanding cuckoo table \(summary)")
            case let .cuckooTableEvent(.finishedExpandingTable(table)):
                let summary = try table.summarize()
                print("Finished expanding cuckoo table \(summary)")
            case let .cuckooTableEvent(.insertedKeywordValuePair(index, _)):
                let reportingPercentage = 10
                let shardFraction = entryCount / reportingPercentage
                if (index + 1).isMultiple(of: shardFraction) {
                    let percentage = Float(reportingPercentage * (index + 1)) / Float(shardFraction)
                    print("Inserted \(index + 1) / \(entryCount) keywords \(percentage)%")
                }
            }
        }

        let keywordPirConfig = config.keywordPirConfig
        let processed = try Server.process(
            database: rows,
            config: config.keywordPirConfig,
            with: context,
            onEvent: logEvent)

        self.server = try Server(context: context, processed: processed)
        self.client = Client(
            keywordParameter: keywordPirConfig.parameter,
            pirParameter: processed.pirParameter,
            context: context)
        self.secretKey = try context.generateSecretKey()
        self.evaluationKey = try client.generateEvaluationKey(using: secretKey)
        self.query = try client.generateQuery(at: [UInt8]("0".utf8), using: secretKey)

        // Validate correctness
        let queryIndex = Int.random(in: 0..<config.databaseConfig.entryCount)
        let query = try client.generateQuery(
            at: [UInt8](String(describing: queryIndex).utf8),
            using: secretKey)

        let response = try server.computeResponse(to: query, using: evaluationKey)
        let decryptedResponse = try client.decrypt(
            response: response,
            at: [UInt8](String(describing: queryIndex).utf8),
            using: secretKey)
        guard decryptedResponse == rows[queryIndex].value else {
            fatalError("Incorrect PIR response")
        }

        self.evaluationKeySize = try evaluationKey.size()
        self.evaluationKeyCount = evaluationKey.config.keyCount
        self.querySize = try query.size()
        self.queryCiphertextCount = query.ciphertexts.count
        self.responseSize = try response.size()
        self.responseCiphertextCount = response.ciphertexts.count
        self.noiseBudget = try response.scaledNoiseBudget(using: secretKey)
    }
}

/// keywordPIR benchmark.
public func keywordPirBenchmark<Scheme: HeScheme>(
    _: Scheme.Type,
    // swiftlint:disable:next force_try
    config: PirBenchmarkConfig<Scheme.Scalar> = try! .init()) -> () -> Void
{
    {
        let benchmarkName = [
            "KeywordPir",
            String(describing: Scheme.self),
            config.encryptionConfig.description,
            "entryCount=\(config.databaseConfig.entryCount)",
            "entrySize=\(config.databaseConfig.entrySizeInBytes)",
            "keyCompression=\(config.keywordPirConfig.keyCompression)",
        ].joined(separator: "/")
        Benchmark(benchmarkName, configuration: config.benchmarkConfig) { benchmark, benchmarkContext in
            for _ in benchmark.scaledIterations {
                try blackHole(benchmarkContext.server.computeResponse(to: benchmarkContext.query,
                                                                      using: benchmarkContext.evaluationKey))
            }
            benchmark.measurement(.evaluationKeySize, benchmarkContext.evaluationKeySize)
            benchmark.measurement(.evaluationKeyCount, benchmarkContext.evaluationKeyCount)
            benchmark.measurement(.querySize, benchmarkContext.querySize)
            benchmark.measurement(.queryCiphertextCount, benchmarkContext.queryCiphertextCount)
            benchmark.measurement(.responseSize, benchmarkContext.responseSize)
            benchmark.measurement(.responseCiphertextCount, benchmarkContext.responseCiphertextCount)
            benchmark.measurement(.noiseBudget, benchmarkContext.noiseBudget)
        } setup: {
            try await KeywordPirBenchmarkContext<MulPirServer<Scheme>, MulPirClient<Scheme>>(
                config: config)
        }
    }
}
