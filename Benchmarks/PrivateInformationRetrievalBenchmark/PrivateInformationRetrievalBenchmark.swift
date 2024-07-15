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

// Benchmarks for Pir functions.
// These benchmarks can be triggered with
// `swift package benchmark --target PIRBenchmark`
// for more readable results

@preconcurrency import Benchmark
import Foundation
import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import PrivateInformationRetrieval
import PrivateInformationRetrievalProtobuf

@usableFromInline let benchmarkConfiguration = Benchmark.Configuration(
    metrics: [
        .wallClock,
        .mallocCountTotal,
        .peakMemoryResident,
        .evaluationKeySize,
        .querySize,
        .responseSize,
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

struct EncryptionParametersConfig {
    let polyDegree: Int
    let plaintextModulusBits: Int
    let coefficientModulusBits: [Int]
}

extension EncryptionParametersConfig: CustomStringConvertible {
    var description: String {
        "N=\(polyDegree)/logt=\(plaintextModulusBits)/logq=\(coefficientModulusBits.description)"
    }
}

extension EncryptionParameters {
    init(from config: EncryptionParametersConfig) throws {
        let plaintextModulus = try Scheme.Scalar.generatePrimes(
            significantBitCounts: [config.plaintextModulusBits],
            preferringSmall: true)[0]
        let coefficientModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: config.coefficientModulusBits,
            preferringSmall: false,
            nttDegree: config.polyDegree)
        try self.init(
            polyDegree: config.polyDegree,
            plaintextModulus: plaintextModulus,
            coefficientModuli: coefficientModuli,
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.quantum128)
    }
}

let noiseBudgetScale = 10

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
         parameterConfig: EncryptionParametersConfig) throws
    {
        let encryptParameter: EncryptionParameters<Server.Scheme> = try EncryptionParameters(from: parameterConfig)
        self.database = getDatabaseForTesting(
            numberOfEntries: pirConfig.entryCount,
            entrySizeInBytes: pirConfig.entrySizeInBytes)
        self.context = try Context(encryptionParameters: encryptParameter)
        self.parameter = Server.generateParameter(config: pirConfig, with: context)
    }
}

func processBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        let entryCount = 1_000_000
        let entrySizeInBytes = 1
        let encryptionConfig = EncryptionParametersConfig(
            polyDegree: 4096,
            plaintextModulusBits: 5,
            coefficientModulusBits: [27, 28, 28])

        let benchmarkName = [
            "Process",
            String(describing: Scheme.self),
            encryptionConfig.description,
            "entryCount=\(entryCount)",
            "entrySize=\(entrySizeInBytes)",
        ].joined(separator: "/")
        // swiftlint:disable closure_parameter_position
        Benchmark(benchmarkName, configuration: benchmarkConfiguration) { (
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
                pirConfig: IndexPirConfig(
                    entryCount: entryCount,
                    entrySizeInBytes: entrySizeInBytes,
                    dimensionCount: 2,
                    batchSize: 1,
                    unevenDimensions: true),
                parameterConfig: encryptionConfig)
        }
        // swiftlint:enable closure_parameter_position
    }
}

struct IndexPirBenchmarkContext<Server: IndexPirServer, Client: IndexPirClient> where Server.Scheme == Client.Scheme {
    let processedDatabase: Server.Database
    let server: Server
    let client: Client
    let secretKey: SecretKey<Client.Scheme>
    let evaluationKey: Server.Scheme.EvaluationKey
    let query: Client.Query
    let evaluationKeySize: Int
    let querySize: Int
    let responseSize: Int
    let noiseBudget: Int

    init(
        server _: Server.Type,
        client _: Client.Type,
        pirConfig: IndexPirConfig,
        parameterConfig: EncryptionParametersConfig) throws
    {
        let encryptParameter: EncryptionParameters<Server.Scheme> = try EncryptionParameters(from: parameterConfig)
        let context = try Context(encryptionParameters: encryptParameter)
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
        self.querySize = try query.size()
        self.responseSize = try response.size()
        self.noiseBudget = try response.scaledNoiseBudget(using: secretKey)
    }
}

func indexPirBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        let entryCount = 1_000_000
        let entrySizeInBytes = 1
        let encryptionConfig = EncryptionParametersConfig(
            polyDegree: 4096,
            plaintextModulusBits: 5,
            coefficientModulusBits: [27, 28, 28])

        let benchmarkName = [
            "IndexPir",
            String(describing: Scheme.self),
            encryptionConfig.description,
            "entryCount=\(entryCount)",
            "entrySize=\(entrySizeInBytes)",
        ].joined(separator: "/")
        // swiftlint:disable closure_parameter_position
        Benchmark(benchmarkName, configuration: benchmarkConfiguration) { (
            benchmark,
            benchmarkContext: IndexPirBenchmarkContext<MulPirServer<Scheme>, MulPirClient<Scheme>>) in
            for _ in benchmark.scaledIterations {
                try blackHole(benchmarkContext.server.computeResponse(to: benchmarkContext.query,
                                                                      using: benchmarkContext
                                                                          .evaluationKey))
            }
            benchmark.measurement(.evaluationKeySize, benchmarkContext.evaluationKeySize)
            benchmark.measurement(.querySize, benchmarkContext.querySize)
            benchmark.measurement(.responseSize, benchmarkContext.responseSize)
            benchmark.measurement(.noiseBudget, benchmarkContext.noiseBudget)
        } setup: {
            try IndexPirBenchmarkContext(
                server: MulPirServer<Scheme>.self,
                client: MulPirClient<Scheme>.self,
                pirConfig: IndexPirConfig(
                    entryCount: entryCount,
                    entrySizeInBytes: entrySizeInBytes,
                    dimensionCount: 2,
                    batchSize: 1,
                    unevenDimensions: true),
                parameterConfig: encryptionConfig)
        }
        // swiftlint:enable closure_parameter_position
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
    let querySize: Int
    let responseSize: Int
    let noiseBudget: Int

    init(
        dimensionCount: Int,
        databaseCount: Int,
        payloadSize: Int,
        parameterConfig: EncryptionParametersConfig) throws
    {
        let encryptParameter: EncryptionParameters<Server.Scheme> = try EncryptionParameters(from: parameterConfig)
        let context = try Context(encryptionParameters: encryptParameter)

        let rows = (0..<databaseCount).map { index in KeywordValuePair(
            keyword: [UInt8](String(index).utf8),
            value: (0..<payloadSize).map { _ in UInt8.random(in: 0..<UInt8.max) })
        }

        let config = try KeywordPirConfig(
            dimensionCount: dimensionCount,
            cuckooTableConfig: CuckooTableConfig
                .defaultKeywordPir(maxSerializedBucketSize: encryptParameter.bytesPerPlaintext),
            unevenDimensions: true)

        let processed = try Server.process(database: rows,
                                           config: config,
                                           with: context)

        self.server = try Server(context: context, processed: processed)
        self.client = Client(
            keywordParameter: config.parameter,
            pirParameter: processed.pirParameter,
            context: context)
        self.secretKey = try context.generateSecretKey()
        self.evaluationKey = try client.generateEvaluationKey(using: secretKey)
        self.query = try client.generateQuery(at: [UInt8]("0".utf8), using: secretKey)

        // Validate correctness
        let queryIndex = Int.random(in: 0..<databaseCount)
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
        self.querySize = try query.size()
        self.responseSize = try response.size()
        self.noiseBudget = try response.scaledNoiseBudget(using: secretKey)
    }
}

func keywordPirBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        let entryCount = 10000
        let entrySizeInBytes = 100
        let encryptionConfig = EncryptionParametersConfig(
            polyDegree: 4096,
            plaintextModulusBits: 5,
            coefficientModulusBits: [27, 28, 28])

        let benchmarkName = [
            "KeywordPir",
            String(describing: Scheme.self),
            encryptionConfig.description,
            "entryCount=\(entryCount)",
            "entrySize=\(entrySizeInBytes)",
        ].joined(separator: "/")
        Benchmark(benchmarkName, configuration: benchmarkConfiguration) { benchmark, benchmarkContext in
            for _ in benchmark.scaledIterations {
                try blackHole(benchmarkContext.server.computeResponse(to: benchmarkContext.query,
                                                                      using: benchmarkContext.evaluationKey))
            }
            benchmark.measurement(.evaluationKeySize, benchmarkContext.evaluationKeySize)
            benchmark.measurement(.querySize, benchmarkContext.querySize)
            benchmark.measurement(.responseSize, benchmarkContext.responseSize)
            benchmark.measurement(.noiseBudget, benchmarkContext.noiseBudget)
        } setup: {
            try KeywordPirBenchmarkContext<MulPirServer<Scheme>, MulPirClient<Scheme>>(
                dimensionCount: 2,
                databaseCount: entryCount,
                payloadSize: entrySizeInBytes,
                parameterConfig: encryptionConfig)
        }
    }
}

extension BenchmarkMetric {
    static var querySize: Self { .custom("Query byte size") }
    static var evaluationKeySize: Self { .custom("Evaluation key byte size") }
    static var responseSize: Self { .custom("Response byte size") }
    static var noiseBudget: Self { .custom("Noise budget x \(noiseBudgetScale)") }
}

nonisolated(unsafe) let benchmarks: () -> Void = {
    processBenchmark(Bfv<UInt32>.self)()
    processBenchmark(Bfv<UInt64>.self)()

    indexPirBenchmark(Bfv<UInt32>.self)()
    indexPirBenchmark(Bfv<UInt64>.self)()

    keywordPirBenchmark(Bfv<UInt32>.self)()
    keywordPirBenchmark(Bfv<UInt64>.self)()
}
