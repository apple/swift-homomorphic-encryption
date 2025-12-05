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
public import Benchmark
import Foundation
public import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import PrivateNearestNeighborSearch

@usableFromInline nonisolated(unsafe) let pnnsBenchmarkConfiguration = Benchmark.Configuration(
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

/// Configuration for PNNS benchmarks.
public struct PnnsBenchmarkConfig {
    /// Database configuration.
    public let databaseConfig: PnnsDatabaseConfig
    /// Encryption parameters configuration.
    public let encryptionConfig: EncryptionParametersConfig
    /// Benchmark configuration.
    public let benchmarkConfig: Benchmark.Configuration

    /// Creates a new ``PnnsBenchmarkConfig``
    /// - Parameters:
    ///   - databaseConfig: Database configuration.
    ///   - benchmarkConfig: Benchmark configuration.
    ///   - encryptionConfig: Encryption parameters configuration.
    public init(databaseConfig: PnnsDatabaseConfig = .init(rowCount: 4096, vectorDimension: 128),
                benchmarkConfig: Benchmark.Configuration = pnnsBenchmarkConfiguration,
                encryptionConfig: EncryptionParametersConfig = .defaultPnns) throws
    {
        self.databaseConfig = databaseConfig
        self.encryptionConfig = encryptionConfig
        self.benchmarkConfig = benchmarkConfig
    }
}

/// Configuration for a PNNS database.
public struct PnnsDatabaseConfig: Sendable {
    /// Number of rows in the database.
    public let rowCount: Int
    /// Dimension of each embedding vector.
    public let vectorDimension: Int
    /// Number of bytes in the metadata of each entry.
    public let metadataSize: Int

    /// Creates a new ``DatabaseConfig``
    /// - Parameters:
    ///   - rowCount: Number of rows in the database.
    ///   - vectorDimension: Dimension of each embedding vector.
    ///   - metadataCount: Number of bytes in the metadata of each entry.
    public init(rowCount: Int, vectorDimension: Int, metadataSize: Int = 0) {
        self.rowCount = rowCount
        self.vectorDimension = vectorDimension
        self.metadataSize = metadataSize
    }
}

private func getDatabaseForTesting(config: PnnsDatabaseConfig) -> Database {
    let rows = (0..<config.rowCount).map { rowIndex in
        let vector = (0..<config.vectorDimension).map { Float($0 + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1) }
        let metadata = Array(repeating: UInt8(rowIndex % Int(UInt8.max)), count: config.metadataSize)
        return DatabaseRow(
            entryId: UInt64(rowIndex),
            entryMetadata: metadata,
            vector: vector)
    }
    return Database(rows: rows)
}

/// process database benchmark.
public func pnnsProcessBenchmark<Scheme: HeScheme>(
    _: Scheme.Type,
    // swiftlint:disable:next force_try
    config: PnnsBenchmarkConfig = try! .init()) -> () -> Void
{
    {
        let benchmarkName = [
            "Process",
            String(describing: Scheme.self),
            config.encryptionConfig.description,
            "rowCount=\(config.databaseConfig.rowCount)",
            "vectorDimension=\(config.databaseConfig.vectorDimension)",
            "metadataSize=\(config.databaseConfig.metadataSize)",
        ].joined(separator: "/")
        // swiftlint:disable closure_parameter_position
        Benchmark(benchmarkName, configuration: config.benchmarkConfig) { (
            benchmark,
            benchmarkContext: PnnsProcessBenchmarkContext<Scheme>) in
            for _ in benchmark.scaledIterations {
                try await blackHole(benchmarkContext.database
                    .process(
                        config: benchmarkContext.serverConfig,
                        contexts: benchmarkContext.contexts))
            }
        } setup: {
            try PnnsProcessBenchmarkContext<Scheme>(
                databaseConfig: config.databaseConfig,
                encryptionConfig: config.encryptionConfig)
        }
        // swiftlint:enable closure_parameter_position
    }
}

/// cosine similarity benchmark.
public func cosineSimilarityBenchmark<Scheme: HeScheme>(_: Scheme.Type,
                                                        // swiftlint:disable:next force_try
                                                        config: PnnsBenchmarkConfig = try! .init(),
                                                        queryCount: Int = 1) -> () -> Void
{
    // swiftlint:disable:next closure_body_length
    {
        let benchmarkName = [
            "CosineSimilarity",
            String(describing: Scheme.self),
            config.encryptionConfig.description,
            "rowCount=\(config.databaseConfig.rowCount)",
            "vectorDimension=\(config.databaseConfig.vectorDimension)",
            "metadataSize=\(config.databaseConfig.metadataSize)",
            "queryCount=\(queryCount)",
        ].joined(separator: "/")
        // swiftlint:disable closure_parameter_position
        Benchmark(benchmarkName, configuration: config.benchmarkConfig) { (
            benchmark,
            benchmarkContext: PnnsBenchmarkContext<Scheme>) in
            let context = benchmarkContext.server.contexts[0]
            let vectorDimension = benchmarkContext.server.config.vectorDimension
            for _ in benchmark.scaledIterations {
                let secretKey = try context.generateSecretKey()
                let evaluationKey = try benchmarkContext.client.generateEvaluationKey(using: secretKey)
                let serializedEvaluationKey = evaluationKey.serialize().proto()
                let data = getDatabaseForTesting(config: PnnsDatabaseConfig(
                    rowCount: queryCount,
                    vectorDimension: vectorDimension))
                let queryVectors = Array2d(data: data.rows.map { row in row.vector })
                let query = try benchmarkContext.client.generateQuery(for: queryVectors, using: secretKey)
                let serializedQuery = try query.proto()

                benchmark.startMeasurement()

                let deserializedEvalKey: EvaluationKey<Scheme> = try serializedEvaluationKey.native(context: context)
                let deserializedQuery: Query<Scheme> = try serializedQuery.native(context: context)
                let response = try await benchmarkContext.server.computeResponse(
                    to: deserializedQuery,
                    using: deserializedEvalKey)
                try blackHole(response.proto())

                benchmark.stopMeasurement()

                let noiseBudget = try response.scaledNoiseBudget(using: secretKey)
                benchmark.measurement(.noiseBudget, noiseBudget)
            }
            benchmark.measurement(.evaluationKeySize, benchmarkContext.evaluationKeySize)
            benchmark.measurement(.evaluationKeyCount, benchmarkContext.evaluationKeyCount)
            benchmark.measurement(.querySize, benchmarkContext.querySize)
            benchmark.measurement(.queryCiphertextCount, benchmarkContext.queryCiphertextCount)
            benchmark.measurement(.responseSize, benchmarkContext.responseSize)
            benchmark.measurement(.responseCiphertextCount, benchmarkContext.responseCiphertextCount)
        } setup: {
            try await PnnsBenchmarkContext<Scheme>(
                databaseConfig: config.databaseConfig,
                encryptionConfig: config.encryptionConfig,
                queryCount: queryCount)
        }
        // swiftlint:enable closure_parameter_position
    }
}

extension PrivateNearestNeighborSearch.Response {
    func scaledNoiseBudget(using secretKey: Scheme.SecretKey) throws -> Int {
        try Int(noiseBudget(using: secretKey, variableTime: true) * Double(
            noiseBudgetScale))
    }
}

struct PnnsProcessBenchmarkContext<Scheme: HeScheme> {
    let database: Database
    let contexts: [Scheme.Context]
    let serverConfig: ServerConfig<Scheme>

    init(databaseConfig: PnnsDatabaseConfig,
         encryptionConfig: EncryptionParametersConfig) throws
    {
        let plaintextModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: encryptionConfig.plaintextModulusBits,
            preferringSmall: true,
            nttDegree: encryptionConfig.polyDegree)
        let coefficientModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: encryptionConfig.coefficientModulusBits,
            preferringSmall: false,
            nttDegree: encryptionConfig.polyDegree)

        let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
            polyDegree: encryptionConfig.polyDegree,
            plaintextModulus: plaintextModuli[0],
            coefficientModuli: coefficientModuli,
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.quantum128)

        let batchSize = 1
        let evaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: MatrixDimensions(
                rowCount: databaseConfig.rowCount,
                columnCount: databaseConfig.vectorDimension),
            maxQueryCount: batchSize,
            encryptionParameters: encryptionParameters,
            scheme: Scheme.self)
        let scalingFactor = ClientConfig<Scheme>
            .maxScalingFactor(
                distanceMetric: .cosineSimilarity,
                vectorDimension: databaseConfig.vectorDimension,
                plaintextModuli: Array(plaintextModuli[1...]))
        let clientConfig = try ClientConfig<Scheme>(
            encryptionParameters: encryptionParameters,
            scalingFactor: scalingFactor,
            queryPacking: .denseRow,
            vectorDimension: databaseConfig.vectorDimension,
            evaluationKeyConfig: evaluationKeyConfig,
            distanceMetric: .cosineSimilarity)
        let babyStepGiantStep = BabyStepGiantStep(vectorDimension: databaseConfig.vectorDimension)
        let serverConfig = ServerConfig<Scheme>(
            clientConfig: clientConfig,
            databasePacking: .diagonal(babyStepGiantStep: babyStepGiantStep))
        self.serverConfig = serverConfig

        self.database = getDatabaseForTesting(config: databaseConfig)
        self.contexts = try serverConfig.encryptionParameters.map { encryptionParameters in
            try Scheme.Context(encryptionParameters: encryptionParameters)
        }
    }
}

struct PnnsBenchmarkContext<Scheme: HeScheme> {
    let processedDatabase: ProcessedDatabase<Scheme>
    let server: Server<Scheme>
    let client: Client<Scheme>
    let contexts: [Scheme.Context]
    let evaluationKeyCount: Int
    let evaluationKeySize: Int
    let querySize: Int
    let queryCiphertextCount: Int
    let responseSize: Int
    let responseCiphertextCount: Int

    init(databaseConfig: PnnsDatabaseConfig,
         encryptionConfig: EncryptionParametersConfig,
         queryCount: Int) async throws
    {
        let plaintextModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: encryptionConfig.plaintextModulusBits,
            preferringSmall: true,
            nttDegree: encryptionConfig.polyDegree)
        let coefficientModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: encryptionConfig.coefficientModulusBits,
            preferringSmall: false,
            nttDegree: encryptionConfig.polyDegree)
        let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
            polyDegree: encryptionConfig.polyDegree,
            plaintextModulus: plaintextModuli[0],
            coefficientModuli: coefficientModuli,
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.quantum128)

        let evaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: MatrixDimensions(
                rowCount: databaseConfig.rowCount,
                columnCount: databaseConfig.vectorDimension),
            maxQueryCount: queryCount,
            encryptionParameters: encryptionParameters,
            scheme: Scheme.self)
        let scalingFactor = ClientConfig<Scheme>
            .maxScalingFactor(
                distanceMetric: .cosineSimilarity,
                vectorDimension: databaseConfig.vectorDimension,
                plaintextModuli: plaintextModuli)
        let clientConfig = try ClientConfig<Scheme>(
            encryptionParameters: encryptionParameters,
            scalingFactor: scalingFactor,
            queryPacking: .denseRow,
            vectorDimension: databaseConfig.vectorDimension,
            evaluationKeyConfig: evaluationKeyConfig,
            distanceMetric: .cosineSimilarity,
            extraPlaintextModuli: Array(plaintextModuli[1...]))

        let babyStepGiantStep = BabyStepGiantStep(vectorDimension: databaseConfig.vectorDimension)
        let serverConfig = ServerConfig<Scheme>(
            clientConfig: clientConfig,
            databasePacking: .diagonal(babyStepGiantStep: babyStepGiantStep))

        let database = getDatabaseForTesting(config: databaseConfig)
        self.contexts = try clientConfig.encryptionParameters
            .map { encryptionParameters in try Scheme.Context(encryptionParameters: encryptionParameters) }
        self.processedDatabase = try await database.process(config: serverConfig, contexts: contexts)
        self.client = try Client(config: clientConfig, contexts: contexts)
        self.server = try Server(database: processedDatabase)
        let secretKey = try client.generateSecretKey()
        let evaluationKey = try client.generateEvaluationKey(using: secretKey)

        // We query exact matches from rows in the database
        let databaseVectors = Array2d(data: database.rows.map { row in row.vector })
        let queryVectors = Array2d(data: database.rows.prefix(queryCount).map { row in row.vector })
        let query = try client.generateQuery(for: queryVectors, using: secretKey)

        let response = try await server.computeResponse(to: query, using: evaluationKey)
        let decrypted = try client.decrypt(response: response, using: secretKey)

        // Validate correctness
        let modulus = clientConfig.plaintextModuli.map { UInt64($0) }.reduce(1, *)
        let expected = try databaseVectors.fixedPointCosineSimilarity(
            queryVectors.transposed(),
            modulus: modulus,
            scalingFactor: Float(clientConfig.scalingFactor))
        precondition(decrypted.distances.data == expected.data, "Wrong response")

        self.evaluationKeySize = try evaluationKey.size()
        self.evaluationKeyCount = evaluationKey.config.keyCount
        self.querySize = try query.size()
        self.queryCiphertextCount = query.ciphertextMatrices.map { matrix in matrix.ciphertexts.count }.sum()
        self.responseSize = try response.size()
        self.responseCiphertextCount = response.ciphertextMatrices
            .map { matrix in matrix.ciphertexts.count }.sum()
    }
}
