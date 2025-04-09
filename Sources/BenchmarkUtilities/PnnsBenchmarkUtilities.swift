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

import Benchmark
import Foundation
import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import PrivateNearestNeighborSearch
import PrivateNearestNeighborSearchProtobuf

@usableFromInline nonisolated(unsafe) let PnnsBenchmarkConfiguration = Benchmark.Configuration(
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

/// process database benchmark.
public func pnnsProcessBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        let databaseConfig = DatabaseConfig(
            rowCount: 4096,
            vectorDimension: 128,
            metadataCount: 0)
        let encryptionConfig = PnnsEncryptionParametersConfig(
            polyDegree: 4096,
            // use plaintextModulusBits: [16, 17] for plaintext CRT
            plaintextModulusBits: [17],
            coefficientModulusBits: [27, 28, 28])

        let benchmarkName = [
            "Process",
            String(describing: Scheme.self),
            encryptionConfig.description,
            "rowCount=\(databaseConfig.rowCount)",
            "vectorDimension=\(databaseConfig.vectorDimension)",
            "metadataCount=\(databaseConfig.metadataCount)",
        ].joined(separator: "/")
        // swiftlint:disable closure_parameter_position
        Benchmark(benchmarkName, configuration: PnnsBenchmarkConfiguration) { (
            benchmark,
            benchmarkContext: PnnsProcessBenchmarkContext<Scheme>) in
            for _ in benchmark.scaledIterations {
                try blackHole(benchmarkContext.database
                    .process(
                        config: benchmarkContext.serverConfig,
                        contexts: benchmarkContext.contexts))
            }
        } setup: {
            try PnnsProcessBenchmarkContext<Scheme>(
                databaseConfig: databaseConfig,
                parameterConfig: encryptionConfig)
        }
        // swiftlint:enable closure_parameter_position
    }
}

/// cosine similarity benchmark.
public func cosineSimilarityBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        let databaseConfig = DatabaseConfig(
            rowCount: 4096,
            vectorDimension: 128,
            metadataCount: 0)
        let encryptionConfig = PnnsEncryptionParametersConfig(
            polyDegree: 4096,
            // use plaintextModulusBits: [16, 17] for plaintext CRT
            plaintextModulusBits: [17],
            coefficientModulusBits: [27, 28, 28])
        let queryCount = 1

        let benchmarkName = [
            "CosineSimilarity",
            String(describing: Scheme.self),
            encryptionConfig.description,
            "rowCount=\(databaseConfig.rowCount)",
            "vectorDimension=\(databaseConfig.vectorDimension)",
            "metadataCount=\(databaseConfig.metadataCount)",
            "queryCount=\(queryCount)",
        ].joined(separator: "/")
        // swiftlint:disable closure_parameter_position
        Benchmark(benchmarkName, configuration: PnnsBenchmarkConfiguration) { (
            benchmark,
            benchmarkContext: PnnsBenchmarkContext<Scheme>) in
            for _ in benchmark.scaledIterations {
                try blackHole(
                    benchmarkContext.server.computeResponse(
                        to: benchmarkContext.query,
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
            try await PnnsBenchmarkContext<Scheme>(
                databaseConfig: databaseConfig,
                parameterConfig: encryptionConfig,
                queryCount: queryCount)
        }
        // swiftlint:enable closure_parameter_position
    }
}

struct DatabaseConfig {
    let rowCount: Int
    let vectorDimension: Int
    let metadataCount: Int

    init(rowCount: Int, vectorDimension: Int, metadataCount: Int = 0) {
        self.rowCount = rowCount
        self.vectorDimension = vectorDimension
        self.metadataCount = metadataCount
    }
}

private func getDatabaseForTesting(config: DatabaseConfig) -> Database {
    let rows = (0..<config.rowCount).map { rowIndex in
        let vector = (0..<config.vectorDimension).map { Float($0 + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1) }
        let metadata = Array(repeating: UInt8(rowIndex % Int(UInt8.max)), count: config.metadataCount)
        return DatabaseRow(
            entryId: UInt64(rowIndex),
            entryMetadata: metadata,
            vector: vector)
    }
    return Database(rows: rows)
}

struct PnnsEncryptionParametersConfig {
    let polyDegree: Int
    let plaintextModulusBits: [Int]
    let coefficientModulusBits: [Int]
}

extension PnnsEncryptionParametersConfig: CustomStringConvertible {
    var description: String {
        "N=\(polyDegree)/logt=\(plaintextModulusBits)/logq=\(coefficientModulusBits.description)"
    }
}

extension EncryptionParameters {
    init(from config: PnnsEncryptionParametersConfig) throws {
        let plaintextModulus = try Scheme.Scalar.generatePrimes(
            significantBitCounts: config.plaintextModulusBits,
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

extension PrivateNearestNeighborSearch.Response {
    func scaledNoiseBudget(using secretKey: Scheme.SecretKey) throws -> Int {
        try Int(
            noiseBudget(using: secretKey, variableTime: true) * Double(
                noiseBudgetScale))
    }
}

struct PnnsProcessBenchmarkContext<Scheme: HeScheme> {
    let database: Database
    let contexts: [Context<Scheme>]
    let serverConfig: ServerConfig<Scheme>

    init(databaseConfig: DatabaseConfig,
         parameterConfig: PnnsEncryptionParametersConfig) throws
    {
        let plaintextModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: parameterConfig.plaintextModulusBits,
            preferringSmall: true,
            nttDegree: parameterConfig.polyDegree)
        let coefficientModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: parameterConfig.coefficientModulusBits,
            preferringSmall: false,
            nttDegree: parameterConfig.polyDegree)

        let encryptionParameters = try EncryptionParameters<Scheme>(
            polyDegree: parameterConfig.polyDegree,
            plaintextModulus: plaintextModuli[0],
            coefficientModuli: coefficientModuli,
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.quantum128)

        let batchSize = 1
        let evaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: MatrixDimensions(
                rowCount: databaseConfig.rowCount,
                columnCount: databaseConfig.vectorDimension),
            encryptionParameters: encryptionParameters,
            maxQueryCount: batchSize)
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
        let serverConfig = ServerConfig(
            clientConfig: clientConfig,
            databasePacking: .diagonal(babyStepGiantStep: babyStepGiantStep))
        self.serverConfig = serverConfig

        self.database = getDatabaseForTesting(config: databaseConfig)
        self.contexts = try serverConfig.encryptionParameters.map { encryptionParameters in
            try Context(encryptionParameters: encryptionParameters)
        }
    }
}

struct PnnsBenchmarkContext<Scheme: HeScheme> {
    let processedDatabase: ProcessedDatabase<Scheme>
    let server: Server<Scheme>
    let client: Client<Scheme>
    let secretKey: SecretKey<Scheme>
    let evaluationKey: Scheme.EvaluationKey
    let evaluationKeyCount: Int
    let query: Query<Scheme>
    let evaluationKeySize: Int
    let querySize: Int
    let queryCiphertextCount: Int
    let responseSize: Int
    let responseCiphertextCount: Int
    let noiseBudget: Int

    init(databaseConfig: DatabaseConfig,
         parameterConfig: PnnsEncryptionParametersConfig,
         queryCount: Int) async throws
    {
        let plaintextModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: parameterConfig.plaintextModulusBits,
            preferringSmall: true,
            nttDegree: parameterConfig.polyDegree)
        let coefficientModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: parameterConfig.coefficientModulusBits,
            preferringSmall: false,
            nttDegree: parameterConfig.polyDegree)
        let encryptionParameters = try EncryptionParameters<Scheme>(
            polyDegree: parameterConfig.polyDegree,
            plaintextModulus: plaintextModuli[0],
            coefficientModuli: coefficientModuli,
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.quantum128)

        let evaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: MatrixDimensions(
                rowCount: databaseConfig.rowCount,
                columnCount: databaseConfig.vectorDimension),
            encryptionParameters: encryptionParameters,
            maxQueryCount: queryCount)
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
        let serverConfig = ServerConfig(
            clientConfig: clientConfig,
            databasePacking: .diagonal(babyStepGiantStep: babyStepGiantStep))

        let database = getDatabaseForTesting(config: databaseConfig)
        let contexts = try clientConfig.encryptionParameters
            .map { encryptionParameters in try Context(encryptionParameters: encryptionParameters) }
        self.processedDatabase = try database.process(config: serverConfig, contexts: contexts)
        self.client = try Client(config: clientConfig, contexts: contexts)
        self.server = try Server(database: processedDatabase)
        self.secretKey = try client.generateSecretKey()
        self.evaluationKey = try client.generateEvaluationKey(using: secretKey)

        // We query exact matches from rows in the database
        let databaseVectors = Array2d(data: database.rows.map { row in row.vector })
        let queryVectors = Array2d(data: database.rows.prefix(queryCount).map { row in row.vector })
        self.query = try client.generateQuery(for: queryVectors, using: secretKey)

        let response = try server.computeResponse(to: query, using: evaluationKey)
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
        self.noiseBudget = try response.scaledNoiseBudget(using: secretKey)
    }
}
