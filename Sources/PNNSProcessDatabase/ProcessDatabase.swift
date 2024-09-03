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

//// Copyright 2024 Apple Inc. and the Swift Homomorphic Encryption project authors
////
//// Licensed under the Apache License, Version 2.0 (the "License");
//// you may not use this file except in compliance with the License.
//// You may obtain a copy of the License at
////
////     http://www.apache.org/licenses/LICENSE-2.0
////
//// Unless required by applicable law or agreed to in writing, software
//// distributed under the License is distributed on an "AS IS" BASIS,
//// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//// See the License for the specific language governing permissions and
//// limitations under the License.
//
import ArgumentParser
import Foundation
import HomomorphicEncryption
import Logging
import PrivateNearestNeighborsSearch
import PrivateNearestNeighborsSearchProtobuf

/// Creates a new `Database` from a given path.
/// - Parameter path: The path to the `Database` file.
/// - Throws: Error upon failure to load the database.
extension Database {
    init(from path: String) throws {
        let database = try Apple_SwiftHomomorphicEncryption_Pnns_V1_Database(from: path)
        self = database.native()
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
        outputDatabase: "/path/to/output/database.binpb",
        outputServerConfig: "path/to/output/server-config.txtpb",
        rlweParameters: .n_8192_logq_3x55_logt_30,
        extraPlaintextModuli: nil,
        distanceMetric: .cosineSimilarity,
        batchSize: 1,
        scalingFactor: nil,
        databasePacking: nil,
        queryPacking: nil,
        trials: 1,
        trialDistanceTolerance: 0.01)

    let inputDatabase: String
    let outputDatabase: String
    let outputServerConfig: String?
    let rlweParameters: PredefinedRlweParameters
    let extraPlaintextModuli: [UInt64]?
    let distanceMetric: DistanceMetric?
    let batchSize: Int?
    let scalingFactor: Int?
    let databasePacking: MatrixPacking?
    let queryPacking: MatrixPacking?
    let trials: Int?
    let trialDistanceTolerance: Float?

    static func defaultJsonString(vectorDimension: Int) -> String {
        // swiftlint:disable:next force_try
        let resolved: ResolvedArguments = try! defaultArguments.resolve(for: vectorDimension, scheme: Bfv<UInt64>.self)
        let defaultArguments = Arguments(
            inputDatabase: resolved.inputDatabase,
            outputDatabase: resolved.outputDatabase,
            outputServerConfig: resolved.outputServerConfig,
            rlweParameters: resolved.rlweParameters,
            extraPlaintextModuli: resolved.extraPlaintextModuli,
            distanceMetric: resolved.distanceMetric,
            batchSize: resolved.batchSize,
            scalingFactor: resolved.scalingFactor,
            databasePacking: resolved.databasePacking,
            queryPacking: resolved.queryPacking,
            trials: resolved.trials,
            trialDistanceTolerance: resolved.trialDistanceTolerance)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // swiftlint:disable:next force_try
        let data = try! encoder.encode(defaultArguments)
        return String(decoding: data, as: UTF8.self)
    }

    func resolve<Scheme: HeScheme>(for vectorDimension: Int, scheme _: Scheme.Type) throws -> ResolvedArguments {
        let distanceMetric = distanceMetric ?? .cosineSimilarity
        let databasePacking = databasePacking ?? .diagonal(
            babyStepGiantStep: BabyStepGiantStep(
                vectorDimension: vectorDimension))
        let queryPacking = queryPacking ?? .denseRow

        let plaintextModuli = [rlweParameters.plaintextModulus] + (extraPlaintextModuli ?? [])
        let scalingFactor = scalingFactor ?? ClientConfig<Scheme>.maxScalingFactor(
            distanceMetric: distanceMetric,
            vectorDimension: vectorDimension,
            plaintextModuli: plaintextModuli.map { Scheme.Scalar($0) })

        return try ResolvedArguments(
            inputDatabase: inputDatabase,
            outputDatabase: outputDatabase,
            outputServerConfig: outputServerConfig,
            rlweParameters: rlweParameters,
            extraPlaintextModuli: extraPlaintextModuli ?? [],
            distanceMetric: distanceMetric,
            batchSize: batchSize ?? 1,
            scalingFactor: scalingFactor,
            databasePacking: databasePacking,
            queryPacking: queryPacking,
            trials: trials ?? 1,
            trialDistanceTolerance: trialDistanceTolerance ?? 0.01)
    }
}

/// The resolved arguments for the database processing.
struct ResolvedArguments: CustomStringConvertible, Encodable {
    let inputDatabase: String
    let outputDatabase: String
    let outputServerConfig: String?
    let rlweParameters: PredefinedRlweParameters
    let extraPlaintextModuli: [UInt64]
    let distanceMetric: DistanceMetric
    let batchSize: Int
    let scalingFactor: Int
    let databasePacking: MatrixPacking
    let queryPacking: MatrixPacking
    let trials: Int
    let trialDistanceTolerance: Float

    var description: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // swiftlint:disable:next force_try
        let data = try! encoder.encode(self)
        return String(decoding: data, as: UTF8.self)
    }

    /// - Parameters:
    ///  - inputDatabase: Path to the input database.
    ///  - outputDatabase: Path to save the processed database.
    ///  - outputServerConfig: Path to save the server configuration.
    ///  - trials: Number of test queries .
    init(
        inputDatabase: String,
        outputDatabase: String,
        outputServerConfig: String?,
        rlweParameters: PredefinedRlweParameters,
        extraPlaintextModuli: [UInt64],
        distanceMetric: DistanceMetric,
        batchSize: Int,
        scalingFactor: Int,
        databasePacking: MatrixPacking,
        queryPacking: MatrixPacking,
        trials: Int,
        trialDistanceTolerance: Float) throws
    {
        self.inputDatabase = inputDatabase
        self.outputDatabase = outputDatabase
        self.outputServerConfig = outputServerConfig
        self.rlweParameters = rlweParameters
        self.extraPlaintextModuli = extraPlaintextModuli
        self.distanceMetric = distanceMetric
        self.batchSize = batchSize
        self.scalingFactor = scalingFactor
        self.databasePacking = databasePacking
        self.queryPacking = queryPacking
        self.trials = trials
        self.trialDistanceTolerance = trialDistanceTolerance
    }
}

@main
struct ProcessDatabase: ParsableCommand {
    static let configuration: CommandConfiguration = .init(
        commandName: "PNNSProcessDatabase")

    static let logger = Logger(label: "PNNSProcessDatabase")

    @Argument(
        help: """
            Path to json configuration file.
            Default for
                - \(Arguments.defaultArguments.rlweParameters),
                - vectorDimension: 128
            \(Arguments.defaultJsonString(vectorDimension: 128))
            """)
    var configFile: String

    /// Performs the processing on the given database.
    /// - Parameters:
    ///   - config: The configuration for the PNNS processing.
    ///   - scheme: The HE scheme.
    /// - Throws: Error upon processing the database.
    @inlinable
    mutating func process<Scheme: HeScheme>(config: Arguments, scheme: Scheme.Type) throws {
        let database = try Database(from: config.inputDatabase)
        guard let vectorDimension = database.rows.first?.vector.count else {
            throw PnnsError.emptyDatabase
        }
        let plaintextMatrixDimensions = try MatrixDimensions(
            rowCount: database.rows.count,
            columnCount: vectorDimension)

        let config: ResolvedArguments = try config.resolve(for: vectorDimension, scheme: Scheme.self)
        ProcessDatabase.logger.info("Processing database with configuration: \(config)")

        let encryptionParameters = try EncryptionParameters<Scheme>(from: config.rlweParameters)
        let clientConfig = try ClientConfig<Scheme>(
            encryptionParams: encryptionParameters,
            scalingFactor: config.scalingFactor,
            queryPacking: config.queryPacking,
            vectorDimension: vectorDimension,
            evaluationKeyConfig: MatrixMultiplication
                .evaluationKeyConfig(
                    plaintextMatrixDimensions: plaintextMatrixDimensions,
                    encryptionParameters: encryptionParameters),
            distanceMetric: config.distanceMetric)
        let serverConfig = ServerConfig<Scheme>(
            clientConfig: clientConfig,
            databasePacking: config.databasePacking)
        let processed = try database.process(config: serverConfig)
        ProcessDatabase.logger.info("Processed database")

        if config.trials > 0 {
            var queryRows = Array2d(data: database.rows.prefix(config.batchSize).map { row in row.vector })
            queryRows.append(rows: Array(
                repeating: 0,
                count: vectorDimension * (config.batchSize - queryRows.rowCount)))

            ProcessDatabase.logger.info("Validating")
            let validationResult = try processed.validate(query: queryRows, trials: config.trials)
            for row in 0..<min(database.rows.count, config.batchSize) {
                let selfProduct = validationResult.databaseDistances.distances.row(row: row)[row]
                let error = abs(selfProduct - 1.0)
                guard error <= config.trialDistanceTolerance else {
                    ProcessDatabase.logger
                        .error("Result error \(error) exceeds tolerance \(config.trialDistanceTolerance)")
                    throw ValidationError("Result error \(error) exceeds tolerance \(config.trialDistanceTolerance)")
                }
            }
            let description = try validationResult.description()
            ProcessDatabase.logger.info("ValidationResult \(description)")
        }

        try processed.serialize().proto().save(to: config.outputDatabase)
        ProcessDatabase.logger.info("Saved processed database to \(config.outputDatabase)")

        if let serverConfigFile = config.outputServerConfig {
            let protoServerConfig = try processed.serverConfig.proto()
            try protoServerConfig.save(to: serverConfigFile)
            ProcessDatabase.logger.info("Saved server configuration to \(serverConfigFile)")
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

extension ValidationResult {
    /// Returns a description of processed database validation.
    public func description() throws -> String {
        func sizeString(byteCount: Int, count: Int, label: String) -> String {
            let sizeKB = String(format: "%.01f", Double(byteCount) / 1000.0)
            return "\(sizeKB) KB (\(count) \(label))"
        }

        var descriptionDict = [String: String]()
        let queryCount: Int = query.ciphertextMatrices.map { matrix in matrix.ciphertexts.count }.sum()
        descriptionDict["query size"] = try sizeString(byteCount: query.size(), count: queryCount, label: "ciphertexts")
        descriptionDict["evaluation key size"] = try sizeString(
            byteCount: evaluationKey.size(),
            count: evaluationKey.config.keyCount,
            label: "keys"
        )

        let responseCount: Int = response.ciphertextMatrices.map { matrix in matrix.ciphertexts.count }.sum()
        descriptionDict["response size"] = try sizeString(byteCount: response.size(), count: responseCount,
                                                          label: "ciphertexts")
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
