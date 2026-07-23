// Copyright 2025-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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
import Logging
import PrivateInformationRetrieval

extension Sequence {
    func mapAsync<T>(_ transform: @escaping (Iterator.Element) async throws -> T) async rethrows -> [T] {
        var result: [T] = []
        for element in self {
            try await result.append(transform(element))
        }
        return result
    }
}

extension Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase {
    struct Statistics {
        let totalEntries: Int
        let totalSize: Int
        let largestEntrySize: Int
        let averageEntrySize: Double

        var averageEntrySizeKiB: Double {
            averageEntrySize / 1024.0
        }

        var largestEntrySizeKiB: Double {
            Double(largestEntrySize) / 1024.0
        }
    }

    func statistics() -> Statistics {
        var largestEntrySize = 0
        var totalSize = 0
        let totalEntries = rows.count

        for row in rows {
            let size = row.value.count
            totalSize += size

            if size > largestEntrySize {
                largestEntrySize = size
            }
        }

        let averageEntrySize = totalEntries > 0 ? Double(totalSize) / Double(totalEntries) : 0.0

        return Statistics(
            totalEntries: totalEntries,
            totalSize: totalSize,
            largestEntrySize: largestEntrySize,
            averageEntrySize: averageEntrySize)
    }
}

struct Arguments: Codable, Equatable, Hashable {
    static let defaultArguments = Arguments(
        inputDatabase: "/path/to/input/database.txtpb",
        outputDatabasePrefix: "/path/to/output/database",
        latticeDimension: 1024,
        errorStdDev: 6.4,
        plaintextModulusBits: 14,
        ciphertextModulusBits: 42,
        shardCount: 5,
        chunkSize: nil,
        seed: nil)

    let inputDatabase: String
    let outputDatabasePrefix: String
    let latticeDimension: Int
    let errorStdDev: Double
    let plaintextModulusBits: Int
    let ciphertextModulusBits: Int
    let shardCount: Int
    let chunkSize: Int?
    let seed: [UInt8]?

    var configFile: String {
        "\(outputDatabasePrefix).config.binpb"
    }

    static func defaultJsonString() -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        // swiftlint:disable:next force_try
        let data = try! encoder.encode(Arguments.defaultArguments)
        // swiftlint:disable:next force_unwrapping
        return String(data: data, encoding: .utf8)!
    }

    func encryptionParams() throws -> SimplePirEncryptionParams {
        guard let errorStdDevEnum = ErrorStdDev.allCases.first(where: { $0.toDouble == errorStdDev }) else {
            throw ValidationError(
                "Unsupported errorStdDev=\(errorStdDev), must be one of \(ErrorStdDev.allCases.map(\.toDouble))")
        }
        return try .init(
            plaintextModulusBits: plaintextModulusBits,
            ciphertextModulusBits: ciphertextModulusBits,
            latticeDimension: latticeDimension,
            errorStdDev: errorStdDevEnum)
    }

    func databaseFile(for shardIndex: Int) -> String {
        "\(outputDatabasePrefix)-\(shardIndex).bin"
    }

    func hintFile(for shardIndex: Int) -> String {
        "\(outputDatabasePrefix)-\(shardIndex).hint.bin"
    }

    func with(chunkSize: Int) -> Arguments {
        Arguments(
            inputDatabase: inputDatabase,
            outputDatabasePrefix: outputDatabasePrefix,
            latticeDimension: latticeDimension,
            errorStdDev: errorStdDev,
            plaintextModulusBits: plaintextModulusBits,
            ciphertextModulusBits: ciphertextModulusBits,
            shardCount: shardCount,
            chunkSize: chunkSize,
            seed: seed)
    }
}

/// This executable is used in tests, which breaks `swift test -c release` when used with `@main`.
/// So we avoid using `@main` here.
struct SimplePirProcessDatabase: AsyncParsableCommand {
    static let configuration: CommandConfiguration = .init(
        commandName: "SimplePIRProcessDatabase")

    static let logger = Logger(label: "SimplePIRProcessDatabase")

    @Argument(
        help: """
            Path to json configuration file.
            Default:
            \(Arguments.defaultJsonString())
            """)
    var configFile: String

    func shardInputDatabase(
        _ inputDatabase: Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase,
        args: Arguments) throws -> (DatabaseMap, [Array2d<UInt8>])
    {
        let entries = inputDatabase.rows.lazy.map { row in
            let originalIndex = Int(String(bytes: row.keyword, encoding: .utf8) ?? "") ?? -1
            return (originalIndex: originalIndex, value: Array(row.value))
        }

        guard let chunkSize = args.chunkSize else {
            throw ValidationError("chunkSize must be set before calling shardInputDatabase")
        }

        return DatabaseMap.shardDatabase(
            entries: entries, shardCount: args.shardCount, chunkSize: chunkSize)
    }

    func processShard<Scalar: ScalarType>(
        _ shard: Array2d<UInt8>,
        shardIndex: Int,
        args: Arguments,
        _: Scalar.Type) async throws -> SimplePirParameters
    {
        let processedShard = try await SimplePirServer<Scalar>.process(
            database: shard,
            encryptionParams: args.encryptionParams(),
            seed: args.seed)
        let databaseFile = args.databaseFile(for: shardIndex)
        let hintFile = args.hintFile(for: shardIndex)

        try processedShard.database.save(to: databaseFile)
        try processedShard.hint.save(to: hintFile)
        return processedShard.params
    }

    func process<Scalar: ScalarType>(args: Arguments, _: Scalar.Type) async throws {
        let inputDatabase = try Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase(
            from: args.inputDatabase)

        let resolvedArgs: Arguments
        if args.chunkSize != nil {
            resolvedArgs = args
        } else {
            let stats = inputDatabase.statistics()
            Self.logger.info("Database statistics: \(stats)")

            let computedChunkSize = (stats.largestEntrySize + args.shardCount - 1) / args.shardCount
            let computedChunkSizeKiB = Double(computedChunkSize) / 1024.0
            let chunkKiB = String(format: "%.2f", computedChunkSizeKiB)
            Self.logger.info(
                "Auto-computed chunk size: \(computedChunkSize) bytes (\(chunkKiB) KiB) for \(args.shardCount) shards")
            resolvedArgs = args.with(chunkSize: computedChunkSize)
        }
        let (databaseMap, shards) = try shardInputDatabase(inputDatabase, args: resolvedArgs)
        var shardParams: [Apple_SwiftHomomorphicEncryption_Pir_V1_SimplePIRParameters] = .init(
            repeating: Apple_SwiftHomomorphicEncryption_Pir_V1_SimplePIRParameters(),
            count: resolvedArgs.shardCount)
        try await withThrowingTaskGroup(of: (Int, SimplePirParameters).self) { group in
            for (shardIndex, shard) in shards.enumerated() {
                group.addTask {
                    let params = try await processShard(
                        shard,
                        shardIndex: shardIndex,
                        args: resolvedArgs,
                        Scalar.self)
                    return (shardIndex, params)
                }
            }
            for try await (shardIndex, params) in group {
                shardParams[shardIndex] = params.proto()
            }
        }

        let config = try Apple_SwiftHomomorphicEncryption_Api_Pir_V1_SimplePIRConfig.with { config in
            config.databaseMapping = databaseMap.proto()
            config.params = shardParams
            config.hintIdentifiers = try (0..<resolvedArgs.shardCount).map { shardIndex in
                let hintFile = resolvedArgs.hintFile(for: shardIndex)
                return try calculateHintFileIdentifier(path: hintFile)
            }
        }

        try config.save(to: resolvedArgs.configFile)

        Self.logger.info("Database processing complete. Starting verification...")

        do {
            try await verifyProcessing(
                args: resolvedArgs,
                inputDatabase: inputDatabase,
                Scalar.self)
        } catch {
            cleanupFiles(args: resolvedArgs)
            throw error
        }
    }

    func calculateHintFileIdentifier(path: String) throws -> Data {
        let file = try Data(contentsOf: URL(filePath: path), options: .alwaysMapped)
        return Data(SHA256.hash(data: file))
    }

    func verifyProcessing<Scalar: ScalarType>(
        args: Arguments,
        inputDatabase: Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase,
        _: Scalar.Type) async throws
    {
        let configFile = args.configFile
        let config = try Apple_SwiftHomomorphicEncryption_Api_Pir_V1_SimplePIRConfig(from: configFile)

        let dbMap = config.databaseMapping.native()
        let entries = dbMap.entries
        let entriesWithFullShards = entries.filter { $0.chunks.count == args.shardCount }
        guard let testEntry = entriesWithFullShards.randomElement() else {
            throw ValidationError(
                "No entries found with chunk count equal to shard count (\(args.shardCount))")
        }
        let testIndex = testEntry.originalIndex
        let shardMap = ShardMap(databaseMap: dbMap)

        Self.logger.info("Testing entry: originalIndex=\(testIndex)")

        var servers: [SimplePirServer<Scalar>] = []
        var clients: [SimplePirClient<DefaultQueryGenerator<Scalar>>] = []

        for shardIndex in 0..<args.shardCount {
            let databaseFile = args.databaseFile(for: shardIndex)
            let hintFile = args.hintFile(for: shardIndex)

            let database = try SimplePirDatabase<Scalar>(from: databaseFile).database
            let hint: Array2d<Scalar> = try Array2d(from: hintFile)

            let params = try config.params[shardIndex].native()
            let server = try await SimplePirServer(
                processedDatabase: database,
                hint: hint,
                params: params)
            servers.append(server)

            let client = try await SimplePirClient(
                queryGenerator: DefaultQueryGenerator<Scalar>(
                    params: params,
                    hint: hint))
            clients.append(client)
        }
        let client = try SimplePirClientForAllShards<DefaultQueryGenerator>(shardMap: shardMap, clients: clients)
        Self.logger.info("Successfully loaded \(servers.count) servers and \(clients.count) clients")

        guard
            let originalRow = inputDatabase.rows.first(where: { row in
                let rowIndex = Int(String(bytes: row.keyword, encoding: .utf8) ?? "") ?? -1
                return rowIndex == testIndex
            })
        else {
            throw ValidationError("Could not find row with originalIndex \(testIndex)")
        }
        let originalValue = Array(originalRow.value)

        guard let queries = try await client.query(for: testIndex) else {
            throw ValidationError("Could not generate query for \(testIndex)")
        }
        let responses = try await queries.enumerated().mapAsync { shardIndex, querisForShard in
            let server = servers[shardIndex]
            let computeStartTime = Date()
            let responses = try await querisForShard.mapAsync { try await server.computeResponse(to: $0.queries) }
            let computeElapsedTime = Date().timeIntervalSince(computeStartTime)
            Self.logger.info(
                "computeResponse time: \(computeElapsedTime) seconds for shard \(shardIndex)")
            return responses
        }
        guard var result = try await client.decrypt(responses: responses, for: testIndex, with: queries) else {
            throw ValidationError("Could not get results for \(testIndex)")
        }
        print(testEntry.size)
        result = Array(result.prefix(testEntry.size))
        let isValid = result.count == originalValue.count && result == originalValue

        guard isValid else {
            let printLength = min(100, min(result.count, originalValue.count))
            Self.logger.error(
                "Verification failed! Retrieved value does not match original for index \(testIndex)")
            Self.logger.error("Expected \(originalValue.count) bytes, got \(result.count) bytes")
            Self.logger.error("First \(printLength) bytes of result: \(Array(result[0..<printLength]))")
            Self.logger.error(
                "First \(printLength) bytes of original: \(Array(originalValue[0..<printLength]))")
            throw ValidationError("Verification failed for index \(testIndex)")
        }

        Self.logger.info(
            "Verification successful! Retrieved value matches original for index \(testIndex)")
    }

    func cleanupFiles(args: Arguments) {
        Self.logger.warning("Cleaning up serialized files.")
        let fileManager = FileManager.default
        for shardIndex in 0..<args.shardCount {
            let databaseFile = args.databaseFile(for: shardIndex)
            let hintFile = args.hintFile(for: shardIndex)
            try? fileManager.removeItem(atPath: databaseFile)
            try? fileManager.removeItem(atPath: hintFile)
        }
        let configFile = args.configFile
        try? fileManager.removeItem(atPath: configFile)
        Self.logger.info("Cleanup complete.")
    }

    mutating func run() async throws {
        let configURL = URL(fileURLWithPath: configFile)
        let configData = try Data(contentsOf: configURL)
        let config = try JSONDecoder().decode(Arguments.self, from: configData)

        switch config.ciphertextModulusBits {
        case 0...32: try await process(args: config, UInt32.self)
        case 33...64: try await process(args: config, UInt64.self)
        default:
            Self.logger.error("Unsupported ciphertext modulus bits: \(config.ciphertextModulusBits)")
        }
    }
}

/// workaround to call the async main, but without using a top-level `await` to not break `swift test -c release`.
let group = DispatchGroup()
group.enter()
let task = Task.detached(priority: .userInitiated) {
    defer { group.leave() }
    await SimplePirProcessDatabase.main()
}

group.wait()
