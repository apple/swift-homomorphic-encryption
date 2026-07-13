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

import Foundation
package import HomomorphicEncryption
import ModularArithmetic
package import PrivateInformationRetrieval
import Testing

extension Sequence {
    func mapAsync<T>(_ transform: @escaping (Iterator.Element) async throws -> T) async rethrows -> [T] {
        var result: [T] = []
        for element in self {
            try await result.append(transform(element))
        }
        return result
    }
}

package struct DatabaseShape {
    package let entryCount: Int
    package let entrySize: Int

    package init(entryCount: Int, entrySize: Int) {
        self.entryCount = entryCount
        self.entrySize = entrySize
    }

    package func makeDatabase() -> Array2d<UInt8> {
        var db = Array2d<UInt8>.zero(rowCount: entryCount, columnCount: entrySize)
        var entry: UInt8 = 0
        for i in db.data.indices {
            db.data[i] = entry
            entry &+= 1
        }
        return db
    }
}

extension Array where Element: Equatable {
    func allElementsUnique() -> Bool {
        for i in 0..<count {
            for j in i + 1..<count where self[i] == self[j] {
                return false
            }
        }
        return true
    }
}

extension Duration {
    var nanoseconds: Int64 {
        components.seconds * 1_000_000_000 + components.attoseconds / 1_000_000_000
    }
}

package enum SimplePirTestsUtils {
    @discardableResult
    package static func runEncryptDecryptRoundTripTest<Server: SimplePirServerProtocol>(plaintextBits: Int,
                                                                                        ciphertextBits: Int,
                                                                                        entryCount: Int,
                                                                                        entrySize: Int,
                                                                                        _: Server
                                                                                            .Type) async throws
        -> SimplePirParameters
    {
        let encryptionParams = try SimplePirEncryptionParams(
            plaintextModulusBits: plaintextBits,
            ciphertextModulusBits: ciphertextBits,
            latticeDimension: 1024,
            errorStdDev: .stdDev64,
            securityLevel: .unchecked)
        let databaseShape = DatabaseShape(entryCount: entryCount, entrySize: entrySize)
        let rawDatabase = databaseShape.makeDatabase()
        let processed = try await Server.process(
            database: rawDatabase,
            encryptionParams: encryptionParams,
            seed: nil)
        let server = try await Server(
            processedDatabase: processed.database.database,
            hint: processed.hint,
            params: processed.params)
        let client = try await SimplePirClient(queryGenerator: DefaultQueryGenerator(
            params: server.params,
            hint: server.hint))

        for _ in 0..<5 {
            let index = Int.random(in: 0..<databaseShape.entryCount)
            let preparedQuery = try await client.query(at: index)
            async let preparedResponse = preparedQuery.prepareResponse()
            let response = try await server.computeResponse(to: preparedQuery.queries)
            let result = try await client.decrypt(responses: response, with: preparedResponse, at: index)

            #expect(rawDatabase.row(index) == result)
        }
        return server.params
    }

    package static func testSimplePirDatabaseSerialization<Scalar: ScalarType>(
        rowCount: Int,
        columnCount: Int,
        _: Scalar.Type) throws
    {
        let testData = Array2d<Scalar>(
            data: (0..<(rowCount * columnCount)).map { Scalar($0 % 256) },
            rowCount: rowCount,
            columnCount: columnCount)

        let database = SimplePirDatabase(database: testData)

        let tempDir = FileManager.default.temporaryDirectory
        let tempFile = tempDir.appendingPathComponent("test_simplepir_db_\(UUID().uuidString).bin").path
        defer {
            try? FileManager.default.removeItem(atPath: tempFile)
        }

        try database.save(to: tempFile)
        let loadedDatabase = try SimplePirDatabase<Scalar>(from: tempFile)

        #expect(loadedDatabase == database)
    }

    package static func testSimplePirDatabaseCorruptedData<Scalar: ScalarType>(
        rowCount: Int,
        columnCount: Int,
        _: Scalar.Type) throws
    {
        let tempDir = FileManager.default.temporaryDirectory
        let tempFile = tempDir.appendingPathComponent("test_simplepir_corrupted_\(UUID().uuidString).bin").path
        defer {
            try? FileManager.default.removeItem(atPath: tempFile)
        }

        // Create a file with header but truncated data
        var corruptedData = Data()
        withUnsafeBytes(of: UInt32(rowCount).bigEndian) { corruptedData.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt32(columnCount).bigEndian) { corruptedData.append(contentsOf: $0) }

        let expectedBytes = rowCount * columnCount * MemoryLayout<Scalar>.stride
        let truncatedData = Data(repeating: 0, count: expectedBytes / 2)
        corruptedData.append(truncatedData)

        try corruptedData.write(to: URL(fileURLWithPath: tempFile))

        #expect(throws: PirError.self) {
            _ = try SimplePirDatabase<Scalar>(from: tempFile)
        }
    }

    package static func testSimplePirFlowWithSharding(rowCount: Int,
                                                      entrySize: Int,
                                                      chunkSize: Int,
                                                      shardCount: Int) async throws
    {
        let plaintextBits = 14
        let ciphertextBits = 42
        let entryCount: Int = rowCount
        let entrySize: Int = entrySize
        let encryptionParams = try SimplePirEncryptionParams(
            plaintextModulusBits: plaintextBits,
            ciphertextModulusBits: ciphertextBits,
            latticeDimension: 1024,
            errorStdDev: .stdDev64,
            securityLevel: .unchecked)
        let databaseShape = DatabaseShape(entryCount: entryCount, entrySize: entrySize)
        let database = databaseShape.makeDatabase()
        let rawDatabase = (0..<entryCount).map { ($0, database.row($0)) }

        let (databaseMap, shards) = DatabaseMap.shardDatabase(
            entries: rawDatabase,
            shardCount: shardCount,
            chunkSize: chunkSize)
        let processedDatabases = try await shards.mapAsync { database in
            try await SimplePirServer<UInt64>.process(
                database: database,
                encryptionParams: encryptionParams,
                seed: nil)
        }
        let servers = try await processedDatabases.mapAsync { processedDatabase in
            try await SimplePirServer(
                processedDatabase: processedDatabase.database.database,
                hint: processedDatabase.hint,
                params: processedDatabase.params)
        }
        let clients = try await processedDatabases.mapAsync { processedDatabase in
            try await SimplePirClient(queryGenerator: DefaultQueryGenerator(
                params: processedDatabase.params,
                hint: processedDatabase.hint))
        }
        let shardClient = try SimplePirClientForAllShards(databaseMap: databaseMap, clients: clients)

        let queryIndex = Int.random(in: 0..<rowCount)
        let queries = try #require(try await shardClient.query(for: queryIndex))
        let queriesToSend: [[Array2d<UInt64>]] = queries.map { queriesForShard in
            queriesForShard.map(\.queries)
        }
        #expect(queriesToSend.map(\.count).max() == queriesToSend.map(\.count).min())
        #expect(queriesToSend.allElementsUnique())
        let responses = try await zip(servers, queriesToSend).mapAsync { server, queries in
            try await queries.mapAsync { query in
                try await server.computeResponse(to: query)
            }
        }
        let result = try await shardClient.decrypt(responses: responses, for: queryIndex, with: queries)
        #expect(result == database.row(queryIndex))
    }

    package static func testSimplePirFlowWithShardingOutOfBounds(
        rowCount: Int,
        entrySize: Int,
        chunkSize: Int,
        shardCount: Int) async throws
    {
        let plaintextBits = 14
        let ciphertextBits = 42
        let entryCount: Int = rowCount
        let entrySize: Int = entrySize
        let encryptionParams = try SimplePirEncryptionParams(
            plaintextModulusBits: plaintextBits,
            ciphertextModulusBits: ciphertextBits,
            latticeDimension: 1024,
            errorStdDev: .stdDev64,
            securityLevel: .unchecked)
        let databaseShape = DatabaseShape(entryCount: entryCount, entrySize: entrySize)
        let database = databaseShape.makeDatabase()
        let rawDatabase = (0..<entryCount).map { ($0, database.row($0)) }

        let (databaseMap, shards) = DatabaseMap.shardDatabase(
            entries: rawDatabase,
            shardCount: shardCount,
            chunkSize: chunkSize)
        let processedDatabases = try await shards.mapAsync { database in
            try await SimplePirServer<UInt64>.process(
                database: database,
                encryptionParams: encryptionParams,
                seed: nil)
        }
        let servers = try await processedDatabases.mapAsync { processedDatabase in
            try await SimplePirServer(
                processedDatabase: processedDatabase.database.database,
                hint: processedDatabase.hint,
                params: processedDatabase.params)
        }
        let clients = try await processedDatabases.mapAsync { processedDatabase in
            try await SimplePirClient(queryGenerator: DefaultQueryGenerator(
                params: processedDatabase.params,
                hint: processedDatabase.hint))
        }
        let shardClient = try SimplePirClientForAllShards(databaseMap: databaseMap, clients: clients)
        let outOfBoundsIndex = entryCount + 100
        let outOfBoundsQueries = try #require(try await shardClient.query(for: outOfBoundsIndex))

        let outOfBoundsQueriesToSend: [[Array2d<UInt64>]] = outOfBoundsQueries.map { queriesForShard in
            queriesForShard.map(\.queries)
        }
        #expect(outOfBoundsQueriesToSend.map(\.count).max() == outOfBoundsQueriesToSend.map(\.count).min())
        #expect(outOfBoundsQueriesToSend.allElementsUnique())

        let outOfBoundsResponses = try await zip(servers, outOfBoundsQueriesToSend).mapAsync { server, queries in
            try await queries.mapAsync { query in
                try await server.computeResponse(to: query)
            }
        }

        let outOfBoundsResult = try await shardClient.decrypt(
            responses: outOfBoundsResponses,
            for: outOfBoundsIndex,
            with: outOfBoundsQueries)
        #expect(outOfBoundsResult == nil)
    }

    package static func testSimplePirFlowWithShardingTimingSideChannel(
        rowCount: Int,
        entrySize: Int,
        chunkSize: Int,
        shardCount: Int) async throws
    {
        let plaintextBits = 14
        let ciphertextBits = 42
        let entryCount: Int = rowCount
        let entrySize: Int = entrySize
        let encryptionParams = try SimplePirEncryptionParams(
            plaintextModulusBits: plaintextBits,
            ciphertextModulusBits: ciphertextBits,
            latticeDimension: 1024,
            errorStdDev: .stdDev64,
            securityLevel: .unchecked)
        let databaseShape = DatabaseShape(entryCount: entryCount, entrySize: entrySize)
        let database = databaseShape.makeDatabase()
        let rawDatabase = (0..<entryCount).map { ($0, database.row($0)) }

        let (databaseMap, shards) = DatabaseMap.shardDatabase(
            entries: rawDatabase,
            shardCount: shardCount,
            chunkSize: chunkSize)
        let processedDatabases = try await shards.mapAsync { database in
            try await SimplePirServer<UInt64>.process(
                database: database,
                encryptionParams: encryptionParams,
                seed: nil)
        }
        let servers = try await processedDatabases.mapAsync { processedDatabase in
            try await SimplePirServer(
                processedDatabase: processedDatabase.database.database,
                hint: processedDatabase.hint,
                params: processedDatabase.params)
        }

        // Run multiple iterations for stable measurements
        let clock = ContinuousClock()
        var inBoundsQueryTimes: [Duration] = []
        var inBoundsDecryptTimes: [Duration] = []

        for _ in 0..<5 {
            let clients = try await processedDatabases.mapAsync { processedDatabase in
                try await SimplePirClient(queryGenerator: DefaultQueryGenerator(
                    params: processedDatabase.params,
                    hint: processedDatabase.hint))
            }
            let shardClient = try SimplePirClientForAllShards(databaseMap: databaseMap, clients: clients)

            let inBoundsIndex = Int.random(in: 0..<100)

            var inBoundsQueries: [[PrecomputedQueries<UInt64>.WithQueryIndices]]?
            let inBoundsQueryTime = try await clock.measure {
                inBoundsQueries = try await shardClient.query(for: inBoundsIndex)
            }
            inBoundsQueryTimes.append(inBoundsQueryTime)

            guard let unwrappedQueries = inBoundsQueries else {
                throw PirError.corruptedData("Failed to generate queries")
            }
            let inBoundsQueriesToSend: [[Array2d<UInt64>]] = unwrappedQueries.map { queriesForShard in
                queriesForShard.map(\.queries)
            }

            let inBoundsResponses = try await zip(servers, inBoundsQueriesToSend).mapAsync { server, queries in
                try await queries.mapAsync { query in
                    try await server.computeResponse(to: query)
                }
            }

            var inBoundsResult: [UInt8]?
            let inBoundsDecryptTime = try await clock.measure {
                inBoundsResult = try await shardClient.decrypt(
                    responses: inBoundsResponses,
                    for: inBoundsIndex,
                    with: unwrappedQueries)
            }
            inBoundsDecryptTimes.append(inBoundsDecryptTime)
            #expect(inBoundsResult == database.row(inBoundsIndex))
        }

        let avgInBoundsQueryTime = inBoundsQueryTimes.reduce(.zero, +) / inBoundsQueryTimes.count
        let avgInBoundsDecryptTime = inBoundsDecryptTimes.reduce(.zero, +) / inBoundsDecryptTimes.count

        var outOfBoundsQueryTimes: [Duration] = []
        var outOfBoundsDecryptTimes: [Duration] = []

        for _ in 0..<5 {
            let clients = try await processedDatabases.mapAsync { processedDatabase in
                try await SimplePirClient(queryGenerator: DefaultQueryGenerator(
                    params: processedDatabase.params,
                    hint: processedDatabase.hint))
            }

            let shardClient = try SimplePirClientForAllShards(databaseMap: databaseMap, clients: clients)

            let outOfBoundsIndex = entryCount + 100
            var outOfBoundsQueries: [[PrecomputedQueries<UInt64>.WithQueryIndices]]?
            let outOfBoundsQueryTime = try await clock.measure {
                outOfBoundsQueries = try await shardClient.query(for: outOfBoundsIndex)
            }
            outOfBoundsQueryTimes.append(outOfBoundsQueryTime)

            guard let unwrappedQueries = outOfBoundsQueries else {
                throw PirError.corruptedData("Failed to generate queries")
            }
            let outOfBoundsQueriesToSend: [[Array2d<UInt64>]] = unwrappedQueries.map { queriesForShard in
                queriesForShard.map(\.queries)
            }

            let outOfBoundsResponses = try await zip(servers, outOfBoundsQueriesToSend).mapAsync { server, queries in
                try await queries.mapAsync { query in
                    try await server.computeResponse(to: query)
                }
            }

            var outOfBoundsResult: [UInt8]?
            let outOfBoundsDecryptTime = try await clock.measure {
                outOfBoundsResult = try await shardClient.decrypt(
                    responses: outOfBoundsResponses,
                    for: outOfBoundsIndex,
                    with: unwrappedQueries)
            }
            outOfBoundsDecryptTimes.append(outOfBoundsDecryptTime)
            #expect(outOfBoundsResult == nil)
        }

        let avgOutOfBoundsQueryTime = outOfBoundsQueryTimes.reduce(.zero, +) / outOfBoundsQueryTimes.count
        let avgOutOfBoundsDecryptTime = outOfBoundsDecryptTimes.reduce(.zero, +) / outOfBoundsDecryptTimes.count

        let queryDiff = abs((avgOutOfBoundsQueryTime - avgInBoundsQueryTime).nanoseconds)
        let decryptDiff = abs((avgOutOfBoundsDecryptTime - avgInBoundsDecryptTime).nanoseconds)

        // Threshold: 0.1 milliseconds (100,000 nanoseconds)
        let threshold: Int64 = 100_000

        #expect(queryDiff < threshold)
        #expect(decryptDiff < threshold)
    }
}
