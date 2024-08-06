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

import HomomorphicEncryption
@testable import PrivateInformationRetrieval
import TestUtilities
import XCTest

class IndexPirTests: XCTestCase {
    func testGenerateParameter() throws {
        let context: Context<Bfv<UInt64>> = try TestUtils.getTestContext()
        // unevenDimensions: false
        do {
            let config = try IndexPirConfig(entryCount: 16,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 1,
                                            unevenDimensions: false,
                                            keyCompression: .noCompression)
            let parameter = MulPir.generateParameter(config: config, with: context)
            XCTAssertEqual(parameter.dimensions, [4, 4])
        }
        do {
            let config = try IndexPirConfig(entryCount: 10,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: false,
                                            keyCompression: .noCompression)
            let parameter = MulPir.generateParameter(config: config, with: context)
            XCTAssertEqual(parameter.dimensions, [4, 3])
        }
        // unevenDimensions: true
        do {
            let config = try IndexPirConfig(entryCount: 15,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 1,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression)
            let parameter = MulPir.generateParameter(config: config, with: context)
            XCTAssertEqual(parameter.dimensions, [5, 3])
        }
        do {
            let config = try IndexPirConfig(entryCount: 15,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression)
            let parameter = MulPir.generateParameter(config: config, with: context)
            XCTAssertEqual(parameter.dimensions, [5, 3])
        }
        do {
            let config = try IndexPirConfig(entryCount: 17,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression)
            let parameter = MulPir.generateParameter(config: config, with: context)
            XCTAssertEqual(parameter.dimensions, [9, 2])
        }
        // no key compression
        do {
            let config = try IndexPirConfig(entryCount: 100,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression)
            let parameter = MulPir.generateParameter(config: config, with: context)
            let evalKeyConfig = EvaluationKeyConfiguration(
                galoisElements: [3, 5, 9, 17],
                hasRelinearizationKey: true)
            XCTAssertEqual(parameter.evaluationKeyConfig, evalKeyConfig)
        }
        // hybrid key compression
        do {
            let config = try IndexPirConfig(entryCount: 100,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .hybridCompression)
            let parameter = MulPir.generateParameter(config: config, with: context)
            let evalKeyConfig = EvaluationKeyConfiguration(
                galoisElements: [3, 5, 9, 17],
                hasRelinearizationKey: true)
            XCTAssertEqual(parameter.evaluationKeyConfig, evalKeyConfig)
        }
        // max key compression
        do {
            let config = try IndexPirConfig(entryCount: 100,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .maxCompression)
            let parameter = MulPir.generateParameter(config: config, with: context)
            let evalKeyConfig = EvaluationKeyConfiguration(
                galoisElements: [3, 5, 9],
                hasRelinearizationKey: true)
            XCTAssertEqual(parameter.evaluationKeyConfig, evalKeyConfig)
        }
    }

    private func getDatabaseForTesting(numberOfEntries: Int,
                                       entrySizeInBytes: Int) -> [[UInt8]]
    {
        (0..<numberOfEntries).map { _ in (0..<entrySizeInBytes)
            .map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
        }
    }

    private func indexPirTestForParameter<Server: IndexPirServer, Client: IndexPirClient>(
        server _: Server.Type,
        client _: Client.Type,
        for parameter: IndexPirParameter,
        with context: Context<Server.Scheme>) throws
        where Server.IndexPir == Client.IndexPir
    {
        let database = getDatabaseForTesting(
            numberOfEntries: parameter.entryCount,
            entrySizeInBytes: parameter.entrySizeInBytes)
        let processedDb = try Server.process(database: database, with: context, using: parameter)

        let server = try Server(parameter: parameter, context: context, database: processedDb)
        let client = Client(parameter: parameter, context: context)

        let secretKey = try context.generateSecretKey()
        let evaluationKey = try client.generateEvaluationKey(using: secretKey)

        for _ in 0..<10 {
            var indices = Array(0..<parameter.batchSize)
            indices.shuffle()
            let batchSize = Int.random(in: 1...parameter.batchSize)
            let queryIndices = Array(indices.prefix(batchSize))
            let query = try client.generateQuery(at: queryIndices, using: secretKey)
            let response = try server.computeResponse(to: query, using: evaluationKey)
            if Server.Scheme.self != NoOpScheme.self {
                XCTAssertFalse(response.isTransparent())
            }
            let decryptedResponse = try client.decrypt(response: response, at: queryIndices, using: secretKey)
            for index in queryIndices.indices {
                XCTAssertEqual(decryptedResponse[index], database[queryIndices[index]])
            }
        }
    }

    private func indexPirTest<Server: IndexPirServer, Client: IndexPirClient>(server: Server.Type,
                                                                              client: Client.Type) throws
        where Server.IndexPir == Client.IndexPir
    {
        let configs = try [
            IndexPirConfig(entryCount: 100,
                           entrySizeInBytes: 1,
                           dimensionCount: 2,
                           batchSize: 2,
                           unevenDimensions: false,
                           keyCompression: .noCompression),
            IndexPirConfig(entryCount: 100,
                           entrySizeInBytes: 8,
                           dimensionCount: 2,
                           batchSize: 2,
                           unevenDimensions: false,
                           keyCompression: .noCompression),
            IndexPirConfig(entryCount: 100,
                           entrySizeInBytes: 24,
                           dimensionCount: 2,
                           batchSize: 2,
                           unevenDimensions: true,
                           keyCompression: .noCompression),
            IndexPirConfig(entryCount: 100,
                           entrySizeInBytes: 24,
                           dimensionCount: 1,
                           batchSize: 2,
                           unevenDimensions: true,
                           keyCompression: .noCompression),
            IndexPirConfig(entryCount: 100,
                           entrySizeInBytes: 24,
                           dimensionCount: 1,
                           batchSize: 2,
                           unevenDimensions: true,
                           keyCompression: .hybridCompression),
            IndexPirConfig(entryCount: 100,
                           entrySizeInBytes: 24,
                           dimensionCount: 1,
                           batchSize: 2,
                           unevenDimensions: true,
                           keyCompression: .maxCompression),
        ]

        let context: Context<Server.Scheme> = try TestUtils.getTestContext()
        for config in configs {
            let parameter = Server.generateParameter(config: config, with: context)
            try indexPirTestForParameter(server: server, client: client, for: parameter, with: context)
        }
    }

    private func mulIndexPirTest<Scheme: HeScheme>(scheme _: Scheme.Type) throws {
        try indexPirTest(server: MulPirServer<Scheme>.self, client: MulPirClient<Scheme>.self)
    }

    func testIndexPir() throws {
        try mulIndexPirTest(scheme: NoOpScheme.self)
        try mulIndexPirTest(scheme: Bfv<UInt32>.self)
        try mulIndexPirTest(scheme: Bfv<UInt64>.self)
    }
}
