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

public import HomomorphicEncryption
public import PrivateInformationRetrieval
public import Testing

extension PirTestUtils {
    /// IndexPir tests.
    public enum IndexPirTests {
        @inlinable
        static func indexPirTestForParameter<Server: IndexPirServer, Client: IndexPirClient>(
            server _: Server.Type,
            client _: Client.Type,
            for parameter: IndexPirParameter,
            with context: Server.Scheme.Context) async throws
            where Server.IndexPir == Client.IndexPir
        {
            let database = if parameter.encodingEntrySize {
                PirTestUtils.randomIndexPirDatabase(
                    entryCount: parameter.entryCount,
                    entrySizeInBytes: 1...parameter.entrySizeInBytes)
            } else {
                PirTestUtils.randomIndexPirDatabase(
                    entryCount: parameter.entryCount,
                    entrySizeInBytes: parameter.entrySizeInBytes)
            }
            let processedDb = try await Server.process(database: database, with: context, using: parameter)

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
                let response = try await server.computeResponse(to: query, using: evaluationKey)
                if Server.Scheme.self != NoOpScheme.self {
                    #expect(!response.isTransparent())
                }
                let decryptedResponse = try client.decrypt(response: response, at: queryIndices, using: secretKey)
                for index in queryIndices.indices {
                    #expect(decryptedResponse[index] == database[queryIndices[index]])
                }
            }
        }

        @inlinable
        static func indexPirTest<Server: IndexPirServer, Client: IndexPirClient>(server: Server.Type,
                                                                                 client: Client.Type) async throws
            where Server.IndexPir == Client.IndexPir
        {
            let configsNotEncodingEntrySize = try [
                IndexPirConfig(entryCount: 100,
                               entrySizeInBytes: 1,
                               dimensionCount: 2,
                               batchSize: 2,
                               unevenDimensions: false,
                               keyCompression: .noCompression,
                               encodingEntrySize: false),
                IndexPirConfig(entryCount: 100,
                               entrySizeInBytes: 8,
                               dimensionCount: 2,
                               batchSize: 2,
                               unevenDimensions: false,
                               keyCompression: .noCompression,
                               encodingEntrySize: false),
                IndexPirConfig(entryCount: 100,
                               entrySizeInBytes: 24,
                               dimensionCount: 2,
                               batchSize: 2,
                               unevenDimensions: true,
                               keyCompression: .noCompression,
                               encodingEntrySize: false),
                IndexPirConfig(entryCount: 100,
                               entrySizeInBytes: 24,
                               dimensionCount: 1,
                               batchSize: 2,
                               unevenDimensions: true,
                               keyCompression: .noCompression,
                               encodingEntrySize: false),
                IndexPirConfig(entryCount: 100,
                               entrySizeInBytes: 24,
                               dimensionCount: 1,
                               batchSize: 2,
                               unevenDimensions: true,
                               keyCompression: .hybridCompression,
                               encodingEntrySize: false),
                IndexPirConfig(entryCount: 100,
                               entrySizeInBytes: 24,
                               dimensionCount: 1,
                               batchSize: 2,
                               unevenDimensions: true,
                               keyCompression: .maxCompression,
                               encodingEntrySize: false),
                IndexPirConfig(entryCount: 100,
                               entrySizeInBytes: 24,
                               dimensionCount: 1,
                               batchSize: 2,
                               unevenDimensions: true,
                               keyCompression: .hybridCompression,
                               encodingEntrySize: false),
            ]
            let configsEncodingEntrySize = configsNotEncodingEntrySize.map { config in
                var config = config
                config.encodingEntrySize = true
                return config
            }
            let configs = configsNotEncodingEntrySize + configsEncodingEntrySize

            let context: Server.Scheme.Context = try TestUtils.getTestContext()
            for config in configs {
                let parameter = Server.generateParameter(config: config, with: context)
                try await indexPirTestForParameter(server: server, client: client, for: parameter, with: context)
            }
        }

        /// Testing indexPir.
        @inlinable
        public static func indexPir<Scheme: HeScheme>(scheme _: Scheme.Type) async throws {
            try await indexPirTest(
                server: MulPirServer<PirUtil<Scheme>>.self,
                client: MulPirClient<PirUtil<Scheme>>.self)
        }
    }

    /// Testing client configuration.
    @inlinable
    func generateParameter() throws {
        let context: Context<Bfv<UInt64>> = try TestUtils.getTestContext()
        // unevenDimensions: false
        do {
            let config = try IndexPirConfig(entryCount: 16,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 1,
                                            unevenDimensions: false,
                                            keyCompression: .noCompression,
                                            encodingEntrySize: false)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            #expect(parameter.dimensions == [4, 4])
        }
        do {
            let config = try IndexPirConfig(entryCount: 10,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: false,
                                            keyCompression: .noCompression,
                                            encodingEntrySize: false)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            #expect(parameter.dimensions == [4, 3])
        }
        // unevenDimensions: true
        do {
            let config = try IndexPirConfig(entryCount: 15,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 1,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression,
                                            encodingEntrySize: false)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            #expect(parameter.dimensions == [5, 3])
        }
        do {
            let config = try IndexPirConfig(entryCount: 15,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression,
                                            encodingEntrySize: false)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            #expect(parameter.dimensions == [5, 3])
        }
        do {
            let config = try IndexPirConfig(entryCount: 17,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression,
                                            encodingEntrySize: false)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            #expect(parameter.dimensions == [9, 2])
        }
        // no key compression
        do {
            let config = try IndexPirConfig(entryCount: 100,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression,
                                            encodingEntrySize: false)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            let evalKeyConfig = EvaluationKeyConfig(
                galoisElements: [3, 5, 9, 17],
                hasRelinearizationKey: true)
            #expect(parameter.evaluationKeyConfig == evalKeyConfig)
        }
        // hybrid key compression
        do {
            let config = try IndexPirConfig(entryCount: 100,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .hybridCompression,
                                            encodingEntrySize: false)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            let evalKeyConfig = EvaluationKeyConfig(
                galoisElements: [3, 5, 9, 17],
                hasRelinearizationKey: true)
            #expect(parameter.evaluationKeyConfig == evalKeyConfig)
        }
        // max key compression
        do {
            let config = try IndexPirConfig(entryCount: 100,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .maxCompression,
                                            encodingEntrySize: false)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            let evalKeyConfig = EvaluationKeyConfig(
                galoisElements: [3, 5, 9],
                hasRelinearizationKey: true)
            #expect(parameter.evaluationKeyConfig == evalKeyConfig)
        }
    }
}
