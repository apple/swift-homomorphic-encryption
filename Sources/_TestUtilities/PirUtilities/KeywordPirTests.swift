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

import HomomorphicEncryption
import PrivateInformationRetrieval
import Testing

extension PirTestUtils {
    /// KeywordPir tests.
    public enum KeywordPirTests {
        /// Tests database serialization.
        @inlinable
        public static func processedDatabaseSerialization<Scheme: HeScheme>(_: Scheme.Type) async throws {
            let rowCount = 100
            let valueSize = 10
            let testDatabase = PirTestUtils.randomKeywordPirDatabase(rowCount: rowCount, valueSize: valueSize)
            let encryptionParameters: EncryptionParameters<Scheme.Scalar> = try TestUtils.getTestEncryptionParameters()
            let testContext = try Scheme.Context(encryptionParameters: encryptionParameters)

            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: PirTestUtils.testCuckooTableConfig(maxSerializedBucketSize: 5 * valueSize),
                unevenDimensions: true,
                keyCompression: .noCompression)
            let processed = try await KeywordPirServer<MulPirServer<PirUtil<Scheme>>>.process(database: testDatabase,
                                                                                              config: keywordConfig,
                                                                                              with: testContext)
            // Ensure we're testing nil plaintexts
            #expect(processed.database.plaintexts.contains { plaintext in plaintext == nil })
            let serialized = try processed.database.serialize()
            let loaded = try ProcessedDatabase<Scheme>(
                from: serialized,
                context: testContext)
            #expect(loaded == processed.database)
        }

        @inlinable
        static func keywordPirTest<PirServer: IndexPirServer, PirClient: IndexPirClient>(
            encryptionParameters: EncryptionParameters<PirServer.Scalar>,
            keywordConfig: KeywordPirConfig,
            server _: PirServer.Type,
            client _: PirClient.Type) async throws where PirServer.IndexPir == PirClient.IndexPir
        {
            // swiftlint:disable:next nesting
            typealias Scheme = PirServer.Scheme
            let testContext = try Scheme.Context(encryptionParameters: encryptionParameters)
            let valueSize = testContext.bytesPerPlaintext / 2
            let testDatabase = PirTestUtils.randomKeywordPirDatabase(rowCount: 100, valueSize: valueSize)

            let processed = try await KeywordPirServer<PirServer>.process(database: testDatabase,
                                                                          config: keywordConfig,
                                                                          with: testContext)
            #expect(processed.pirParameter.dimensions.product() > 1, "trivial PIR")

            let server = try KeywordPirServer<PirServer>(
                context: testContext,
                processed: processed)
            let client = KeywordPirClient<PirClient>(
                keywordParameter: keywordConfig.parameter, pirParameter: processed.pirParameter,
                context: testContext)
            let secretKey = try testContext.generateSecretKey()
            let evaluationKey = try client.generateEvaluationKey(using: secretKey)
            let shuffledValues = Array(testDatabase.indices).shuffled()
            for index in shuffledValues.prefix(10) {
                let query = try client.generateQuery(at: testDatabase[index].keyword, using: secretKey)
                let response = try await server.computeResponse(to: query, using: evaluationKey)
                if Scheme.self != NoOpScheme.self {
                    #expect(!response.isTransparent())
                }
                let result = try client.decrypt(response: response, at: testDatabase[index].keyword, using: secretKey)
                #expect(result == testDatabase[index].value)
            }
            let noKey = PirTestUtils.generateRandomBytes(size: 5)
            let query = try client.generateQuery(at: noKey, using: secretKey)
            let response = try await server.computeResponse(to: query, using: evaluationKey)
            if Scheme.self != NoOpScheme.self {
                #expect(!response.isTransparent())
            }
            let result = try client.decrypt(response: response, at: noKey, using: secretKey)
            #expect(result == nil)
        }

        /// Testing Keyword MulPir with 1 hash function.
        @inlinable
        public static func keywordPirMulPir1HashFunction<Scheme: HeScheme>(_: Scheme.Type) async throws {
            let cuckooTableConfig = try CuckooTableConfig(
                hashFunctionCount: 1,
                maxEvictionCount: 100,
                maxSerializedBucketSize: 200,
                bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.3))
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: cuckooTableConfig,
                unevenDimensions: true,
                keyCompression: .noCompression)
            try await Self.keywordPirTest(
                encryptionParameters: TestUtils.getTestEncryptionParameters(),
                keywordConfig: keywordConfig,
                server: MulPirServer<PirUtil<Scheme>>.self,
                client: MulPirClient<PirUtil<Scheme>>.self)
        }

        /// Testing Keyword MulPir with 3 hash functions.
        @inlinable
        public static func keywordPirMulPir3HashFunctions<Scheme: HeScheme>(_: Scheme.Type) async throws {
            let cuckooTableConfig = try CuckooTableConfig(
                hashFunctionCount: 3,
                maxEvictionCount: 100,
                maxSerializedBucketSize: 200,
                bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.9))
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: cuckooTableConfig,
                unevenDimensions: true, keyCompression: .noCompression)
            try await keywordPirTest(
                encryptionParameters: TestUtils.getTestEncryptionParameters(),
                keywordConfig: keywordConfig,
                server: MulPirServer<PirUtil<Scheme>>.self,
                client: MulPirClient<PirUtil<Scheme>>.self)
        }

        /// Testing Keyword MulPir with 1 dimension.
        @inlinable
        public static func keywordPirMulPir1Dimension<Scheme: HeScheme>(_: Scheme.Type) async throws {
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 1,
                cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                    maxSerializedBucketSize: 100),
                unevenDimensions: true, keyCompression: .noCompression)
            try await Self.keywordPirTest(
                encryptionParameters: TestUtils.getTestEncryptionParameters(),
                keywordConfig: keywordConfig,
                server: MulPirServer<PirUtil<Scheme>>.self,
                client: MulPirClient<PirUtil<Scheme>>.self)
        }

        /// Testing Keyword MulPir with 2 dimensions.
        @inlinable
        public static func keywordPirMulPir2Dimensions<Scheme: HeScheme>(_: Scheme.Type) async throws {
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                    maxSerializedBucketSize: 100),
                unevenDimensions: true, keyCompression: .noCompression)
            try await keywordPirTest(
                encryptionParameters: TestUtils.getTestEncryptionParameters(),
                keywordConfig: keywordConfig,
                server: MulPirServer<PirUtil<Scheme>>.self,
                client: MulPirClient<PirUtil<Scheme>>.self)
        }

        /// Testing Keyword MulPir with hybrid key compression.
        @inlinable
        public static func keywordPirMulPirHybridKeyCompression<Scheme: HeScheme>(_: Scheme.Type) async throws {
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                    maxSerializedBucketSize: 100),
                unevenDimensions: true, keyCompression: .hybridCompression)
            try await Self.keywordPirTest(
                encryptionParameters: TestUtils.getTestEncryptionParameters(),
                keywordConfig: keywordConfig,
                server: MulPirServer<PirUtil<Scheme>>.self,
                client: MulPirClient<PirUtil<Scheme>>.self)
        }

        /// Testing Keyword MulPir with max key compression.
        @inlinable
        public static func keywordPirMulPirMaxKeyCompression<Scheme: HeScheme>(_: Scheme.Type) async throws {
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                    maxSerializedBucketSize: 100),
                unevenDimensions: true, keyCompression: .maxCompression)
            try await Self.keywordPirTest(
                encryptionParameters: TestUtils.getTestEncryptionParameters(),
                keywordConfig: keywordConfig,
                server: MulPirServer<PirUtil<Scheme>>.self,
                client: MulPirClient<PirUtil<Scheme>>.self)
        }

        /// Testing Keyword MulPir with larger parameters.
        @inlinable
        public static func keywordPirMulPirLargeParameters<Scheme: HeScheme>(_: Scheme.Type) async throws {
            if Scheme.Scalar.self == UInt32.self {
                let parameters = try EncryptionParameters<Scheme.Scalar>(from: PredefinedRlweParameters
                    .n_4096_logq_27_28_28_logt_5)
                let keywordConfig = try KeywordPirConfig(
                    dimensionCount: 2,
                    cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                        maxSerializedBucketSize: 3 * parameters.bytesPerPlaintext),
                    unevenDimensions: true, keyCompression: .noCompression)
                try await Self.keywordPirTest(
                    encryptionParameters: parameters,
                    keywordConfig: keywordConfig,
                    server: MulPirServer<PirUtil<Scheme>>.self,
                    client: MulPirClient<PirUtil<Scheme>>.self)
            } else if Scheme.Scalar.self == UInt64.self, Scheme.self != NoOpScheme.self {
                let parameters = try EncryptionParameters<Scheme.Scalar>(from: PredefinedRlweParameters
                    .insecure_n_512_logq_4x60_logt_20)
                let keywordConfig = try KeywordPirConfig(
                    dimensionCount: 2,
                    cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                        maxSerializedBucketSize: 3 * parameters.bytesPerPlaintext),
                    unevenDimensions: true, keyCompression: .noCompression)
                try await Self.keywordPirTest(
                    encryptionParameters: parameters,
                    keywordConfig: keywordConfig,
                    server: MulPirServer<PirUtil<Scheme>>.self,
                    client: MulPirClient<PirUtil<Scheme>>.self)
            }
            if Scheme.self == NoOpScheme.self {
                let noOpParameters = try EncryptionParameters<NoOpScheme.Scalar>(from: PredefinedRlweParameters
                    .insecure_n_512_logq_4x60_logt_20)
                let keywordConfig = try KeywordPirConfig(
                    dimensionCount: 2,
                    cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                        maxSerializedBucketSize: 3 * noOpParameters.bytesPerPlaintext),
                    unevenDimensions: true, keyCompression: .noCompression)
                try await Self.keywordPirTest(
                    encryptionParameters: noOpParameters,
                    keywordConfig: keywordConfig,
                    server: MulPirServer<PirUtil<NoOpScheme>>.self,
                    client: MulPirClient<PirUtil<NoOpScheme>>.self)
            }
        }

        /// Testing Keyword Pir fixed configuration.
        @inlinable
        public static func keywordPirFixedConfig<Scheme: HeScheme>(_: Scheme.Type) async throws {
            let rowCount = 100
            let valueSize = 9
            let encryptionParams: EncryptionParameters<Scheme.Scalar> = try TestUtils.getTestEncryptionParameters()
            let testContext = try Scheme.Context(encryptionParameters: encryptionParams)
            var rng = TestRng()

            let (pirParameter, keywordConfig): (IndexPirParameter, KeywordPirConfig) = try await {
                let cuckooConfig = try CuckooTableConfig(
                    hashFunctionCount: 2,
                    maxEvictionCount: 100,
                    maxSerializedBucketSize: HashBucket.serializedSize(singleValueSize: valueSize) * 4,
                    bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.7))
                let keywordConfig = try KeywordPirConfig(
                    dimensionCount: 2,
                    cuckooTableConfig: cuckooConfig,
                    unevenDimensions: true, keyCompression: .noCompression)
                let testDatabase = PirTestUtils.randomKeywordPirDatabase(
                    rowCount: rowCount,
                    valueSize: valueSize,
                    using: &rng)
                let processed = try await KeywordPirServer<MulPirServer<PirUtil<Scheme>>>.process(
                    database: testDatabase,
                    config: keywordConfig,
                    with: testContext)
                let newConfig = try KeywordPirConfig(
                    dimensionCount: 2,
                    cuckooTableConfig: cuckooConfig.freezingTableSize(
                        maxSerializedBucketSize: processed.pirParameter.entrySizeInBytes,
                        bucketCount: processed.pirParameter.entryCount * processed.pirParameter.batchSize),
                    unevenDimensions: true, keyCompression: .noCompression)
                return (processed.pirParameter, newConfig)
            }()

            // tweak database slightly, and re-use same PirParameters
            let testDatabase = PirTestUtils.randomKeywordPirDatabase(
                rowCount: rowCount + 1,
                valueSize: valueSize - 1,
                using: &rng)
            let processed = try await KeywordPirServer<MulPirServer<PirUtil<Scheme>>>.process(database: testDatabase,
                                                                                              config: keywordConfig,
                                                                                              with: testContext)
            #expect(processed.pirParameter == pirParameter)
            let server = try KeywordPirServer<MulPirServer<PirUtil<Scheme>>>(
                context: testContext,
                processed: processed)
            let client = KeywordPirClient<MulPirClient<PirUtil<Scheme>>>(
                keywordParameter: keywordConfig.parameter,
                pirParameter: processed.pirParameter,
                context: testContext)
            let secretKey = try testContext.generateSecretKey()
            let evaluationKey = try client.generateEvaluationKey(using: secretKey)
            let shuffledValues = Array(testDatabase.indices).shuffled()
            for index in shuffledValues.prefix(1) {
                let query = try client.generateQuery(at: testDatabase[index].keyword, using: secretKey)
                let response = try await server.computeResponse(to: query, using: evaluationKey)
                if Scheme.self != NoOpScheme.self {
                    #expect(!response.isTransparent())
                }
                let result = try client.decrypt(
                    response: response,
                    at: testDatabase[index].keyword,
                    using: secretKey)
                #expect(result == testDatabase[index].value)
            }
            let noKey = PirTestUtils.generateRandomBytes(size: 5)
            let query = try client.generateQuery(at: noKey, using: secretKey)
            let response = try await server.computeResponse(to: query, using: evaluationKey)
            if Scheme.self != NoOpScheme.self {
                #expect(!response.isTransparent())
            }
            let result = try client.decrypt(response: response, at: noKey, using: secretKey)
            #expect(result == nil)
        }

        /// Test sharding.
        @inlinable
        public static func sharding<PirUtil: PirUtilProtocol>(_: PirUtil.Type) async throws {
            // swiftlint:disable nesting
            typealias PirClient = MulPirClient<PirUtil>
            typealias PirServer = MulPirServer<PirUtil>
            // swiftlint:enable nesting

            let rowCount = 1000
            let valueSize = 10
            let rlweParameters = PredefinedRlweParameters.n_4096_logq_27_28_28_logt_5
            let encryptionParameters = try EncryptionParameters<PirUtil.Scheme.Scalar>(from: rlweParameters)
            let testContext = try PirUtil.Scheme.Context(encryptionParameters: encryptionParameters)
            let shardCount = 2

            let cuckooConfig = try CuckooTableConfig(
                hashFunctionCount: 2,
                maxEvictionCount: 100,
                maxSerializedBucketSize: valueSize * 5,
                bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.5))
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: cuckooConfig,
                unevenDimensions: true, keyCompression: .noCompression)
            let databaseConfig = KeywordDatabaseConfig(
                sharding: Sharding.shardCount(shardCount),
                keywordPirConfig: keywordConfig)
            let testDatabase = PirTestUtils.randomKeywordPirDatabase(rowCount: rowCount, valueSize: valueSize)

            let args = try ProcessKeywordDatabase.Arguments<PirUtil.Scheme.Scalar>(
                databaseConfig: databaseConfig,
                encryptionParameters: encryptionParameters,
                algorithm: PirAlgorithm.mulPir, keyCompression: .noCompression,
                trialsPerShard: 1)
            let processed: ProcessKeywordDatabase.Processed<PirUtil.Scheme> = try await ProcessKeywordDatabase.process(
                rows: testDatabase,
                with: args, using: PirUtil.self)
            #expect(processed.shards.count == shardCount)

            let servers = try [String: KeywordPirServer<PirServer>](uniqueKeysWithValues: processed.shards
                .map { shard in
                    try (shard.key, KeywordPirServer<PirServer>(
                        context: testContext,
                        processed: shard.value))
                })
            let clients = [String: KeywordPirClient<PirClient>](uniqueKeysWithValues: processed.shards
                .map { shard in
                    (shard.key, KeywordPirClient<PirClient>(
                        keywordParameter: keywordConfig.parameter, pirParameter: shard.value.pirParameter,
                        context: testContext))
                })
            let secretKey = try testContext.generateSecretKey()
            let evaluationKey = try PirClient.Scheme
                .generateEvaluationKey(
                    context: testContext,
                    config: processed.evaluationKeyConfig,
                    using: secretKey)
            let shuffledValues = Array(testDatabase.indices).shuffled()
            for index in shuffledValues.prefix(3) {
                let keyword = testDatabase[index].keyword
                let shardID = keyword.shardID(shardCount: shardCount)
                let client = try #require(clients[shardID])
                let query = try client.generateQuery(at: testDatabase[index].keyword, using: secretKey)
                let response = try await #require(servers[shardID]).computeResponse(to: query, using: evaluationKey)
                if PirUtil.Scheme.self != NoOpScheme.self {
                    #expect(!response.isTransparent())
                }
                let result = try client.decrypt(
                    response: response,
                    at: testDatabase[index].keyword,
                    using: secretKey)
                #expect(result == testDatabase[index].value)
            }
            let noKey = PirTestUtils.generateRandomBytes(size: 3)
            let shardID = noKey.shardID(shardCount: shardCount)
            let client = try #require(clients[shardID])
            let query = try client.generateQuery(at: noKey, using: secretKey)
            let response = try await #require(servers[shardID]).computeResponse(to: query, using: evaluationKey)
            if PirUtil.Scheme.self != NoOpScheme.self {
                #expect(!response.isTransparent())
            }
            let result = try client.decrypt(response: response, at: noKey, using: secretKey)
            #expect(result == nil)
        }

        /// Test limiting entries per response.
        @inlinable
        public static func limitEntriesPerResponse<Scheme: HeScheme>(_: Scheme.Type) async throws {
            // swiftlint:disable nesting
            typealias PirClient = MulPirClient<PirUtil<Scheme>>
            typealias PirServer = MulPirServer<PirUtil<Scheme>>
            // swiftlint:enable nesting

            let rlweParams = PredefinedRlweParameters.n_4096_logq_27_28_28_logt_5
            let context = try PirServer.Scheme.Context(encryptionParameters: .init(from: rlweParams))
            let numberOfEntriesPerResponse = 8
            let hashFunctionCount = 2
            var testRng = TestRng()
            let testDatabase = PirTestUtils.randomKeywordPirDatabase(rowCount: 1000, valueSize: 1, using: &testRng)
            let config = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: CuckooTableConfig(
                    hashFunctionCount: hashFunctionCount,
                    maxEvictionCount: 100,
                    maxSerializedBucketSize: context.bytesPerPlaintext,
                    bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.5),
                    slotCount: numberOfEntriesPerResponse / hashFunctionCount),
                unevenDimensions: true,
                keyCompression: .noCompression,
                useMaxSerializedBucketSize: true)
            let processed = try await KeywordPirServer<PirServer>.process(
                database: testDatabase,
                config: config,
                with: context)
            let server = try KeywordPirServer<PirServer>(
                context: context,
                processed: processed)
            let client = KeywordPirClient<PirClient>(
                keywordParameter: config.parameter,
                pirParameter: processed.pirParameter,
                context: context)
            let secretKey = try context.generateSecretKey()
            let evaluationKey = try client.generateEvaluationKey(using: secretKey)
            let randomKeyValuePair = try #require(testDatabase.randomElement())
            let query = try client.generateQuery(at: randomKeyValuePair.keyword, using: secretKey)
            let response = try await server.computeResponse(to: query, using: evaluationKey)
            let result = try client.decrypt(response: response, at: randomKeyValuePair.keyword, using: secretKey)
            #expect(result == randomKeyValuePair.value)
            let entriesFound = try client.countEntriesInResponse(response: response, using: secretKey)
            #expect(entriesFound <= numberOfEntriesPerResponse)
        }
    }
}
