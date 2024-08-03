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

extension Response {
    func isTransparent() -> Bool {
        ciphertexts.flatMap { $0 }.allSatisfy
            { ciphertext in ciphertext.isTransparent() }
    }
}

class KeywordPirTests: XCTestCase {
    func testProcessedDatabaseSerialization() throws {
        func runTest<PirServer: IndexPirServer, PirClient: IndexPirClient>(
            encryptionParameters: EncryptionParameters<PirServer.Scheme>,
            server _: PirServer.Type,
            client _: PirClient.Type) throws where PirServer.IndexPir == PirClient.IndexPir
        {
            let rowCount = 100
            let valueSize = 10
            let testDatabase = PirTestUtils.getTestTable(rowCount: rowCount, valueSize: valueSize)
            let testContext: Context<PirServer.Scheme> = try Context(encryptionParameters: encryptionParameters)

            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: PirTestUtils.testCuckooTableConfig(maxSerializedBucketSize: 5 * valueSize),
                unevenDimensions: true)
            let processed = try KeywordPirServer<PirServer>.process(database: testDatabase,
                                                                    config: keywordConfig,
                                                                    with: testContext)
            // Ensure we're testing nil plaintexts
            XCTAssertTrue(processed.database.plaintexts.contains { plaintext in plaintext == nil })
            let serialized = try processed.database.serialize()
            let loaded = try ProcessedDatabase<PirServer.Scheme>(
                from: serialized,
                context: testContext)
            XCTAssertEqual(loaded, processed.database)
        }
        try runTest(encryptionParameters: TestUtils.getTestEncryptionParameters(), server:
            MulPirServer<Bfv<UInt32>>.self, client: MulPirClient<Bfv<UInt32>>.self)
        try runTest(encryptionParameters: TestUtils.getTestEncryptionParameters(), server:
            MulPirServer<Bfv<UInt64>>.self, client: MulPirClient<Bfv<UInt64>>.self)
    }

    private func KeywordPirTest<PirServer: IndexPirServer, PirClient: IndexPirClient>(
        encryptionParameters: EncryptionParameters<PirServer.Scheme>,
        keywordConfig: KeywordPirConfig,
        server _: PirServer.Type,
        client _: PirClient.Type) throws where PirServer.IndexPir == PirClient.IndexPir
    {
        let testContext: Context<PirServer.Scheme> = try Context(encryptionParameters: encryptionParameters)
        let valueSize = testContext.bytesPerPlaintext / 2
        let testDatabase = PirTestUtils.getTestTable(rowCount: 100, valueSize: valueSize)

        let processed = try KeywordPirServer<PirServer>.process(database: testDatabase,
                                                                config: keywordConfig,
                                                                with: testContext)
        XCTAssertGreaterThan(processed.pirParameter.dimensions.product(), 1, "trivial PIR")

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
            let response = try server.computeResponse(to: query, using: evaluationKey)
            if PirServer.Scheme.self != NoOpScheme.self {
                XCTAssertFalse(response.isTransparent())
            }
            let result = try client.decrypt(response: response, at: testDatabase[index].keyword, using: secretKey)
            XCTAssertEqual(result, testDatabase[index].value)
        }
        let noKey = PirTestUtils.generateRandomData(size: 5)
        let query = try client.generateQuery(at: noKey, using: secretKey)
        let response = try server.computeResponse(to: query, using: evaluationKey)
        if PirServer.Scheme.self != NoOpScheme.self {
            XCTAssertFalse(response.isTransparent())
        }
        let result = try client.decrypt(response: response, at: noKey, using: secretKey)
        XCTAssertNil(result)
    }

    func testKeywordPirMulPir1HashFunction() throws {
        let cuckooTableConfig = try CuckooTableConfig(
            hashFunctionCount: 1,
            maxEvictionCount: 100,
            maxSerializedBucketSize: 200,
            bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.3))
        let keywordConfig = try KeywordPirConfig(
            dimensionCount: 2,
            cuckooTableConfig: cuckooTableConfig,
            unevenDimensions: true)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<NoOpScheme>.self,
            client: MulPirClient<NoOpScheme>.self)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<Bfv<UInt32>>.self,
            client: MulPirClient<Bfv<UInt32>>.self)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<Bfv<UInt64>>.self,
            client: MulPirClient<Bfv<UInt64>>.self)
    }

    func testKeywordPirMulPir3HashFunctions() throws {
        let cuckooTableConfig = try CuckooTableConfig(
            hashFunctionCount: 3,
            maxEvictionCount: 100,
            maxSerializedBucketSize: 200,
            bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.9))
        let keywordConfig = try KeywordPirConfig(
            dimensionCount: 2,
            cuckooTableConfig: cuckooTableConfig,
            unevenDimensions: true)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<NoOpScheme>.self,
            client: MulPirClient<NoOpScheme>.self)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<Bfv<UInt32>>.self,
            client: MulPirClient<Bfv<UInt32>>.self)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<Bfv<UInt64>>.self,
            client: MulPirClient<Bfv<UInt64>>.self)
    }

    func testKeywordPirMulPir1Dimension() throws {
        let keywordConfig = try KeywordPirConfig(
            dimensionCount: 1,
            cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                maxSerializedBucketSize: 100),
            unevenDimensions: true)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<NoOpScheme>.self,
            client: MulPirClient<NoOpScheme>.self)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<Bfv<UInt32>>.self,
            client: MulPirClient<Bfv<UInt32>>.self)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<Bfv<UInt64>>.self,
            client: MulPirClient<Bfv<UInt64>>.self)
    }

    func testKeywordPirMulPir2Dimensions() throws {
        let keywordConfig = try KeywordPirConfig(
            dimensionCount: 2,
            cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                maxSerializedBucketSize: 100),
            unevenDimensions: true)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<NoOpScheme>.self,
            client: MulPirClient<NoOpScheme>.self)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<Bfv<UInt32>>.self,
            client: MulPirClient<Bfv<UInt32>>.self)
        try KeywordPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            server: MulPirServer<Bfv<UInt64>>.self,
            client: MulPirClient<Bfv<UInt64>>.self)
    }

    func testKeywordPirMulPirLargerParameters() throws {
        do {
            let noOpParameters = try EncryptionParameters<NoOpScheme>(from: PredefinedRlweParameters
                .insecure_n_512_logq_4x60_logt_20)
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                    maxSerializedBucketSize: 3 * noOpParameters.bytesPerPlaintext),
                unevenDimensions: true)
            try KeywordPirTest(
                encryptionParameters: noOpParameters,
                keywordConfig: keywordConfig,
                server: MulPirServer<NoOpScheme>.self,
                client: MulPirClient<NoOpScheme>.self)
        }
        do {
            let bfv32Parameters = try EncryptionParameters<Bfv<UInt32>>(from: PredefinedRlweParameters
                .n_4096_logq_27_28_28_logt_5)
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                    maxSerializedBucketSize: 3 * bfv32Parameters.bytesPerPlaintext),
                unevenDimensions: true)
            try KeywordPirTest(
                encryptionParameters: bfv32Parameters,
                keywordConfig: keywordConfig,
                server: MulPirServer<Bfv<UInt32>>.self,
                client: MulPirClient<Bfv<UInt32>>.self)
        }
        do {
            let bfv64Parameters = try EncryptionParameters<Bfv<UInt64>>(from: PredefinedRlweParameters
                .insecure_n_512_logq_4x60_logt_20)
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: PirTestUtils.testCuckooTableConfig(
                    maxSerializedBucketSize: 3 * bfv64Parameters.bytesPerPlaintext),
                unevenDimensions: true)
            try KeywordPirTest(
                encryptionParameters: bfv64Parameters,
                keywordConfig: keywordConfig,
                server: MulPirServer<Bfv<UInt64>>.self,
                client: MulPirClient<Bfv<UInt64>>.self)
        }
    }

    func testKeywordPirFixedConfig() throws {
        func runTest<PirServer: IndexPirServer, PirClient: IndexPirClient>(
            encryptionParameters: EncryptionParameters<PirServer.Scheme>,
            server _: PirServer.Type,
            client _: PirClient.Type) throws where PirServer.IndexPir == PirClient.IndexPir
        {
            let rowCount = 100
            let valueSize = 9
            let testContext: Context<PirServer.Scheme> = try Context(encryptionParameters: encryptionParameters)
            var rng = TestRng()

            let (pirParameter, keywordConfig): (IndexPirParameter, KeywordPirConfig) = try {
                let cuckooConfig = try CuckooTableConfig(
                    hashFunctionCount: 2,
                    maxEvictionCount: 100,
                    maxSerializedBucketSize: HashBucket.serializedSize(singleValueSize: valueSize) * 4,
                    bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.7))
                let keywordConfig = try KeywordPirConfig(
                    dimensionCount: 2,
                    cuckooTableConfig: cuckooConfig,
                    unevenDimensions: true)
                let testDatabase = PirTestUtils.getTestTable(rowCount: rowCount, valueSize: valueSize, using: &rng)
                let processed = try KeywordPirServer<PirServer>.process(database: testDatabase,
                                                                        config: keywordConfig,
                                                                        with: testContext)
                let newConfig = try KeywordPirConfig(
                    dimensionCount: 2,
                    cuckooTableConfig: cuckooConfig
                        .freezingTableSize(
                            maxSerializedBucketSize: processed.pirParameter.entrySizeInBytes,
                            bucketCount: processed.pirParameter.entryCount * processed.pirParameter.batchSize),
                    unevenDimensions: true)
                return (processed.pirParameter, newConfig)
            }()

            // tweak database slightly, and re-use same PirParameters
            let testDatabase = PirTestUtils.getTestTable(rowCount: rowCount + 1, valueSize: valueSize - 1, using: &rng)
            let processed = try KeywordPirServer<PirServer>.process(database: testDatabase,
                                                                    config: keywordConfig,
                                                                    with: testContext)
            XCTAssertEqual(processed.pirParameter, pirParameter)
            let server = try KeywordPirServer<PirServer>(
                context: testContext,
                processed: processed)
            let client = KeywordPirClient<PirClient>(
                keywordParameter: keywordConfig.parameter,
                pirParameter: processed.pirParameter,
                context: testContext)
            let secretKey = try testContext.generateSecretKey()
            let evaluationKey = try client.generateEvaluationKey(using: secretKey)
            let shuffledValues = Array(testDatabase.indices).shuffled()
            for index in shuffledValues.prefix(1) {
                let query = try client.generateQuery(at: testDatabase[index].keyword, using: secretKey)
                let response = try server.computeResponse(to: query, using: evaluationKey)
                if PirServer.Scheme.self != NoOpScheme.self {
                    XCTAssertFalse(response.isTransparent())
                }
                let result = try client.decrypt(response: response, at: testDatabase[index].keyword, using: secretKey)
                XCTAssertEqual(result, testDatabase[index].value)
            }
            let noKey = PirTestUtils.generateRandomData(size: 5)
            let query = try client.generateQuery(at: noKey, using: secretKey)
            let response = try server.computeResponse(to: query, using: evaluationKey)
            if PirServer.Scheme.self != NoOpScheme.self {
                XCTAssertFalse(response.isTransparent())
            }
            let result = try client.decrypt(response: response, at: noKey, using: secretKey)
            XCTAssertNil(result)
        }
        try runTest(encryptionParameters: TestUtils.getTestEncryptionParameters(), server:
            MulPirServer<Bfv<UInt32>>.self, client: MulPirClient<Bfv<UInt32>>.self)
        try runTest(encryptionParameters: TestUtils.getTestEncryptionParameters(), server:
            MulPirServer<Bfv<UInt64>>.self, client: MulPirClient<Bfv<UInt64>>.self)
    }

    func testClientBugWorkaround() throws {
        func runTest<PirServer: IndexPirServer, PirClient: IndexPirClient>(
            rlweParams: PredefinedRlweParameters,
            server _: PirServer.Type,
            client _: PirClient.Type) throws where PirServer.IndexPir == PirClient.IndexPir
        {
            let context: Context<PirServer.Scheme> = try Context(encryptionParameters: .init(from: rlweParams))

            var testRng = TestRng()
            let testDatabase = PirTestUtils.getTestTable(rowCount: 1000, valueSize: 1, using: &testRng)
            let config = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: .defaultKeywordPir(maxSerializedBucketSize: 1024),
                unevenDimensions: true)
            let processed = try KeywordPirServer<PirServer>.process(
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
            let query = try client.generateQuery(at: [], using: secretKey)
            let response = try server.computeResponse(to: query, using: evaluationKey)
            let result = try client.decrypt(response: response, at: [], using: secretKey)
            XCTAssertNil(result)
        }
        let rlweParams = PredefinedRlweParameters.n_4096_logq_27_28_28_logt_5
        try runTest(rlweParams: rlweParams, server:
            MulPirServer<Bfv<UInt32>>.self, client: MulPirClient<Bfv<UInt32>>.self)
        try runTest(rlweParams: rlweParams, server:
            MulPirServer<Bfv<UInt64>>.self, client: MulPirClient<Bfv<UInt64>>.self)
    }

    func testInvalidArguments() throws {
        let cuckooConfig = try CuckooTableConfig(
            hashFunctionCount: 2,
            maxEvictionCount: 100,
            maxSerializedBucketSize: 10 * 5,
            bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.5))
        let keywordConfig = try KeywordPirConfig(
            dimensionCount: 2,
            cuckooTableConfig: cuckooConfig,
            unevenDimensions: true)
        let databaseConfig = KeywordDatabaseConfig(
            sharding: Sharding.shardCount(1),
            keywordPirConfig: keywordConfig)
        let encryptionParameters = try EncryptionParameters<Bfv<UInt32>>(
            from: .n_4096_logq_27_28_28_logt_5)
        XCTAssertThrowsError(try ProcessKeywordDatabase.Arguments(
            databaseConfig: databaseConfig,
            encryptionParameters: encryptionParameters,
            algorithm: PirAlgorithm.aclsPir,
            trialsPerShard: 1),
        error: PirError.invalidPirAlgorithm(PirAlgorithm.aclsPir))
    }

    func testSharding() throws {
        func runTest<PirServer: IndexPirServer, PirClient: IndexPirClient>(
            rlweParameters: PredefinedRlweParameters,
            server _: PirServer.Type,
            client _: PirClient.Type) throws where PirServer.IndexPir == PirClient.IndexPir
        {
            let rowCount = 1000
            let valueSize = 10
            let encryptionParameters = try EncryptionParameters<PirServer.Scheme>(from: rlweParameters)
            let testContext: Context<PirServer.Scheme> = try Context(
                encryptionParameters: encryptionParameters)
            let shardCount = 2

            let cuckooConfig = try CuckooTableConfig(
                hashFunctionCount: 2,
                maxEvictionCount: 100,
                maxSerializedBucketSize: valueSize * 5,
                bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.5))
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: cuckooConfig,
                unevenDimensions: true)
            let databaseConfig = KeywordDatabaseConfig(
                sharding: Sharding.shardCount(shardCount),
                keywordPirConfig: keywordConfig)
            let testDatabase = PirTestUtils.getTestTable(rowCount: rowCount, valueSize: valueSize)

            let args = try ProcessKeywordDatabase.Arguments(
                databaseConfig: databaseConfig,
                encryptionParameters: encryptionParameters,
                algorithm: PirAlgorithm.mulPir,
                trialsPerShard: 1)
            let processed: ProcessKeywordDatabase.Processed<PirServer.Scheme> = try ProcessKeywordDatabase.process(
                rows: testDatabase,
                with: args)

            XCTAssertEqual(processed.shards.count, shardCount)

            let servers = try [String: KeywordPirServer<PirServer>](uniqueKeysWithValues: processed.shards
                .map { shard in
                    try (shard.key, KeywordPirServer<PirServer>(
                        context: testContext,
                        processed: shard.value))
                })
            let clients = [String: KeywordPirClient<PirClient>](uniqueKeysWithValues: processed.shards.map { shard in
                (shard.key, KeywordPirClient<PirClient>(
                    keywordParameter: keywordConfig.parameter, pirParameter: shard.value.pirParameter,
                    context: testContext))
            })
            let secretKey = try testContext.generateSecretKey()
            let evaluationKey = try PirClient.Scheme
                .generateEvaluationKey(
                    context: testContext,
                    configuration: processed.evaluationKeyConfiguration,
                    using: secretKey)
            let shuffledValues = Array(testDatabase.indices).shuffled()
            for index in shuffledValues.prefix(3) {
                let keyword = testDatabase[index].keyword
                let shardID = keyword.shardID(shardCount: shardCount)
                let client = try XCTUnwrap(clients[shardID])
                let query = try client.generateQuery(at: testDatabase[index].keyword, using: secretKey)
                let response = try XCTUnwrap(servers[shardID]).computeResponse(to: query, using: evaluationKey)
                if PirServer.Scheme.self != NoOpScheme.self {
                    XCTAssertFalse(response.isTransparent())
                }
                let result = try client.decrypt(response: response, at: testDatabase[index].keyword, using: secretKey)
                XCTAssertEqual(result, testDatabase[index].value)
            }
            let noKey = PirTestUtils.generateRandomData(size: 3)
            let shardID = noKey.shardID(shardCount: shardCount)
            let client = try XCTUnwrap(clients[shardID])
            let query = try client.generateQuery(at: noKey, using: secretKey)
            let response = try XCTUnwrap(servers[shardID]).computeResponse(to: query, using: evaluationKey)
            if PirServer.Scheme.self != NoOpScheme.self {
                XCTAssertFalse(response.isTransparent())
            }
            let result = try client.decrypt(response: response, at: noKey, using: secretKey)
            XCTAssertNil(result)
        }

        let rlweParameters = PredefinedRlweParameters.insecure_n_512_logq_4x60_logt_20
        try runTest(rlweParameters: rlweParameters, server:
            MulPirServer<Bfv<UInt64>>.self, client: MulPirClient<Bfv<UInt64>>.self)
    }
}
