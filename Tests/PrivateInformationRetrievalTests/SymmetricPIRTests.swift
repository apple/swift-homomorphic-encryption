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

import _CryptoExtras
import Crypto
import HomomorphicEncryption
@testable import PrivateInformationRetrieval
import TestUtilities
import XCTest

class SymmetricPIRTests: XCTestCase {
    private func generateSymmetricPirConfig() throws -> SymmetricPirConfig {
        let secretKey = [UInt8](OprfPrivateKey().rawRepresentation)
        return try SymmetricPirConfig(
            oprfSecretKey: secretKey, configType: .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128)
    }

    func testOprfRoundtrip() throws {
        func roundTrip(keyword: [UInt8], server: OprfServer,
                       client: OprfClient) throws -> (OprfQuery, OprfClient.ParsedOprfOutput)
        {
            // Client
            let queryContext = try client.queryContext(at: keyword)
            // Server
            let response = try server.computeResponse(query: queryContext.query)
            // Client
            let output = try client.parse(oprfResponse: response, with: queryContext)

            return (queryContext.query, output)
        }
        let config = try generateSymmetricPirConfig()
        let server = try OprfServer(symmetricPirConfig: config)
        let client = try OprfClient(symmetricPirClientConfig: config.clientConfig())

        let keyword: [UInt8] = [1, 2, 3, 4, 5]
        let (query1, output1) = try roundTrip(keyword: keyword, server: server, client: client)
        let (query2, output2) = try roundTrip(keyword: keyword, server: server, client: client)

        XCTAssertNotEqual(query1.oprfRepresentation, query2.oprfRepresentation)
        XCTAssertEqual(output1, output2)
    }

    func testSymmetricPIRDatabase() throws {
        let shardCount = 1
        let rowCount = 10
        let valueSize = 3
        let testDatabase = PirTestUtils.getTestTable(rowCount: rowCount, valueSize: valueSize)

        let symmetricPirConfig = try generateSymmetricPirConfig()
        let encryptedDatabase = try KeywordDatabase(
            rows: testDatabase,
            sharding: .shardCount(shardCount),
            symmetricPirConfig: symmetricPirConfig)

        let oprfSecretKey = try OprfPrivateKey(rawRepresentation: symmetricPirConfig.oprfSecretKey)

        let testIndex = Int.random(in: 0..<rowCount)
        let testKeyword = Data(testDatabase[testIndex].keyword)
        let testValue = Data(testDatabase[testIndex].value)

        let finalizeHash = try oprfSecretKey.evaluate(Data(testKeyword))
        let testShard = try XCTUnwrap(encryptedDatabase.shards["0"])
        let obliviousKeywordSize = symmetricPirConfig.configType.obliviousKeywordSize
        let aesKeySize = symmetricPirConfig.configType.entryEncryptionKeySize
        XCTAssertNotNil(testShard.rows[[UInt8](finalizeHash.prefix(obliviousKeywordSize))])
        XCTAssertNil(testShard.rows[[UInt8](finalizeHash.prefix(1))])

        let encryptedValue = try XCTUnwrap(testShard.rows[[UInt8](finalizeHash.prefix(Int(obliviousKeywordSize)))])
        let key = SymmetricKey(data: finalizeHash.suffix(Int(aesKeySize)))

        let defaultNonceSize = 12
        let defaultTagSize = 16
        var sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: finalizeHash.prefix(defaultNonceSize)),
            ciphertext: encryptedValue.dropLast(defaultTagSize),
            tag: encryptedValue.suffix(defaultTagSize))

        let decryptedValue = try AES.GCM.open(sealedBox, using: key)
        XCTAssertEqual(testValue, decryptedValue)

        // wrong nonce test
        sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: finalizeHash.prefix(defaultNonceSize + 1)),
            ciphertext: encryptedValue.dropLast(defaultTagSize),
            tag: encryptedValue.suffix(defaultTagSize))

        XCTAssertThrowsError(try AES.GCM.open(sealedBox, using: key))
    }

    private func SymmetricPirTest<PirServer: IndexPirServer, PirClient: IndexPirClient>(
        encryptionParameters: EncryptionParameters<PirServer.Scheme>,
        keywordConfig: KeywordPirConfig,
        symmetricPirConfig: SymmetricPirConfig,
        server _: PirServer.Type,
        client _: PirClient.Type) throws where PirServer.IndexPir == PirClient.IndexPir
    {
        let context: Context<PirServer.Scheme> = try Context(encryptionParameters: encryptionParameters)
        let valueSize = context.bytesPerPlaintext / 2
        let plainDatabase = PirTestUtils.getTestTable(rowCount: 100, valueSize: valueSize)
        let encryptedDatabase = try KeywordDatabase.symmetricPIRProcess(
            database: plainDatabase,
            config: symmetricPirConfig)
        let processed = try KeywordPirServer<PirServer>.process(database: encryptedDatabase,
                                                                config: keywordConfig,
                                                                with: context,
                                                                symmetricPirConfig: symmetricPirConfig)
        let server = try KeywordPirServer<PirServer>(
            context: context,
            processed: processed)
        let client = KeywordPirClient<PirClient>(
            keywordParameter: keywordConfig.parameter, pirParameter: processed.pirParameter,
            context: context)
        let secretKey = try context.generateSecretKey()
        let evaluationKey = try client.generateEvaluationKey(using: secretKey)
        let shuffledValues = Array(plainDatabase.indices).shuffled()

        let oprfServer = try OprfServer(symmetricPirConfig: symmetricPirConfig)
        precondition(keywordConfig.symmetricPirClientConfig != nil)
        let oprfClient = try OprfClient(symmetricPirClientConfig: XCTUnwrap(keywordConfig.symmetricPirClientConfig))
        for index in shuffledValues.prefix(10) {
            // OPRF oblivious keyword
            let oprfQueryContext = try oprfClient.queryContext(at: plainDatabase[index].keyword)
            let oprfResponse = try oprfServer.computeResponse(query: oprfQueryContext.query)
            let parsedOprfOutput = try oprfClient.parse(oprfResponse: oprfResponse, with: oprfQueryContext)
            // Keyword PIR
            let query = try client.generateQuery(at: parsedOprfOutput.obliviousKeyword, using: secretKey)
            let response = try server.computeResponse(to: query, using: evaluationKey)
            XCTAssertFalse(response.isTransparent())
            let result = try client.decrypt(response: response, at: parsedOprfOutput.obliviousKeyword, using: secretKey)
            // SPIR decryption
            XCTAssertNotNil(result)
            let spirResult = try result.map { res in
                try oprfClient.decrypt(encryptedEntry: res, with: parsedOprfOutput)
            }
            XCTAssertEqual(spirResult, plainDatabase[index].value)
        }
    }

    func testSymmetricPIRFullRoundTrip() throws {
        let symmetricPirConfig = try generateSymmetricPirConfig()
        let keywordConfig = try KeywordPirConfig(
            dimensionCount: 2,
            cuckooTableConfig: PirTestUtils.testCuckooTableConfig(maxSerializedBucketSize: 100),
            unevenDimensions: true,
            keyCompression: .noCompression,
            symmetricPirClientConfig: symmetricPirConfig.clientConfig())

        try SymmetricPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            symmetricPirConfig: symmetricPirConfig,
            server: MulPirServer<Bfv<UInt32>>.self,
            client: MulPirClient<Bfv<UInt32>>.self)
        try SymmetricPirTest(
            encryptionParameters: TestUtils.getTestEncryptionParameters(),
            keywordConfig: keywordConfig,
            symmetricPirConfig: symmetricPirConfig,
            server: MulPirServer<Bfv<UInt64>>.self,
            client: MulPirClient<Bfv<UInt64>>.self)
    }
}
