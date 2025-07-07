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
import _TestUtilities
import Crypto
import Foundation
import HomomorphicEncryption
@testable import PrivateInformationRetrieval
import Testing

@Suite
struct SymmetricPirTests {
    @Test
    func oprfRoundtrip() throws {
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
        let config = try PirTestUtils.SymmetricPirTests.generateSymmetricPirConfig()
        let server = try OprfServer(symmetricPirConfig: config)
        let client = try OprfClient(symmetricPirClientConfig: config.clientConfig())

        let keyword: [UInt8] = [1, 2, 3, 4, 5]
        let (query1, output1) = try roundTrip(keyword: keyword, server: server, client: client)
        let (query2, output2) = try roundTrip(keyword: keyword, server: server, client: client)

        #expect(query1.oprfRepresentation != query2.oprfRepresentation)
        #expect(output1 == output2)
    }

    @Test
    func database() throws {
        let shardCount = 1
        let rowCount = 10
        let valueSize = 3
        let testDatabase = PirTestUtils.randomKeywordPirDatabase(rowCount: rowCount, valueSize: valueSize)

        let config = try PirTestUtils.SymmetricPirTests.generateSymmetricPirConfig()
        let encryptedDatabase = try KeywordDatabase(
            rows: testDatabase,
            sharding: .shardCount(shardCount),
            symmetricPirConfig: config)

        let oprfSecretKey = try OprfPrivateKey(rawRepresentation: config.oprfSecretKey.value)

        let testIndex = Int.random(in: 0..<rowCount)
        let testKeyword = Data(testDatabase[testIndex].keyword)
        let testValue = Data(testDatabase[testIndex].value)

        let finalizeHash = try oprfSecretKey.evaluate(Data(testKeyword))
        let testShard = try #require(encryptedDatabase.shards["0"])
        let obliviousKeywordSize = config.configType.obliviousKeywordSize
        let aesKeySize = config.configType.entryEncryptionKeySize
        #expect(testShard.rows[[UInt8](finalizeHash.prefix(obliviousKeywordSize))] != nil)
        #expect(testShard.rows[[UInt8](finalizeHash.prefix(1))] == nil)

        let encryptedValue = try #require(testShard.rows[[UInt8](finalizeHash.prefix(Int(obliviousKeywordSize)))])
        let key = SymmetricKey(data: finalizeHash.suffix(Int(aesKeySize)))

        let defaultNonceSize = 12
        let defaultTagSize = 16
        var sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: finalizeHash.prefix(defaultNonceSize)),
            ciphertext: encryptedValue.dropLast(defaultTagSize),
            tag: encryptedValue.suffix(defaultTagSize))

        let decryptedValue = try AES.GCM.open(sealedBox, using: key)
        #expect(testValue == decryptedValue)

        // wrong nonce test
        sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: finalizeHash.prefix(defaultNonceSize + 1)),
            ciphertext: encryptedValue.dropLast(defaultTagSize),
            tag: encryptedValue.suffix(defaultTagSize))

        #expect(throws: (any Error).self) { try AES.GCM.open(sealedBox, using: key) }
    }

    @Test
    func roundTrip() throws {
        try PirTestUtils.SymmetricPirTests.roundTrip(Bfv<UInt32>.self)
        try PirTestUtils.SymmetricPirTests.roundTrip(Bfv<UInt64>.self)
    }
}
