// Copyright 2024-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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
import HomomorphicEncryption
@testable import PIRProcessDatabase
@testable import PrivateInformationRetrieval
import Testing

struct ProcessDatabaseTests {
    @Test
    func argumentsJsonParsing() throws {
        do {
            let configString = """
                {
                  "inputDatabase": "input-database.txtpb",
                  "outputDatabase": "output-database.txtpb",
                  "outputEvaluationKeyConfig": "output-evaluation-key-config.txtpb",
                  "outputPirParameters": "output-pir-params.txtpb",
                  "rlweParameters": "insecure_n_8_logq_5x18_logt_5",
                  "databaseType": "keyword",
                  "databaseEncryptionKeyPath": "teststring",
                  "trialsPerShard": 1,
                  "sharding": {
                    "shardCount": 10
                  }
                }
                """
            let configData = try #require(configString.data(using: .utf8))
            let parsedConfig = try JSONDecoder().decode(PIRProcessDatabase.Arguments.self, from: configData)

            let config = try PIRProcessDatabase.Arguments(
                inputDatabase: "input-database.txtpb",
                outputDatabase: "output-database.txtpb",
                outputPirParameters: "output-pir-params.txtpb",
                rlweParameters: PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5,
                databaseType: .keyword,
                outputEvaluationKeyConfig: "output-evaluation-key-config.txtpb",
                sharding: Sharding(shardCount: 10),
                trialsPerShard: 1)
            #expect(parsedConfig == config)
        }

        // Can parse default JSON string
        do {
            let configString = PIRProcessDatabase.Arguments.defaultJsonString()
            let configData = try #require(configString.data(using: .utf8))
            #expect(throws: Never.self) {
                try JSONDecoder().decode(PIRProcessDatabase.Arguments.self, from: configData)
            }
        }
    }

    @Test
    func shardingArgumentsDecoding() throws {
        func decoded(sharding shardingJSON: String) throws -> Arguments {
            let json = """
                {
                  "rlweParameters": "n_4096_logq_27_28_28_logt_5",
                  "databaseType": "keyword",
                  "inputDatabase": "input.txtpb",
                  "outputDatabase": "output-SHARD_ID.bin",
                  "outputPirParameters": "params-SHARD_ID.txtpb",
                  "sharding": \(shardingJSON),
                  "trialsPerShard": 1
                }
                """
            return try JSONDecoder().decode(Arguments.self, from: Data(json.utf8))
        }

        let rowCount = 100

        // Valid: fixed shard counts
        #expect(try decoded(sharding: #"{"shardCount": 4}"#).sharding?.shardCount(for: rowCount) == 4)
        #expect(try decoded(sharding: #"{"shardCount": 1}"#).sharding?.shardCount(for: rowCount) == 1)
        #expect(try decoded(sharding: #"{"shardCount": 4, "maxShardCount": 8}"#).sharding?
            .shardCount(for: rowCount) == 4)
        #expect(try decoded(sharding: #"{"shardCount": 4, "requirePowerOfTwoShardCount": true}"#).sharding?
            .shardCount(for: rowCount) == 4)

        // Valid: entry-count-per-shard (100 rows)
        #expect(try decoded(sharding: #"{"entryCountPerShard": 25}"#).sharding?
            .shardCount(for: rowCount) == 4) // 100/25 = 4
        #expect(try decoded(sharding: #"{"entryCountPerShard": 30, "maxShardCount": 2}"#).sharding?
            .shardCount(for: rowCount) == 2) // 100/30=3 → cap 2
        #expect(try decoded(sharding: #"{"entryCountPerShard": 30, "requirePowerOfTwoShardCount": true}"#).sharding?
            .shardCount(for: rowCount) == 2) // 3 → floor 2
        #expect(try decoded(
            sharding: #"{"entryCountPerShard": 30, "maxShardCount": 6, "requirePowerOfTwoShardCount": true}"#)
            .sharding?.shardCount(for: rowCount) == 2) // 3 → cap 6 (no-op) → floor 2

        // Invalid: rejected at config decode time
        #expect(throws: PirError.self) { try decoded(sharding: #"{"shardCount": 0}"#) }
        #expect(throws: PirError.self) { try decoded(sharding: #"{"shardCount": 5, "maxShardCount": 3}"#) }
        #expect(throws: PirError.self) {
            try decoded(sharding: #"{"shardCount": 3, "requirePowerOfTwoShardCount": true}"#)
        }
        #expect(throws: PirError.self) { try decoded(sharding: #"{"entryCountPerShard": 0}"#) }
    }

    @Test
    func unevenDimensionsDecoding() throws {
        func decoded(unevenDimensions: String) throws -> Arguments {
            let json = """
                {
                  "rlweParameters": "n_4096_logq_27_28_28_logt_5",
                  "databaseType": "keyword",
                  "inputDatabase": "input.txtpb",
                  "outputDatabase": "output-SHARD_ID.bin",
                  "outputPirParameters": "params-SHARD_ID.txtpb",
                  "unevenDimensions": \(unevenDimensions)
                }
                """
            return try JSONDecoder().decode(Arguments.self, from: Data(json.utf8))
        }

        #expect(try decoded(unevenDimensions: "true").unevenDimensions == true)
        #expect(try decoded(unevenDimensions: "false").unevenDimensions == false)

        // Omitting the field leaves it nil (defaults to true at processing time)
        let json = """
            {
              "rlweParameters": "n_4096_logq_27_28_28_logt_5",
              "databaseType": "keyword",
              "inputDatabase": "input.txtpb",
              "outputDatabase": "output-SHARD_ID.bin",
              "outputPirParameters": "params-SHARD_ID.txtpb"
            }
            """
        let noField = try JSONDecoder().decode(Arguments.self, from: Data(json.utf8))
        #expect(noField.unevenDimensions == nil)
    }

    @Test
    func symmetricPirMaxSerializedBucketSize() throws {
        let tempDir = FileManager.default.temporaryDirectory
        let keyFile = tempDir.appendingPathComponent("test_symmetric_pir_key_\(UUID().uuidString).txt").path
        defer {
            try? FileManager.default.removeItem(atPath: keyFile)
        }
        let arguments = Arguments(
            inputDatabase: "input.txtpb",
            outputDatabase: "output-SHARD_ID.bin",
            outputPirParameters: "params-SHARD_ID.txtpb",
            rlweParameters: .n_4096_logq_27_28_28_logt_5,
            databaseType: .keyword,
            outputEvaluationKeyConfig: nil,
            symmetricPirArguments: SymmetricPirArguments(
                databaseEncryptionKeyFilePath: nil,
                configType: nil,
                outputDatabaseEncryptionKeyFilePath: keyFile))

        // With 2048 bytes per plaintext, the encryption tag makes values of 998...1012 and 2022...2037 bytes
        // outgrow a bucket sized for the unencrypted value. Test both ends of each range and their neighbors.
        for valueSize in [997, 998, 1012, 1013, 2021, 2022, 2037, 2038] {
            let rows = [KeywordValuePair(keyword: [1, 2, 3], value: [UInt8](repeating: 0, count: valueSize))]
            let resolved = try arguments.resolveForKeywordDatabase(for: rows, scheme: Bfv<UInt64>.self)
            let encryptedRows = try KeywordDatabase.symmetricPIRProcess(
                database: rows,
                config: #require(resolved.symmetricPirConfig))
            #expect(throws: Never.self, "value size \(valueSize)") {
                try CuckooTable(config: resolved.cuckooTableConfig, database: encryptedRows)
            }
        }
    }
}
