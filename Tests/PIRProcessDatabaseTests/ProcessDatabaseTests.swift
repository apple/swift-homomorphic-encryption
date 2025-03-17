// Copyright 2024-2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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
import PrivateInformationRetrieval
import Testing

@Suite
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
                  "databaseEncryptionKeyPath": "teststring",
                  "trialsPerShard": 1,
                  "sharding": {
                    "shardCount": 10
                  }
                }
                """
            let configData = try #require(configString.data(using: .utf8))
            let parsedConfig = try #require(try JSONDecoder().decode(
                PIRProcessDatabase.Arguments.self,
                from: configData))

            let config = PIRProcessDatabase.Arguments(
                inputDatabase: "input-database.txtpb",
                outputDatabase: "output-database.txtpb",
                outputPirParameters: "output-pir-params.txtpb",
                rlweParameters: PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5,
                outputEvaluationKeyConfig: "output-evaluation-key-config.txtpb",
                sharding: Sharding.shardCount(10),
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
}
