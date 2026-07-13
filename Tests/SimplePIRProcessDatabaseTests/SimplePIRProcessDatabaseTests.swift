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
@testable import SimplePIRProcessDatabase
import Testing

struct SimplePIRProcessDatabaseTests {
    @Test
    func argumentsJsonParsing() throws {
        // Test parsing with explicit chunkSize
        do {
            let configString = """
                {
                  "inputDatabase": "input-database.txtpb",
                  "outputDatabasePrefix": "output-database",
                  "latticeDimension": 1024,
                  "errorStdDev": 6.4,
                  "plaintextModulusBits": 14,
                  "ciphertextModulusBits": 42,
                  "shardCount": 5,
                  "chunkSize": 20000
                }
                """
            let configData = try #require(configString.data(using: .utf8))
            let parsedConfig = try JSONDecoder().decode(SimplePIRProcessDatabase.Arguments.self, from: configData)

            #expect(parsedConfig.chunkSize == 20000)
            #expect(parsedConfig.shardCount == 5)
        }
        // Test parsing with nil chunkSize
        do {
            let configString = """
                {
                  "inputDatabase": "input-database.txtpb",
                  "outputDatabasePrefix": "output-database",
                  "latticeDimension": 1024,
                  "errorStdDev": 6.4,
                  "plaintextModulusBits": 14,
                  "ciphertextModulusBits": 42,
                  "shardCount": 5
                }
                """
            let configData = try #require(configString.data(using: .utf8))
            let parsedConfig = try JSONDecoder().decode(SimplePIRProcessDatabase.Arguments.self, from: configData)

            #expect(parsedConfig.chunkSize == nil)
            #expect(parsedConfig.shardCount == 5)
        }
        // Test parsing defaultJsonString
        do {
            let configString = SimplePIRProcessDatabase.Arguments.defaultJsonString()
            let configData = try #require(configString.data(using: .utf8))
            #expect(throws: Never.self) {
                try JSONDecoder().decode(SimplePIRProcessDatabase.Arguments.self, from: configData)
            }
        }
    }
}
