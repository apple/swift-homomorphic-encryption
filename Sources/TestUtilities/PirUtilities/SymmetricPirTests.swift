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
import HomomorphicEncryption
import PrivateInformationRetrieval
import Testing

extension PirTestUtils {
    /// Symmetric PIR tests.
    public enum SymmetricPirTests {
        /// Test generating configuration.
        @inlinable
        public static func generateSymmetricPirConfig() throws -> SymmetricPirConfig {
            let secretKey = [UInt8](OprfPrivateKey().rawRepresentation)
            return try SymmetricPirConfig(
                oprfSecretKey: secretKey, configType: .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128)
        }

        /// Tests symmetric PIR round trip.
        @inlinable
        public static func roundTrip<Scheme: HeScheme>(_: Scheme.Type) throws {
            // swiftlint:disable nesting
            typealias PirClient = MulPirClient<Scheme>
            typealias PirServer = MulPirServer<Scheme>
            // swiftlint:enable nesting

            let symmetricPirConfig = try Self.generateSymmetricPirConfig()
            let keywordConfig = try KeywordPirConfig(
                dimensionCount: 2,
                cuckooTableConfig: PirTestUtils.testCuckooTableConfig(maxSerializedBucketSize: 100),
                unevenDimensions: true,
                keyCompression: .noCompression,
                symmetricPirClientConfig: symmetricPirConfig.clientConfig())

            let encryptionParameters: EncryptionParameters<Scheme.Scalar> = try TestUtils.getTestEncryptionParameters()
            let context: Context<Scheme> = try Context(encryptionParameters: encryptionParameters)
            let valueSize = context.bytesPerPlaintext / 2
            let plainDatabase = PirTestUtils.randomKeywordPirDatabase(rowCount: 100, valueSize: valueSize)
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
            let oprfClient = try OprfClient(symmetricPirClientConfig: #require(keywordConfig.symmetricPirClientConfig))
            for index in shuffledValues.prefix(10) {
                // OPRF oblivious keyword
                let oprfQueryContext = try oprfClient.queryContext(at: plainDatabase[index].keyword)
                let oprfResponse = try oprfServer.computeResponse(query: oprfQueryContext.query)
                let parsedOprfOutput = try oprfClient.parse(oprfResponse: oprfResponse, with: oprfQueryContext)
                // Keyword PIR
                let query = try client.generateQuery(at: parsedOprfOutput.obliviousKeyword, using: secretKey)
                let response = try server.computeResponse(to: query, using: evaluationKey)
                #expect(!response.isTransparent())
                let result = try client.decrypt(
                    response: response,
                    at: parsedOprfOutput.obliviousKeyword,
                    using: secretKey)
                // SPIR decryption
                #expect(result != nil)
                let spirResult = try result.map { res in
                    try oprfClient.decrypt(encryptedEntry: res, with: parsedOprfOutput)
                }
                #expect(spirResult == plainDatabase[index].value)
            }
        }
    }
}
