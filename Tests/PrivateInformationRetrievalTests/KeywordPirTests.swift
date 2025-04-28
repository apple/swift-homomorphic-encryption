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

import _TestUtilities
import HomomorphicEncryption
@testable import PrivateInformationRetrieval
import Testing

@Suite
struct KeywordPirTests {
    @Test
    func processedDatabaseSerialization() throws {
        try PirTestUtils.KeywordPirTests.processedDatabaseSerialization(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.processedDatabaseSerialization(Bfv<UInt64>.self)
    }

    @Test
    func keywordPirMulPir1HashFunction() throws {
        try PirTestUtils.KeywordPirTests.keywordPirMulPir1HashFunction(NoOpScheme.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPir1HashFunction(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPir1HashFunction(Bfv<UInt64>.self)
    }

    @Test
    func keywordPirMulPir3HashFunctions() throws {
        try PirTestUtils.KeywordPirTests.keywordPirMulPir3HashFunctions(NoOpScheme.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPir3HashFunctions(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPir3HashFunctions(Bfv<UInt64>.self)
    }

    @Test
    func keywordPirMulPir1Dimension() throws {
        try PirTestUtils.KeywordPirTests.keywordPirMulPir1Dimension(NoOpScheme.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPir1Dimension(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPir1Dimension(Bfv<UInt64>.self)
    }

    @Test
    func keywordPirMulPir2Dimensions() throws {
        try PirTestUtils.KeywordPirTests.keywordPirMulPir2Dimensions(NoOpScheme.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPir2Dimensions(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPir2Dimensions(Bfv<UInt64>.self)
    }

    @Test
    func keywordPirMulPirHybridKeyCompression() throws {
        try PirTestUtils.KeywordPirTests.keywordPirMulPirHybridKeyCompression(NoOpScheme.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPirHybridKeyCompression(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPirHybridKeyCompression(Bfv<UInt64>.self)
    }

    @Test
    func keywordPirMulPirMaxKeyCompression() throws {
        try PirTestUtils.KeywordPirTests.keywordPirMulPirMaxKeyCompression(NoOpScheme.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPirMaxKeyCompression(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPirMaxKeyCompression(Bfv<UInt64>.self)
    }

    @Test
    func keywordPirMulPirLargeParameters() throws {
        try PirTestUtils.KeywordPirTests.keywordPirMulPirLargeParameters(NoOpScheme.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPirLargeParameters(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.keywordPirMulPirLargeParameters(Bfv<UInt64>.self)
    }

    @Test
    func keywordPirFixedConfig() throws {
        try PirTestUtils.KeywordPirTests.keywordPirFixedConfig(NoOpScheme.self)
        try PirTestUtils.KeywordPirTests.keywordPirFixedConfig(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.keywordPirFixedConfig(Bfv<UInt64>.self)
    }

    @Test
    func sharding() throws {
        // TODO: make compatible with NoOpScheme
        try PirTestUtils.KeywordPirTests.sharding(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.sharding(Bfv<UInt64>.self)
    }

    @Test
    func limitEntriesPerResponse() throws {
        // TODO: make compatible with NoOpScheme.
        try PirTestUtils.KeywordPirTests.limitEntriesPerResponse(Bfv<UInt32>.self)
        try PirTestUtils.KeywordPirTests.limitEntriesPerResponse(Bfv<UInt64>.self)
    }

    @Test
    func invalidArguments() throws {
        let cuckooConfig = try CuckooTableConfig(
            hashFunctionCount: 2,
            maxEvictionCount: 100,
            maxSerializedBucketSize: 10 * 5,
            bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.5))
        let keywordConfig = try KeywordPirConfig(
            dimensionCount: 2,
            cuckooTableConfig: cuckooConfig,
            unevenDimensions: true, keyCompression: .noCompression)
        let databaseConfig = KeywordDatabaseConfig(
            sharding: Sharding.shardCount(1),
            keywordPirConfig: keywordConfig)
        let encryptionParameters = try EncryptionParameters<UInt32>(from: .n_4096_logq_27_28_28_logt_5)
        #expect(throws: PirError.invalidPirAlgorithm(PirAlgorithm.aclsPir)) {
            try ProcessKeywordDatabase.Arguments<UInt32>(
                databaseConfig: databaseConfig,
                encryptionParameters: encryptionParameters,
                algorithm: PirAlgorithm.aclsPir, keyCompression: .noCompression,
                trialsPerShard: 1)
        }
    }
}
