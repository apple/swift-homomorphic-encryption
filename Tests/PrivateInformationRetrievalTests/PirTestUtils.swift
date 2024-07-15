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

import Foundation
import HomomorphicEncryption
@testable import PrivateInformationRetrieval
import TestUtilities

package enum PirTestUtils {
    static func testCuckooTableConfig(maxSerializedBucketSize: Int) throws -> CuckooTableConfig {
        let defaultConfig: CuckooTableConfig = .defaultKeywordPir(
            maxSerializedBucketSize: maxSerializedBucketSize)
        return try CuckooTableConfig(
            hashFunctionCount: defaultConfig.hashFunctionCount,
            maxEvictionCount: defaultConfig.maxEvictionCount,
            maxSerializedBucketSize: defaultConfig.maxSerializedBucketSize,
            bucketCount: defaultConfig.bucketCount)
    }

    static func getTestParameter<PIR: IndexPirProtocol>(
        pir _: PIR.Type,
        with context: Context<PIR.Scheme>,
        entryCount: Int,
        entrySizeInBytes: Int,
        batchSize: Int = 10) throws -> IndexPirParameter
    {
        let config = try IndexPirConfig(
            entryCount: entryCount,
            entrySizeInBytes: entrySizeInBytes,
            dimensionCount: 2,
            batchSize: batchSize,
            unevenDimensions: true)
        return PIR.generateParameter(config: config, with: context)
    }

    static func generateRandomData(size: Int) -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        return generateRandomData(size: size, using: &rng)
    }

    static func generateRandomData(size: Int, using rng: inout some PseudoRandomNumberGenerator) -> [UInt8] {
        var data = [UInt8](repeating: 0, count: size)
        rng.fill(&data)
        return data
    }

    static func getTestTable(rowCount: Int, valueSize: Int) -> [KeywordValuePair] {
        var rng = SystemRandomNumberGenerator()
        return getTestTable(rowCount: rowCount, valueSize: valueSize, using: &rng)
    }

    static func getTestTable(
        rowCount: Int,
        valueSize: Int,
        using rng: inout some PseudoRandomNumberGenerator,
        keywordSize: Int = 30) -> [KeywordValuePair]
    {
        precondition(rowCount > 0)
        var keywords: Set<KeywordValuePair.Keyword> = []
        var rows: [KeywordValuePair] = []
        rows.reserveCapacity(rowCount)
        repeat {
            let keyword = PirTestUtils.generateRandomData(size: keywordSize, using: &rng)
            if keywords.contains(keyword) {
                continue
            }
            keywords.insert(keyword)
            let value = PirTestUtils.generateRandomData(size: valueSize, using: &rng)
            rows.append(KeywordValuePair(keyword: keyword, value: value))
        } while rows.count < rowCount
        return rows
    }
}
