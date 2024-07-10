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

    static func generateRandomData(size: Int, using rng: inout some RandomNumberGenerator) -> [UInt8] {
        (0..<size).map { _ in UInt8.random(in: 0...UInt8.max, using: &rng) }
    }

    static func getTestTable(rowCount: Int, valueSize: Int) -> [KeywordValuePair] {
        var rng = SystemRandomNumberGenerator()
        return getTestTable(rowCount: rowCount, valueSize: valueSize, using: &rng)
    }

    static func getTestTable(
        rowCount: Int,
        valueSize: Int,
        using rng: inout some RandomNumberGenerator,
        keywordSize: Int = 30) -> [KeywordValuePair]
    {
        var rows = [KeywordValuePair]()
        repeat {
            let keyword = PirTestUtils.generateRandomData(size: keywordSize, using: &rng)
            if !rows.contains(where: { existingPair in keyword == existingPair.keyword }) {
                rows.append(KeywordValuePair(
                    keyword: keyword,
                    value: PirTestUtils.generateRandomData(size: valueSize, using: &rng)))
            }
        } while rows.count < rowCount
        return rows
    }
}
