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

import _TestUtilities
import Foundation
@testable import PrivateInformationRetrieval
import Testing

struct KeywordDatabaseTests {
    @Test
    func shardingCodable() throws {
        // Basic round-trips
        for sharding in try [Sharding(shardCount: 10), Sharding(entryCountPerShard: 11)] {
            let encoded = try JSONEncoder().encode(sharding)
            let decoded = try JSONDecoder().decode(Sharding.self, from: encoded)
            #expect(decoded == sharding)
        }
        // Round-trip with optional fields set
        let sharding = try Sharding(entryCountPerShard: 100, maxShardCount: 16,
                                    requirePowerOfTwoShardCount: true)
        let encoded = try JSONEncoder().encode(sharding)
        let decoded = try JSONDecoder().decode(Sharding.self, from: encoded)
        #expect(decoded == sharding)
    }

    @Test
    func shardingCodableValidation() throws {
        // Both keys present must throw
        let bothSet = #"{"shardCount": 5, "entryCountPerShard": 10}"#
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(Sharding.self, from: Data(bothSet.utf8))
        }
        // Neither key present must throw
        let neitherSet = #"{}"#
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(Sharding.self, from: Data(neitherSet.utf8))
        }
    }

    @Test
    func shardingStrategy() throws {
        #expect(try Sharding(shardCount: 5).strategy == .shardCount(5))
        #expect(try Sharding(entryCountPerShard: 100).strategy == .entryCountPerShard(100))
    }

    @Test
    func shardingShardCount() throws {
        // Invalid count throws
        #expect(throws: PirError.self) {
            try Sharding(shardCount: 0)
        }

        // maxShardCount: exceeded throws
        #expect(throws: PirError.self) {
            try Sharding(shardCount: 4, maxShardCount: 3)
        }

        // requirePowerOfTwoShardCount: not a power of two throws
        #expect(throws: PirError.self) {
            try Sharding(shardCount: 3, requirePowerOfTwoShardCount: true)
        }

        // Valid: fixed shard count
        #expect(try Sharding(shardCount: 4).strategy == .shardCount(4))

        // Valid: maxShardCount not exceeded
        #expect(try Sharding(shardCount: 4, maxShardCount: 8).strategy == .shardCount(4))

        // Valid: already a power of two
        #expect(try Sharding(shardCount: 8, requirePowerOfTwoShardCount: true).strategy == .shardCount(8))
    }

    @Test
    func shardingEntryCountPerShard() throws {
        // Invalid count throws at init
        #expect(throws: PirError.self) {
            try Sharding(entryCountPerShard: 0)
        }

        // Use enough rows to ensure all expected shards are populated
        let rowCount = 1000
        let rows = PirTestUtils.randomKeywordPirDatabase(rowCount: rowCount, valueSize: 3)

        // Basic: 1000 rows / 100 per shard = 10 shards
        let sharding10 = try Sharding(entryCountPerShard: 100)
        #expect(try KeywordDatabase(rows: rows, sharding: sharding10).shards.count == 10)

        // Fewer rows than entryCountPerShard floors to 1 shard
        let sharding1 = try Sharding(entryCountPerShard: 2000)
        #expect(try KeywordDatabase(rows: rows, sharding: sharding1).shards.count == 1)

        // maxShardCount caps the computed count
        let shardingCapped = try Sharding(entryCountPerShard: 100, maxShardCount: 8)
        #expect(try KeywordDatabase(rows: rows, sharding: shardingCapped).shards.count == 8)

        // requirePowerOfTwoShardCount floors to nearest power of two (10 -> 8)
        let shardingPow2 = try Sharding(entryCountPerShard: 100, requirePowerOfTwoShardCount: true)
        #expect(try KeywordDatabase(rows: rows, sharding: shardingPow2).shards.count == 8)

        // Both: cap first then floor to power of two (10 -> cap 6 -> floor 4)
        let shardingBoth = try Sharding(entryCountPerShard: 100, maxShardCount: 6,
                                        requirePowerOfTwoShardCount: true)
        #expect(try KeywordDatabase(rows: rows, sharding: shardingBoth).shards.count == 4)

        // Both: result already a power of two after cap (10 -> cap 8 -> 8)
        let shardingBoth2 = try Sharding(entryCountPerShard: 100, maxShardCount: 8,
                                         requirePowerOfTwoShardCount: true)
        #expect(try KeywordDatabase(rows: rows, sharding: shardingBoth2).shards.count == 8)
    }

    @Test
    func sharding() throws {
        let shardCount = 10
        let rowCount = 10
        let valueSize = 3
        let testDatabase = PirTestUtils.randomKeywordPirDatabase(rowCount: rowCount, valueSize: valueSize)

        let database = try KeywordDatabase(
            rows: testDatabase,
            sharding: Sharding(shardCount: shardCount))
        #expect(database.shards.count <= shardCount)
        #expect(database.shards.map { shard in shard.value.rows.count }.sum() == rowCount)
        for row in testDatabase {
            #expect(database.shards.contains { shard in shard.value[row.keyword] == row.value })
        }
    }

    @Test
    func shardingKnownAnswerTest() {
        var shardingFunction = ShardingFunction.sha256
        func checkKeywordShard(_ keyword: KeywordValuePair.Keyword, shardCount: Int, expectedShard: Int) {
            #expect(shardingFunction.shardIndex(keyword: keyword, shardCount: shardCount) == expectedShard)
        }

        checkKeywordShard([0, 0, 0, 0], shardCount: 41, expectedShard: 2)
        checkKeywordShard([0, 0, 0, 0], shardCount: 1001, expectedShard: 635)
        checkKeywordShard([1, 2, 3], shardCount: 1001, expectedShard: 903)
        checkKeywordShard([3, 2, 1], shardCount: 1001, expectedShard: 842)

        shardingFunction = .doubleMod(otherShardCount: 2000)

        checkKeywordShard([0, 0, 0, 0], shardCount: 41, expectedShard: 32)
        checkKeywordShard([0, 0, 0, 0], shardCount: 1001, expectedShard: 319)
        checkKeywordShard([1, 2, 3], shardCount: 1001, expectedShard: 922)
        checkKeywordShard([3, 2, 1], shardCount: 1001, expectedShard: 328)
    }

    @Test
    func shardingFunctionCodable() throws {
        for shardingFunction in [ShardingFunction.sha256, ShardingFunction.doubleMod(otherShardCount: 42)] {
            let encoded = try JSONEncoder().encode(shardingFunction)
            let decoded = try JSONDecoder().decode(ShardingFunction.self, from: encoded)
            #expect(decoded == shardingFunction)
        }
    }
}
