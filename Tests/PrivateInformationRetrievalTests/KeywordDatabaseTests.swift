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

@testable import PrivateInformationRetrieval
import XCTest

class KeywordDatabaseTests: XCTestCase {
    func testShardingCodable() throws {
        for sharding in [Sharding.shardCount(10), Sharding.entryCountPerShard(11)] {
            let encoded = try JSONEncoder().encode(sharding)
            let decoded = try JSONDecoder().decode(Sharding.self, from: encoded)
            XCTAssertEqual(decoded, sharding)
        }
    }

    func testSharding() throws {
        let shardCount = 10
        let rowCount = 10
        let valueSize = 3
        let testDatabase = PirTestUtils.getTestTable(rowCount: rowCount, valueSize: valueSize)

        let database = try KeywordDatabase(
            rows: testDatabase,
            sharding: .shardCount(shardCount))
        XCTAssertLessThanOrEqual(database.shards.count, shardCount)
        XCTAssertEqual(database.shards.map { shard in shard.value.rows.count }.sum(), rowCount)
        for row in testDatabase {
            XCTAssert(database.shards.contains { shard in shard.value[row.keyword] == row.value })
        }
    }

    func testShardingKnownAnswerTest() throws {
        var shardingFunction = ShardingFunction.sha256
        func checkKeywordShard(_ keyword: KeywordValuePair.Keyword, shardCount: Int, expectedShard: Int) {
            XCTAssertEqual(shardingFunction.shardIndex(keyword: keyword, shardCount: shardCount), expectedShard)
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

    func testShardingFunctionCodable() throws {
        for shardingFunction in [ShardingFunction.sha256, ShardingFunction.doubleMod(otherShardCount: 42)] {
            let encoded = try JSONEncoder().encode(shardingFunction)
            let decoded = try JSONDecoder().decode(ShardingFunction.self, from: encoded)
            XCTAssertEqual(decoded, shardingFunction)
        }
    }
}
