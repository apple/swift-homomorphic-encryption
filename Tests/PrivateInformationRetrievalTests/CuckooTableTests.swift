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
@testable import PrivateInformationRetrieval
import Testing

@Suite
struct CuckooTableTests {
    @Test
    func cuckooTableEntries() throws {
        let valueSize = 100
        let testDatabase = PirTestUtils.getTestTable(
            rowCount: 1000,
            valueSize: valueSize)
        let config = try PirTestUtils.testCuckooTableConfig(maxSerializedBucketSize: 4 * valueSize)

        let cuckooTable = try CuckooTable(config: config, database: testDatabase)
        #expect(cuckooTable.entryCount == testDatabase.count)

        for entry in testDatabase {
            let indices = HashKeyword.hashIndices(
                keyword: entry.keyword,
                bucketCount: cuckooTable.bucketsPerTable,
                hashFunctionCount: config.hashFunctionCount).enumerated()
            var foundEntry = false
            for (tableIndex, hashIndex) in indices {
                let tableEntries = cuckooTable.buckets[cuckooTable.index(tableIndex: tableIndex, index: hashIndex)]
                for tableEntry in tableEntries {
                    if foundEntry {
                        #expect(tableEntry.keyword != entry.keyword)
                    } else {
                        if tableEntry.keyword == entry.keyword {
                            #expect(tableEntry.value == entry.value)
                            foundEntry = true
                        }
                    }
                }
            }
            #expect(foundEntry)
            #expect(cuckooTable[entry.keyword] == entry.value)
        }
    }

    @Test
    func reproduceCuckooTable() throws {
        let valueSize = 10
        let testDatabase = PirTestUtils.getTestTable(rowCount: 1000, valueSize: valueSize)
        let config = try PirTestUtils.testCuckooTableConfig(maxSerializedBucketSize: valueSize * 5)
        let rng1 = TestRng(counter: 0)
        let rng2 = TestRng(counter: 0)

        let cuckooTable1 = try CuckooTable(config: config, database: testDatabase, using: rng1)
        let cuckooTable2 = try CuckooTable(config: config, database: testDatabase, using: rng2)
        #expect(try cuckooTable1.serializeBuckets() == cuckooTable2.serializeBuckets())
    }

    @Test
    func summarize() throws {
        var rng = TestRng(counter: 1)
        let valueSize = 10
        let testDatabase = PirTestUtils.getTestTable(rowCount: 100, valueSize: valueSize, using: &rng)

        let config = try CuckooTableConfig(
            hashFunctionCount: 2,
            maxEvictionCount: 100,
            maxSerializedBucketSize: valueSize * 5,
            bucketCount:
            .allowExpansion(
                expansionFactor: 1.1,
                targetLoadFactor: 0.9))

        let cuckooTable = try CuckooTable(config: config, database: testDatabase, using: rng)
        let summary = CuckooTable.CuckooTableInformation(
            entryCount: 100,
            bucketCount: 80,
            emptyBucketCount: 19,
            loadFactor: 0.52)
        #expect(try cuckooTable.summarize() == summary)
    }

    @Test
    func cuckooTableLargestSerializedBucketSize() throws {
        let valueSize = 10
        let testDatabase = PirTestUtils.getTestTable(rowCount: 1000, valueSize: valueSize)
        let config = try CuckooTableConfig(
            hashFunctionCount: 2,
            maxEvictionCount: 20,
            maxSerializedBucketSize: 5 * valueSize,
            bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.9))
        let rng = TestRng(counter: 0)
        let cuckooTable = try CuckooTable(config: config, database: testDatabase, using: rng)

        let maxSerializedBucketSize = try cuckooTable.maxSerializedBucketSize()
        #expect(try cuckooTable.serializeBuckets().count <= maxSerializedBucketSize * cuckooTable.buckets.count)

        let bucketSizes = try cuckooTable.buckets.map { bucket in try bucket.serializedSize() }
        #expect(bucketSizes.contains(maxSerializedBucketSize))
    }

    @Test
    func cuckooTableFixedSize() throws {
        var rng = TestRng(counter: 0)
        let testDatabase = PirTestUtils.getTestTable(rowCount: 100, valueSize: 10, using: &rng)
        let maxSerializedBucketSize = 50
        let cuckooConfig = try {
            // use a smaller load factor, to ensure the fixed size is possible
            let config = try CuckooTableConfig(hashFunctionCount: 2,
                                               maxEvictionCount: 100,
                                               maxSerializedBucketSize: maxSerializedBucketSize,
                                               bucketCount:
                                               .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.5))
            let cuckooTable = try CuckooTable(config: config, database: testDatabase, using: rng)
            return try config
                .freezingTableSize(
                    maxSerializedBucketSize: cuckooTable.maxSerializedBucketSize(),
                    bucketCount: cuckooTable.buckets.count)
        }()
        let cuckooTable = try CuckooTable(config: cuckooConfig, database: testDatabase, using: rng)
        #expect(try cuckooTable.maxSerializedBucketSize() <= maxSerializedBucketSize)
        switch cuckooConfig.bucketCount {
        case let .fixedSize(bucketCount: bucketCount):
            #expect(cuckooTable.buckets.count == bucketCount)
        default:
            Issue.record("Cuckoo config was not fixed size")
        }
    }

    @Test
    func cuckooTableSmallSlotCount() throws {
        let valueSize = 10
        let slotCount = 7
        let testDatabase = PirTestUtils.getTestTable(rowCount: 1000, valueSize: valueSize)
        let config = try CuckooTableConfig(
            hashFunctionCount: 2,
            maxEvictionCount: 100,
            maxSerializedBucketSize: 5000, // large value to limit based on number of slots
            bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.9),
            slotCount: slotCount)
        let rng = TestRng(counter: 0)

        let cuckooTable = try CuckooTable(config: config, database: testDatabase, using: rng)
        for bucket in cuckooTable.buckets {
            #expect(bucket.slots.count <= slotCount)
        }
    }
}
