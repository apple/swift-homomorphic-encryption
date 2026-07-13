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
@testable import MemoryMapping
import Testing

/// Extension to force MMapDictionary into using 64 bit offsets
extension MMapDictionary.Builder {
    func build(offsetType: MMapDictionary.OffsetType,
               loadFactor: Double = MMapDictionary.defaultLoadFactor) throws -> Data
    {
        func inner<Offset: FixedWidthInteger>(_: Offset.Type) throws -> Data {
            let sizes = calculateSize(Offset.self, bucketCount: bucketCount)
            return try buildWithOffset(Offset.self, offsetType: offsetType, bucketCount: bucketCount, sizes: sizes)
        }

        let bucketCount = try calculateBucketCount(loadFactor: loadFactor)
        return switch offsetType {
        case .uint32: try inner(UInt32.self)
        case .uint64: try inner(UInt64.self)
        }
    }

    func write(
        to path: String,
        offsetType: MMapDictionary.OffsetType,
        loadFactor: Double = MMapDictionary.defaultLoadFactor) throws
    {
        let data = try build(offsetType: offsetType, loadFactor: loadFactor)
        let url = URL(fileURLWithPath: path)
        try data.write(to: url, options: .atomic)
    }
}

struct MMapDictionaryTests {
    // MARK: - Builder Tests

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func builderCanInsertAndBuildEmptyDictionary(offsetType: MMapDictionary.OffsetType) throws {
        let builder = MMapDictionary.Builder()
        let data = try builder.build(offsetType: offsetType)

        // Should have header + buckets (minimum 16 buckets)
        let expectedSize = MMapDictionary
            .headerSize + (16 * MMapDictionary.bucketEntrySize(offsetType: offsetType)) // header + 16 buckets
        #expect(data.count == expectedSize)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func builderCanInsertMultipleEntries(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "key1", value: [1, 2, 3])
        builder.insert(key: "key2", value: [4, 5, 6])
        builder.insert(key: "key3", value: [7, 8, 9])
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)

        let value1 = try dict["key1"]
        let value2 = try dict["key2"]
        let value3 = try dict["key3"]

        #expect(value1 == [1, 2, 3])
        #expect(value2 == [4, 5, 6])
        #expect(value3 == [7, 8, 9])
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func builderHandlesUTF8KeysCorrectly(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "hello", value: [1])
        builder.insert(key: "こんにちは", value: [2]) // Japanese
        builder.insert(key: "你好", value: [3]) // Chinese
        builder.insert(key: "مرحبا", value: [4]) // Arabic
        builder.insert(key: "🌍🌎🌏", value: [5]) // Emoji
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)

        #expect(try dict["hello"] == [1])
        #expect(try dict["こんにちは"] == [2])
        #expect(try dict["你好"] == [3])
        #expect(try dict["مرحبا"] == [4])
        #expect(try dict["🌍🌎🌏"] == [5])
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func builderHandlesEmptyKeyAndEmptyValues(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "", value: [])
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let result = try dict[""]

        // swiftlint:disable:next empty_collection_literal
        #expect(result == [])
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func builderHandlesLargeValues(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        let largeValue = Array(repeating: UInt8(42), count: 10000)
        var builder = MMapDictionary.Builder()
        builder.insert(key: "large", value: largeValue)
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let result = try dict["large"]

        #expect(result == largeValue)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func builderRespectsCustomLoadFactor(offsetType: MMapDictionary.OffsetType) throws {
        var builder = MMapDictionary.Builder()
        // Insert 10 entries
        for i in 0..<10 {
            builder.insert(key: "test\(i)", value: [UInt8(i)])
        }

        // With load factor 0.5, we should get 20 buckets (10 / 0.5 = 20)
        let data = try builder.build(offsetType: offsetType, loadFactor: 0.5)

        // Calculate exact expected size:
        let bucketsSize = 20 * MMapDictionary.bucketEntrySize(offsetType: offsetType)
        // Entries: 10 entries, each entry is:
        //   - Key length: 4 bytes
        //   - Key data: 5 bytes ("test0" to "test9")
        //   - Value length: 4 bytes
        //   - Value data: 1 byte
        // Total per entry: 4 + keyLen + 4 + 1
        //   "test0" through "test9" = 5 bytes each
        let entriesSize = 10 * (4 + 5 + 4 + 1) // 10 entries × 14 bytes each = 140 bytes
        let exactSize = MMapDictionary.headerSize + bucketsSize + entriesSize
        #expect(data.count == exactSize)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func builderThrowsOnInvalidLoadFactor(offsetType: MMapDictionary.OffsetType) throws {
        var builder = MMapDictionary.Builder()
        for i in 0..<10 {
            builder.insert(key: "key\(i)", value: [UInt8(i)])
        }

        // Load factor must be > 0.0 and <= 1.0
        #expect(throws: MMapDictionaryError.self) {
            _ = try builder.build(offsetType: offsetType, loadFactor: 0.0)
        }

        #expect(throws: MMapDictionaryError.self) {
            _ = try builder.build(offsetType: offsetType, loadFactor: -0.5)
        }

        #expect(throws: MMapDictionaryError.self) {
            _ = try builder.build(offsetType: offsetType, loadFactor: 1.5)
        }

        // Valid edge case: exactly 1.0 should work
        _ = try builder.build(offsetType: offsetType, loadFactor: 1.0)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func loadFactorEdgeCasesWithEmptyDictionary(offsetType: MMapDictionary.OffsetType) throws {
        let builder = MMapDictionary.Builder()

        // All valid load factors should work with empty dictionary
        _ = try builder.build(offsetType: offsetType, loadFactor: 0.25)
        _ = try builder.build(offsetType: offsetType, loadFactor: 0.5)
        _ = try builder.build(offsetType: offsetType, loadFactor: 0.75)
        _ = try builder.build(offsetType: offsetType, loadFactor: 1.0)

        // Even with empty dictionary, minimum bucket count (16) should be used
        let data = try builder.build(offsetType: offsetType, loadFactor: 0.1)
        let exactSize = MMapDictionary.headerSize + (16 * MMapDictionary.bucketEntrySize(offsetType: offsetType))
        #expect(data.count == exactSize)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func extremeLoadFactorsWithManyEntries(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        for i in 0..<100 {
            builder.insert(key: "key_\(i)", value: [UInt8(i % 256)])
        }

        // Very low load factor (0.1) = 1000 buckets for 100 entries
        // Should have excellent lookup performance but use more memory
        try builder.write(to: path, offsetType: offsetType, loadFactor: 0.1)
        let dict1 = try MMapDictionary(path: path)

        // Verify all entries are retrievable
        for i in 0..<100 {
            let result = try dict1["key_\(i)"]
            #expect(result == [UInt8(i % 256)])
        }

        cleanup(path: path)

        // Very high load factor (1.0) = 100 buckets for 100 entries
        // Should still work but with more collisions
        try builder.write(to: path, offsetType: offsetType, loadFactor: 1.0)
        let dict2 = try MMapDictionary(path: path)

        for i in 0..<100 {
            let result = try dict2["key_\(i)"]
            #expect(result == [UInt8(i % 256)])
        }
    }

    @Test(
        .disabled("Disabled by default because of large memory requirements"))
    func builderWillSwitchTo64bitOffsetsAndLookupAndOtherConvenienceMethodsStillWorkCorrectly() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()

        // Create enough data to force 64-bit offsets
        // We need total data size > 4GB to require 64-bit offsets
        // Insert a large value that would push offsets beyond 32-bit range in a real scenario
        let largeValueSize = 1 << 30 // 1 GB per entry
        let numberOfEntries = 4

        for i in 0..<numberOfEntries {
            let key = "large_entry_\(i)"
            let value = Array(repeating: UInt8(i % 256), count: largeValueSize)
            builder.insert(key: key, value: value)
        }

        // Add some small entries too
        builder.insert(key: "small1", value: [1, 2, 3])
        builder.insert(key: "small2", value: [4, 5, 6])

        try builder.write(to: path)
        print(path)
        let dict = try MMapDictionary(path: path)

        // Verify all large entries are retrievable
        for i in 0..<numberOfEntries {
            let key = "large_entry_\(i)"
            let expectedValue = Array(repeating: UInt8(i % 256), count: largeValueSize)
            let result = try dict[key]
            #expect(result == expectedValue, "Large entry \(i) should be retrievable")
        }

        // Verify small entries still work
        #expect(try dict["small1"] == [1, 2, 3])
        #expect(try dict["small2"] == [4, 5, 6])

        // Test withValue closure works
        let byteCount = try dict.withValue(forKey: "large_entry_0") { span in
            span.byteCount
        }
        #expect(byteCount == largeValueSize)

        // Test count method
        #expect(try dict.count() == numberOfEntries + 2)

        // Test keys method returns correct count
        #expect(try dict.keys().count == numberOfEntries + 2)

        // Verify keys are in insertion order
        let allKeys = try dict.keys()
        for i in 0..<numberOfEntries {
            #expect(allKeys[i] == Array("large_entry_\(i)".utf8))
        }
        #expect(allKeys[numberOfEntries] == Array("small1".utf8))
        #expect(allKeys[numberOfEntries + 1] == Array("small2".utf8))

        // Test keys(count:) works
        let firstThreeKeys = try dict.keys(count: 3)
        #expect(firstThreeKeys.count == 3)
        #expect(firstThreeKeys[0] == Array("large_entry_0".utf8))
        #expect(firstThreeKeys[1] == Array("large_entry_1".utf8))
        #expect(firstThreeKeys[2] == Array("large_entry_2".utf8))
    }

    // MARK: - Lookup Tests

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func lookupReturnsNilForNonExistentKey(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "exists", value: [1, 2, 3])
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let result = try dict["doesNotExist"]

        #expect(result == nil)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func withValueClosureReceivesCorrectSpan(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "test", value: [10, 20, 30, 40])
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)

        let byteCount = try dict.withValue(forKey: "test") { span in
            span.byteCount
        }

        #expect(byteCount == 4)

        let firstByte = try dict.withValue(forKey: "test") { span in
            span.withUnsafeBytes { buffer in
                buffer.first
            }
        }

        #expect(firstByte == 10)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func withValueReturnsNilForMissingKey(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        let builder = MMapDictionary.Builder()
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let result = try dict.withValue(forKey: "missing") { span in
            span.byteCount
        }

        #expect(result == nil)
    }

    // MARK: - Hash Collision Tests

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func dictionaryHandlesHashCollisionsWithLinearProbing(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()

        // Insert many entries to force collisions
        for i in 0..<50 {
            builder.insert(key: "key_\(i)", value: [UInt8(i % 256)])
        }

        // Use load factor of 1.0 (buckets = entries)
        // This maximizes collisions but should still work with linear probing
        try builder.write(to: path, offsetType: offsetType, loadFactor: 1.0)

        let dict = try MMapDictionary(path: path)

        // Verify all entries can be retrieved
        for i in 0..<50 {
            let result = try dict["key_\(i)"]
            #expect(result == [UInt8(i % 256)])
        }
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func guaranteedHashCollisionWithLinearProbing(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        // Helper functions:

        func computeHash(string: String) -> UInt64 {
            MMapDictionary.hash(bytes: string.utf8.span.bytes)
        }

        func bucketIndex(hash: UInt64, bucketCount: Int = 16) -> Int {
            Int(hash % UInt64(bucketCount))
        }

        func hashPrefix(hash: UInt64) -> UInt32 {
            UInt32(hash & 0xFFFF_FFFF)
        }

        // MARK: Test Case 1: Same Bucket, Different Prefix

        // These keys hash to the same bucket but have different prefixes.
        // Linear probing should place the second key in the next bucket.
        let sameBucketKey1 = "A"
        let sameBucketKey2 = "Q"

        let hash1 = computeHash(string: sameBucketKey1)
        let hash2 = computeHash(string: sameBucketKey2)

        // Verify collision scenario: same bucket, different prefix
        #expect(bucketIndex(hash: hash1) == bucketIndex(hash: hash2), "Keys should hash to same bucket")
        #expect(hashPrefix(hash: hash1) != hashPrefix(hash: hash2), "Keys should have different hash prefixes")

        var builder = MMapDictionary.Builder()
        builder.insert(key: sameBucketKey1, value: [1])
        builder.insert(key: sameBucketKey2, value: [2])
        try builder.write(to: path, offsetType: offsetType)
        var dict = try MMapDictionary(path: path)

        // Verify both values are retrievable despite collision
        #expect(try dict[sameBucketKey1] == [1], "First key should be retrievable")
        #expect(try dict[sameBucketKey2] == [2], "Second key should be retrievable via linear probing")

        // MARK: Test Case 2: Same Bucket, Same Prefix (Worst Case)

        // These keys have both the same bucket AND same prefix.
        // This is the worst-case collision where only full key comparison differentiates them.
        let samePrefixKey1 = ")UN[1"
        let samePrefixKey2 = ")C3Z&xC"

        let prefixHash1 = computeHash(string: samePrefixKey1)
        let prefixHash2 = computeHash(string: samePrefixKey2)

        // Verify worst-case collision: same bucket AND same prefix
        #expect(
            bucketIndex(hash: prefixHash1) == bucketIndex(hash: prefixHash2),
            "Keys should hash to same bucket")
        #expect(
            hashPrefix(hash: prefixHash1) == hashPrefix(hash: prefixHash2),
            "Keys should have identical hash prefixes")

        builder = MMapDictionary.Builder()
        builder.insert(key: samePrefixKey1, value: [11])
        builder.insert(key: samePrefixKey2, value: [22])
        try builder.write(to: path, offsetType: offsetType)
        dict = try MMapDictionary(path: path)

        // Verify full key comparison works correctly
        #expect(
            try dict[samePrefixKey1] == [11],
            "First key should be retrievable with full key comparison")
        #expect(
            try dict[samePrefixKey2] == [22],
            "Second key should be retrievable with full key comparison")

        // MARK: Test Case 3: Multiple Collisions with Different Entries

        // Test that we can mix colliding and non-colliding keys
        cleanup(path: path)

        builder = MMapDictionary.Builder()
        builder.insert(key: sameBucketKey1, value: [1])
        builder.insert(key: "unique_key", value: [100]) // Non-colliding key
        builder.insert(key: sameBucketKey2, value: [2])
        builder.insert(key: samePrefixKey1, value: [11])
        builder.insert(key: "another_unique", value: [200]) // Non-colliding key
        builder.insert(key: samePrefixKey2, value: [22])
        try builder.write(to: path, offsetType: offsetType)
        dict = try MMapDictionary(path: path)

        // Verify all keys are retrievable regardless of collision status
        #expect(try dict[sameBucketKey1] == [1])
        #expect(try dict["unique_key"] == [100])
        #expect(try dict[sameBucketKey2] == [2])
        #expect(try dict[samePrefixKey1] == [11])
        #expect(try dict["another_unique"] == [200])
        #expect(try dict[samePrefixKey2] == [22])

        // Verify the dictionary has the correct count
        #expect(try dict.count() == 6, "Dictionary should contain all 6 entries")
    }

    // MARK: - Extra methods Tests

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func keysAreReturnedInInsertionOrder(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()

        let keys = (0..<1000).map { _ in
            var key = Array(repeating: UInt8(0), count: 16)
            for i in key.indices {
                key[i] = UInt8.random(in: UInt8.min...UInt8.max)
            }
            return key
        }

        for key in keys {
            builder.insert(key: key.span.bytes, value: [1].span.bytes)
        }

        try builder.write(to: path, offsetType: offsetType)
        let dict = try MMapDictionary(path: path)

        #expect(try dict.keys().count == 1000)
        #expect(try dict.keys() == keys)
        #expect(try dict.keys(count: 15) == Array(keys.prefix(15)))
    }

    // MARK: - Count Method Tests

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func countReturnsZeroForEmptyDictionary(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        let builder = MMapDictionary.Builder()
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let count = try dict.count()

        #expect(count == 0)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func countReturnsSingleEntryForSingleItem(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "single", value: [42])
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let count = try dict.count()

        #expect(count == 1)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func countReturnsCorrectValueForMultipleEntries(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        let entryCount = 50
        for i in 0..<entryCount {
            builder.insert(key: "key_\(i)", value: [UInt8(i % 256)])
        }
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let count = try dict.count()

        #expect(count == entryCount)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func countHandlesEntriesWithEmptyKeys(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "", value: [1])
        builder.insert(key: "normal", value: [2])
        builder.insert(key: "another", value: [3])
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let count = try dict.count()

        #expect(count == 3)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func countHandlesEntriesWithEmptyValues(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "empty_value", value: [])
        builder.insert(key: "normal", value: [1, 2, 3])
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let count = try dict.count()

        #expect(count == 2)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func countWithLargeNumberOfEntries(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        let entryCount = 5000
        for i in 0..<entryCount {
            builder.insert(key: "entry_\(i)", value: [UInt8(i % 256)])
        }
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let count = try dict.count()

        #expect(count == entryCount)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func countWithDifferentLoadFactors(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        let entryCount = 100
        for i in 0..<entryCount {
            builder.insert(key: "test_\(i)", value: [UInt8(i % 256)])
        }

        // Test with different load factors
        for loadFactor in [0.25, 0.5, 0.75, 1.0] {
            cleanup(path: path)
            try builder.write(to: path, offsetType: offsetType, loadFactor: loadFactor)
            let dict = try MMapDictionary(path: path)
            let count = try dict.count()

            #expect(count == entryCount, "Count should be \(entryCount) with load factor \(loadFactor)")
        }
    }

    // MARK: - LongestProbeRun Method Tests

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func longestProbeRunReturnsZeroForEmptyDictionary(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        let builder = MMapDictionary.Builder()
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let longestRun = try dict.longestProbeRun()

        #expect(longestRun == 0, "Empty dictionary should have zero longest probe run")
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func longestProbeRunForSingleEntry(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "single", value: [42])
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let longestRun = try dict.longestProbeRun()

        #expect(longestRun == 1, "Single entry should have longest run of 1")
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func longestProbeRunWithLowLoadFactor(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        for i in 0..<10 {
            builder.insert(key: "entry_\(i)", value: [UInt8(i)])
        }

        // Low load factor (0.1) should result in minimal collisions
        try builder.write(to: path, offsetType: offsetType, loadFactor: 0.1)

        let dict = try MMapDictionary(path: path)
        let longestRun = try dict.longestProbeRun()

        // With load factor of 0.1, we expect very few consecutive entries
        // Longest run should be relatively small
        #expect(longestRun <= 10, "Low load factor should result in short probe runs")
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func longestProbeRunWithHighLoadFactor(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        for i in 0..<50 {
            builder.insert(key: "collision_\(i)", value: [UInt8(i % 256)])
        }

        // High load factor (1.0) should result in more collisions
        try builder.write(to: path, offsetType: offsetType, loadFactor: 1.0)

        let dict = try MMapDictionary(path: path)
        let longestRun = try dict.longestProbeRun()

        // With load factor of 1.0, we expect longer runs of consecutive entries
        #expect(longestRun >= 1, "Should have at least one entry")
        #expect(longestRun <= 50, "Longest run can't exceed total entries")
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func longestProbeRunComparisonAcrossLoadFactors(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        for i in 0..<100 {
            builder.insert(key: "test_\(i)", value: [UInt8(i % 256)])
        }

        // Lower load factors should generally result in shorter probe runs
        try builder.write(to: path, offsetType: offsetType, loadFactor: 0.25)
        let dict1 = try MMapDictionary(path: path)
        let runLowLoad = try dict1.longestProbeRun()

        cleanup(path: path)

        // Higher load factors should generally result in longer probe runs
        try builder.write(to: path, offsetType: offsetType, loadFactor: 1.0)
        let dict2 = try MMapDictionary(path: path)
        let runHighLoad = try dict2.longestProbeRun()

        // This is a statistical expectation - high load should have equal or longer runs
        #expect(
            runHighLoad >= runLowLoad,
            "High load factor (\(runHighLoad)) should have >= probe run than low load factor (\(runLowLoad))")
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func longestProbeRunWithManyEntries(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        let entryCount = 1000
        for i in 0..<entryCount {
            builder.insert(key: "item_\(i)", value: [UInt8(i % 256)])
        }

        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let longestRun = try dict.longestProbeRun()
        let count = try dict.count()

        #expect(count == entryCount, "Should have all entries")
        #expect(longestRun >= 1, "Should have at least one entry")
        #expect(
            longestRun <= entryCount,
            "Longest run cannot exceed total entry count")
    }

    // MARK: - Error Handling Tests

    @Test
    func openingNonExistentFileThrowsError() {
        #expect(throws: Error.self) {
            _ = try MMapDictionary(path: "/nonexistent/path/file.mmap")
        }
    }

    @Test
    func openingFileWithInvalidMagicNumberThrowsError() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        // Create a file with wrong magic number
        var data = Data()
        withUnsafeBytes(of: UInt32(0xDEAD_BEEF)) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt32(16)) { data.append(contentsOf: $0) }
        data.append(Data(repeating: 0, count: 200))

        try data.write(to: URL(fileURLWithPath: path))

        #expect(throws: MMapDictionaryError.self) {
            _ = try MMapDictionary(path: path)
        }
    }

    @Test
    func openingFileThatIsTooSmallThrowsError() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        // Create a file that's too small
        let data = Data([1, 2, 3])
        try data.write(to: URL(fileURLWithPath: path))

        #expect(throws: MMapDictionaryError.self) {
            _ = try MMapDictionary(path: path)
        }
    }

    @Test
    func openingFileWithZeroBucketCountThrowsError() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        // Create a file with valid magic but zero buckets
        var data = Data()
        withUnsafeBytes(of: UInt32(0x4D4D_4150)) { data.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt32(0)) { data.append(contentsOf: $0) }

        try data.write(to: URL(fileURLWithPath: path))

        #expect(throws: MMapDictionaryError.self) {
            _ = try MMapDictionary(path: path)
        }
    }

    // MARK: - Integration Tests

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func dictionaryPersistsDataCorrectly(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        // Create and write dictionary
        var builder = MMapDictionary.Builder()
        builder.insert(key: "persistent", value: [99, 88, 77])
        try builder.write(to: path, offsetType: offsetType)

        // Open it multiple times
        for _ in 0..<3 {
            let dict = try MMapDictionary(path: path)
            let result = try dict["persistent"]
            #expect(result == [99, 88, 77])
        }
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func dictionaryHandlesManyEntriesEfficiently(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        let entryCount = 1000

        // Insert many entries
        for i in 0..<entryCount {
            let key = "key_\(i)"
            let value = Array(String(i).utf8)
            builder.insert(key: key, value: value)
        }

        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)

        // Verify random sampling of entries
        let samplesToCheck = [0, 100, 500, 999]
        for i in samplesToCheck {
            let key = "key_\(i)"
            let expected = Array(String(i).utf8)
            let result = try dict[key]
            #expect(result == expected)
        }
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func lookupArrayCreatesIndependentCopy(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "test", value: [1, 2, 3, 4, 5])
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)

        // Get the array
        var result1 = try dict["test"]
        let result2 = try dict["test"]

        // Modify first array
        result1?[0] = 99

        // Second array should be unchanged
        #expect(result1 == [99, 2, 3, 4, 5])
        #expect(result2 == [1, 2, 3, 4, 5])
    }

    // MARK: - Performance Characteristics Tests

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func dictionaryLoadFactorAffectsFileSize(offsetType: MMapDictionary.OffsetType) throws {
        var builder = MMapDictionary.Builder()
        for i in 0..<10 {
            builder.insert(key: "key\(i)", value: [UInt8(i)])
        }

        let dataSparse = try builder.build(offsetType: offsetType, loadFactor: 0.25) // Low load factor = more buckets
        let dataDense = try builder.build(offsetType: offsetType, loadFactor: 0.9) // High load factor = fewer buckets

        // Sparse should be larger due to more buckets
        #expect(dataSparse.count > dataDense.count)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func emptyKeyIsValid(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "", value: [42])
        try builder.write(to: path, offsetType: offsetType)

        let dict = try MMapDictionary(path: path)
        let result = try dict[""]

        #expect(result == [42])
    }
}

// MARK: - Fuzzing Tests

struct MMapDictionaryFuzzingTests {
    /// Generates random bytes of varying length
    private func randomBytes(maxLength: Int = 1000) -> [UInt8] {
        let length = Int.random(in: 0...maxLength)
        return (0..<length).map { _ in UInt8.random(in: 0...255) }
    }

    /// Helper to build, write, and verify a set of key-value pairs
    private func verifyDictionary(
        _ entries: [String: [UInt8]],
        offsetType: MMapDictionary.OffsetType = .uint32,
        loadFactor: Double? = nil,
        file _: StaticString = #file,
        line _: UInt = #line) throws
    {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        for (key, value) in entries {
            builder.insert(key: key, value: value)
        }

        if let loadFactor {
            try builder.write(to: path, offsetType: offsetType, loadFactor: loadFactor)
        } else {
            try builder.write(to: path, offsetType: offsetType)
        }
        let dict = try MMapDictionary(path: path)

        for (key, expectedValue) in entries {
            let result = try dict[key]
            #expect(result == expectedValue, "Mismatch for key: \(key)")
        }
    }

    @Test(
        arguments: MMapDictionary.OffsetType.allCases,
        [0.25, 0.5])
    func fuzzTestWithExtremeSizes(offsetType: MMapDictionary.OffsetType, _: Double) throws {
        var entries: [String: [UInt8]] = [:]

        // Extreme key lengths
        for length in [0, 1, 10, 100, 1000, 10000, 50000] {
            let key = String(repeating: "x", count: length)
            entries[key] = randomBytes(maxLength: 100)
        }

        // Extreme value lengths
        for (index, length) in [0, 1, 10, 100, 1000, 10000, 100_000].enumerated() {
            entries["val_\(index)"] = Array(repeating: UInt8(index % 256), count: length)
        }

        try verifyDictionary(entries, offsetType: offsetType)
    }

    @Test(
        arguments: MMapDictionary.OffsetType.allCases,
        [0.25, 0.5, 0.75, 0.9, 1.0])
    func fuzzTestWithVaryingLoadFactors(offsetType: MMapDictionary.OffsetType, loadFactor: Double) throws {
        var entries: [String: [UInt8]] = [:]
        for i in 0..<100 {
            entries["key_\(i)"] = [UInt8(i % 256)]
        }

        try verifyDictionary(entries, offsetType: offsetType, loadFactor: loadFactor)
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func fuzzTestWithDuplicateKeysReturnsFirstValue(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()

        // Insert same key multiple times
        let firstValue: [UInt8] = [1, 2, 3, 4, 5]
        builder.insert(key: "duplicate", value: firstValue)

        for _ in 0..<10 {
            builder.insert(key: "duplicate", value: randomBytes(maxLength: 100))
        }

        try builder.write(to: path, offsetType: offsetType)
        let dict = try MMapDictionary(path: path)

        // With linear probing, should always return the first value inserted
        let result = try dict["duplicate"]
        #expect(result == firstValue, "Linear probing should return the first inserted value for duplicate keys")
    }
}

struct MMapDictionaryCorruptionFuzzingTests {
    /// Creates a valid MMap dictionary file for corruption testing
    private func createValidFile(offsetType: MMapDictionary.OffsetType = .uint32) throws -> Data {
        var builder = MMapDictionary.Builder()
        builder.insert(key: "test1", value: [1, 2, 3])
        builder.insert(key: "test2", value: [4, 5, 6])
        builder.insert(key: "test3", value: [7, 8, 9])
        return try builder.build(offsetType: offsetType)
    }

    /// Attempts to load a potentially corrupted file and verifies proper error handling
    /// - Parameters:
    ///   - path: Path to the file to load
    ///   - queryKey: Optional key to query after loading
    /// - Note: This function expects either successful load (with optional query) or proper error handling.
    ///         Accepts both MMapDictionaryError and system errors (e.g., for missing files)
    private func attemptLoad(path: String, queryKey: String = "test") {
        do {
            let dict = try MMapDictionary(path: path)
            _ = try? dict[queryKey]
            // Successfully loaded - acceptable for some edge cases
        } catch {
            #expect(
                error is MMapDictionaryError || error is MemoryMappingError,
                "Unexpected error type: \(type(of: error))")
        }
    }

    // MARK: - Corruption Tests

    @Test(
        arguments: [
            (pattern: "random", sizes: [0, 1, 7, 8, 16, 100, 1000, 10000]),
            (pattern: "zeros", sizes: [0, 8, 16, 100, 1000]),
            (pattern: "ones", sizes: [0, 8, 16, 100, 1000]),
        ])
    func fuzzTestWithInvalidFilePatterns(patternAndSizes: (pattern: String, sizes: [Int])) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        let (pattern, sizes) = patternAndSizes
        for size in sizes {
            let data = switch pattern {
            case "random":
                Data((0..<size).map { _ in UInt8.random(in: 0...255) })
            case "zeros":
                Data(repeating: 0, count: size)
            case "ones":
                Data(repeating: 0xFF, count: size)
            default:
                Data(repeating: 0xAA, count: size)
            }

            try data.write(to: URL(fileURLWithPath: path))
            attemptLoad(path: path)
            cleanup(path: path)
        }
    }

    @Test(arguments: [0xAA, 0x55, 0xCC, 0x33])
    func fuzzTestWithRepeatingBytePatterns(pattern: UInt8) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        for size in [8, 16, 100, 1000] {
            let data = Data(repeating: pattern, count: size)
            try data.write(to: URL(fileURLWithPath: path))
            attemptLoad(path: path)
            cleanup(path: path)
        }
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func fuzzTestWithCorruptedValidFileRegions(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        let validData = try createValidFile(offsetType: offsetType)
        // Test corruption in different file regions
        let regions = [
            (name: "header", range: 0..<min(8, validData.count)),
            (name: "buckets", range: 8..<min(200, validData.count)),
            (name: "entries", range: 100..<validData.count),
        ]

        for region in regions {
            // Corrupt random bytes in this region
            for _ in 0..<10 {
                guard !region.range.isEmpty else { continue }

                var corruptedData = validData
                let position = Int.random(in: region.range)
                corruptedData[position] = UInt8.random(in: 0...255)

                try corruptedData.write(to: URL(fileURLWithPath: path))
                attemptLoad(path: path, queryKey: "test1")
                cleanup(path: path)
            }
        }
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func fuzzTestWithTruncatedFiles(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        let validData = try createValidFile(offsetType: offsetType)

        // Test truncation at key boundaries
        let truncationPoints = [0, 4, 7, 8, 16, validData.count / 2, validData.count - 1]

        for truncateAt in truncationPoints where truncateAt <= validData.count {
            try validData.prefix(truncateAt).write(to: URL(fileURLWithPath: path))
            attemptLoad(path: path, queryKey: "test1")
            cleanup(path: path)
        }
    }

    @Test(arguments: MMapDictionary.OffsetType.allCases)
    func fuzzTestWithRandomBitFlips(offsetType: MMapDictionary.OffsetType) throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        let validData = try createValidFile(offsetType: offsetType)

        // Flip random bits in random positions
        for _ in 0..<20 {
            var corruptedData = validData
            let flipCount = Int.random(in: 1...10)

            for _ in 0..<flipCount {
                let position = Int.random(in: 0..<corruptedData.count)
                let bitPosition = Int.random(in: 0...7)
                corruptedData[position] ^= (1 << bitPosition)
            }

            try corruptedData.write(to: URL(fileURLWithPath: path))
            attemptLoad(path: path, queryKey: "test1")
            cleanup(path: path)
        }
    }

    @Test
    func fuzzTestWithInvalidMetadata() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        struct InvalidFile {
            let name: String
            let data: () throws -> Data
        }

        let invalidFiles: [InvalidFile] = [
            InvalidFile(name: "overflow bucket count") {
                var d = Data()
                withUnsafeBytes(of: UInt32(0x4D4D_4150)) { d.append(contentsOf: $0) }
                withUnsafeBytes(of: UInt32.max) { d.append(contentsOf: $0) }
                return d
            },
            InvalidFile(name: "invalid offsets") {
                var d = Data()
                withUnsafeBytes(of: UInt32(0x4D4D_4150)) { d.append(contentsOf: $0) }
                withUnsafeBytes(of: UInt32(16)) { d.append(contentsOf: $0) }
                for _ in 0..<16 {
                    withUnsafeBytes(of: UInt32(0x1234_5678)) { d.append(contentsOf: $0) }
                    withUnsafeBytes(of: UInt32.random(in: 1000...1_000_000)) { d.append(contentsOf: $0) }
                }
                return d
            },
            InvalidFile(name: "invalid key length") {
                var d = Data()
                withUnsafeBytes(of: UInt32(0x4D4D_4150)) { d.append(contentsOf: $0) }
                withUnsafeBytes(of: UInt32(1)) { d.append(contentsOf: $0) }
                withUnsafeBytes(of: UInt32(0x1234_5678)) { d.append(contentsOf: $0) }
                withUnsafeBytes(of: UInt32(16)) { d.append(contentsOf: $0) }
                withUnsafeBytes(of: UInt32(1_000_000)) { d.append(contentsOf: $0) }
                return d
            },
            InvalidFile(name: "appended garbage") {
                var d = try createValidFile()
                let garbage = Data((0..<Int.random(in: 0...1000)).map { _ in UInt8.random(in: 0...255) })
                d.append(garbage)
                return d
            },
        ]

        for invalidFile in invalidFiles {
            let data = try invalidFile.data()
            try data.write(to: URL(fileURLWithPath: path))
            attemptLoad(path: path)
            cleanup(path: path)
        }
    }
}
