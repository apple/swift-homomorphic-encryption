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
import HomomorphicEncryption // This import is needed for dividingCeil

/// Configuration for a `CuckooTable`.
public struct CuckooTableConfig: Hashable, Codable, Sendable {
    /// Configuration for the number of buckets in a `CuckooTable`.
    public enum BucketCountConfig: Hashable, Codable, Sendable {
        /// Allow increasing the number of buckets.
        ///
        /// The load factor measures what fraction of the cuckoo table's capacity is filled with data, as measured by
        /// serialization size. The target load factor is used to reserve capacity in the cuckoo table at initialization
        /// and expansion as entries are inserted.
        ///
        /// - Parameters:
        ///   - expansionFactor: Multiplicative factor by which to increase the number of buckets during expansion. Must
        /// be > 1.0.
        ///   - targetLoadFactor: Must be in `[0, 1]`.
        case allowExpansion(expansionFactor: Double, targetLoadFactor: Double)
        /// Fixed number of buckets.
        ///
        /// Useful to ensure different databases result in the same PIR configuration.
        case fixedSize(bucketCount: Int)
    }

    /// Number of hash functions to use.
    public let hashFunctionCount: Int

    /// Maximum number of evictions when inserting a new entry.
    public let maxEvictionCount: Int

    /// Maximum number of bytes in a serialized bucket.
    public let maxSerializedBucketSize: Int

    /// Number of buckets.
    public let bucketCount: BucketCountConfig

    /// Whether to enable multiple tables setting.
    ///
    /// If enabled, this setting will store only entries using the same hash function, into the same bucket.
    /// This can help improve PIR runtime.
    public let multipleTables: Bool

    /// Maximum number of slots in a bucket.
    public let slotCount: Int

    /// Initializes a ``CuckooTableConfig``.
    /// - Parameters:
    ///   - hashFunctionCount: Number of hash functions.
    ///   - maxEvictionCount: Maximum number of evictions when inserting a new entry.
    ///   - maxSerializedBucketSize: Maximum number of bytes in a serialized bucket.
    ///   - bucketCount: Number of buckets.
    ///   - multipleTables: Whether to enable multiple tables setting.
    ///   - slotCount: How many entries can fit in a bucket.
    /// - Throws: Error upon invalid configuration arguments.
    public init(
        hashFunctionCount: Int,
        maxEvictionCount: Int,
        maxSerializedBucketSize: Int,
        bucketCount: BucketCountConfig,
        multipleTables: Bool = true,
        slotCount: Int = HashBucket.maxSlotCount) throws
    {
        self.hashFunctionCount = hashFunctionCount
        self.maxEvictionCount = maxEvictionCount
        self.maxSerializedBucketSize = maxSerializedBucketSize
        self.bucketCount = bucketCount
        self.multipleTables = multipleTables
        self.slotCount = slotCount
        try validate()
    }

    /// Default configuration for KeywordPir queries.
    ///
    /// The configuration is valid for cuckoo buckets with serialization size at most `maxSerializedBucketSize`.
    /// - Parameter maxSerializedBucketSize: Maximum number of bytes in a serialized bucket.
    /// - Returns: A default configuration for KeywordPir queries.
    public static func defaultKeywordPir(maxSerializedBucketSize: Int) -> Self {
        // default shouldn't throw
        // swiftlint:disable:next force_try
        try! Self(
            hashFunctionCount: 2,
            maxEvictionCount: 100,
            maxSerializedBucketSize: maxSerializedBucketSize,
            bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.9))
    }

    /// Converts the configuration into one with a fixed bucket count.
    /// - Parameters:
    ///   - maxSerializedBucketSize: Maximum number of evictions when inserting a new entry.
    ///   - bucketCount: Number of buckets in the new configuration.
    /// - Returns: The new configuration.
    /// - Throws: Error upon failure to convert the configuration.
    func freezingTableSize(maxSerializedBucketSize: Int, bucketCount: Int) throws -> Self {
        try .init(
            hashFunctionCount: hashFunctionCount,
            maxEvictionCount: maxEvictionCount,
            maxSerializedBucketSize: maxSerializedBucketSize,
            bucketCount: .fixedSize(bucketCount: bucketCount),
            multipleTables: multipleTables)
    }

    /// Validates the configuration is valid.
    /// - Throws: Error upon invalid configuration.
    func validate() throws {
        guard hashFunctionCount > 0,
              maxSerializedBucketSize >= HashBucket.serializedSize(singleValueSize: 0),
              slotCount > 0,
              slotCount <= HashBucket.maxSlotCount
        else {
            throw PirError.invalidCuckooConfig(config: self)
        }
        switch bucketCount {
        case let .allowExpansion(expansionFactor: expansionFactor, targetLoadFactor: targetLoadFactor):
            guard expansionFactor > 1.0, targetLoadFactor < 1.0 else {
                throw PirError.invalidCuckooConfig(config: self)
            }
        case let .fixedSize(bucketCount: bucketCount):
            guard maxSerializedBucketSize > 0, bucketCount > 0 else {
                throw PirError.invalidCuckooConfig(config: self)
            }
        }
    }
}

@usableFromInline
struct CuckooBucketEntry {
    @usableFromInline let keywordValuePair: KeywordValuePair

    @usableFromInline var keyword: KeywordValuePair.Keyword { keywordValuePair.keyword }
    var value: KeywordValuePair.Value { keywordValuePair.value }

    @inlinable
    init(keywordValuePair: KeywordValuePair) {
        self.keywordValuePair = keywordValuePair
    }
}

@usableFromInline
struct CuckooBucket {
    @usableFromInline var slots: [CuckooBucketEntry]

    @usableFromInline var values: [KeywordValuePair.Value] {
        slots.map(\.value)
    }

    @inlinable
    init(slots: [CuckooBucketEntry] = []) {
        self.slots = slots
    }

    @inlinable
    func serializedSize() throws -> Int {
        try HashBucket(from: self).serializedSize()
    }

    /// Returns the serialized representation of the bucket.
    @inlinable
    func serialize() throws -> [UInt8] {
        try HashBucket(from: self).serialize()
    }

    @inlinable
    func canInsert(value: KeywordValuePair.Value, with config: CuckooTableConfig) -> Bool {
        let hasSlots = slots.count < config.slotCount
        return hasSlots && HashBucket.serializedSize(values: values + [value]) <= config.maxSerializedBucketSize
    }

    /// Returns the indices at which `newValue` can be swapped.
    @inlinable
    func swapIndices(newValue: KeywordValuePair.Value, with config: CuckooTableConfig) -> [Int] {
        let currentValues = values
        // Loop over prefixes that include `newValue` but omit a single existing value
        let concatenated = currentValues + [newValue] + currentValues
        return (0..<values.count).filter { swapIndex in
            let prefix = concatenated[(swapIndex + 1)..<(swapIndex + 1 + values.count)]
            return HashBucket.serializedSize(values: prefix) <= config.maxSerializedBucketSize
        }
    }
}

extension CuckooBucket: RangeReplaceableCollection {
    @usableFromInline typealias Index = Int
    @usableFromInline typealias Element = CuckooBucketEntry

    @usableFromInline var startIndex: Index { slots.startIndex }
    @usableFromInline var endIndex: Index { slots.endIndex }

    @inlinable
    init() {
        self.init(slots: [])
    }

    @inlinable
    func index(after i: Index) -> Index {
        slots.index(after: i)
    }

    @inlinable
    mutating func replaceSubrange(_ subrange: Range<Self.Index>, with newElements: some Collection<CuckooBucketEntry>) {
        slots.replaceSubrange(subrange, with: newElements)
    }

    @inlinable
    subscript(index: Index) -> Iterator.Element {
        get { slots[index] }
        set { slots[index] = newValue }
    }
}

/// A Cuckoo table is a data structure that stores a set of keyword-value pairs, using cuckoo hashing to resolve
/// conflicts.
@usableFromInline
struct CuckooTable {
    typealias KeywordHash = UInt64
    struct CuckooTableInformation: Equatable {
        let entryCount: Int
        let bucketCount: Int
        let emptyBucketCount: Int
        let loadFactor: Float
    }

    @usableFromInline
    struct EvictIndex {
        @usableFromInline let bucketIndex: Int
        @usableFromInline let evictIndexInBucket: Int

        @inlinable
        init(bucketIndex: Int, evictIndexInBucket: Int) {
            self.bucketIndex = bucketIndex
            self.evictIndexInBucket = evictIndexInBucket
        }
    }

    @usableFromInline let config: CuckooTableConfig
    @usableFromInline var buckets: [CuckooBucket]
    @usableFromInline var rng: RandomNumberGenerator

    @usableFromInline var entryCount: Int {
        buckets.map(\.count).sum()
    }

    @usableFromInline var bucketsPerTable: Int { buckets.count / tableCount }
    @usableFromInline var tableCount: Int { config.multipleTables ? config.hashFunctionCount : 1 }

    init(
        config: CuckooTableConfig,
        database: some Collection<(KeywordValuePair.Keyword, KeywordValuePair.Value)>,
        using rng: RandomNumberGenerator = SystemRandomNumberGenerator()) throws
    {
        try self.init(
            config: config,
            database: database.map { keyword, value in KeywordValuePair(keyword: keyword, value: value) },
            using: rng)
    }

    @inlinable
    init(
        config: CuckooTableConfig,
        database: some Collection<KeywordValuePair>,
        using rng: RandomNumberGenerator = SystemRandomNumberGenerator()) throws
    {
        self.config = config
        let targetBucketCount: Int
        self.buckets = []
        self.rng = rng
        switch config.bucketCount {
        case let .allowExpansion(_, targetLoadFactor: targetLoadFactor):
            let minDatabaseSerializedSize: Int = HashBucket.serializedSize(values: database.map { pair in pair.value })
            let minBucketCount = minDatabaseSerializedSize.dividingCeil(
                config.maxSerializedBucketSize, variableTime: true)
            targetBucketCount = Int(ceil(Double(minBucketCount) / targetLoadFactor)).nextMultiple(
                of: tableCount,
                variableTime: true)
        case let .fixedSize(bucketCount: bucketCount):
            targetBucketCount = bucketCount.nextMultiple(of: tableCount, variableTime: true)
        }
        self.buckets = Array(repeating: CuckooBucket(), count: targetBucketCount)

        for keywordValuePair in database {
            try insert(keywordValuePair)
        }
    }

    func summarize() throws -> CuckooTableInformation {
        let bucketEntryCounts = buckets.map(\.count)
        let emptyBucketCount: Int = bucketEntryCounts.map { entryCount in entryCount == 0 ? 1 : 0 }.sum()
        let entryCount: Int = bucketEntryCounts.sum()

        let serializedSize: Int = try buckets.map { try $0.serializedSize() }.sum()
        let loadFactor = Float(serializedSize) / Float(buckets.count * config.maxSerializedBucketSize)
        return CuckooTableInformation(
            entryCount: entryCount,
            bucketCount: buckets.count,
            emptyBucketCount: emptyBucketCount,
            loadFactor: loadFactor)
    }

    @inlinable
    func serializeBuckets() throws -> [[UInt8]] {
        try buckets.map { bucket in try bucket.serialize() }
    }

    /// Returns the serialization size in bytes of the largest bucket.
    func maxSerializedBucketSize() throws -> Int {
        try buckets.map { bucket in try bucket.serializedSize() }.max() ?? 0
    }

    @inlinable
    mutating func insert(_ keywordValuePair: KeywordValuePair) throws {
        guard HashBucket.serializedSize(singleValueSize: keywordValuePair.value.count) <= config
            .maxSerializedBucketSize
        else {
            throw PirError.failedToConstructCuckooTable(
                """
                Unable to insert value with keyword \(keywordValuePair.keyword) \
                (\(keywordValuePair.value.count) byte value), \
                because the resulting hashbucket would be larger than 'maxSerializedBucketSize'.
                """)
        }
        try insertLoop(keywordValuePair: keywordValuePair, remainingEvictionCount: config.maxEvictionCount)
    }

    @inlinable
    mutating func insertLoop(keywordValuePair: KeywordValuePair, remainingEvictionCount: Int) throws {
        if remainingEvictionCount == 0 {
            switch config.bucketCount {
            case .allowExpansion:
                try expand()
                try insert(keywordValuePair)
            default:
                throw PirError
                    .failedToConstructCuckooTable(
                        """
                        Unable to insert value with keyword \(keywordValuePair.keyword) \
                        into table with \(entryCount) entries. \
                        Consider enabling table expansion in config.
                        """)
            }
        }
        let keywordHashIndices = HashKeyword.hashIndices(
            keyword: keywordValuePair.keyword,
            bucketCount: bucketsPerTable,
            hashFunctionCount: config.hashFunctionCount).enumerated()

        // return if the keyword already exists
        for (tableIndex, hashIndex) in keywordHashIndices
            where buckets[index(tableIndex: tableIndex, index: hashIndex)]
            .contains(where: { existingPair in existingPair.keyword == keywordValuePair.keyword })
        {
            return
        }

        let cuckooBucketEntry = CuckooBucketEntry(keywordValuePair: keywordValuePair)
        // try to insert if there is an empty slot
        for (tableIndex, hashIndex) in keywordHashIndices
            where buckets[index(tableIndex: tableIndex, index: hashIndex)].canInsert(
                value: keywordValuePair.value,
                with: config)
        {
            buckets[index(tableIndex: tableIndex, index: hashIndex)].append(cuckooBucketEntry)
            return
        }

        // try to evict if it's full
        let evictIndices = keywordHashIndices.flatMap { tableIndex, bucketIndex in
            let actualIndex = index(tableIndex: tableIndex, index: bucketIndex)
            return buckets[actualIndex].swapIndices(newValue: keywordValuePair.value, with: config)
                .map { evictIndexInBucket in
                    EvictIndex(bucketIndex: actualIndex, evictIndexInBucket: evictIndexInBucket)
                }
        }
        if let evictIndex = evictIndices.randomElement(using: &rng) {
            let evictedKeywordValuePair = buckets[evictIndex.bucketIndex][evictIndex.evictIndexInBucket]
            buckets[evictIndex.bucketIndex][evictIndex.evictIndexInBucket] = cuckooBucketEntry
            try insertLoop(
                keywordValuePair: evictedKeywordValuePair.keywordValuePair,
                remainingEvictionCount: remainingEvictionCount - 1)
        } else {
            try expand()
        }
    }

    @inlinable
    func index(tableIndex: Int, index: Int) -> Int {
        tableCount == 1 ? index : tableIndex * bucketsPerTable + index
    }

    @inlinable
    mutating func expand() throws {
        switch config.bucketCount {
        case let .allowExpansion(expansionFactor: expansionFactor, _):
            let oldTable = buckets
            let bucketCount = Int(ceil(Double(buckets.count) * expansionFactor)).nextMultiple(
                of: tableCount,
                variableTime: true)
            buckets = Array(repeating: CuckooBucket(), count: bucketCount)
            for bucket in oldTable {
                for entry in bucket {
                    do {
                        try insert(entry.keywordValuePair)
                    } catch {
                        throw PirError.failedToConstructCuckooTable("Expanding Cuckoo table failed")
                    }
                }
            }
        default:
            throw PirError
                .failedToConstructCuckooTable(
                    "Needed to expand a Cuckoo table that doesn't allow expansion")
        }
    }

    subscript(_ keyword: KeywordValuePair.Keyword) -> KeywordValuePair.Value? {
        let keywordHashIndices = HashKeyword.hashIndices(
            keyword: keyword,
            bucketCount: bucketsPerTable,
            hashFunctionCount: config.hashFunctionCount).enumerated()
        for (tableIndex, hashIndex) in keywordHashIndices {
            let bucket = buckets[index(tableIndex: tableIndex, index: hashIndex)]
            for entry in bucket.slots where entry.keyword == keyword {
                return entry.value
            }
        }
        return nil
    }
}
