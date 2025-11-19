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

public import Crypto
public import Foundation

/// Bucket storing a list of (hash(keyword), value) pairs.
public struct HashBucket: Equatable {
    /// Keyword hash is a UInt64.
    @usableFromInline typealias KeywordHash = UInt64
    @usableFromInline typealias HashBucketValue = [UInt8]

    /// One entry in the HashBucket.
    @usableFromInline
    struct HashBucketEntry: Equatable {
        /// Maximum size of the value.
        @usableFromInline static var maxValueSize: Int {
            // Constrained by serialization.
            Int(UInt16.max)
        }

        /// Hash of the keyword.
        @usableFromInline let keywordHash: KeywordHash
        /// Value.
        @usableFromInline let value: HashBucketValue

        @inlinable
        init(keywordHash: KeywordHash, value: HashBucketValue) {
            self.keywordHash = keywordHash
            self.value = value
        }

        /// Deserialize one HashBucketEntry.
        /// - Parameters:
        ///   - buffer: The raw buffer from where to deserialize the entry.
        ///   - offset: The offset in the buffer where the entry should start from. After successful deserialization,
        /// the offset will be updated to the next entry.
        /// - Throws: Error upon invalid buffer.
        init(deserialize buffer: UnsafeRawBufferPointer, offset: inout Int) throws {
            guard buffer.count >= offset + MemoryLayout<KeywordHash>.size + MemoryLayout<UInt16>.size else {
                throw PirError
                    .corruptedData(
                        "Serialized HashBucketEntry should at least have a keyword hash and a value size.")
            }
            self.keywordHash = buffer.loadUnaligned(fromByteOffset: offset, as: KeywordHash.self)
            offset += MemoryLayout<KeywordHash>.size
            let valueSize = Int(buffer.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
            offset += MemoryLayout<UInt16>.size
            var value = [UInt8](repeating: 0, count: valueSize)
            guard offset + valueSize <= buffer.count,
                  buffer[offset..<offset + valueSize].count == valueSize
            else {
                // invalid format
                throw PirError.corruptedData("HashBucketEntry buffer has less data than expected")
            }
            value.withUnsafeMutableBytes { valueBuffer in
                valueBuffer.copyBytes(from: buffer[offset..<offset + valueSize])
            }
            offset += valueSize
            self.value = value
        }

        /// Returns the number of bytes in a serialized ``HashBucket`` with `value`.
        @inlinable
        static func serializedSize(value: HashBucketValue) -> Int {
            serializedSize(valueSize: value.count)
        }

        @inlinable
        static func serializedSize(valueSize: Int) -> Int {
            var size = MemoryLayout<KeywordHash>.size
            size += MemoryLayout<UInt16>.size // size of value in bytes
            size += valueSize // value itself
            return size
        }

        @inlinable
        func serialize() throws -> [UInt8] {
            guard value.count <= Self.maxValueSize else {
                throw PirError.invalidHashBucketEntryValueSize(maxSize: Int(UInt16.max))
            }
            var data = withUnsafeBytes(of: keywordHash) { [UInt8]($0) }
            data.reserveCapacity(MemoryLayout<UInt16>.size + value.count)
            let valueSizeBytes = UInt16(value.count)
            withUnsafeBytes(of: valueSizeBytes) { buffer in
                data.append(contentsOf: buffer)
            }

            data += value
            return data
        }
    }

    /// Maximum number of slots in a bucket.
    ///
    /// Restricted by the UInt8 type that is used to serialize the slot count.
    @usableFromInline static let maxSlotCount: Int = .init(UInt8.max)

    /// Entries in the bucket.
    @usableFromInline let slots: [HashBucketEntry]

    /// Deserializes a HashBucket.
    /// - Parameter rawBucket: Serialized ``HashBucket`` buffer.
    /// - Throws: Error upon invalid buffer.
    init(deserialize rawBucket: [UInt8]) throws {
        guard !rawBucket.isEmpty else {
            throw PirError.corruptedData("Serialized HashBucket shouldn't be empty.")
        }
        var entries: [HashBucketEntry] = []
        try rawBucket.withUnsafeBytes { buffer in
            let count = buffer.load(as: UInt8.self)
            entries.reserveCapacity(Int(count))
            var offset = 1
            for _ in 0..<count {
                try entries.append(HashBucketEntry(deserialize: buffer, offset: &offset))
            }
        }

        self.slots = entries
    }

    init(slots: [HashBucketEntry]) {
        self.slots = slots
    }

    @inlinable
    init(from cuckooBucket: CuckooBucket) throws {
        try self.init(slots: cuckooBucket.map(\.keywordValuePair))
    }

    @inlinable
    init(slots: [KeywordValuePair]) throws {
        guard slots.count <= Self.maxSlotCount else {
            throw PirError.invalidHashBucketSlotCount(maxCount: Self.maxSlotCount)
        }
        self.slots = slots.map { kvPair in
            HashBucketEntry(keywordHash: HashKeyword.hash(keyword: kvPair.keyword), value: kvPair.value)
        }
    }

    @inlinable
    static func serializedSize(values: some Collection<HashBucketValue>) -> Int {
        var size = MemoryLayout<UInt8>.size // slot count
        for value in values {
            size += HashBucketEntry.serializedSize(value: value)
        }
        return size
    }

    /// Computes the size of a ``HashBucket`` with a single keyword-value pair.
    /// - Parameter singleValueSize: Number of bytes in the value.
    /// - Returns: The number of bytes in the serialized ``HashBucket``.
    @inlinable
    package static func serializedSize(singleValueSize: Int) -> Int {
        MemoryLayout<UInt8>.size + HashBucketEntry.serializedSize(valueSize: singleValueSize)
    }

    @inlinable
    func serializedSize() -> Int {
        Self.serializedSize(values: slots.map(\.value))
    }

    @inlinable
    func serialize() throws -> [UInt8] {
        guard slots.count <= Self.maxSlotCount else {
            throw PirError
                .invalidHashBucketSlotCount(maxCount: Self.maxSlotCount)
        }
        var data = [UInt8(slots.count)]
        for slot in slots {
            data += try slot.serialize()
        }
        return data
    }

    /// Look up a value associated with a keyword.
    /// - Parameter keyword: The keyword to look for.
    /// - Returns: The value associated with the `keyword`, or `nil` if the keyword is not in the ``HashBucket``.
    func find(keyword: [UInt8]) -> [UInt8]? {
        let hash = HashKeyword.hash(keyword: keyword)
        return find(hash: hash)
    }

    /// Look up a value associated with a keyword.
    /// - Parameter hash: The hash of the keyword to look for.
    /// - Returns: The value associated with the `keyword`, or `nil` if the keyword is not in the ``HashBucket``.
    func find(hash: KeywordHash) -> [UInt8]? {
        for item in slots where item.keywordHash == hash {
            return item.value
        }
        return nil
    }
}

@usableFromInline
enum HashKeyword {
    /// Keyword hash is a UInt64.
    @usableFromInline typealias KeywordHash = UInt64
    @usableFromInline static let maxRetries = 10

    /// Computes unique indices that a keyword hashes to.
    /// - Parameters:
    ///   - keyword: The keyword to hash.
    ///   - bucketCount: Number of buckets.
    ///   - hashFunctionCount: number of candidate indices to produce.
    /// - Returns: An array of indices, which are the possible locations for the `keyword` in a cuckoo hash table.
    @inlinable
    static func hashIndices(keyword: [UInt8], bucketCount: Int, hashFunctionCount: Int) -> [Int] {
        let keywordHash = hash(keyword: keyword)
        var candidates: [Int] = []
        for _ in 0..<hashFunctionCount {
            var counter = UInt8(0)
            var bucketIndex = indexFromHash(keywordHash: keywordHash, bucketCount: bucketCount, counter: counter)
            while candidates.contains(bucketIndex), counter < maxRetries {
                counter += 1
                bucketIndex = indexFromHash(keywordHash: keywordHash, bucketCount: bucketCount, counter: counter)
            }
            candidates.append(bucketIndex)
        }

        return candidates
    }

    /// Convert a hash to a index into a bucket.
    /// - Parameters:
    ///   - keywordHash: the hash of the keyword.
    ///   - bucketCount: number of buckets.
    ///   - counter: additional counter to randomize the output.
    /// - Returns: a pseudorandom index in range `0..<bucketCount`.
    @inlinable
    static func indexFromHash(keywordHash: KeywordHash, bucketCount: Int, counter: UInt8) -> Int {
        var hasher = SHA256()
        let bigEndian = keywordHash.bigEndian
        withUnsafeBytes(of: bigEndian) { buffer in
            hasher.update(bufferPointer: buffer)
        }
        hasher.update(data: [counter])
        let digest = hasher.finalize()
        let hash = digest.withUnsafeBytes { buffer in
            buffer.load(as: UInt64.self)
        }

        return Int(hash % UInt64(bucketCount))
    }

    /// Compute the hash of a keyword.
    /// - Parameter keyword: The keyword to hash.
    /// - Returns: The hash of the keyword: SHA256(keyword) truncated to the first 8 bytes and interpreted as a little
    /// endian UInt64.
    @inlinable
    static func hash(keyword: [UInt8]) -> KeywordHash {
        let digest = SHA256.hash(data: keyword)
        return digest.withUnsafeBytes { buffer in
            buffer.load(as: UInt64.self)
        }
    }
}
