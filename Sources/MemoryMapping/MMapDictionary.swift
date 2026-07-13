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

public import Foundation

/// A memory-mapped dictionary that provides zero-copy, zero-deserialization access to key-value data.
///
/// `MMapDictionary` is designed for efficient read-only access to large datasets without loading
/// them entirely into memory. Once built, the dictionary file can be memory-mapped and queried
/// with minimal overhead.
///
/// ## Features
/// - **Zero-copy access**: Values are accessed directly from the memory-mapped file using `RawSpan`
/// - **Zero deserialization**: No parsing or decoding required when opening the file
/// - **Efficient lookups**: Uses FNV-1a hash function with linear probing for collision resolution
/// - **Type-safe**: Keys are byte arrays, values are byte arrays
/// - **Safe memory access**: Uses `RawSpan` for bounds-checked access without manual pointer management
///
/// ## Usage
/// ```swift
/// // Building a dictionary
/// var builder = MMapDictionary.Builder()
/// builder.insert(key: "name", value: [72, 101, 108, 108, 111]) // "Hello"
/// builder.insert(key: "count", value: [0, 0, 0, 42])
/// try builder.write(to: "/path/to/file.mmap")
///
/// // Reading from the dictionary
/// let dict = try MMapDictionary(path: "/path/to/file.mmap")
/// let value = try dict.withValue(forKey: "name") { span in
///     // Process the span without copying
///     return String(decoding: span.withUnsafeBytes { $0 }, as: UTF8.self)
/// }
/// ```
///
/// ## File Format
/// The dictionary uses a compact binary format optimized for memory mapping:
///
/// **Header (8 bytes):**
/// - Magic number: 4 bytes (0x4D4D4150 - "MMAP" for UInt32 offsets, or 0x4D4D4151 - "MMAQ" for UInt64 offsets)
/// - Bucket count: 4 bytes (UInt32)
///
/// **Hash Buckets (variable size × bucket count):**
/// - Hash prefix: 4 bytes (UInt32) - Lower 32 bits of the key's hash
/// - Offset: 4 or 8 bytes (UInt32 or UInt64) - Byte offset to the key/value entry (0 if empty)
///   - UInt32 offsets (8 bytes per bucket): Used when total file size < 4GB
///   - UInt64 offsets (12 bytes per bucket): Used when total file size ≥ 4GB
///
/// **Key/Value Entries (variable size):**
/// - Key length: 4 bytes (UInt32)
/// - Key data: variable (UTF-8 encoded bytes)
/// - Value length: 4 bytes (UInt32)
/// - Value data: variable (raw bytes)
///
/// ## Performance Characteristics
/// - **Lookup**: O(1) average, O(n) worst case with hash collisions
/// - **Memory**: Only the accessed pages are loaded into RAM (OS managed)
/// - **Load factor**: Default ~0.75 (configurable during build)
/// - **Hash collisions**: Handled via linear probing
///
/// ## Thread Safety
/// `MMapDictionary` is safe for concurrent reads from multiple threads.
/// The underlying memory-mapped buffer is read-only after initialization.
///
/// ## See Also
/// - ``Builder``: For creating new memory-mapped dictionaries
/// - ``withValue(forKey:_:)``: For zero-copy value access
/// - ``lookupArray(key:)``: For convenience when copying values
public final class MMapDictionary: @unchecked Sendable {
    public typealias HashPrefix = UInt32

    enum OffsetType: CaseIterable {
        case uint32
        case uint64

        var magicNumber: UInt32 {
            switch self {
            case .uint32: 0x4D4D_4150 // "MMAP"
            case .uint64: 0x4D4D_4151 // "MMAQ" (MMAP + 1)
            }
        }

        var offsetSize: Int {
            switch self {
            case .uint32: MemoryLayout<UInt32>.size
            case .uint64: MemoryLayout<UInt64>.size
            }
        }
    }

    /// Size of the file header in bytes (magic number + bucket count).
    public static let headerSize = MemoryLayout<UInt32>.size + MemoryLayout<UInt32>.size // magic + bucket count

    /// The default load factor to use if not specified during initialization.
    public static let defaultLoadFactor: Double = 0.75

    /// Buffer that holds the underlying memory. Note: the memory is never mutated.
    private let buffer: UnsafeMutableRawBufferPointer

    /// Offset type
    let offsetType: OffsetType

    /// The total number of buckets in the hash table (both empty and occupied).
    public let bucketCount: Int

    /// Size of each bucket entry in bytes (hash prefix + offset).
    var bucketEntrySize: Int {
        Self.bucketEntrySize(offsetType: offsetType)
    }

    /// The total size of the memory-mapped file in bytes.
    public var fileSize: Int {
        buffer.count
    }

    /// The size of the bucket table in bytes.
    public var bucketsSize: Int {
        bucketCount * bucketEntrySize
    }

    /// The size of the key-value data in bytes.
    public var keysAndValuesSize: Int {
        fileSize - Self.headerSize - bucketsSize
    }

    /// Initialize from memory-mapped file using MemoryMapping.
    /// - Parameter path: The file path to the memory-mapped dictionary file.
    /// - Throws: `MMapDictionaryError` if the file format is invalid or cannot be opened.
    public init(path: String) throws {
        self.buffer = try MemoryMapping.openFile(path: path)

        guard buffer.count >= Self.headerSize else {
            MemoryMapping.unmap(buffer)
            throw MMapDictionaryError.invalidFormat("File too small")
        }

        // Read header using Span
        let headerSpan = RawSpan(_unsafeBytes: buffer)
        let magic = headerSpan.unsafeLoadUnaligned(fromByteOffset: 0, as: UInt32.self)

        let offsetType = OffsetType.allCases.first { type in
            type.magicNumber == magic
        }

        guard let offsetType else {
            MemoryMapping.unmap(buffer)
            throw MMapDictionaryError.invalidFormat("Invalid magic number")
        }

        self.offsetType = offsetType
        self.bucketCount = Int(headerSpan.unsafeLoadUnaligned(
            fromByteOffset: MemoryLayout<UInt32>.size,
            as: UInt32.self))

        guard bucketCount > 0 else {
            MemoryMapping.unmap(buffer)
            throw MMapDictionaryError.invalidFormat("Invalid bucket count")
        }
    }

    static func bucketEntrySize(offsetType: OffsetType) -> Int {
        MemoryLayout<HashPrefix>.size + offsetType.offsetSize
    }

    /// Stable hash function using FNV-1a algorithm.
    /// This hash is deterministic and will produce the same results across executions.
    static func hash(bytes: RawSpan) -> UInt64 {
        // FNV-1a 64-bit hash
        // https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function
        let fnvOffsetBasis: UInt64 = 0xCBF2_9CE4_8422_2325
        let fnvPrime: UInt64 = 0x100_0000_01B3

        var hash = fnvOffsetBasis
        for i in bytes.byteOffsets {
            hash ^= UInt64(bytes.unsafeLoadUnaligned(fromByteOffset: i, as: UInt8.self))
            hash = hash &* fnvPrime
        }
        return hash
    }

    /// Returns the value associated with the given key, or nil if the key is not found.
    /// - Parameters:
    ///   - key: The key to look up.
    ///   - body: The closure to execute with the found RawSpan.
    /// - Returns: The result of the closure, or nil if the key is not found.
    public func withValue<R>(forKey key: RawSpan, _ body: (RawSpan) throws -> R) throws -> R? {
        switch offsetType {
        case .uint32:
            try lookupWithOffset(UInt32.self, key: key, perform: body)
        case .uint64:
            try lookupWithOffset(UInt64.self, key: key, perform: body)
        }
    }

    /// Internal lookup that executes a closure with the found RawSpan.
    /// This method is specialized based on the offset type for maximum performance.
    @inline(__always)
    private func lookupWithOffset<Offset: FixedWidthInteger & BitwiseCopyable, R>(
        _: Offset.Type,
        key: RawSpan,
        perform body: (RawSpan) throws -> R) throws -> R?
    {
        let hash = Self.hash(bytes: key)
        let hashPrefix = UInt32(hash & 0xFFFF_FFFF)
        let initialBucketIndex = Int(hash % UInt64(bucketCount))
        let bucketEntrySize = bucketEntrySize

        // Get span over entire buffer
        let fullSpan = RawSpan(_unsafeBytes: buffer)

        // Linear probing to find the key
        var probe = initialBucketIndex

        repeat {
            // Read bucket entry using Span
            let bucketOffset = Self.headerSize + probe * bucketEntrySize
            guard bucketOffset + bucketEntrySize <= fullSpan.byteCount else {
                throw MMapDictionaryError.corruptedData("Invalid bucket offset")
            }

            // Read directly from the full span at the calculated offset
            let storedHashPrefix = fullSpan.unsafeLoadUnaligned(
                fromByteOffset: bucketOffset,
                as: HashPrefix.self)

            let entryOffsetValue = fullSpan.unsafeLoadUnaligned(
                fromByteOffset: bucketOffset + MemoryLayout<HashPrefix>.size,
                as: Offset.self)

            // Empty bucket - key not found
            if entryOffsetValue == 0 {
                return nil
            }

            // Hash mismatch - continue probing
            if storedHashPrefix != hashPrefix {
                probe = (probe + 1) % bucketCount
                continue
            }

            guard let entryOffset = Int(exactly: entryOffsetValue) else {
                throw MMapDictionaryError.corruptedData("Entry offset value exceeds Int range")
            }

            // Hash matches - verify key
            guard entryOffset + MemoryLayout<UInt32>.size <= fullSpan.byteCount else {
                throw MMapDictionaryError.corruptedData("Invalid entry offset")
            }

            // Read key length
            let keyLength = Int(fullSpan.unsafeLoadUnaligned(
                fromByteOffset: entryOffset,
                as: UInt32.self))

            let keyStart = entryOffset + MemoryLayout<UInt32>.size
            let keyRange = keyStart..<keyStart + keyLength
            guard keyRange.upperBound <= fullSpan.byteCount else {
                throw MMapDictionaryError.corruptedData("Invalid key length")
            }
            let keySpan = fullSpan.extracting(keyRange)

            // Compare keys using memcmp for efficient zero-copy comparison
            let match = keyLength == key.byteCount && (keyLength == 0 || key.withUnsafeBytes { keyBytes in
                keySpan.withUnsafeBytes { candidateKeyBuffer in
                    // force unwrap is safe, because we verified that the length is not zero
                    // swiftlint:disable:next force_unwrapping
                    memcmp(candidateKeyBuffer.baseAddress!, keyBytes.baseAddress!, keyLength) == 0
                }
            })

            // Key matches - read and return value
            if match {
                let valueOffset = keyStart + keyLength

                guard valueOffset + MemoryLayout<UInt32>.size <= fullSpan.byteCount else {
                    throw MMapDictionaryError.corruptedData("Invalid value length position")
                }

                let valueLength = Int(fullSpan.unsafeLoadUnaligned(
                    fromByteOffset: valueOffset,
                    as: UInt32.self))

                let valueStart = valueOffset + MemoryLayout<UInt32>.size
                let valueRange = valueStart..<valueStart + valueLength
                guard valueRange.upperBound <= fullSpan.byteCount else {
                    throw MMapDictionaryError.corruptedData("Invalid value length")
                }

                // Execute the closure with a RawSpan view into the memory-mapped buffer (zero-copy)
                return try body(fullSpan.extracting(valueRange))
            }

            // Hash matches but key doesn't - continue probing
            probe = (probe + 1) % bucketCount
        } while probe != initialBucketIndex

        // Probed all buckets without finding the key
        return nil
    }

    deinit {
        MemoryMapping.unmap(buffer)
    }
}

// MARK: - Builder

extension MMapDictionary {
    /// Builder for creating memory-mapped dictionaries.
    ///
    /// The `Builder` collects key-value pairs and generates the binary format that can be
    /// memory-mapped by `MMapDictionary`. Hash computation and bucket allocation are deferred
    /// until the `build()` method is called for optimal performance.
    ///
    /// ## Usage
    /// ```swift
    /// var builder = MMapDictionary.Builder()
    /// builder.insert(key: "user", value: [1, 2, 3, 4])
    /// builder.insert(key: "session", value: [5, 6, 7, 8])
    ///
    /// // Write directly to a file
    /// try builder.write(to: "/path/to/dict.mmap")
    ///
    /// // Or get the data for further processing
    /// let data = try builder.build()
    /// ```
    ///
    /// ## Performance
    /// - `insert()` is O(1) - just appends to an array
    /// - `build()` is O(n) where n is the number of entries
    /// - Hash computation happens only during `build()`, not during `insert()`
    ///
    /// ## Load Factor
    /// By default, the builder uses a load factor of 0.75 (75% full).
    /// You can adjust this to trade off memory vs. lookup performance:
    /// - **Lower load factor** (0.5): Faster lookups, uses more memory
    /// - **Higher load factor** (0.9): Slower lookups, uses less memory
    ///
    /// ```swift
    /// // Use lower load factor for faster lookups
    /// try builder.build(loadFactor: 0.5)
    /// ```
    public struct Builder {
        private var entries: [(key: [UInt8], value: [UInt8])] = []

        /// Creates a new, empty builder.
        public init() {}

        /// Inserts a key-value pair into the dictionary using raw byte spans.
        ///
        /// This method accepts keys and values as `RawSpan` instances, which allows for
        /// zero-copy insertion when the data is already available as a span. The spans will
        /// be copied into the builder's internal storage.
        ///
        /// Duplicate keys are allowed during insertion, but due to linear probing collision
        /// resolution, only the **first** inserted value for a given key will be retrievable
        /// during lookup. Subsequent insertions with the same key will be stored but unreachable.
        ///
        /// - Parameters:
        ///   - key: The key as a `RawSpan` pointing to raw bytes.
        ///   - value: The value as a `RawSpan` pointing to raw bytes.
        ///
        /// - Complexity: O(1) amortized (due to array append).
        public mutating func insert(key: RawSpan, value: RawSpan) {
            entries.append((key: Array(span: key), value: Array(span: value)))
        }

        /// Inserts a key-value pair into the dictionary.
        ///
        /// This is a convenience method that accepts String keys, which are automatically
        /// converted to UTF-8 byte arrays for storage. Duplicate keys are allowed during
        /// insertion, but due to linear probing collision resolution, only the **first**
        /// inserted value for a given key will be retrievable during lookup. Subsequent
        /// insertions with the same key will be stored but will be unreachable.
        ///
        /// - Parameters:
        ///   - key: The key as a UTF-8 string. Will be converted to bytes for storage.
        ///   - value: The value as a byte array.
        ///
        /// - Complexity: O(1) amortized (array append + UTF-8 conversion).
        public mutating func insert(key: String, value: [UInt8]) {
            entries.append((key: Array(key.utf8), value: value))
        }

        /// Builds the memory-mapped dictionary data.
        ///
        /// This method computes hashes for all keys, allocates buckets, and generates
        /// the binary format. The resulting `Data` can be written to a file and later
        /// memory-mapped with `MMapDictionary(path:)`.
        ///
        /// - Parameter loadFactor: The target load factor (entries / buckets) ranging from 0.0 to 1.0.
        ///   Defaults to 0.75. Lower values use more memory but provide faster lookups.
        ///   Higher values use less memory but may have more hash collisions.
        ///
        /// - Returns: Binary data in the memory-mapped dictionary format.
        ///
        /// - Throws:
        ///   - `MMapDictionaryError.invalidLoadFactor`: If load factor is not in the range (0.0, 1.0].
        ///   - `MMapDictionaryError.tooManyCollisions`: If the bucket table is too small for the entries.
        ///
        /// - Complexity: O(n) where n is the number of entries.
        public func build(loadFactor: Double = MMapDictionary.defaultLoadFactor) throws -> Data {
            let bucketCount = try calculateBucketCount(loadFactor: loadFactor)
            let sizes = calculateSize(UInt32.self, bucketCount: bucketCount)
            let totalSize = MMapDictionary.headerSize + sizes.bucketsSize + sizes.entriesSize
            if totalSize < UInt32.max {
                return try buildWithOffset(UInt32.self, offsetType: .uint32, bucketCount: bucketCount, sizes: sizes)
            }

            return try buildWithOffset(
                UInt64.self,
                offsetType: .uint64,
                bucketCount: bucketCount,
                sizes: calculateSize(UInt64.self, bucketCount: bucketCount))
        }

        func calculateBucketCount(loadFactor: Double) throws -> Int {
            // Validate load factor
            guard loadFactor > 0.0, loadFactor <= 1.0 else {
                throw MMapDictionaryError.invalidLoadFactor("Load factor must be in range (0.0, 1.0]")
            }
            // Calculate bucket count from load factor
            // loadFactor = entries / buckets
            // buckets = entries / loadFactor
            let calculatedBuckets = Int(ceil(Double(entries.count) / loadFactor))
            return max(calculatedBuckets, 16) // there are always at least 16 buckets
        }

        func calculateSize<Offset: FixedWidthInteger>(_: Offset.Type,
                                                      bucketCount: Int) -> (bucketsSize: Int, entriesSize: Int)
        {
            let bucketEntrySize = MemoryLayout<HashPrefix>.size + MemoryLayout<Offset>.size
            let bucketsSize = bucketCount * bucketEntrySize
            let entriesSize = entries.reduce(0) { total, entry in
                total + MemoryLayout<UInt32>.size + entry.key.count + MemoryLayout<UInt32>.size + entry.value
                    .count // keyLen + key + valueLen + value
            }
            return (bucketsSize, entriesSize)
        }

        func buildWithOffset<Offset: FixedWidthInteger>(
            _: Offset.Type,
            offsetType: OffsetType,
            bucketCount: Int,
            sizes: (bucketsSize: Int, entriesSize: Int)) throws -> Data
        {
            // swiftlint:disable:next nesting
            typealias BucketEntry = (hashPrefix: HashPrefix, offset: Offset)
            var buckets = Array(repeating: BucketEntry(hashPrefix: 0, offset: 0),
                                count: bucketCount)

            let bucketsSize = sizes.bucketsSize
            let totalSize = MMapDictionary.headerSize + bucketsSize + sizes.entriesSize
            // Pre-allocate the entire buffer to avoid reallocation and copying
            var result = Data(capacity: totalSize)

            // Write header
            withUnsafeBytes(of: offsetType.magicNumber) { result.append(contentsOf: $0) }
            withUnsafeBytes(of: UInt32(bucketCount)) { result.append(contentsOf: $0) }

            // Calculate entry offsets and populate bucket table
            var currentOffset = headerSize + bucketsSize

            for entry in entries {
                // Compute hash only when building
                let hash = MMapDictionary.hash(bytes: entry.key.span.bytes)
                let hashPrefix = UInt32(hash & 0xFFFF_FFFF)
                let bucketIndex = Int(hash % UInt64(bucketCount))

                // Handle collisions with linear probing
                var probe = bucketIndex
                while buckets[probe].offset != 0 {
                    probe = (probe + 1) % bucketCount

                    // If we've probed all buckets, we need more buckets
                    if probe == bucketIndex {
                        throw MMapDictionaryError.tooManyCollisions("Bucket table is full")
                    }
                }

                buckets[probe] = (hashPrefix: hashPrefix, offset: Offset(currentOffset))
                currentOffset += MemoryLayout<UInt32>.size + entry.key.count + MemoryLayout<UInt32>.size + entry.value
                    .count
            }

            // Write buckets
            for bucket in buckets {
                withUnsafeBytes(of: bucket.hashPrefix) { result.append(contentsOf: $0) }
                withUnsafeBytes(of: bucket.offset) { result.append(contentsOf: $0) }
            }

            // Write entries directly to result buffer (no intermediate Data objects)
            for entry in entries {
                withUnsafeBytes(of: UInt32(entry.key.count)) { result.append(contentsOf: $0) }
                result.append(contentsOf: entry.key)
                withUnsafeBytes(of: UInt32(entry.value.count)) { result.append(contentsOf: $0) }
                result.append(contentsOf: entry.value)
            }

            assert(result.count == totalSize)
            return result
        }

        /// Builds and writes the dictionary to a file URL.
        ///
        /// This is a convenience method that calls `build()` and writes the result atomically.
        ///
        /// - Parameters:
        ///   - url: The file URL to write to.
        ///   - loadFactor: The target load factor (see ``build(loadFactor:)`` for details).
        ///
        /// - Throws:
        ///   - `MMapDictionaryError.invalidLoadFactor`: If load factor is invalid.
        ///   - `MMapDictionaryError.tooManyCollisions`: If the bucket table is too small.
        ///   - File I/O errors from `Data.write(to:options:)`.
        public func write(to url: URL, loadFactor: Double = MMapDictionary.defaultLoadFactor) throws {
            let data = try build(loadFactor: loadFactor)
            try data.write(to: url, options: .atomic)
        }

        /// Builds and writes the dictionary to a file path.
        ///
        /// This is a convenience method that calls `build()` and writes the result atomically.
        ///
        /// - Parameters:
        ///   - path: The file path to write to.
        ///   - loadFactor: The target load factor (see ``build(loadFactor:)`` for details).
        ///
        /// - Throws:
        ///   - `MMapDictionaryError.invalidLoadFactor`: If load factor is invalid.
        ///   - `MMapDictionaryError.tooManyCollisions`: If the bucket table is too small.
        ///   - File I/O errors from `Data.write(to:options:)`.
        public func write(to path: String, loadFactor: Double = MMapDictionary.defaultLoadFactor) throws {
            let data = try build(loadFactor: loadFactor)
            let url = URL(fileURLWithPath: path)
            try data.write(to: url, options: .atomic)
        }
    }
}

// MARK: - Convenience Methods

extension MMapDictionary {
    /// Returns the value associated with the given key, or nil if the key is not found.
    /// - Parameters:
    ///   - key: The key to look up.
    ///   - body: The closure to execute with the found RawSpan.
    /// - Returns: The result of the closure, or nil if the key is not found.
    public func withValue<R>(forKey key: String, _ body: (RawSpan) throws -> R) throws -> R? {
        try withValue(forKey: key.utf8.span.bytes, body)
    }

    /// Returns the value associated with the given key as a byte array, or nil if the key is not found.
    ///
    /// This subscript provides convenient access to dictionary values by copying them into a byte array.
    /// For zero-copy access, use ``withValue(forKey:_:)`` instead.
    ///
    /// - Parameter key: The key to look up, either as a `RawSpan` or `String`.
    /// - Returns: The value as a byte array, or `nil` if the key is not found.
    /// - Throws: `MMapDictionaryError.corruptedData` if the file format is invalid.
    ///
    /// - Complexity: O(1) average, O(n) worst case with hash collisions, plus O(m) for copying
    ///   the value where m is the size of the value in bytes.
    ///
    /// - Note: This method copies the value from the memory-mapped file into a new array.
    ///   For performance-critical code that processes large values, prefer ``withValue(forKey:_:)``
    ///   which provides zero-copy access via `RawSpan`.
    public subscript(key: RawSpan) -> [UInt8]? {
        get throws {
            try withValue(forKey: key) { span in
                Array(span: span)
            }
        }
    }

    /// Returns the value associated with the given key as a byte array, or nil if the key is not found.
    ///
    /// This subscript provides convenient access to dictionary values using a String key.
    /// The key is automatically converted to UTF-8 bytes for lookup. For zero-copy access,
    /// use ``withValue(forKey:_:)`` instead.
    ///
    /// - Parameter key: The key to look up as a UTF-8 string.
    /// - Returns: The value as a byte array, or `nil` if the key is not found.
    /// - Throws: `MMapDictionaryError.corruptedData` if the file format is invalid.
    ///
    /// - Complexity: O(1) average, O(n) worst case with hash collisions, plus O(m) for copying
    ///   the value where m is the size of the value in bytes.
    ///
    /// - Note: This method copies the value from the memory-mapped file into a new array.
    ///   For performance-critical code that processes large values, prefer ``withValue(forKey:_:)``
    ///   which provides zero-copy access via `RawSpan`.
    public subscript(key: String) -> [UInt8]? {
        get throws {
            try self[key.utf8.span.bytes]
        }
    }
}

// MARK: - Introspection Methods

extension MMapDictionary {
    /// Returns the total number of key-value pairs stored in the dictionary.
    ///
    /// This method scans through all buckets to count non-empty entries.
    ///
    /// - Returns: The number of key-value pairs in the dictionary.
    /// - Throws: `MMapDictionaryError.corruptedData` if the file format is invalid.
    /// - Complexity: O(b) where b is the number of buckets.
    public func count() throws -> Int {
        switch offsetType {
        case .uint32:
            try countWithOffset(UInt32.self)
        case .uint64:
            try countWithOffset(UInt64.self)
        }
    }

    @inline(__always)
    private func countWithOffset<Offset: FixedWidthInteger & BitwiseCopyable>(_: Offset.Type) throws -> Int {
        let fullSpan = RawSpan(_unsafeBytes: buffer)
        let bucketEntrySize = bucketEntrySize
        var count = 0

        for bucketIndex in 0..<bucketCount {
            let bucketOffset = Self.headerSize + bucketIndex * bucketEntrySize
            guard bucketOffset + bucketEntrySize <= fullSpan.byteCount else {
                throw MMapDictionaryError.corruptedData("Invalid bucket offset")
            }

            let entryOffset = fullSpan.unsafeLoadUnaligned(
                fromByteOffset: bucketOffset + MemoryLayout<HashPrefix>.size,
                as: Offset.self)

            // Non-zero offset means this bucket contains an entry
            if entryOffset != 0 {
                count += 1
            }
        }

        return count
    }

    /// Returns the longest run of consecutive non-empty buckets.
    ///
    /// This metric indicates the worst-case linear probing distance, which can help
    /// assess hash table performance. A longer run suggests more collisions and
    /// potentially slower lookups.
    ///
    /// - Returns: The length of the longest consecutive sequence of non-empty buckets.
    /// - Throws: `MMapDictionaryError.corruptedData` if the file format is invalid.
    /// - Complexity: O(b) where b is the number of buckets.
    public func longestProbeRun() throws -> Int {
        switch offsetType {
        case .uint32:
            try longestProbeRunWithOffset(UInt32.self)
        case .uint64:
            try longestProbeRunWithOffset(UInt64.self)
        }
    }

    @inline(__always)
    private func longestProbeRunWithOffset<Offset: FixedWidthInteger & BitwiseCopyable>(_: Offset.Type) throws
        -> Int
    {
        let fullSpan = RawSpan(_unsafeBytes: buffer)
        let bucketEntrySize = bucketEntrySize
        var maxRun = 0
        var currentRun = 0

        for bucketIndex in 0..<bucketCount {
            let bucketOffset = Self.headerSize + bucketIndex * bucketEntrySize
            guard bucketOffset + bucketEntrySize <= fullSpan.byteCount else {
                throw MMapDictionaryError.corruptedData("Invalid bucket offset")
            }

            let entryOffset = fullSpan.unsafeLoadUnaligned(
                fromByteOffset: bucketOffset + MemoryLayout<HashPrefix>.size,
                as: Offset.self)

            if entryOffset != 0 {
                currentRun += 1
                maxRun = max(maxRun, currentRun)
            } else {
                currentRun = 0
            }
        }

        return maxRun
    }

    /// Returns keys in the dictionary in insertion order.
    ///
    /// This method iterates through the key-value entries sequentially as they appear
    /// in the file, which corresponds to the order they were inserted during building.
    ///
    /// - Parameter count: The maximum number of keys to return. Pass nil to return all keys.
    /// - Returns: An array of keys as byte arrays in insertion order.
    /// - Throws: `MMapDictionaryError.corruptedData` if the file format is invalid.
    /// - Complexity: O(n) where n is the number of entries (or count, if specified).
    public func keys(count: Int? = nil) throws -> [[UInt8]] {
        let fullSpan = RawSpan(_unsafeBytes: buffer)
        let bucketEntrySize = bucketEntrySize
        var keys: [[UInt8]] = []
        if let count {
            keys.reserveCapacity(count)
        } else {
            keys.reserveCapacity(bucketCount / 2) // Rough estimate based on typical load factor
        }
        let count = count ?? Int.max

        var currentOffset = Self.headerSize + bucketCount * bucketEntrySize
        while currentOffset + MemoryLayout<UInt32>.size < fullSpan.byteCount,
              keys.count < count
        {
            // Read key length
            let keyLength = Int(fullSpan.unsafeLoadUnaligned(
                fromByteOffset: currentOffset,
                as: UInt32.self))

            let keyStart = currentOffset + MemoryLayout<UInt32>.size
            let keyRange = keyStart..<keyStart + keyLength
            guard keyRange.upperBound <= fullSpan.byteCount else {
                throw MMapDictionaryError.corruptedData("Invalid key length")
            }

            let keySpan = fullSpan.extracting(keyRange)
            keys.append(Array(span: keySpan))

            currentOffset = keyRange.upperBound
            // read value length
            guard currentOffset + MemoryLayout<UInt32>.size <= fullSpan.byteCount else {
                throw MMapDictionaryError.corruptedData("Invalid key length")
            }

            let valueLength = Int(fullSpan.unsafeLoadUnaligned(fromByteOffset: currentOffset, as: UInt32.self))
            currentOffset += MemoryLayout<UInt32>.size + valueLength
        }

        return keys
    }
}

extension [UInt8] {
    /// Creates a `[UInt8]` from a `RawSpan`.
    /// - Parameter span: The `RawSpan` to read from.
    init(span: RawSpan) {
        if span.isEmpty {
            self.init()
            return
        }
        self.init(unsafeUninitializedCapacity: span.byteCount) { buffer, initializedCount in
            span.withUnsafeBytes { sourceBytes in
                // swiftlint:disable:next force_unwrapping
                buffer.baseAddress!.initialize(from: sourceBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                               count: span.byteCount)
            }
            initializedCount = span.byteCount
        }
    }
}
