// Copyright 2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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
import MemoryMapping
import Testing

struct MMapDictionaryPublicTests {
    // MARK: - Basic Usage Examples

    @Test
    func createAndQuerySimpleDictionary() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        // Step 1: Create a builder
        var builder = MMapDictionary.Builder()

        // Step 2: Insert key-value pairs
        builder.insert(key: "name", value: Array("Alice".utf8))
        builder.insert(key: "city", value: Array("San Francisco".utf8))
        builder.insert(key: "role", value: Array("Engineer".utf8))

        // Step 3: Write to file
        try builder.write(to: path)

        // Step 4: Open the dictionary
        let dict = try MMapDictionary(path: path)

        // Step 5: Query values
        let name = try dict["name"]
        let city = try dict["city"]
        let role = try dict["role"]

        // Step 6: Verify results
        #expect(name == Array("Alice".utf8))
        #expect(city == Array("San Francisco".utf8))
        #expect(role == Array("Engineer".utf8))
    }

    @Test
    func queryNonExistentKeyReturnsNil() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "exists", value: [1, 2, 3])
        try builder.write(to: path)

        let dict = try MMapDictionary(path: path)
        let result = try dict["doesNotExist"]

        #expect(result == nil)
    }

    // MARK: - Builder API Examples

    @Test
    func builderWithCustomLoadFactor() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()

        // Add 100 entries
        for i in 0..<100 {
            builder.insert(key: "key\(i)", value: Array("value\(i)".utf8))
        }

        // Use a lower load factor for better lookup performance
        try builder.write(to: path, loadFactor: 0.5)

        let dict = try MMapDictionary(path: path)

        // Verify some entries
        let value0 = try dict["key0"]
        let value99 = try dict["key99"]

        #expect(value0 == Array("value0".utf8))
        #expect(value99 == Array("value99".utf8))
    }

    @Test
    func builderWithURLBasedWrite() throws {
        let tempDir = FileManager.default.temporaryDirectory
        let url = tempDir.appendingPathComponent("test_\(UUID().uuidString).mmap")
        defer { try? FileManager.default.removeItem(at: url) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "test", value: [42])

        // Write using URL instead of path string
        try builder.write(to: url)

        let dict = try MMapDictionary(path: url.path)
        let value = try dict["test"]

        #expect(value == [42])
    }

    @Test
    func builderWithRawByteSpans() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()

        // Use RawSpan for both key and value
        let keyBytes: [UInt8] = [0x01, 0x02, 0x03]
        let valueBytes: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD]

        builder.insert(key: keyBytes.span.bytes, value: valueBytes.span.bytes)
        try builder.write(to: path)

        let dict = try MMapDictionary(path: path)
        let result = try dict[keyBytes.span.bytes]

        #expect(result == valueBytes)
    }

    // MARK: - Lookup API Examples

    @Test
    func lookupWithWithValueClosureForZeroCopyAccess() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "data", value: [10, 20, 30, 40, 50])
        try builder.write(to: path)

        let dict = try MMapDictionary(path: path)

        // Use withValue for zero-copy access to the data
        let sum = try dict.withValue(forKey: "data") { span in
            span.withUnsafeBytes { buffer in
                buffer.reduce(0, +)
            }
        }

        #expect(sum == 150) // 10 + 20 + 30 + 40 + 50
    }

    @Test
    func lookupWithWithValueReturnsNilForMissingKey() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "exists", value: [1, 2, 3])
        try builder.write(to: path)

        let dict = try MMapDictionary(path: path)

        let result = try dict.withValue(forKey: "missing") { span in
            span.byteCount
        }

        #expect(result == nil)
    }

    @Test
    func lookupConvertingValueToString() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()
        builder.insert(key: "message", value: Array("Hello, World!".utf8))
        try builder.write(to: path)

        let dict = try MMapDictionary(path: path)

        // Lookup and convert to String
        if let bytes = try dict["message"],
           let message = String(bytes: bytes, encoding: .utf8)
        {
            #expect(message == "Hello, World!")
        } else {
            Issue.record("Failed to lookup or decode message")
        }
    }

    // MARK: - Introspection API Examples

    @Test
    func countNumberOfEntries() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()

        // Insert 50 entries
        for i in 0..<50 {
            builder.insert(key: "entry_\(i)", value: [UInt8(i)])
        }

        try builder.write(to: path)
        let dict = try MMapDictionary(path: path)

        // Get the count
        let count = try dict.count()
        #expect(count == 50)
    }

    @Test
    func getAllKeysInInsertionOrder() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()

        let expectedKeys = ["first", "second", "third", "fourth", "fifth"]
        for key in expectedKeys {
            builder.insert(key: key, value: [1])
        }

        try builder.write(to: path)
        let dict = try MMapDictionary(path: path)

        // Get all keys
        let keys = try dict.keys()

        #expect(keys.count == 5)

        // Verify keys are in insertion order
        for (index, expectedKey) in expectedKeys.enumerated() {
            #expect(keys[index] == Array(expectedKey.utf8))
        }
    }

    @Test
    func getLimitedNumberOfKeys() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()

        for i in 0..<100 {
            builder.insert(key: "key\(i)", value: [UInt8(i)])
        }

        try builder.write(to: path)
        let dict = try MMapDictionary(path: path)

        // Get only the first 10 keys
        let firstTenKeys = try dict.keys(count: 10)

        #expect(firstTenKeys.count == 10)
        #expect(firstTenKeys[0] == Array("key0".utf8))
        #expect(firstTenKeys[9] == Array("key9".utf8))
    }

    @Test
    func checkLongestProbeRunForPerformanceAnalysis() throws {
        let path = temporaryFilePath()
        defer { cleanup(path: path) }

        var builder = MMapDictionary.Builder()

        // Insert many entries to create collisions
        for i in 0..<100 {
            builder.insert(key: "entry_\(i)", value: [UInt8(i)])
        }

        // Use high load factor to increase collisions
        try builder.write(to: path, loadFactor: 0.9)
        let dict = try MMapDictionary(path: path)

        // Get the longest probe run (useful for performance analysis)
        let maxRun = try dict.longestProbeRun()

        // With 100 entries and load factor 0.9, we expect some collisions
        #expect(maxRun > 0)
    }
}
