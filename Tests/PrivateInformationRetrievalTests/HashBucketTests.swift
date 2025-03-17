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
import XCTest

class HashBucketTests: XCTestCase {
    private let rawBucket: [UInt8] = [3, 24, 95, 141, 179, 34, 113, 254, 37, 5,
                                      0, 87, 111, 114, 108, 100, 82, 117, 17, 222,
                                      175, 220, 211, 74, 6, 0, 77, 97, 97, 105, 108,
                                      109, 192, 21, 173, 109, 218, 248, 187, 80, 8,
                                      0, 68, 97, 114, 107, 110, 101, 115, 115]

    private func getTestEntry() -> HashBucket.HashBucketEntry {
        let size = Int.random(in: 1...100)
        let randomData = PirTestUtils.generateRandomData(size: size)

        return HashBucket.HashBucketEntry(keywordHash: UInt64.random(in: UInt64.min...UInt64.max), value: randomData)
    }

    private func getTestBucket() -> HashBucket {
        let count = Int.random(in: 1...10)
        return HashBucket(slots: (0..<count).map { _ in getTestEntry() })
    }

    func testSerialization() throws {
        let testBucket = getTestBucket()
        let serialized = try testBucket.serialize()
        let deserialized = try HashBucket(deserialize: serialized)
        XCTAssertEqual(testBucket, deserialized)
    }

    func testSerializationError() throws {
        let size = Int(UInt16.max) + 1
        let randomData = PirTestUtils.generateRandomData(size: size)
        let testBucket = HashBucket.HashBucketEntry(
            keywordHash: UInt64.random(in: UInt64.min...UInt64.max),
            value: randomData)
        XCTAssertThrowsError(
            try testBucket.serialize(),
            error: PirError.invalidHashBucketEntryValueSize(
                maxSize: Int(
                    HashBucket.HashBucketEntry.maxValueSize)))
    }

    func testHashBucketEntrySerializationSize() throws {
        let testBucketEntry = getTestEntry()
        let serialized = try testBucketEntry.serialize()
        XCTAssertEqual(
            serialized.count,
            HashBucket.HashBucketEntry
                .serializedSize(value: testBucketEntry.value))
    }

    func testHashBucketSerializationSize() throws {
        let testBucket = getTestBucket()
        let serialized = try testBucket.serialize()
        XCTAssertEqual(
            serialized.count,
            HashBucket.serializedSize(values: testBucket.slots.map { slot in slot.value }))
    }

    func testHashIndices() {
        XCTAssertEqual(
            HashKeyword.hashIndices(keyword: [0, 1, 2, 3], bucketCount: 8, hashFunctionCount: 3),
            [7, 3, 0])
        let indices = [1989, 1767, 1260, 242, 1122]
        XCTAssertEqual(
            HashKeyword.hashIndices(keyword: [3, 2, 1, 0], bucketCount: 2048, hashFunctionCount: 5),
            indices)
    }

    func testBucketDeserialization() throws {
        let bucket = try HashBucket(deserialize: rawBucket)
        XCTAssertEqual(bucket.find(keyword: [UInt8]("Hello".utf8)), [UInt8]("World".utf8))
        XCTAssertEqual(bucket.find(keyword: [UInt8]("Goodbye".utf8)), [UInt8]("Darkness".utf8))
        XCTAssertEqual(bucket.slots.count, 3)
    }
}
