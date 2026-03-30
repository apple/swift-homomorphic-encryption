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
@testable import HomomorphicEncryption
import Testing

struct UtilTests {
    @Test
    func allUnique() {
        #expect([Bool]().allUnique())
        #expect(["1"].allUnique())
        #expect([1, 2, 3].allUnique())
        #expect(![1, 1, 2].allUnique())
        #expect(![1, 2, 1].allUnique())
        #expect(![2, 1, 1].allUnique())
    }

    @Test
    func ballsInBinCount() {
        #expect(TestUtils.expectedBallsInBinsCount(binCount: 1, ballCount: 1, count: 0).isClose(to: 0))
        #expect(TestUtils.expectedBallsInBinsCount(binCount: 1, ballCount: 1, count: 1).isClose(to: 1))
        #expect(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 1, count: 0).isClose(to: 1))
        #expect(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 1, count: 1).isClose(to: 1))
        #expect(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 2, count: 0).isClose(to: 0.5))
        #expect(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 3, count: 0).isClose(to: 0.25))
        #expect(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 3, count: 1).isClose(to: 0.75))
        #expect(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 4, count: 4).isClose(to: 0.125))
    }

    @Test
    func toRemainder() {
        #expect((-8).toRemainder(7, variableTime: true) == 6)
        #expect((-7).toRemainder(7, variableTime: true) == 0)
        #expect((-6).toRemainder(7, variableTime: true) == 1)
        #expect(6.toRemainder(7, variableTime: true) == 6)
        #expect(7.toRemainder(7, variableTime: true) == 0)
        #expect(8.toRemainder(7, variableTime: true) == 1)
    }

    @Test
    func product() {
        #expect([UInt8]().product() == 1)
        #expect([7].product() == 7)
        #expect([1, 2, 3].product() == 6)
        #expect([UInt8(255), UInt8(2)].product() == UInt16(510))

        var values = [UInt32]()
        for count in 1...31 {
            values.append(UInt32(1 << count))
            let sumOfPowers = count * (count + 1) / 2
            #expect(values.product() == Width32<UInt32>(1) << sumOfPowers)
        }
    }

    @Test
    func sum() {
        #expect([UInt8]().sum() == 0)
        #expect([7].sum() == 7)
        #expect([1, 2, 3].sum() == 6)
        #expect([UInt8(255), UInt8(2)].sum() == UInt16(257))
    }

    @Test
    func hexString() {
        #expect(Array(base64Encoded: "AAAA") == Array(hexEncoded: "000000"))
        #expect(Array(base64Encoded: "AAAB") == Array(hexEncoded: "000001"))
        let data = Array(randomByteCount: 64)
        let hexString = data.hexEncodedString()
        #expect(Array(hexEncoded: hexString) == data)
    }

    @Test
    func base64EncodedString() throws {
        #expect(try #require(Array(base64Encoded: "AAAA")).base64EncodedString() == "AAAA")
        #expect(try #require(Array(base64Encoded: "AAAB")).base64EncodedString() == "AAAB")
        let data = Array(randomByteCount: 64)
        let base64String = data.base64EncodedString()
        #expect(Array(base64Encoded: base64String) == data)
    }

    @Test
    func concurrentMap() async throws {
        // Empty collection
        let empty: [Int] = []

        #expect(try await empty.concurrentMap { $0 * 2 }.isEmpty)

        // Single element
        #expect(try await [42].concurrentMap { $0 * 2 } == [84])

        // Multiple elements, ordered (default) — output order must match input order
        let input = Array(0..<20)
        let ordered = try await input.concurrentMap { $0 * $0 }
        #expect(ordered == input.map { $0 * $0 })

        // Multiple elements, unordered — all elements present regardless of order
        let unordered = try await input.concurrentMap(ordered: false) { $0 * $0 }
        #expect(unordered.sorted() == input.map { $0 * $0 }.sorted())

        // Async transform
        let asyncResult = try await input.concurrentMap { value -> Int in
            try await Task.sleep(nanoseconds: 1)
            return value + 1
        }
        #expect(asyncResult == input.map { $0 + 1 })

        // Error propagation
        struct ConcurrentMapError: Error {}
        await #expect(throws: ConcurrentMapError.self) {
            try await input.concurrentMap { value -> Int in
                if value == 5 { throw ConcurrentMapError() }
                return value
            }
        }
    }

    @Test
    func concurrentConsumingMap() async throws {
        // Empty collection
        var empty: [Int] = []

        #expect(try await empty.concurrentConsumingMap { $0 * 2 }.isEmpty)

        // Single element
        var single = [42]
        #expect(try await single.concurrentConsumingMap { $0 * 2 } == [84])

        // Multiple elements, ordered (default) — output order must match input order
        var input = Array(0..<20)
        let ordered = try await input.concurrentConsumingMap { $0 * $0 }
        #expect(ordered == (0..<20).map { $0 * $0 })

        // Multiple elements, unordered — all elements present regardless of order
        var input2 = Array(0..<20)
        let unordered = try await input2.concurrentConsumingMap(ordered: false) { $0 * $0 }
        #expect(unordered.sorted() == (0..<20).map { $0 * $0 }.sorted())

        // Async transform
        var input3 = Array(0..<20)
        let asyncResult = try await input3.concurrentConsumingMap { value -> Int in
            try await Task.sleep(nanoseconds: 1)
            return value + 1
        }
        #expect(asyncResult == (0..<20).map { $0 + 1 })

        // Error propagation
        struct ConcurrentConsumingMapError: Error {}
        var input4 = Array(0..<20)
        await #expect(throws: ConcurrentConsumingMapError.self) {
            try await input4.concurrentConsumingMap { value -> Int in
                if value == 5 { throw ConcurrentConsumingMapError() }
                return value
            }
        }
    }
}
