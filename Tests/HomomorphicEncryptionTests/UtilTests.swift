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
@testable import HomomorphicEncryption
import Testing

@Suite
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
}
