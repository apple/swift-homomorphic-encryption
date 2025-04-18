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

@testable import HomomorphicEncryption
import TestUtilities
import XCTest

class UtilTests: XCTestCase {
    func testAllUnique() {
        XCTAssertTrue([Bool]().allUnique())
        XCTAssertTrue(["1"].allUnique())
        XCTAssertTrue([1, 2, 3].allUnique())
        XCTAssertFalse([1, 1, 2].allUnique())
        XCTAssertFalse([1, 2, 1].allUnique())
        XCTAssertFalse([2, 1, 1].allUnique())
    }

    func testBallsInBinCount() {
        XCTAssertIsClose(TestUtils.expectedBallsInBinsCount(binCount: 1, ballCount: 1, count: 0), 0)
        XCTAssertIsClose(TestUtils.expectedBallsInBinsCount(binCount: 1, ballCount: 1, count: 1), 1)
        XCTAssertIsClose(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 1, count: 0), 1)
        XCTAssertIsClose(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 1, count: 1), 1)
        XCTAssertIsClose(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 2, count: 0), 0.5)
        XCTAssertIsClose(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 3, count: 0), 0.25)
        XCTAssertIsClose(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 3, count: 1), 0.75)
        XCTAssertIsClose(TestUtils.expectedBallsInBinsCount(binCount: 2, ballCount: 4, count: 4), 0.125)
    }

    func testToRemainder() {
        XCTAssertEqual((-8).toRemainder(7, variableTime: true), 6)
        XCTAssertEqual((-7).toRemainder(7, variableTime: true), 0)
        XCTAssertEqual((-6).toRemainder(7, variableTime: true), 1)
        XCTAssertEqual(6.toRemainder(7, variableTime: true), 6)
        XCTAssertEqual(7.toRemainder(7, variableTime: true), 0)
        XCTAssertEqual(8.toRemainder(7, variableTime: true), 1)
    }

    func testProduct() {
        XCTAssertEqual([UInt8]().product(), 1)
        XCTAssertEqual([7].product(), 7)
        XCTAssertEqual([1, 2, 3].product(), 6)
        XCTAssertEqual([UInt8(255), UInt8(2)].product(), UInt16(510))

        XCTAssertEqual([UInt32(1 << 17), UInt32(1 << 17)].product(), Width32<UInt32>(1 << 34))
    }

    func testSum() {
        XCTAssertEqual([UInt8]().sum(), 0)
        XCTAssertEqual([7].sum(), 7)
        XCTAssertEqual([1, 2, 3].sum(), 6)
        XCTAssertEqual([UInt8(255), UInt8(2)].sum(), UInt16(257))
    }

    func testHexString() {
        XCTAssertEqual(Array(base64Encoded: "AAAA"), Array(hexEncoded: "000000"))
        XCTAssertEqual(Array(base64Encoded: "AAAB"), Array(hexEncoded: "000001"))
        let data = Array(randomByteCount: 64)
        let hexString = data.hexEncodedString()
        XCTAssertEqual(Array(hexEncoded: hexString), data)
    }

    func testBase64EncodedString() {
        XCTAssertEqual("AAAA", try XCTUnwrap(Array(base64Encoded: "AAAA")).base64EncodedString())
        XCTAssertEqual("AAAB", try XCTUnwrap(Array(base64Encoded: "AAAB")).base64EncodedString())
        let data = Array(randomByteCount: 64)
        let base64String = data.base64EncodedString()
        XCTAssertEqual(Array(base64Encoded: base64String), data)
    }
}
