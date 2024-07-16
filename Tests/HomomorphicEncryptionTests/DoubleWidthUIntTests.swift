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

// This source file is part of the Swift.org open source project
//
// Copyright (c) 2024 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors

// Taken from
// https://github.com/swiftlang/swift/blob/fc23eef2d2b2e42116ac94a6cc0d0d2cc96688f5/test/Prototypes/DoubleWidth.swift.gyb
// and modified to accommodate changes to `DoubleWidthUInt.swift`.

@testable import HomomorphicEncryption
import XCTest

// A lot of false positives
// swiftlint:disable xct_specific_matcher
class DoubleWidthTests: XCTestCase {
    private typealias DWU16 = DoubleWidthUInt<UInt8>
    private typealias DWUInt128 = DoubleWidthUInt<UInt64>
    private typealias DWUInt256 = DoubleWidthUInt<DWUInt128>

    private func assertWordsEqual(_ lhs: DoubleWidthUInt<some Any>.Words, _ rhs: [UInt]) {
        XCTAssertEqual(lhs.count, rhs.count)
        for (x, y) in zip(lhs, rhs) {
            XCTAssertEqual(x, y)
        }
    }

    func testLiterals() throws {
        let w: DoubleWidthUInt<UInt8> = 100
        XCTAssertEqual(w, 100)

        let x: DoubleWidthUInt<UInt8> = 1000
        XCTAssertEqual(x, 1000)
    }

    func testArithmeticUnsigned() throws {
        let x: DoubleWidthUInt<UInt8> = 1000
        let y: DoubleWidthUInt<UInt8> = 1111
        XCTAssertEqual(x + 1, 1001)
        XCTAssertEqual(x + 1, 1001)
        XCTAssertEqual(x + x, 2000)
        XCTAssertEqual(x - (1 as DoubleWidthUInt<UInt8>), 999)
        XCTAssertEqual(x - x, 0)
        XCTAssertEqual(y - x, 111)

        XCTAssertEqual(x * 7, 7000)
        XCTAssertEqual(y * 7, 7777)

        XCTAssertEqual(x / 3, 333)
        XCTAssertEqual(x / x, 1)
        XCTAssertEqual(x / y, 0)
        XCTAssertEqual(y / x, 1)

        XCTAssertEqual(x % 3, 1)
        XCTAssertEqual(x % y, x)

        do {
            let lhs = DoubleWidthUInt<UInt8>((high: 0b0011_0000, low: 0))
            let rhs = DoubleWidthUInt<UInt8>((high: 0b0010_0000, low: 0))
            XCTAssertEqual(lhs % rhs, 4096)
        }
        do {
            let lhs = DWUInt128((high: 0xA0C7_D716_5CF0_1386, low: 0xBF3F_66A9_3056_143F))
            let rhs = DWUInt128((high: 0x9AC3_A19B_1E7D_6B83, low: 0x5139_2979_2D58_8736))
            XCTAssertEqual(String(lhs % rhs), "7997221894243298914179865336050715913")
        }
        do {
            let lhs = DWUInt128((high: 0xEA8A_9116_B7AF_33B7, low: 0x3D9D_6779_DDD2_2CA3))
            let rhs = DWUInt128((high: 0xC367_3EFC_7F1F_37CC, low: 0x312F_6610_57D0_BA94))
            XCTAssertEqual(String(lhs % rhs), "52023287460685389410162512181093036559")
        }
        do {
            // swiftlint:disable:next force_unwrapping
            let lhs = DWUInt256("2369676578372158364766242369061213561181961479062237766620")!
            // swiftlint:disable:next force_unwrapping
            let rhs = DWUInt256("102797312405202436815976773795958969482")!
            XCTAssertEqual(String(lhs / rhs), "23051931251193218442")
        }
        do {
            // swiftlint:disable:next force_unwrapping
            let lhs = DWUInt256("96467201117289166187766181030232879447148862859323917044548749804018359008044")!
            // swiftlint:disable:next force_unwrapping
            let rhs = DWUInt256("4646260627574879223760172113656436161581617773435991717024")!
            XCTAssertEqual(String(lhs / rhs), "20762331011904583253")
        }

        let prod = (0xFF01 as DoubleWidthUInt<UInt8>).multipliedFullWidth(by: 0x101)
        XCTAssertEqual(prod.high, 256)
        XCTAssertEqual(prod.low, 1)
    }

    func testArithmeticOverflow() {
        do {
            let x = DWUInt128.max
            let (y, o) = x.addingReportingOverflow(1)
            XCTAssertEqual(y, 0)
            XCTAssertTrue(y == (0 as Int))
            XCTAssertTrue(o)
        }

        XCTAssertFalse(DWUInt128.isSigned)
        XCTAssertEqual(DWUInt128.bitWidth, 128)

        assertWordsEqual(DWUInt128.max.words, Array(repeatElement(UInt.max, count: 128 / UInt.bitWidth)))
    }

    func testInitialization() {
        typealias DWU16 = DoubleWidthUInt<UInt8>
        XCTAssert(DWU16(UInt16.max) == UInt16.max)
        XCTAssertNil(DWU16(exactly: UInt32.max))
        XCTAssertTrue(DWU16(UInt16.max) == UInt16.max)
        XCTAssertNil(DWU16(exactly: UInt32.max))
        XCTAssertEqual(DWU16(truncatingIfNeeded: UInt64.max), DWU16.max)
    }

    func testMagnitude() {
        typealias DWU16 = DoubleWidthUInt<UInt8>

        XCTAssertTrue(DWU16.min.magnitude == UInt16.min.magnitude)
        XCTAssertTrue((42 as DWU16).magnitude == (42 as UInt16).magnitude)
        XCTAssertTrue(DWU16.max.magnitude == UInt16.max.magnitude)
    }

    func testTwoWords() {
        typealias DWUInt = DoubleWidthUInt<UInt>

        XCTAssertEqual(1, DWUInt(truncatingIfNeeded: 1))

        XCTAssertNil(UInt(exactly: DWUInt(UInt.max) + 1))

        XCTAssertTrue(DWUInt(UInt.max) + 1 > UInt.max)
    }

    func testBitShifts() {
        typealias DWU64 = DoubleWidthUInt<DoubleWidthUInt<DoubleWidthUInt<UInt8>>>

        func f<T: FixedWidthInteger, U: FixedWidthInteger>(_ x: T, type _: U.Type) {
            let y = U(x)
            XCTAssertEqual(T.bitWidth, U.bitWidth)
            for i in -(T.bitWidth + 1)...(T.bitWidth + 1) {
                XCTAssertTrue(x << i == y << i)
                XCTAssertTrue(x >> i == y >> i)

                XCTAssertTrue(x &<< i == y &<< i)
                XCTAssertTrue(x &>> i == y &>> i)
            }
        }

        f(1 as UInt64, type: DWU64.self)
        f(~(~0 as UInt64 >> 1), type: DWU64.self)
        f(UInt64.max, type: DWU64.self)
        // 0b01010101_10100101_11110000_10100101_11110000_10100101_11110000_10100101
        f(17_340_530_535_757_639_845 as UInt64, type: DWU64.self)
    }

    func testIsMultiple() {
        func isMultipleTest<T: FixedWidthInteger>(type _: T.Type) {
            XCTAssertTrue(T.min.isMultiple(of: 2))
            XCTAssertFalse(T.max.isMultiple(of: 10))
            // Test that these do not crash.
            XCTAssertTrue((0 as T).isMultiple(of: 0))
            XCTAssertFalse((1 as T).isMultiple(of: 0))
            XCTAssertTrue(T.min.isMultiple(of: 0 &- 1))
        }
        isMultipleTest(type: DWUInt128.self)
    }

    func testConversions() {
        XCTAssertTrue(DWU16(1 << 16 - 1) == Int(1 << 16 - 1))
        XCTAssertTrue(DWU16(0) == Int(0))

        XCTAssertTrue(DWU16(Double(1 << 16 - 1)) == Int(1 << 16 - 1))
        XCTAssertTrue(DWU16(Double(0)) == Int(0))

        XCTAssertTrue(DWU16(Double(1 << 16 - 1) + 0.9) == Int(1 << 16 - 1))
        XCTAssertTrue(DWU16(Double(0) - 0.9) == Int(0))

        XCTAssertEqual(DWU16(0.00001), 0)
    }

    func testExactConversions() {
        // swiftlint:disable:next force_unwrapping
        XCTAssertEqual(DWU16(Double(1 << 16 - 1)), DWU16(exactly: Double(1 << 16 - 1))!)
        // swiftlint:disable:next force_unwrapping
        XCTAssertEqual(DWU16(Double(0)), DWU16(exactly: Double(0))!)

        XCTAssertNil(DWU16(exactly: Double(1 << 16 - 1) + 0.9))
        XCTAssertNil(DWU16(exactly: Double(0) - 0.9))

        XCTAssertNil(DWU16(exactly: Double(1 << 16)))
        XCTAssertNil(DWU16(exactly: Double(-1)))

        XCTAssertNil(DWU16(exactly: 0.00001))

        XCTAssertNil(DWU16(exactly: Double.nan))
        XCTAssertNil(DWU16(exactly: Float.nan))
        XCTAssertNil(DWU16(exactly: Double.infinity))
        XCTAssertNil(DWU16(exactly: Float.infinity))
    }

    func testStringConversions() {
        XCTAssertEqual(String(DWUInt256.max, radix: 16),
                       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        XCTAssertEqual(String(DWUInt256.min, radix: 16), "0")

        XCTAssertEqual(String(DWUInt256.max, radix: 2), """
            1111111111111111111111111111111111111111111111111111111111111111\
            1111111111111111111111111111111111111111111111111111111111111111\
            1111111111111111111111111111111111111111111111111111111111111111\
            1111111111111111111111111111111111111111111111111111111111111111
            """)
        XCTAssertEqual(String(DWUInt256.min, radix: 2), "0")

        XCTAssertEqual(String(DWUInt128.max, radix: 10),
                       "340282366920938463463374607431768211455")
        XCTAssertEqual(String(DWUInt128.min, radix: 10), "0")
    }

    func testWords() {
        assertWordsEqual((0 as DoubleWidthUInt<UInt8>).words, [0])
        assertWordsEqual((1 as DoubleWidthUInt<UInt8>).words, [1])
        assertWordsEqual((255 as DoubleWidthUInt<UInt8>).words, [255])
        assertWordsEqual((256 as DoubleWidthUInt<UInt8>).words, [256])
        assertWordsEqual(DoubleWidthUInt<UInt8>.max.words, [65535])
        assertWordsEqual(DoubleWidthUInt<UInt8>.min.words, [0])

        assertWordsEqual((0 as DWUInt128).words,
                         Array(repeatElement(0 as UInt, count: 128 / UInt.bitWidth)))
        assertWordsEqual((DWUInt128.max).words,
                         Array(repeatElement(UInt.max, count: 128 / UInt.bitWidth)))
        assertWordsEqual((1 as DWUInt128).words,
                         [1] + Array(repeating: 0, count: 128 / UInt.bitWidth - 1))
    }
}

// swiftlint:enable xct_specific_matcher
