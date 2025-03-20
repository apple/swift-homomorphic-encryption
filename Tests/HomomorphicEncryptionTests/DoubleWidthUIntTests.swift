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
import Testing

@Suite
struct DoubleWidthTests {
    private typealias DWU16 = DoubleWidthUInt<UInt8>
    private typealias DWUInt128 = DoubleWidthUInt<UInt64>
    private typealias DWUInt256 = DoubleWidthUInt<DWUInt128>

    private func expectWordsEqual(_ lhs: DoubleWidthUInt<some Any>.Words, _ rhs: [UInt]) {
        #expect(lhs.count == rhs.count)
        for (x, y) in zip(lhs, rhs) {
            #expect(x == y)
        }
    }

    @Test
    func literals() throws {
        let w: DoubleWidthUInt<UInt8> = 100
        #expect(w == 100)

        let x: DoubleWidthUInt<UInt8> = 1000
        #expect(x == 1000)
    }

    @Test
    func arithmeticUnsigned() throws {
        let x: DoubleWidthUInt<UInt8> = 1000
        let y: DoubleWidthUInt<UInt8> = 1111
        #expect(x + 1 == 1001)
        #expect(x + 1 == 1001)
        #expect(x + x == 2000)
        #expect(x - (1 as DoubleWidthUInt<UInt8>) == 999)
        #expect(x - x == 0)
        #expect(y - x == 111)

        #expect(x * 7 == 7000)
        #expect(y * 7 == 7777)

        #expect(x / 3 == 333)
        #expect(x / x == 1)
        #expect(x / y == 0)
        #expect(y / x == 1)

        #expect(x % 3 == 1)
        #expect(x % y == x)

        do {
            let lhs = DoubleWidthUInt<UInt8>((high: 0b0011_0000, low: 0))
            let rhs = DoubleWidthUInt<UInt8>((high: 0b0010_0000, low: 0))
            #expect(lhs % rhs == 4096)
        }
        do {
            let lhs = DWUInt128((high: 0xA0C7_D716_5CF0_1386, low: 0xBF3F_66A9_3056_143F))
            let rhs = DWUInt128((high: 0x9AC3_A19B_1E7D_6B83, low: 0x5139_2979_2D58_8736))
            #expect(String(lhs % rhs) == "7997221894243298914179865336050715913")
        }
        do {
            let lhs = DWUInt128((high: 0xEA8A_9116_B7AF_33B7, low: 0x3D9D_6779_DDD2_2CA3))
            let rhs = DWUInt128((high: 0xC367_3EFC_7F1F_37CC, low: 0x312F_6610_57D0_BA94))
            #expect(String(lhs % rhs) == "52023287460685389410162512181093036559")
        }
        do {
            // swiftlint:disable:next force_unwrapping
            let lhs = DWUInt256("2369676578372158364766242369061213561181961479062237766620")!
            // swiftlint:disable:next force_unwrapping
            let rhs = DWUInt256("102797312405202436815976773795958969482")!
            #expect(String(lhs / rhs) == "23051931251193218442")
        }
        do {
            // swiftlint:disable:next force_unwrapping
            let lhs = DWUInt256("96467201117289166187766181030232879447148862859323917044548749804018359008044")!
            // swiftlint:disable:next force_unwrapping
            let rhs = DWUInt256("4646260627574879223760172113656436161581617773435991717024")!
            #expect(String(lhs / rhs) == "20762331011904583253")
        }

        let prod = (0xFF01 as DoubleWidthUInt<UInt8>).multipliedFullWidth(by: 0x101)
        #expect(prod.high == 256)
        #expect(prod.low == 1)
    }

    @Test
    func arithmeticOverflow() {
        do {
            let x = DWUInt128.max
            let (y, o) = x.addingReportingOverflow(1)
            #expect(y == 0)
            #expect(y == (0 as Int))
            #expect(o)
        }

        #expect(!DWUInt128.isSigned)
        #expect(DWUInt128.bitWidth == 128)

        expectWordsEqual(DWUInt128.max.words, Array(repeatElement(UInt.max, count: 128 / UInt.bitWidth)))
    }

    @Test
    func initialization() {
        typealias DWU16 = DoubleWidthUInt<UInt8>
        #expect(DWU16(UInt16.max) == UInt16.max)
        #expect(DWU16(exactly: UInt32.max) == nil)
        #expect(DWU16(UInt16.max) == UInt16.max)
        #expect(DWU16(exactly: UInt32.max) == nil)
        #expect(DWU16(truncatingIfNeeded: UInt64.max) == DWU16.max)
    }

    @Test
    func magnitude() {
        typealias DWU16 = DoubleWidthUInt<UInt8>

        #expect(DWU16.min.magnitude == UInt16.min.magnitude)
        #expect((42 as DWU16).magnitude == (42 as UInt16).magnitude)
        #expect(DWU16.max.magnitude == UInt16.max.magnitude)
    }

    @Test
    func twoWords() {
        typealias DWUInt = DoubleWidthUInt<UInt>

        #expect(DWUInt(truncatingIfNeeded: 1) == 1)

        #expect(UInt(exactly: DWUInt(UInt.max) + 1) == nil)

        #expect(DWUInt(UInt.max) + 1 > UInt.max)
    }

    @Test
    func bitShifts() {
        typealias DWU64 = DoubleWidthUInt<DoubleWidthUInt<DoubleWidthUInt<UInt8>>>

        func f<T: FixedWidthInteger, U: FixedWidthInteger>(_ x: T, type _: U.Type) {
            let y = U(x)
            #expect(T.bitWidth == U.bitWidth)
            for i in -(T.bitWidth + 1)...(T.bitWidth + 1) {
                #expect(x << i == y << i)
                #expect(x >> i == y >> i)

                #expect(x &<< i == y &<< i)
                #expect(x &>> i == y &>> i)
            }
        }

        f(1 as UInt64, type: DWU64.self)
        f(~(~0 as UInt64 >> 1), type: DWU64.self)
        f(UInt64.max, type: DWU64.self)
        // 0b01010101_10100101_11110000_10100101_11110000_10100101_11110000_10100101
        f(17_340_530_535_757_639_845 as UInt64, type: DWU64.self)
    }

    @Test
    func isMultiple() {
        func isMultipleTest<T: FixedWidthInteger>(type _: T.Type) {
            #expect(T.min.isMultiple(of: 2))
            #expect(!T.max.isMultiple(of: 10))
            // Test that these do not crash.
            #expect((0 as T).isMultiple(of: 0))
            #expect(!(1 as T).isMultiple(of: 0))
            #expect(T.min.isMultiple(of: 0 &- 1))
        }
        isMultipleTest(type: DWUInt128.self)
    }

    @Test
    func conversions() {
        #expect(DWU16(1 << 16 - 1) == Int(1 << 16 - 1))
        #expect(DWU16(0) == Int(0))

        #expect(DWU16(Double(1 << 16 - 1)) == Int(1 << 16 - 1))
        #expect(DWU16(Double(0)) == Int(0))

        #expect(DWU16(Double(1 << 16 - 1) + 0.9) == Int(1 << 16 - 1))
        #expect(DWU16(Double(0) - 0.9) == Int(0))

        #expect(DWU16(0.00001) == 0)
    }

    @Test
    func exactConversions() {
        // swiftlint:disable:next force_unwrapping
        #expect(DWU16(Double(1 << 16 - 1)) == DWU16(exactly: Double(1 << 16 - 1))!)
        // swiftlint:disable:next force_unwrapping
        #expect(DWU16(Double(0)) == DWU16(exactly: Double(0))!)

        #expect(DWU16(exactly: Double(1 << 16 - 1) + 0.9) == nil)
        #expect(DWU16(exactly: Double(0) - 0.9) == nil)

        #expect(DWU16(exactly: Double(1 << 16)) == nil)
        #expect(DWU16(exactly: Double(-1)) == nil)

        #expect(DWU16(exactly: 0.00001) == nil)

        #expect(DWU16(exactly: Double.nan) == nil)
        #expect(DWU16(exactly: Float.nan) == nil)
        #expect(DWU16(exactly: Double.infinity) == nil)
        #expect(DWU16(exactly: Float.infinity) == nil)
    }

    @Test
    func stringConversions() {
        #expect(String(DWUInt256.max, radix: 16) ==
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        #expect(String(DWUInt256.min, radix: 16) == "0")

        #expect(String(DWUInt256.max, radix: 2) == """
            1111111111111111111111111111111111111111111111111111111111111111\
            1111111111111111111111111111111111111111111111111111111111111111\
            1111111111111111111111111111111111111111111111111111111111111111\
            1111111111111111111111111111111111111111111111111111111111111111
            """)
        #expect(String(DWUInt256.min, radix: 2) == "0")

        #expect(String(DWUInt128.max, radix: 10) ==
            "340282366920938463463374607431768211455")
        #expect(String(DWUInt128.min, radix: 10) == "0")
    }

    @Test
    func words() {
        expectWordsEqual((0 as DoubleWidthUInt<UInt8>).words, [0])
        expectWordsEqual((1 as DoubleWidthUInt<UInt8>).words, [1])
        expectWordsEqual((255 as DoubleWidthUInt<UInt8>).words, [255])
        expectWordsEqual((256 as DoubleWidthUInt<UInt8>).words, [256])
        expectWordsEqual(DoubleWidthUInt<UInt8>.max.words, [65535])
        expectWordsEqual(DoubleWidthUInt<UInt8>.min.words, [0])

        expectWordsEqual((0 as DWUInt128).words,
                         Array(repeatElement(0 as UInt, count: 128 / UInt.bitWidth)))
        expectWordsEqual((DWUInt128.max).words,
                         Array(repeatElement(UInt.max, count: 128 / UInt.bitWidth)))
        expectWordsEqual((1 as DWUInt128).words,
                         [1] + Array(repeating: 0, count: 128 / UInt.bitWidth - 1))
    }
}
