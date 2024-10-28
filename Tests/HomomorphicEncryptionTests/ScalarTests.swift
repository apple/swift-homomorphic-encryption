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

@testable import HomomorphicEncryption
import ModularArithmetic
import TestUtilities
import XCTest

class ScalarTests: XCTestCase {
    func testSubtractIfExceeds() {
        do {
            let modulus: UInt32 = (1 << 29) - 63
            XCTAssertEqual(UInt32(2 * modulus + 1).subtractIfExceeds(modulus), modulus + 1)
            XCTAssertEqual(UInt32(modulus - 1).subtractIfExceeds(modulus), modulus - 1)
        }
        do {
            let modulus: UInt32 = (1 << 31) - 10
            let max = (UInt32.max >> 1) + modulus
            XCTAssertEqual(UInt32(max).subtractIfExceeds(modulus), max - modulus)
            XCTAssertEqual(UInt32(modulus - 1).subtractIfExceeds(modulus), modulus - 1)
        }
    }

    func testAddMod() {
        XCTAssertEqual(UInt32(0).addMod(1, modulus: 3), 1)
        XCTAssertEqual(UInt32(1).addMod(2, modulus: 3), 0)
        XCTAssertEqual(UInt32(2).addMod(2, modulus: 3), 1)

        XCTAssertEqual(UInt64(0).addMod(1, modulus: 3), 1)
        XCTAssertEqual(UInt64(1).addMod(2, modulus: 3), 0)
        XCTAssertEqual(UInt64(2).addMod(2, modulus: 3), 1)

        let one = UInt64(1)
        XCTAssertEqual((one << 62).addMod((one << 62) + 3, modulus: (one << 62) + 4), (one << 62) - 1)
    }

    func testNegateMod() {
        XCTAssertEqual(UInt32(0).negateMod(modulus: 3), 0)
        XCTAssertEqual(UInt32(1).negateMod(modulus: 3), 2)
        XCTAssertEqual(UInt32(2).negateMod(modulus: 3), 1)

        XCTAssertEqual(UInt64(0).negateMod(modulus: 3), 0)
        XCTAssertEqual(UInt64(1).negateMod(modulus: 3), 2)
        XCTAssertEqual(UInt64(2).negateMod(modulus: 3), 1)
    }

    func testSubtractMod() {
        XCTAssertEqual(UInt32(0).subtractMod(2, modulus: 3), 1)
        XCTAssertEqual(UInt32(1).subtractMod(1, modulus: 3), 0)
        XCTAssertEqual(UInt32(2).subtractMod(1, modulus: 3), 1)

        XCTAssertEqual(UInt64(0).subtractMod(2, modulus: 3), 1)
        XCTAssertEqual(UInt64(1).subtractMod(1, modulus: 3), 0)
        XCTAssertEqual(UInt64(2).subtractMod(1, modulus: 3), 1)
    }

    func testPowMod() {
        XCTAssertEqual(UInt32(0).powMod(exponent: 1, modulus: 2, variableTime: true), 0)
        XCTAssertEqual(UInt32(2).powMod(exponent: 3, modulus: 10, variableTime: true), 8)
        XCTAssertEqual(UInt32(3).powMod(exponent: 6, modulus: 10, variableTime: true), 9)
        XCTAssertEqual(UInt32(6).powMod(exponent: 3, modulus: 10, variableTime: true), 6)

        XCTAssertEqual(UInt32(12345).powMod(exponent: 3, modulus: 123_456_789, variableTime: true), 7_956_054)
        XCTAssertEqual(UInt64(12345).powMod(exponent: 4, modulus: 123_456_789, variableTime: true), 69_339_375)
        XCTAssertEqual(UInt64(12345).powMod(exponent: 1000, modulus: 123_456_789, variableTime: true), 74_706_300)
    }

    func testInverseMod() throws {
        XCTAssertEqual(try UInt32(1).inverseMod(modulus: 2, variableTime: true), 1)
        XCTAssertEqual(try UInt32(4).inverseMod(modulus: 19, variableTime: true), 5)
        XCTAssertEqual(try UInt32(4).inverseMod(modulus: 19, variableTime: true), 5)

        let x = UInt64((1 << 58) + (1 << 32))
        let modulus = UInt64((1 << 60) - 279)

        let inverse = try x.inverseMod(modulus: modulus, variableTime: true)
        XCTAssertEqual(inverse.multiplyMod(x, modulus: modulus, variableTime: true), 1)

        XCTAssertThrowsError(
            try UInt32(4).inverseMod(modulus: 16, variableTime: true),
            error: HeError.notInvertible(modulus: 16))
        XCTAssertThrowsError(
            try UInt32(0).inverseMod(modulus: 7, variableTime: true),
            error: HeError.notInvertible(modulus: 7))
    }

    func testIsPowerOfTwo() {
        XCTAssertFalse((-4).isPowerOfTwo)
        XCTAssertFalse(0.isPowerOfTwo)
        for shift in 0..<UInt64.bitWidth {
            XCTAssertTrue((UInt64(1) << shift).isPowerOfTwo)
            XCTAssertFalse(((UInt64(1) << shift) + 5).isPowerOfTwo)
        }
        for shift in 0..<UInt32.bitWidth {
            XCTAssertTrue((UInt32(1) << shift).isPowerOfTwo)
            XCTAssertFalse(((UInt32(1) << shift) + 5).isPowerOfTwo)
        }
    }

    func testNextPowerOfTwo() {
        XCTAssertEqual(0.nextPowerOfTwo, 1)
        XCTAssertEqual(1.nextPowerOfTwo, 1)
        XCTAssertEqual(2.nextPowerOfTwo, 2)
        XCTAssertEqual(3.nextPowerOfTwo, 4)
        XCTAssertEqual(4.nextPowerOfTwo, 4)
    }

    func testPreviousPowerOfTwo() {
        XCTAssertEqual(1.previousPowerOfTwo, 1)
        XCTAssertEqual(2.previousPowerOfTwo, 2)
        XCTAssertEqual(3.previousPowerOfTwo, 2)
        XCTAssertEqual(4.previousPowerOfTwo, 4)
        XCTAssertEqual(63.previousPowerOfTwo, 32)
        XCTAssertEqual(64.previousPowerOfTwo, 64)
        XCTAssertEqual(65.previousPowerOfTwo, 64)
    }

    func testNextMultiple() {
        XCTAssertEqual(0.nextMultiple(of: 0, variableTime: true), 0)
        XCTAssertEqual(0.nextMultiple(of: 7, variableTime: true), 0)
        XCTAssertEqual(3.nextMultiple(of: 7, variableTime: true), 7)
        XCTAssertEqual(7.nextMultiple(of: 7, variableTime: true), 7)
        XCTAssertEqual(8.nextMultiple(of: 7, variableTime: true), 14)
    }

    func testPreviousMultiple() {
        XCTAssertEqual(0.previousMultiple(of: 0, variableTime: true), 0)
        XCTAssertEqual(0.previousMultiple(of: 7, variableTime: true), 0)
        XCTAssertEqual(3.previousMultiple(of: 7, variableTime: true), 0)
        XCTAssertEqual(7.previousMultiple(of: 7, variableTime: true), 7)
        XCTAssertEqual(8.previousMultiple(of: 7, variableTime: true), 7)
    }

    func testIsPrime() {
        let smallPrimes = [2, 3, 5, UInt32(1 << 14) - 65, UInt32(1 << 15) - 49, UInt32(1 << 16) - 17]
        let primes = smallPrimes + [(UInt32(1) << 28) - 183, (UInt32(1) << 29) - 3]
        let composites = [UInt64(1)] + zip(primes, primes.shuffled()).map { UInt64($0) * UInt64($1) }
        for prime in primes {
            XCTAssertTrue(prime.isPrime(variableTime: true))
        }
        for composite in composites {
            XCTAssertFalse(composite.isPrime(variableTime: true))
        }

        let primes1k: Int = (1..<UInt32(1000)).count { $0.isPrime(variableTime: true) }
        XCTAssertEqual(primes1k, 168)
    }

    func testGeneratePrimes() throws {
        XCTAssertEqual(
            try UInt64.generatePrimes(significantBitCounts: [62], preferringSmall: false),
            [UInt64(4_611_686_018_427_387_847)])
        XCTAssertEqual(
            try UInt64.generatePrimes(significantBitCounts: [61], preferringSmall: false),
            [UInt64(2_305_843_009_213_693_951)])
        XCTAssertEqual(
            try UInt64.generatePrimes(significantBitCounts: [60], preferringSmall: true),
            [576_460_752_303_423_619])
        XCTAssertEqual(
            try UInt64.generatePrimes(significantBitCounts: [60], preferringSmall: false),
            [1_152_921_504_606_846_883])
        XCTAssertEqual(
            try UInt64.generatePrimes(significantBitCounts: [45, 46, 46], preferringSmall: false),
            [35_184_372_088_777,
             70_368_744_177_643,
             70_368_744_177_607])
        XCTAssertEqual(
            try UInt64.generatePrimes(significantBitCounts: [45, 46, 45, 46, 45], preferringSmall: true),
            [17_592_186_044_423,
             35_184_372_088_891,
             17_592_186_044_437,
             35_184_372_088_907,
             17_592_186_044_443])
        XCTAssertEqual(
            try UInt32.generatePrimes(significantBitCounts: [27, 28, 28], preferringSmall: true, nttDegree: 1024),
            [67_127_297,
             134_246_401,
             134_250_497])
        XCTAssertEqual(
            try UInt32.generatePrimes(significantBitCounts: [30], preferringSmall: false, nttDegree: 2048),
            [1_073_692_673])

        XCTAssertThrowsError(
            try UInt32.generatePrimes(significantBitCounts: [5], preferringSmall: true, nttDegree: 1024),
            error: HeError.notEnoughPrimes(significantBitCounts: [5], preferringSmall: true, nttDegree: 1024))
    }

    func testMultiplyConstantModulus() {
        func runMultiplyConstantModulusTest<T: ScalarType>(_: T.Type) {
            for _ in 0...100 {
                let p = T.random(in: 0..<(1 << (T.bitWidth - 1)))
                let x = T.random(in: 0..<p)
                let y = T.random(in: 0..<p)
                let modulus = MultiplyConstantModulus(multiplicand: x, modulus: p, variableTime: true)
                let prod = modulus.multiplyMod(y)
                XCTAssertEqual(
                    prod,
                    x.multiplyMod(y, modulus: p, variableTime: true))
            }
        }
        runMultiplyConstantModulusTest(UInt32.self)
        runMultiplyConstantModulusTest(UInt64.self)
    }

    func testMultiplyMod() {
        XCTAssertEqual(0.multiplyMod(3, modulus: 5, variableTime: true), 0)
        XCTAssertEqual(1.multiplyMod(3, modulus: 5, variableTime: true), 3)
        XCTAssertEqual(2.multiplyMod(3, modulus: 5, variableTime: true), 1)
        XCTAssertEqual(3.multiplyMod(3, modulus: 5, variableTime: true), 4)
        XCTAssertEqual(4.multiplyMod(3, modulus: 5, variableTime: true), 2)

        XCTAssertEqual(
            ((UInt32(1) << 31) - 1).multiplyMod((UInt32(1) << 31) - 2, modulus: UInt32(1) << 31, variableTime: true),
            2)
        XCTAssertEqual(
            ((UInt64(1) << 63) - 1).multiplyMod((UInt64(1) << 63) - 2, modulus: UInt64(1) << 63, variableTime: true),
            2)
    }

    func testReverseBits() {
        XCTAssertEqual(UInt32(0).reverseBits(bitCount: 1), 0)
        XCTAssertEqual(UInt32(0).reverseBits(bitCount: 32), 0)

        XCTAssertEqual((UInt32(1) << 31).reverseBits(bitCount: 32), 1)
        XCTAssertEqual(UInt32.max.reverseBits(bitCount: 32), UInt32.max)

        XCTAssertEqual(UInt32(0xFF00_F00F).reverseBits(bitCount: 32), 0xF00F_00FF)
        XCTAssertEqual(UInt32(0xFF00).reverseBits(bitCount: 16), 0x00FF)
    }

    func testDividingFloor() {
        func runDividingFloorSingleWidthTest<T: ScalarType>(_: T.Type) {
            for shift in 2..<T.bitWidth - 3 {
                for _ in 0..<100 {
                    let p = T.random(in: 2..<(1 << shift))
                    let modulus = Modulus<T>(modulus: p, variableTime: true)
                    let x = T.random(in: 0...T.max)
                    XCTAssertEqual(modulus.dividingFloor(dividend: x), x / p)
                    XCTAssertEqual(x.dividingFloor(by: modulus), x / p)
                }
            }
        }

        func runDividingFloorDoubleWidthTest<T: ScalarType>(_: T.Type) {
            for shift in 2..<T.bitWidth - 3 {
                for _ in 0..<100 {
                    let p = T.random(in: 2..<(1 << shift))
                    let modulus = Modulus<T>(modulus: p, variableTime: true)
                    let x = T.DoubleWidth((
                        high: T.random(in: 0...T.max),
                        low: T.Magnitude.random(in: 0...T.Magnitude.max)))
                    XCTAssertEqual(modulus.dividingFloor(dividend: x), x / T.DoubleWidth(p))
                    XCTAssertEqual(x.dividingFloor(by: modulus), x / T.DoubleWidth(p))
                }
            }
        }

        runDividingFloorSingleWidthTest(UInt32.self)
        runDividingFloorSingleWidthTest(UInt64.self)
        runDividingFloorDoubleWidthTest(UInt32.self)
        runDividingFloorDoubleWidthTest(UInt64.self)
    }

    func testReduceSingleWord() {
        func runReduceSingleWordTest<T: ScalarType>(_: T.Type) {
            for shift in 2..<T.bitWidth - 3 {
                for _ in 0..<100 {
                    let p = T.random(in: 2..<(1 << shift))
                    let modulus = ReduceModulus<T>(
                        modulus: p,
                        bound: ReduceModulus.InputBound.SingleWord,
                        variableTime: true)
                    let x = T.random(in: 0..<p)
                    XCTAssertEqual(modulus.reduce(x), x % p)

                    let xAny = T.random(in: p...T.max)
                    XCTAssertEqual(modulus.reduce(xAny), xAny % p)
                }
            }
        }
        runReduceSingleWordTest(UInt32.self)
        runReduceSingleWordTest(UInt64.self)
    }

    func testReduceSignedSingleWord() {
        func runReduceSingleWordTest<T: ScalarType>(_: T.Type) {
            func slowSignedReduce(of x: T.SignedScalar, mod modulus: T) -> T {
                let remainder = x.quotientAndRemainder(dividingBy: T.SignedScalar(modulus)).remainder
                return T(remainder < 0 ? remainder + T.SignedScalar(modulus) : remainder)
            }

            for shift in 2..<T.bitWidth - 3 {
                for _ in 0..<100 {
                    let p = T.random(in: 3..<(1 << shift))
                    let modulus = ReduceModulus<T>(
                        modulus: p,
                        bound: ReduceModulus.InputBound.SingleWord,
                        variableTime: true)
                    let pSigned = T.SignedScalar(p)
                    let x = T.SignedScalar.random(in: -pSigned / 2..<pSigned / 2)
                    XCTAssertEqual(modulus.reduce(x), slowSignedReduce(of: x, mod: p))

                    let largePositive = T.SignedScalar.random(in: pSigned / 2...T.SignedScalar.max)
                    XCTAssertEqual(modulus.reduce(largePositive), slowSignedReduce(of: largePositive, mod: p))

                    let largeNegative = T.SignedScalar.random(in: -pSigned / 2..<0)
                    XCTAssertEqual(modulus.reduce(largeNegative), slowSignedReduce(of: largeNegative, mod: p))
                }
            }
        }
        runReduceSingleWordTest(UInt32.self)
        runReduceSingleWordTest(UInt64.self)
    }

    func testReduceModulusSquared() {
        func runReduceModulusSquaredTest<T: ScalarType>(_: T.Type) {
            for shift in 2..<T.bitWidth - 3 {
                for _ in 0...100 {
                    let p = T.random(in: 2..<(1 << shift))
                    let modulus = ReduceModulus(
                        modulus: p,
                        bound: ReduceModulus.InputBound.ModulusSquared,
                        variableTime: true)
                    let x = T.random(in: 0..<p)
                    let y = T.random(in: 0..<p)
                    let prod = T.DoubleWidth(x.multipliedFullWidth(by: y))
                    XCTAssertEqual(modulus.reduceProduct(prod), x.multiplyMod(y, modulus: p, variableTime: true))
                }
            }
        }
        runReduceModulusSquaredTest(UInt32.self)
        runReduceModulusSquaredTest(UInt64.self)
    }

    func testReduceDoubleWord() {
        func runReduceDoubleWordTest<T: ScalarType>(_: T.Type) {
            for shift in 2..<T.bitWidth - 3 {
                for _ in 0...100 {
                    let p = T.random(in: 2..<(1 << shift))
                    let modulus = ReduceModulus(
                        modulus: p,
                        bound: ReduceModulus.InputBound.DoubleWord,
                        variableTime: true)
                    let x = T.DoubleWidth((
                        high: T.random(in: 0...T.max),
                        low: T.Magnitude.random(in: 0...T.Magnitude.max)))
                    let xModP = (x % T.DoubleWidth(p))
                    XCTAssertEqual(modulus.reduce(x), T(xModP))
                }
            }
        }
        runReduceDoubleWordTest(UInt32.self)
        runReduceDoubleWordTest(UInt64.self)
    }

    func testReduceMultiplyMod() {
        func runReduceMultiplyModTest<T: ScalarType>(_: T.Type) {
            for shift in 2..<T.bitWidth - 3 {
                for _ in 0...100 {
                    let p = T.random(in: 2..<(1 << shift))
                    let modulus = ReduceModulus(
                        modulus: p,
                        bound: ReduceModulus.InputBound.ModulusSquared,
                        variableTime: true)
                    let x = T.random(in: 0..<p)
                    let y = T.random(in: 0..<p)
                    let xModP = x.multiplyMod(y, modulus: p, variableTime: true)
                    XCTAssertEqual(modulus.multiplyMod(x, y), xModP)
                }
            }
        }
        runReduceMultiplyModTest(UInt32.self)
        runReduceMultiplyModTest(UInt64.self)
    }

    func testLog2() {
        XCTAssertEqual(1.log2, 0)
        XCTAssertEqual(2.log2, 1)
        XCTAssertEqual(3.log2, 1)
        XCTAssertEqual(4.log2, 2)
        XCTAssertEqual(5.log2, 2)
    }

    func testCeilLog2() {
        XCTAssertEqual(1.ceilLog2, 0)
        XCTAssertEqual(2.ceilLog2, 1)
        XCTAssertEqual(3.ceilLog2, 2)
        XCTAssertEqual(4.ceilLog2, 2)
        XCTAssertEqual(5.ceilLog2, 3)
    }

    func testSignificantBits() {
        XCTAssertEqual(0.significantBitCount, 0)
        XCTAssertEqual(1.significantBitCount, 1)
        XCTAssertEqual(2.significantBitCount, 2)
        XCTAssertEqual(3.significantBitCount, 2)
        XCTAssertEqual(4.significantBitCount, 3)
        XCTAssertEqual(5.significantBitCount, 3)
    }

    func testDividingCeil() {
        XCTAssertEqual(Int32(0).dividingCeil(3, variableTime: true), 0)
        XCTAssertEqual(Int32(9).dividingCeil(3, variableTime: true), 3)
        XCTAssertEqual(Int32(9).dividingCeil(2, variableTime: true), 5)
        XCTAssertEqual(Int32(9).dividingCeil(10, variableTime: true), 1)

        XCTAssertEqual(Int32(0).dividingCeil(-3, variableTime: true), 0)
        XCTAssertEqual(Int32(9).dividingCeil(-3, variableTime: true), -3)
        XCTAssertEqual(Int32(9).dividingCeil(-2, variableTime: true), -4)
        XCTAssertEqual(Int32(9).dividingCeil(-10, variableTime: true), 0)

        XCTAssertEqual(Int32(-9).dividingCeil(3, variableTime: true), -3)
        XCTAssertEqual(Int32(-9).dividingCeil(2, variableTime: true), -4)
        XCTAssertEqual(Int32(-9).dividingCeil(10, variableTime: true), 0)

        XCTAssertEqual(Int32(-9).dividingCeil(-3, variableTime: true), 3)
        XCTAssertEqual(Int32(-9).dividingCeil(-2, variableTime: true), 5)
        XCTAssertEqual(Int32(-9).dividingCeil(-10, variableTime: true), 1)
    }

    func testConstantTimeSelect() {
        XCTAssertEqual(UInt32.constantTimeSelect(if: UInt32.max, then: 1, else: 2), 1)
        XCTAssertEqual(UInt32.constantTimeSelect(if: 0, then: 1, else: 2), 2)

        XCTAssertEqual(UInt64.constantTimeSelect(if: UInt64.max, then: 1, else: 2), 1)
        XCTAssertEqual(UInt64.constantTimeSelect(if: 0, then: 1, else: 2), 2)
    }

    func testConstantTimeGreaterThan() {
        XCTAssertEqual(UInt32(5).constantTimeGreaterThan(5), 0)
        XCTAssertEqual(UInt32(5).constantTimeGreaterThan(4), UInt32.max)
        for _ in 0..<100 {
            let x = UInt32.random(in: 0...UInt32.max)
            let y = UInt32.random(in: 0...UInt32.max)
            XCTAssertEqual(x.constantTimeGreaterThan(y), x > y ? UInt32.max : 0)
        }
    }

    func testConstantTimeGreaterThanOrEqual() {
        XCTAssertEqual(UInt32(5).constantTimeGreaterThanOrEqual(6), 0)
        XCTAssertEqual(UInt32(5).constantTimeGreaterThanOrEqual(5), UInt32.max)
        XCTAssertEqual(UInt32(5).constantTimeGreaterThanOrEqual(4), UInt32.max)
        for _ in 0..<100 {
            let x = UInt32.random(in: 0...UInt32.max)
            let y = UInt32.random(in: 0...UInt32.max)
            XCTAssertEqual(x.constantTimeGreaterThanOrEqual(y), x >= y ? UInt32.max : 0)
            XCTAssertEqual(x.constantTimeGreaterThanOrEqual(x), UInt32.max)
        }
    }

    func testConstantTimeEqual() {
        XCTAssertEqual(UInt32(5).constantTimeEqual(5), UInt32.max)
        XCTAssertEqual(UInt32(5).constantTimeEqual(4), 0)
        XCTAssertEqual(UInt64.max.constantTimeEqual(UInt64.max), UInt64.max)
        XCTAssertEqual(UInt64.max.constantTimeEqual(UInt64.max - 1), 0)
    }

    func testConstantTimeMostSignificantBit() {
        XCTAssertEqual(UInt32.max.constantTimeMostSignificantBit(), UInt32.max)
        XCTAssertEqual((UInt32.max >> 1).constantTimeMostSignificantBit(), 0)
    }

    func testConstantTimeLessThan() {
        XCTAssertEqual(UInt32(5).constantTimeLessThan(5), 0)
        XCTAssertEqual(UInt32(4).constantTimeLessThan(5), UInt32.max)
        for _ in 0..<100 {
            let x = UInt32.random(in: 0...UInt32.max)
            let y = UInt32.random(in: 0...UInt32.max)
            XCTAssertEqual(x.constantTimeLessThan(y), x < y ? UInt32.max : 0)
        }
    }

    func testRemainderToCentered() throws {
        func runTest<T: ScalarType>(modulus: T) throws {
            var centered = (0..<modulus).map { v in
                v.remainderToCentered(modulus: modulus)
            }
            centered.sort()
            let signedModulus = T.SignedScalar(modulus)
            let expected = Array((-signedModulus / 2...((signedModulus - 1) / 2)))
            XCTAssertEqual(centered, expected)
        }
        try runTest(modulus: UInt32(97))
        try runTest(modulus: UInt64(110))
    }

    func testSignedConstantTimeSelect() {
        XCTAssertEqual(Int32.constantTimeSelect(if: UInt32.max, then: -1, else: -2), -1)
        XCTAssertEqual(Int32.constantTimeSelect(if: 0, then: -1, else: 2), 2)

        XCTAssertEqual(Int64.constantTimeSelect(if: UInt64.max, then: -1, else: -2), -1)
        XCTAssertEqual(Int64.constantTimeSelect(if: 0, then: -1, else: 2), 2)
    }

    func testCenteredToRemainder() throws {
        func runTest<T: SignedScalarType>(modulus: T) {
            var remainders = (-modulus / 2...((modulus - 1) / 2)).map { v in
                let remainder = v.centeredToRemainder(modulus: T.UnsignedScalar(modulus))
                let centeredRoundtrip = remainder.remainderToCentered(modulus: T.UnsignedScalar(modulus))
                XCTAssertEqual(centeredRoundtrip, v)
                return remainder
            }
            remainders.sort()
            let expected: [T.UnsignedScalar] = Array(0..<T.UnsignedScalar(modulus))
            XCTAssertEqual(remainders, expected)
        }
        runTest(modulus: Int32(97))
        runTest(modulus: Int64(110))
    }

    func testCenteredRemainderRoundTrip() throws {
        func runTest<T: SignedScalarType>(modulus: T) {
            let unsignedModulus = T.UnsignedScalar(modulus)
            let low: T = -modulus / 2
            let high: T = (modulus - 1) / 2
            let signedValues: [T] = [low, low + 1, low + 2, -1, 0, 1, high - 2, high - 1, high]
            let signedRoundTrip = signedValues.map { value in
                value.centeredToRemainder(modulus: unsignedModulus)
            }.map { value in
                value.remainderToCentered(modulus: unsignedModulus)
            }
            XCTAssertEqual(signedValues, signedRoundTrip)

            let mid: T.UnsignedScalar = (unsignedModulus - 1) / 2
            let values: [T.UnsignedScalar] = [0, 1, 2, mid - 1, mid, mid + 1, unsignedModulus - 2, unsignedModulus - 1]
            let roundTrip = values.map { value in
                value.remainderToCentered(modulus: unsignedModulus)
            }.map { value in
                value.centeredToRemainder(modulus: unsignedModulus)
            }
            XCTAssertEqual(values, roundTrip)
        }
        runTest(modulus: Int32(1 << 31 - 63))
        runTest(modulus: Int64(1 << 62))
    }
}
