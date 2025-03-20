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
import ModularArithmetic
import Testing

@Suite
struct ScalarTests {
    @Test
    func subtractIfExceeds() {
        do {
            let modulus: UInt32 = (1 << 29) - 63
            #expect(UInt32(2 * modulus + 1).subtractIfExceeds(modulus) == modulus + 1)
            #expect(UInt32(modulus - 1).subtractIfExceeds(modulus) == modulus - 1)
        }
        do {
            let modulus: UInt32 = (1 << 31) - 10
            let max = (UInt32.max >> 1) + modulus
            #expect(UInt32(max).subtractIfExceeds(modulus) == max - modulus)
            #expect(UInt32(modulus - 1).subtractIfExceeds(modulus) == modulus - 1)
        }
    }

    @Test
    func addMod() {
        #expect(UInt32(0).addMod(1, modulus: 3) == 1)
        #expect(UInt32(1).addMod(2, modulus: 3) == 0)
        #expect(UInt32(2).addMod(2, modulus: 3) == 1)

        #expect(UInt64(0).addMod(1, modulus: 3) == 1)
        #expect(UInt64(1).addMod(2, modulus: 3) == 0)
        #expect(UInt64(2).addMod(2, modulus: 3) == 1)

        let one = UInt64(1)
        #expect((one << 62).addMod((one << 62) + 3, modulus: (one << 62) + 4) == (one << 62) - 1)
    }

    @Test
    func negateMod() {
        #expect(UInt32(0).negateMod(modulus: 3) == 0)
        #expect(UInt32(1).negateMod(modulus: 3) == 2)
        #expect(UInt32(2).negateMod(modulus: 3) == 1)

        #expect(UInt64(0).negateMod(modulus: 3) == 0)
        #expect(UInt64(1).negateMod(modulus: 3) == 2)
        #expect(UInt64(2).negateMod(modulus: 3) == 1)
    }

    @Test
    func subtractMod() {
        #expect(UInt32(0).subtractMod(2, modulus: 3) == 1)
        #expect(UInt32(1).subtractMod(1, modulus: 3) == 0)
        #expect(UInt32(2).subtractMod(1, modulus: 3) == 1)

        #expect(UInt64(0).subtractMod(2, modulus: 3) == 1)
        #expect(UInt64(1).subtractMod(1, modulus: 3) == 0)
        #expect(UInt64(2).subtractMod(1, modulus: 3) == 1)
    }

    @Test
    func powMod() {
        #expect(UInt32(0).powMod(exponent: 1, modulus: 2, variableTime: true) == 0)
        #expect(UInt32(2).powMod(exponent: 3, modulus: 10, variableTime: true) == 8)
        #expect(UInt32(3).powMod(exponent: 6, modulus: 10, variableTime: true) == 9)
        #expect(UInt32(6).powMod(exponent: 3, modulus: 10, variableTime: true) == 6)

        #expect(UInt32(12345).powMod(exponent: 3, modulus: 123_456_789, variableTime: true) == 7_956_054)
        #expect(UInt64(12345).powMod(exponent: 4, modulus: 123_456_789, variableTime: true) == 69_339_375)
        #expect(UInt64(12345).powMod(exponent: 1000, modulus: 123_456_789, variableTime: true) == 74_706_300)
    }

    @Test
    func inverseMod() throws {
        #expect(try UInt32(1).inverseMod(modulus: 2, variableTime: true) == 1)
        #expect(try UInt32(4).inverseMod(modulus: 19, variableTime: true) == 5)
        #expect(try UInt32(4).inverseMod(modulus: 19, variableTime: true) == 5)

        let x = UInt64((1 << 58) + (1 << 32))
        let modulus = UInt64((1 << 60) - 279)

        let inverse = try x.inverseMod(modulus: modulus, variableTime: true)
        #expect(inverse.multiplyMod(x, modulus: modulus, variableTime: true) == 1)

        #expect(throws: HeError.notInvertible(modulus: 16)) {
            try UInt32(4).inverseMod(modulus: 16, variableTime: true)
        }
        #expect(throws: HeError.notInvertible(modulus: 7)) {
            try UInt32(0).inverseMod(modulus: 7, variableTime: true)
        }
    }

    @Test
    func isPowerOfTwo() {
        #expect(!(-4).isPowerOfTwo)
        #expect(!0.isPowerOfTwo)
        for shift in 0..<UInt64.bitWidth {
            #expect((UInt64(1) << shift).isPowerOfTwo)
            #expect(!((UInt64(1) << shift) + 5).isPowerOfTwo)
        }
        for shift in 0..<UInt32.bitWidth {
            #expect((UInt32(1) << shift).isPowerOfTwo)
            #expect(!((UInt32(1) << shift) + 5).isPowerOfTwo)
        }
    }

    @Test
    func nextPowerOfTwo() {
        #expect(0.nextPowerOfTwo == 1)
        #expect(1.nextPowerOfTwo == 1)
        #expect(2.nextPowerOfTwo == 2)
        #expect(3.nextPowerOfTwo == 4)
        #expect(4.nextPowerOfTwo == 4)
    }

    @Test
    func previousPowerOfTwo() {
        #expect(1.previousPowerOfTwo == 1)
        #expect(2.previousPowerOfTwo == 2)
        #expect(3.previousPowerOfTwo == 2)
        #expect(4.previousPowerOfTwo == 4)
        #expect(63.previousPowerOfTwo == 32)
        #expect(64.previousPowerOfTwo == 64)
        #expect(65.previousPowerOfTwo == 64)
    }

    @Test
    func nextMultiple() {
        #expect(0.nextMultiple(of: 0, variableTime: true) == 0)
        #expect(0.nextMultiple(of: 7, variableTime: true) == 0)
        #expect(3.nextMultiple(of: 7, variableTime: true) == 7)
        #expect(7.nextMultiple(of: 7, variableTime: true) == 7)
        #expect(8.nextMultiple(of: 7, variableTime: true) == 14)
    }

    @Test
    func previousMultiple() {
        #expect(0.previousMultiple(of: 0, variableTime: true) == 0)
        #expect(0.previousMultiple(of: 7, variableTime: true) == 0)
        #expect(3.previousMultiple(of: 7, variableTime: true) == 0)
        #expect(7.previousMultiple(of: 7, variableTime: true) == 7)
        #expect(8.previousMultiple(of: 7, variableTime: true) == 7)
    }

    @Test
    func isPrime() {
        let smallPrimes = [2, 3, 5, UInt32(1 << 14) - 65, UInt32(1 << 15) - 49, UInt32(1 << 16) - 17]
        let primes = smallPrimes + [(UInt32(1) << 28) - 183, (UInt32(1) << 29) - 3]
        let composites = [UInt64(1)] + zip(primes, primes.shuffled()).map { UInt64($0) * UInt64($1) }
        for prime in primes {
            #expect(prime.isPrime(variableTime: true))
        }
        for composite in composites {
            #expect(!composite.isPrime(variableTime: true))
        }

        let primes1k: Int = (1..<UInt32(1000)).count { $0.isPrime(variableTime: true) }
        #expect(primes1k == 168)
    }

    @Test
    func generatePrimes() throws {
        #expect(
            try UInt64.generatePrimes(significantBitCounts: [62], preferringSmall: false) ==
                [UInt64(4_611_686_018_427_387_847)])
        #expect(
            try UInt64.generatePrimes(significantBitCounts: [61], preferringSmall: false) ==
                [UInt64(2_305_843_009_213_693_951)])
        #expect(
            try UInt64.generatePrimes(significantBitCounts: [60], preferringSmall: true) ==
                [576_460_752_303_423_619])
        #expect(
            try UInt64.generatePrimes(significantBitCounts: [60], preferringSmall: false) ==
                [1_152_921_504_606_846_883])
        #expect(
            try UInt64.generatePrimes(significantBitCounts: [45, 46, 46], preferringSmall: false) ==
                [35_184_372_088_777,
                 70_368_744_177_643,
                 70_368_744_177_607])
        #expect(
            try UInt64.generatePrimes(significantBitCounts: [45, 46, 45, 46, 45], preferringSmall: true) ==
                [17_592_186_044_423,
                 35_184_372_088_891,
                 17_592_186_044_437,
                 35_184_372_088_907,
                 17_592_186_044_443])
        #expect(
            try UInt32.generatePrimes(significantBitCounts: [27, 28, 28], preferringSmall: true, nttDegree: 1024) ==
                [67_127_297,
                 134_246_401,
                 134_250_497])
        #expect(
            try UInt32.generatePrimes(significantBitCounts: [30], preferringSmall: false, nttDegree: 2048) ==
                [1_073_692_673])

        #expect(throws: HeError.notEnoughPrimes(significantBitCounts: [5], preferringSmall: true, nttDegree: 1024)) {
            try UInt32.generatePrimes(significantBitCounts: [5], preferringSmall: true, nttDegree: 1024)
        }
    }

    @Test
    func multiplyConstantModulus() {
        func runMultiplyConstantModulusTest<T: ScalarType>(_: T.Type) {
            for _ in 0...100 {
                let p = T.random(in: 0..<(1 << (T.bitWidth - 1)))
                let x = T.random(in: 0..<p)
                let y = T.random(in: 0..<p)
                let modulus = MultiplyConstantModulus(multiplicand: x, modulus: p, variableTime: true)
                let prod = modulus.multiplyMod(y)
                #expect(prod == x.multiplyMod(y, modulus: p, variableTime: true))
            }
        }
        runMultiplyConstantModulusTest(UInt32.self)
        runMultiplyConstantModulusTest(UInt64.self)
    }

    @Test
    func multiplyMod() {
        #expect(0.multiplyMod(3, modulus: 5, variableTime: true) == 0)
        #expect(1.multiplyMod(3, modulus: 5, variableTime: true) == 3)
        #expect(2.multiplyMod(3, modulus: 5, variableTime: true) == 1)
        #expect(3.multiplyMod(3, modulus: 5, variableTime: true) == 4)
        #expect(4.multiplyMod(3, modulus: 5, variableTime: true) == 2)

        #expect(
            ((UInt32(1) << 31) - 1).multiplyMod((UInt32(1) << 31) - 2, modulus: UInt32(1) << 31, variableTime: true) ==
                2)
        #expect(
            ((UInt64(1) << 63) - 1).multiplyMod((UInt64(1) << 63) - 2, modulus: UInt64(1) << 63, variableTime: true) ==
                2)
    }

    @Test
    func reverseBits() {
        #expect(UInt32(0).reverseBits(bitCount: 1) == 0)
        #expect(UInt32(0).reverseBits(bitCount: 32) == 0)

        #expect((UInt32(1) << 31).reverseBits(bitCount: 32) == 1)
        #expect(UInt32.max.reverseBits(bitCount: 32) == UInt32.max)

        #expect(UInt32(0xFF00_F00F).reverseBits(bitCount: 32) == 0xF00F_00FF)
        #expect(UInt32(0xFF00).reverseBits(bitCount: 16) == 0x00FF)
    }

    @Test
    func dividingFloor() {
        func runDividingFloorSingleWidthTest<T: ScalarType>(_: T.Type) {
            for shift in 2..<T.bitWidth - 3 {
                for _ in 0..<100 {
                    let p = T.random(in: 2..<(1 << shift))
                    let modulus = Modulus<T>(modulus: p, variableTime: true)
                    let x = T.random(in: 0...T.max)
                    #expect(modulus.dividingFloor(dividend: x) == x / p)
                    #expect(x.dividingFloor(by: modulus) == x / p)
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
                    #expect(modulus.dividingFloor(dividend: x) == x / T.DoubleWidth(p))
                    #expect(x.dividingFloor(by: modulus) == x / T.DoubleWidth(p))
                }
            }
        }

        runDividingFloorSingleWidthTest(UInt32.self)
        runDividingFloorSingleWidthTest(UInt64.self)
        runDividingFloorDoubleWidthTest(UInt32.self)
        runDividingFloorDoubleWidthTest(UInt64.self)
    }

    @Test
    func reduceSingleWord() {
        func runReduceSingleWordTest<T: ScalarType>(_: T.Type) {
            for shift in 2..<T.bitWidth - 3 {
                for _ in 0..<100 {
                    let p = T.random(in: 2..<(1 << shift))
                    let modulus = ReduceModulus<T>(
                        modulus: p,
                        bound: ReduceModulus.InputBound.SingleWord,
                        variableTime: true)
                    let x = T.random(in: 0..<p)
                    #expect(modulus.reduce(x) == x % p)

                    let xAny = T.random(in: p...T.max)
                    #expect(modulus.reduce(xAny) == xAny % p)
                }
            }
        }
        runReduceSingleWordTest(UInt32.self)
        runReduceSingleWordTest(UInt64.self)
    }

    @Test
    func reduceSignedSingleWord() {
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
                    #expect(modulus.reduce(x) == slowSignedReduce(of: x, mod: p))

                    let largePositive = T.SignedScalar.random(in: pSigned / 2...T.SignedScalar.max)
                    #expect(modulus.reduce(largePositive) == slowSignedReduce(of: largePositive, mod: p))

                    let largeNegative = T.SignedScalar.random(in: -pSigned / 2..<0)
                    #expect(modulus.reduce(largeNegative) == slowSignedReduce(of: largeNegative, mod: p))
                }
            }
        }
        runReduceSingleWordTest(UInt32.self)
        runReduceSingleWordTest(UInt64.self)
    }

    @Test
    func reduceModulusSquared() {
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
                    #expect(modulus.reduceProduct(prod) == x.multiplyMod(y, modulus: p, variableTime: true))
                }
            }
        }
        runReduceModulusSquaredTest(UInt32.self)
        runReduceModulusSquaredTest(UInt64.self)
    }

    @Test
    func reduceDoubleWord() {
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
                    #expect(modulus.reduce(x) == T(xModP))
                }
            }
        }
        runReduceDoubleWordTest(UInt32.self)
        runReduceDoubleWordTest(UInt64.self)
    }

    @Test
    func reduceMultiplyMod() {
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
                    #expect(modulus.multiplyMod(x, y) == xModP)
                }
            }
        }
        runReduceMultiplyModTest(UInt32.self)
        runReduceMultiplyModTest(UInt64.self)
    }

    @Test
    func log2() {
        #expect(1.log2 == 0)
        #expect(2.log2 == 1)
        #expect(3.log2 == 1)
        #expect(4.log2 == 2)
        #expect(5.log2 == 2)
    }

    @Test
    func ceilLog2() {
        #expect(1.ceilLog2 == 0)
        #expect(2.ceilLog2 == 1)
        #expect(3.ceilLog2 == 2)
        #expect(4.ceilLog2 == 2)
        #expect(5.ceilLog2 == 3)
    }

    @Test
    func significantBits() {
        #expect(0.significantBitCount == 0)
        #expect(1.significantBitCount == 1)
        #expect(2.significantBitCount == 2)
        #expect(3.significantBitCount == 2)
        #expect(4.significantBitCount == 3)
        #expect(5.significantBitCount == 3)
    }

    @Test
    func dividingCeil() {
        #expect(Int32(0).dividingCeil(3, variableTime: true) == 0)
        #expect(Int32(9).dividingCeil(3, variableTime: true) == 3)
        #expect(Int32(9).dividingCeil(2, variableTime: true) == 5)
        #expect(Int32(9).dividingCeil(10, variableTime: true) == 1)

        #expect(Int32(0).dividingCeil(-3, variableTime: true) == 0)
        #expect(Int32(9).dividingCeil(-3, variableTime: true) == -3)
        #expect(Int32(9).dividingCeil(-2, variableTime: true) == -4)
        #expect(Int32(9).dividingCeil(-10, variableTime: true) == 0)

        #expect(Int32(-9).dividingCeil(3, variableTime: true) == -3)
        #expect(Int32(-9).dividingCeil(2, variableTime: true) == -4)
        #expect(Int32(-9).dividingCeil(10, variableTime: true) == 0)

        #expect(Int32(-9).dividingCeil(-3, variableTime: true) == 3)
        #expect(Int32(-9).dividingCeil(-2, variableTime: true) == 5)
        #expect(Int32(-9).dividingCeil(-10, variableTime: true) == 1)
    }

    @Test
    func constantTimeSelect() {
        #expect(UInt32.constantTimeSelect(if: UInt32.max, then: 1, else: 2) == 1)
        #expect(UInt32.constantTimeSelect(if: 0, then: 1, else: 2) == 2)

        #expect(UInt64.constantTimeSelect(if: UInt64.max, then: 1, else: 2) == 1)
        #expect(UInt64.constantTimeSelect(if: 0, then: 1, else: 2) == 2)
    }

    @Test
    func constantTimeGreaterThan() {
        #expect(UInt32(5).constantTimeGreaterThan(5) == 0)
        #expect(UInt32(5).constantTimeGreaterThan(4) == UInt32.max)
        for _ in 0..<100 {
            let x = UInt32.random(in: 0...UInt32.max)
            let y = UInt32.random(in: 0...UInt32.max)
            #expect(x.constantTimeGreaterThan(y) == (x > y ? UInt32.max : 0))
        }
    }

    @Test
    func constantTimeGreaterThanOrEqual() {
        #expect(UInt32(5).constantTimeGreaterThanOrEqual(6) == 0)
        #expect(UInt32(5).constantTimeGreaterThanOrEqual(5) == UInt32.max)
        #expect(UInt32(5).constantTimeGreaterThanOrEqual(4) == UInt32.max)
        for _ in 0..<100 {
            let x = UInt32.random(in: 0...UInt32.max)
            let y = UInt32.random(in: 0...UInt32.max)
            #expect(x.constantTimeGreaterThanOrEqual(y) == (x >= y ? UInt32.max : 0))
            #expect(x.constantTimeGreaterThanOrEqual(x) == UInt32.max)
        }
    }

    @Test
    func constantTimeEqual() {
        #expect(UInt32(5).constantTimeEqual(5) == UInt32.max)
        #expect(UInt32(5).constantTimeEqual(4) == 0)
        #expect(UInt64.max.constantTimeEqual(UInt64.max) == UInt64.max)
        #expect(UInt64.max.constantTimeEqual(UInt64.max - 1) == 0)
    }

    @Test
    func constantTimeMostSignificantBit() {
        #expect(UInt32.max.constantTimeMostSignificantBit() == UInt32.max)
        #expect((UInt32.max >> 1).constantTimeMostSignificantBit() == 0)
    }

    @Test
    func constantTimeLessThan() {
        #expect(UInt32(5).constantTimeLessThan(5) == 0)
        #expect(UInt32(4).constantTimeLessThan(5) == UInt32.max)
        for _ in 0..<100 {
            let x = UInt32.random(in: 0...UInt32.max)
            let y = UInt32.random(in: 0...UInt32.max)
            #expect(x.constantTimeLessThan(y) == (x < y ? UInt32.max : 0))
        }
    }

    @Test
    func remainderToCentered() throws {
        func runTest<T: ScalarType>(modulus: T) throws {
            var centered = (0..<modulus).map { v in
                v.remainderToCentered(modulus: modulus)
            }
            centered.sort()
            let signedModulus = T.SignedScalar(modulus)
            let expected = Array((-signedModulus / 2...((signedModulus - 1) / 2)))
            #expect(centered == expected)
        }
        try runTest(modulus: UInt32(97))
        try runTest(modulus: UInt64(110))
    }

    @Test
    func signedConstantTimeSelect() {
        #expect(Int32.constantTimeSelect(if: UInt32.max, then: -1, else: -2) == -1)
        #expect(Int32.constantTimeSelect(if: 0, then: -1, else: 2) == 2)

        #expect(Int64.constantTimeSelect(if: UInt64.max, then: -1, else: -2) == -1)
        #expect(Int64.constantTimeSelect(if: 0, then: -1, else: 2) == 2)
    }

    @Test
    func centeredToRemainder() throws {
        func runTest<T: SignedScalarType>(modulus: T) {
            var remainders = (-modulus / 2...((modulus - 1) / 2)).map { v in
                let remainder = v.centeredToRemainder(modulus: T.UnsignedScalar(modulus))
                let centeredRoundtrip = remainder.remainderToCentered(modulus: T.UnsignedScalar(modulus))
                #expect(centeredRoundtrip == v)
                return remainder
            }
            remainders.sort()
            let expected: [T.UnsignedScalar] = Array(0..<T.UnsignedScalar(modulus))
            #expect(remainders == expected)
        }
        runTest(modulus: Int32(97))
        runTest(modulus: Int64(110))
    }

    @Test
    func centeredRemainderRoundTrip() throws {
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
            #expect(signedValues == signedRoundTrip)

            let mid: T.UnsignedScalar = (unsignedModulus - 1) / 2
            let values: [T.UnsignedScalar] = [0, 1, 2, mid - 1, mid, mid + 1, unsignedModulus - 2, unsignedModulus - 1]
            let roundTrip = values.map { value in
                value.remainderToCentered(modulus: unsignedModulus)
            }.map { value in
                value.centeredToRemainder(modulus: unsignedModulus)
            }
            #expect(values == roundTrip)
        }
        runTest(modulus: Int32(1 << 31 - 63))
        runTest(modulus: Int64(1 << 62))
    }
}
