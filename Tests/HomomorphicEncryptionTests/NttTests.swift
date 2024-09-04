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
import XCTest

final class NttTests: XCTestCase {
    func testIsPrimitiveRootOfUnity() {
        XCTAssertTrue(UInt32(12).isPrimitiveRootOfUnity(degree: 2, modulus: 13))
        XCTAssertFalse(UInt32(11).isPrimitiveRootOfUnity(degree: 2, modulus: 13))
        XCTAssertFalse(UInt32(12).isPrimitiveRootOfUnity(degree: 4, modulus: 13))

        XCTAssertTrue(UInt64(28).isPrimitiveRootOfUnity(degree: 2, modulus: 29))
        XCTAssertTrue(UInt64(12).isPrimitiveRootOfUnity(degree: 4, modulus: 29))
        XCTAssertFalse(UInt64(12).isPrimitiveRootOfUnity(degree: 2, modulus: 29))
        XCTAssertFalse(UInt64(12).isPrimitiveRootOfUnity(degree: 8, modulus: 29))

        XCTAssertTrue(UInt64(1_234_565_440).isPrimitiveRootOfUnity(degree: 2, modulus: 1_234_565_441))
        XCTAssertTrue(UInt64(960_907_033).isPrimitiveRootOfUnity(degree: 8, modulus: 1_234_565_441))
        XCTAssertTrue(UInt64(1_180_581_915).isPrimitiveRootOfUnity(degree: 16, modulus: 1_234_565_441))
        XCTAssertFalse(UInt64(1_180_581_915).isPrimitiveRootOfUnity(degree: 32, modulus: 1_234_565_441))
        XCTAssertFalse(UInt64(1_180_581_915).isPrimitiveRootOfUnity(degree: 8, modulus: 1_234_565_441))
        XCTAssertFalse(UInt64(1_180_581_915).isPrimitiveRootOfUnity(degree: 2, modulus: 1_234_565_441))
    }

    func testMinPrimitiveRootOfUnity() {
        XCTAssertEqual(UInt32(11).minPrimitiveRootOfUnity(degree: 2), 10)
        XCTAssertEqual(UInt32(29).minPrimitiveRootOfUnity(degree: 2), 28)
        XCTAssertEqual(UInt32(29).minPrimitiveRootOfUnity(degree: 4), 12)
        XCTAssertEqual(UInt64(1_234_565_441).minPrimitiveRootOfUnity(degree: 2), 1_234_565_440)
        XCTAssertEqual(UInt64(1_234_565_441).minPrimitiveRootOfUnity(degree: 8), 249_725_733)
    }

    private func runNttTest<T: ScalarType>(
        moduli: [T],
        coeffData: [[T]],
        evalData: [[T]]) throws
    {
        let rowCount = coeffData.count
        let columnCount = coeffData[0].count
        precondition(evalData.count == rowCount)
        precondition(evalData[0].count == columnCount)

        let coeffData = Array2d(data: coeffData)
        let evalData = Array2d(data: evalData)

        let context = try PolyContext(degree: columnCount, moduli: moduli)
        let polyCoeff = PolyRq<T, Coeff>(context: context, data: coeffData)
        let polyEval = PolyRq<T, Eval>(context: context, data: evalData)

        XCTAssertEqual(try polyCoeff.forwardNtt(), polyEval)
        XCTAssertEqual(try polyEval.inverseNtt(), polyCoeff)
        XCTAssertEqual(try polyEval.convertToCoeffFormat(), polyCoeff)
        XCTAssertEqual(try polyCoeff.convertToCoeffFormat(), polyCoeff)
        XCTAssertEqual(try polyEval.convertToEvalFormat(), polyEval)
        XCTAssertEqual(try polyCoeff.convertToEvalFormat(), polyEval)
    }

    func testNtt2() throws {
        try runNttTest(moduli: [UInt32(97)], coeffData: [[0, 0]], evalData: [[0, 0]])
        try runNttTest(moduli: [UInt32(97)], coeffData: [[1, 0]], evalData: [[1, 1]])

        try runNttTest(moduli: [UInt32(97)], coeffData: [[1, 2]], evalData: [[45, 54]])
        try runNttTest(moduli: [UInt32(113)], coeffData: [[3, 4]], evalData: [[63, 56]])
        try runNttTest(moduli: [UInt32(97), UInt32(113)], coeffData: [[1, 2], [3, 4]], evalData: [[45, 54], [63, 56]])
    }

    func testNtt4() throws {
        try runNttTest(moduli: [UInt32(97)], coeffData: [[0, 0, 0, 0]], evalData: [[0, 0, 0, 0]])
        try runNttTest(moduli: [UInt32(97)], coeffData: [[1, 0, 0, 0]], evalData: [[1, 1, 1, 1]])
        try runNttTest(moduli: [UInt32(97)], coeffData: [[1, 2, 3, 4]], evalData: [[30, 7, 64, 0]])
        try runNttTest(moduli: [UInt32(97), UInt32(113)],
                       coeffData: [[1, 2, 3, 4], [5, 6, 7, 8]], evalData: [[30, 7, 64, 0], [108, 31, 103, 4]])
    }

    func testNtt8() throws {
        try runNttTest(
            moduli: [UInt32(4_194_353)],
            coeffData: [[0, 0, 0, 0, 0, 0, 0, 0]],
            evalData: [[0, 0, 0, 0, 0, 0, 0, 0]])
        try runNttTest(
            moduli: [UInt32(4_194_353)],
            coeffData: [[1, 0, 0, 0, 0, 0, 0, 0]],
            evalData: [[1, 1, 1, 1, 1, 1, 1, 1]])
        try runNttTest(
            moduli: [UInt32(4_194_353)],
            coeffData: [[1, 2, 3, 4, 5, 6, 7, 8]],
            evalData: [[3_372_683, 765_982, 387_853, 2_657_954, 2_013_665, 1_280_882, 2_457_874, 3_840_527]])
        try runNttTest(
            moduli: [UInt32(4_194_353), UInt32(113)],
            coeffData: [[1, 2, 3, 4, 5, 6, 7, 8], [1, 0, 0, 0, 0, 0, 0, 0]],
            evalData: [
                [3_372_683, 765_982, 387_853, 2_657_954, 2_013_665, 1_280_882, 2_457_874, 3_840_527],
                [1, 1, 1, 1, 1, 1, 1, 1],
            ])
    }

    func testNtt16() throws {
        // modulus near top of range
        try runNttTest(
            moduli: [UInt32(536_870_849)],
            coeffData: [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
            evalData: [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]])
        try runNttTest(
            moduli: [UInt32(536_870_849)],
            coeffData: [[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
            evalData: [[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]])
        try runNttTest(
            moduli: [UInt32(536_870_849)],
            coeffData: [[
                477_051_601,
                421_524_611,
                456_257_859,
                247_136_825,
                128_775_020,
                76_785_070,
                49_764_016,
                525_812_772,
                325_605_371,
                88_935_943,
                255_470_762,
                39_507_048,
                404_978_219,
                379_383_003,
                244_420_585,
                346_826_612,
            ]], evalData: [[
                230_846_094,
                480_599_401,
                157_364_576,
                360_442_736,
                531_052_463,
                294_311_347,
                432_899_854,
                219_721_533,
                286_807_067,
                260_650_843,
                362_842_688,
                315_862_017,
                493_042_020,
                520_739_674,
                167_758_416,
                370_401_491,
            ]])
    }

    func testNtt32() throws {
        let modulus = UInt32(769)

        let zeros = [UInt32](repeating: 0, count: 32)
        var oneHot = zeros
        oneHot[0] = 1
        try runNttTest(moduli: [modulus], coeffData: [zeros], evalData: [zeros])
        try runNttTest(moduli: [modulus], coeffData: [oneHot], evalData: [Array(repeating: UInt32(1), count: 32)])

        let coeffData: [UInt32] = [401, 203, 221, 352, 487, 151, 405, 356, 343, 424, 635, 757, 457, 280, 624, 353,
                                   496, 353, 624, 280, 457, 757, 635, 424, 343, 356, 405, 151, 487, 352, 221, 203]
        let evalData: [UInt32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                                  24, 25, 26, 27, 28, 29, 30, 31, 32]
        try runNttTest(moduli: [modulus], coeffData: [coeffData], evalData: [evalData])
        try runNttTest(moduli: [modulus], coeffData: [coeffData], evalData: [evalData])
    }

    func testNtt4096() throws {
        let modulus = UInt64(557_057)
        let degree = 4096
        let zeros = [UInt64](repeating: 0, count: degree)
        var oneHot = zeros
        oneHot[0] = 1
        try runNttTest(moduli: [modulus], coeffData: [zeros], evalData: [zeros])
        try runNttTest(moduli: [modulus], coeffData: [oneHot], evalData: [Array(repeating: 1, count: degree)])
    }

    func testNttRoundtrip() throws {
        let degree = 256
        // Test large modulus
        let moduli = try UInt64.generatePrimes(
            significantBitCounts: [60, 62],
            preferringSmall: false,
            nttDegree: degree)
        let context = try PolyContext(degree: degree, moduli: moduli)
        let polyCoeff = PolyRq<_, Coeff>.random(context: context)
        let polyEval = try polyCoeff.forwardNtt()
        let polyRoundtrip = try polyEval.inverseNtt()
        XCTAssertEqual(polyRoundtrip, polyCoeff)
    }

    func testNttMatchesNaive() throws {
        func naiveMultiplication<T: ScalarType>(_ x: [T], _ y: [T], modulus: T) -> [T] {
            precondition(x.count == y.count)
            let n = x.count
            var result = Array(repeating: T(0), count: n)
            for i in 0..<n {
                for j in 0...i {
                    let prod = x[j].multiplyMod(y[i - j], modulus: modulus, variableTime: true)
                    result[i] = result[i].addMod(prod, modulus: modulus)
                }
                // Reduce using X^N = -1
                for j in (i + 1)..<n {
                    let prod = x[j].multiplyMod(y[n + i - j], modulus: modulus, variableTime: true)
                    result[i] = result[i].subtractMod(prod, modulus: modulus)
                }
            }
            return result
        }

        func nttMultiplication<T: ScalarType>(_ x: PolyRq<T, Coeff>,
                                              _ y: PolyRq<T, Coeff>) throws -> PolyRq<T, Coeff>
        {
            var xEval = try x.forwardNtt()
            let yEval = try y.forwardNtt()
            xEval *= yEval
            return try xEval.inverseNtt()
        }

        let degree = 128
        let moduli = try UInt32.generatePrimes(
            significantBitCounts: [30],
            preferringSmall: false,
            nttDegree: degree)
        let context = try PolyContext(degree: degree, moduli: moduli)
        let x = PolyRq<_, Coeff>.random(context: context)
        let y = PolyRq<_, Coeff>.random(context: context)

        let prodNtt = try nttMultiplication(x, y)
        let prodNaive = naiveMultiplication(x.data.data, y.data.data, modulus: moduli[0])

        XCTAssertEqual(prodNtt.data.data, prodNaive)
    }
}
