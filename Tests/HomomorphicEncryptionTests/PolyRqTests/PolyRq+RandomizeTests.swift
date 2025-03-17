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
import XCTest

final class PolyRqRandomizeTests: XCTestCase {
    func testRandomizeUniform() throws {
        func runRandomizeUniformTest<T: ScalarType>(_: T.Type) throws {
            let context = try PolyContext<T>(degree: 1024, moduli: [40961, 59393, 61441])
            var poly = PolyRq<T, Coeff>.zero(context: context)
            poly.randomizeUniform()
            TestUtils.uniformnessTest(poly: poly)
        }

        try runRandomizeUniformTest(UInt32.self)
        try runRandomizeUniformTest(UInt64.self)
    }

    func testCenteredBinomialDistribution() throws {
        func runCenteredBinomialDistributionTest<T: ScalarType>(_: T.Type) throws {
            let n = 8192
            let moduli: [T] = [268_582_913, 268_664_833, 268_730_369, 268_779_521]
            for moduliCount in 1..<5 {
                let moduliSlice = moduli[..<moduliCount]
                let context = try PolyContext<T>(degree: n, moduli: Array(moduliSlice))
                var poly = PolyRq<T, Coeff>.zero(context: context)
                poly.randomizeCenteredBinomialDistribution(standardDeviation: 3.2)
                TestUtils.centeredBinomialDistributionTest(poly: poly)
            }
        }

        try runCenteredBinomialDistributionTest(UInt32.self)
        try runCenteredBinomialDistributionTest(UInt64.self)
    }

    func testTernaryDistribution() throws {
        func runTernaryDistributionTest<T: ScalarType>(_: T.Type) throws {
            let n = 8192
            let moduli: [T] = [268_582_913, 268_664_833, 268_730_369, 268_779_521]
            for moduliCount in 1..<5 {
                let moduliSlice = moduli[..<moduliCount]
                let context = try PolyContext<T>(degree: n, moduli: Array(moduliSlice))
                var poly = PolyRq<T, Coeff>.zero(context: context)
                poly.randomizeTernary()
                // Bonferroni correction for p-value to avoid false failures
                TestUtils.ternaryDistributionTest(poly: poly, pValue: 0.001 / Double((1..<5).count))
            }
        }

        try runTernaryDistributionTest(UInt32.self)
        try runTernaryDistributionTest(UInt64.self)
    }

    private func runRandomizeInteropTest<T>(
        hexSeed: String,
        moduli: [T],
        polyData: [[Int]],
        createRandomPoly: (PolyContext<T>, inout PseudoRandomNumberGenerator) -> PolyRq<T, Coeff>) throws
        where T: ScalarType
    {
        let polyData = polyData.map { $0.map { T($0) } }
        let seed = try XCTUnwrap(Array(hexEncoded: hexSeed))
        var rng: any PseudoRandomNumberGenerator = try NistAes128Ctr(seed: seed)
        let polyContext: PolyContext<T> = try PolyContext(degree: 4, moduli: moduli)
        // test the first poly
        do {
            let poly = createRandomPoly(polyContext, &rng)
            let data = Array2d<T>(data: polyData[0], rowCount: 2, columnCount: 4)
            let expected = PolyRq<T, Coeff>(context: polyContext, data: data)
            XCTAssertEqual(poly, expected)
        }
        // generate a bunch of polys
        for _ in 0..<1000 {
            _ = createRandomPoly(polyContext, &rng)
        }
        // test another poly
        do {
            let poly = createRandomPoly(polyContext, &rng)
            let data = Array2d<T>(data: polyData[1], rowCount: 2, columnCount: 4)
            let expected = PolyRq<T, Coeff>(context: polyContext, data: data)
            XCTAssertEqual(poly, expected)
        }
        // generate a bunch of polys
        for _ in 0..<1000 {
            _ = createRandomPoly(polyContext, &rng)
        }
        // test another poly
        do {
            let poly = createRandomPoly(polyContext, &rng)
            let data = Array2d<T>(data: polyData[2], rowCount: 2, columnCount: 4)
            let expected = PolyRq<T, Coeff>(context: polyContext, data: data)
            XCTAssertEqual(poly, expected)
        }
    }

    func testRandomizeInteropUniform() throws {
        let uniformZeroSeedPolyData = [
            [4, 0, 2, 8, 10, 9, 3, 2],
            [5, 6, 0, 5, 1, 3, 6, 11],
            [0, 3, 4, 4, 8, 9, 0, 10],
        ]

        func runUniform1<T: ScalarType>(_: T.Type) throws {
            try runRandomizeInteropTest(hexSeed: "0000000000000000000000000000000000000000000000000000000000000000",
                                        moduli: [11, 13],
                                        polyData: uniformZeroSeedPolyData)
            { polyContext, rng in
                PolyRq<T, Coeff>.random(context: polyContext, using: &rng)
            }
        }

        try runUniform1(UInt32.self)
        try runUniform1(UInt64.self)

        let uniformFixedSeedPolyData = [
            [9, 6, 9, 0, 10, 8, 7, 3],
            [2, 9, 9, 1, 12, 0, 0, 12],
            [5, 1, 0, 10, 8, 2, 8, 1],
        ]

        func runUniform2<T: ScalarType>(_: T.Type) throws {
            try runRandomizeInteropTest(hexSeed: "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
                                        moduli: [11, 13],
                                        polyData: uniformFixedSeedPolyData)
            { polyContext, rng in
                PolyRq<T, Coeff>.random(context: polyContext, using: &rng)
            }
        }

        try runUniform2(UInt32.self)
        try runUniform2(UInt64.self)
    }

    func testRandomizeInteropTernary() throws {
        let ternaryPolyData = [
            [0, 10, 10, 1, 0, 12, 12, 1],
            [1, 10, 1, 0, 1, 12, 1, 0],
            [1, 0, 0, 1, 1, 0, 0, 1],
        ]

        func runTernary<T: ScalarType>(_: T.Type) throws {
            try runRandomizeInteropTest(hexSeed: "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
                                        moduli: [T(11), T(13)],
                                        polyData: ternaryPolyData)
            { polyContext, rng in
                var poly = PolyRq<T, Coeff>.zero(context: polyContext)
                poly.randomizeTernary(using: &rng)
                return poly
            }
        }

        try runTernary(UInt32.self)
        try runTernary(UInt64.self)
    }

    func testRandomizeInteropCenteredBinomial() throws {
        let centeredBinomialPolyData = [
            [22, 0, 0, 22, 28, 0, 0, 28],
            [2, 4, 22, 1, 2, 4, 28, 1],
            [3, 0, 22, 20, 3, 0, 28, 26],
        ]

        func runCenteredBinomial<T: ScalarType>(_: T.Type) throws {
            try runRandomizeInteropTest(hexSeed: "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
                                        moduli: [T(23), T(29)],
                                        polyData: centeredBinomialPolyData)
            { polyContext, rng in
                var poly = PolyRq<T, Coeff>.zero(context: polyContext)
                poly.randomizeCenteredBinomialDistribution(
                    standardDeviation: ErrorStdDev.stdDev32.toDouble,
                    using: &rng)
                return poly
            }
        }

        try runCenteredBinomial(UInt32.self)
        try runCenteredBinomial(UInt64.self)
    }
}
