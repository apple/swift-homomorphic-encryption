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
import TestUtilities
import XCTest

final class RnsBaseConverterTests: XCTestCase {
    func testConvertApproximate() throws {
        func runTestConvertApproximate<T: ScalarType>(
            _: T.Type,
            degree: Int,
            significantBitCounts: [Int]) throws
        {
            let inputSignificantBitCounts = try significantBitCounts + [XCTUnwrap(significantBitCounts.last)]
            var inputModuli = try T.generatePrimes(
                significantBitCounts: inputSignificantBitCounts,
                preferringSmall: true)
            let t = try XCTUnwrap(inputModuli.popLast())
            let q: T.DoubleWidth = inputModuli.product()

            let inputContext = try PolyContext<T>(degree: degree, moduli: inputModuli)
            let outputContext = try PolyContext<T>(degree: degree, moduli: [t])
            let referenceX = (0..<degree).map { _ in T.DoubleWidth.random(in: 0..<q) }
            let rnsBaseConverter = try RnsBaseConverter<T>(from: inputContext, to: outputContext)
            let data = referenceX.map { bigInt in TestUtils.crtDecompose(value: bigInt, moduli: inputContext.moduli) }
            let inputData = Array2d(data: data).transposed()

            let input = PolyRq<T, Coeff>(context: inputContext, data: inputData)
            let output = try rnsBaseConverter.convertApproximate(poly: input)

            for (coeff, x) in zip(output.poly(rnsIndex: 0), referenceX) {
                // coeff = (x + a_x * q) % t, where a_x \in [0, num_in_moduli-1]
                // try to recover the exact x
                let possibleX = (0..<inputContext.moduli.count).map { aX in
                    (x + T.DoubleWidth(aX) * q) % T.DoubleWidth(t)
                }
                XCTAssert(possibleX.contains(T.DoubleWidth(coeff)))
            }
        }

        try runTestConvertApproximate(UInt32.self, degree: 64, significantBitCounts: [29])
        try runTestConvertApproximate(UInt32.self, degree: 32, significantBitCounts: [25, 25])
        try runTestConvertApproximate(UInt32.self, degree: 16, significantBitCounts: [20, 20, 20])
        try runTestConvertApproximate(UInt32.self, degree: 8, significantBitCounts: [15, 15, 15, 15])
        try runTestConvertApproximate(UInt32.self, degree: 4, significantBitCounts: [10, 10, 10, 10, 10])

        try runTestConvertApproximate(UInt64.self, degree: 64, significantBitCounts: [60])
        try runTestConvertApproximate(UInt64.self, degree: 32, significantBitCounts: [50, 50])
        try runTestConvertApproximate(UInt64.self, degree: 16, significantBitCounts: [40, 40, 40])
        try runTestConvertApproximate(UInt64.self, degree: 8, significantBitCounts: [30, 30, 30, 30])
        try runTestConvertApproximate(UInt64.self, degree: 4, significantBitCounts: [20, 20, 20, 20, 20])
    }

    func testCrtCompose() throws {
        func runTestCrtCompose<T: ScalarType>(
            _: T.Type,
            degree: Int,
            significantBitCounts: [Int]) throws
        {
            let inputSignificantBitCounts = significantBitCounts
            let inputModuli = try T.generatePrimes(
                significantBitCounts: inputSignificantBitCounts,
                preferringSmall: true)

            let inputContext = try PolyContext<T>(degree: degree, moduli: inputModuli)
            let outputContext = try PolyContext<T>(degree: degree, moduli: [T(2)]) // Arbitrary
            let poly: PolyRq<T, Coeff> = PolyRq.random(context: inputContext)

            let rnsBaseConverter = try RnsBaseConverter<T>(from: inputContext, to: outputContext)
            let composed: [QuadWidth<T>] = try rnsBaseConverter.crtCompose(poly: poly)

            for (coeffIndex, composed) in composed.enumerated() {
                let roundTripValues = TestUtils.crtDecompose(value: composed, moduli: inputContext.moduli)
                let rnsCoeffs = poly.coefficient(coeffIndex: coeffIndex)
                XCTAssertEqual(roundTripValues, rnsCoeffs)
            }
        }

        try runTestCrtCompose(UInt32.self, degree: 32, significantBitCounts: [29])
        try runTestCrtCompose(UInt32.self, degree: 16, significantBitCounts: [25, 25])
        try runTestCrtCompose(UInt32.self, degree: 8, significantBitCounts: [20, 20, 20])
        try runTestCrtCompose(UInt32.self, degree: 4, significantBitCounts: [15, 15, 15, 15])
        try runTestCrtCompose(UInt32.self, degree: 2, significantBitCounts: [10, 10, 10, 10, 10])

        try runTestCrtCompose(UInt64.self, degree: 32, significantBitCounts: [60])
        try runTestCrtCompose(UInt64.self, degree: 16, significantBitCounts: [50, 50])
        try runTestCrtCompose(UInt64.self, degree: 8, significantBitCounts: [40, 40, 40])
        try runTestCrtCompose(UInt64.self, degree: 4, significantBitCounts: [30, 30, 30, 30])
        try runTestCrtCompose(UInt64.self, degree: 2, significantBitCounts: [20, 20, 20, 20, 20])
    }
}
