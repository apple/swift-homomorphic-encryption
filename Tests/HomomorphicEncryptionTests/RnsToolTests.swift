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
struct RnsToolTests {
    @Test
    func scaleAndRound() throws {
        func runTestScaleAndRound<T: ScalarType>(
            degree: Int,
            inputModuli: [T],
            outputModulus: T) throws
        {
            let inputContext = try PolyContext(degree: degree, moduli: inputModuli)
            let outputContext = try PolyContext(degree: degree, moduli: [outputModulus])
            let rnsTool = try RnsTool(from: inputContext, to: outputContext)

            let q: T = inputModuli.product()
            let k = inputModuli.count
            let t = outputModulus
            let delta = q / t
            let correctionFactor = T.rnsCorrectionFactor
            let vBound = Double(q) / Double(t) * (0.5 - Double(k) / Double(correctionFactor)) - Double(q % t) / 2.0
            for _ in 0...10 {
                let vs = (0..<degree).map { _ in T.random(in: 0..<T(vBound)) }
                let ms = (0..<degree).map { _ in T.random(in: 0..<t) }
                let cts = zip(vs, ms).map { v, m in (delta * m + v) % q }

                let inputData = Array2d(
                    data: cts.flatMap { ct in inputModuli.map { modulus in ct % modulus } },
                    rowCount: degree,
                    columnCount: inputModuli.count)
                let input = PolyRq<T, Coeff>(
                    context: inputContext,
                    data: inputData.transposed())
                let output = try rnsTool.scaleAndRound(poly: input, scalingFactor: 1)
                #expect(output.data.data == ms)
            }
        }

        try runTestScaleAndRound(degree: 1, inputModuli: [31, 37].map(UInt32.init), outputModulus: UInt32(11))
        try runTestScaleAndRound(degree: 4, inputModuli: [31, 37].map(UInt64.init), outputModulus: UInt64(11))
        try runTestScaleAndRound(
            degree: 8,
            inputModuli: UInt32.generatePrimes(significantBitCounts: [10, 10, 10], preferringSmall: true),
            outputModulus: UInt32.generatePrimes(significantBitCounts: [8], preferringSmall: true)[0])
        try runTestScaleAndRound(
            degree: 8,
            inputModuli: UInt64.generatePrimes(significantBitCounts: [20, 20, 20], preferringSmall: true),
            outputModulus: UInt64.generatePrimes(significantBitCounts: [15], preferringSmall: true)[0])
    }

    @Test
    func convertApproximateBskMTilde() throws {
        func runTestConvertApproximateBskMTilde<T: ScalarType>(
            _: T.Type,
            degree: Int,
            significantBitCounts: [Int]) throws
        {
            let inputSignificantBitCounts = try significantBitCounts + [#require(significantBitCounts.last)]
            var inputModuli = try T.generatePrimes(
                significantBitCounts: inputSignificantBitCounts,
                preferringSmall: true)
            let t = try #require(inputModuli.min())
            inputModuli = inputModuli.filter { modulus in modulus != t }
            let q: OctoWidth<T> = inputModuli.product()

            let inputContext = try PolyContext<T>(degree: degree, moduli: inputModuli)
            let outputContext = try PolyContext<T>(degree: degree, moduli: [t])
            let rnsTool = try RnsTool(from: inputContext, to: outputContext)

            let referenceX = (0..<degree).map { _ in OctoWidth<T>.random(in: 0..<q) }
            let data = referenceX.map { bigInt in TestUtils.crtDecompose(value: bigInt, moduli: inputContext.moduli) }
            let inputData = Array2d(data: data).transposed()

            let input = PolyRq<T, Coeff>(context: inputContext, data: inputData)
            let output = try rnsTool.convertApproximateBskMTilde(poly: input)

            let baseBskMtilde: OctoWidth<T> = output.moduli.product()
            let mTildeModQ = OctoWidth<T>(T.mTilde) % q

            for (coeffIndex, x) in referenceX.enumerated() {
                let outputCoeff = output.rnsIndices(coeffIndex: coeffIndex).map { index in output.data[index] }
                // coeff = (x + a_x * q) % t, where a_x \in [0, num_in_moduli-1]
                // try to recover the exact x
                let possibleX = (0..<inputContext.moduli.count).map { aX in
                    ((x * mTildeModQ) % q + OctoWidth<T>(aX) * q) % baseBskMtilde
                }
                #expect(possibleX.contains { possibleX in
                    let possibleXCrt = TestUtils.crtDecompose(value: possibleX, moduli: output.moduli)
                    return possibleXCrt == outputCoeff
                })
            }
        }

        try runTestConvertApproximateBskMTilde(UInt32.self, degree: 32, significantBitCounts: [22, 22])
        try runTestConvertApproximateBskMTilde(UInt32.self, degree: 16, significantBitCounts: [23, 23, 23])
        try runTestConvertApproximateBskMTilde(UInt32.self, degree: 8, significantBitCounts: [24, 24, 24, 24])

        try runTestConvertApproximateBskMTilde(UInt64.self, degree: 32, significantBitCounts: [20, 20])
        try runTestConvertApproximateBskMTilde(UInt64.self, degree: 16, significantBitCounts: [30, 30, 30])
        try runTestConvertApproximateBskMTilde(UInt64.self, degree: 8, significantBitCounts: [40, 40, 40, 40])
    }

    @Test
    func montgomeryReduce() throws {
        func runTestMontgomeryReduceTest<T: ScalarType>(
            _: T.Type,
            degree: Int,
            inputModuli: [T],
            inputData: Array2d<T>,
            expectedData: Array2d<T>) throws
        {
            let qContext = try PolyContext(degree: degree, moduli: inputModuli)
            let outputContext = try PolyContext(degree: degree, moduli: [T(2)]) // Arbitrary
            let rnsTool = try RnsTool(from: qContext, to: outputContext)
            let bSkMtildeContext = rnsTool.rnsConvertQToBSkMTilde.outputContext

            var poly: PolyRq<T, Coeff> = PolyRq(context: bSkMtildeContext, data: inputData)
            try rnsTool.smallMontgomeryReduce(poly: &poly)

            let bSkContext = try #require(bSkMtildeContext.next)
            let expectedPoly: PolyRq<T, Coeff> = PolyRq(context: bSkContext, data: expectedData)
            #expect(poly == expectedPoly)
        }

        // 1 modulus
        do {
            let moduli = try UInt64.generatePrimes(significantBitCounts: [36], preferringSmall: true)
            let inputData = Array2d(
                data: [UInt64.mTilde, 2 * UInt64.mTilde, UInt64.mTilde, 2 * UInt64.mTilde, 0, 0],
                rowCount: 3,
                columnCount: 2)
            try runTestMontgomeryReduceTest(UInt64.self, degree: 2, inputModuli: moduli,
                                            inputData: inputData,
                                            expectedData: Array2d(data: [1, 2, 1, 2], rowCount: 2, columnCount: 2))
        }
        // 2 moduli
        do {
            let moduli = try UInt64.generatePrimes(significantBitCounts: [36, 36], preferringSmall: true)
            let m = UInt64.mTilde
            let inputData = Array2d(
                data: [m, 2 * m, m, 2 * m, m, 2 * m, 0, 0],
                rowCount: 4,
                columnCount: 2)
            try runTestMontgomeryReduceTest(UInt64.self, degree: 2, inputModuli: moduli,
                                            inputData: inputData,
                                            expectedData: Array2d(
                                                data: [1, 2, 1, 2, 1, 2],
                                                rowCount: 3,
                                                columnCount: 2))
        }
    }

    @Test
    func liftQToQBsk() throws {
        func runTestLiftQToQBsk<T: ScalarType>(
            _: T.Type,
            degree: Int,
            significantBitCounts: [Int]) throws
        {
            let inputModuli = try T.generatePrimes(significantBitCounts: significantBitCounts, preferringSmall: true)
            let inputContext = try PolyContext(degree: degree, moduli: inputModuli)
            let outputContext = try PolyContext(degree: degree, moduli: [T(2)]) // arbitrary
            let rnsTool = try RnsTool(from: inputContext, to: outputContext)
            let q: OctoWidth<T> = inputModuli.product()

            let referenceX = (0..<degree).map { _ in OctoWidth<T>.random(in: 0..<q) }
            let data = referenceX.map { bigInt in TestUtils.crtDecompose(value: bigInt, moduli: inputContext.moduli) }
            let inputData = Array2d(data: data).transposed()
            let input: PolyRq<T, Coeff> = PolyRq(context: inputContext, data: inputData)
            let output = try rnsTool.liftQToQBsk(poly: input)

            let qBskMTildeModuli = rnsTool.qBskContext.moduli
            let qBskMTilde: OctoWidth<T> = qBskMTildeModuli.product()
            for (coeffIndex, x) in referenceX.enumerated() {
                let expected = if x > (q / 2) {
                    qBskMTilde - (q - x)
                } else {
                    x
                }
                let expectedCrt = TestUtils.crtDecompose(value: expected, moduli: qBskMTildeModuli)
                let outputCrt = output.rnsIndices(coeffIndex: coeffIndex).map { index in output.data[index] }
                #expect(outputCrt == expectedCrt)
            }
        }

        try runTestLiftQToQBsk(UInt32.self, degree: 4, significantBitCounts: [20, 20])
        try runTestLiftQToQBsk(UInt32.self, degree: 8, significantBitCounts: [25, 25, 25])
        try runTestLiftQToQBsk(UInt32.self, degree: 16, significantBitCounts: [27, 27, 27, 27])

        try runTestLiftQToQBsk(UInt64.self, degree: 4, significantBitCounts: [20, 20])
        try runTestLiftQToQBsk(UInt64.self, degree: 8, significantBitCounts: [30, 30, 30])
        try runTestLiftQToQBsk(UInt64.self, degree: 16, significantBitCounts: [40, 40, 40, 40])
    }

    @Test
    func approximateFloor() throws {
        func runTestApproximateFloor<T: ScalarType>(_: T.Type, degree: Int, significantBitCounts: [Int]) throws {
            let inputModuli = try T.generatePrimes(significantBitCounts: significantBitCounts, preferringSmall: true)
            let inputContext = try PolyContext(degree: degree, moduli: inputModuli)
            let outputContext = try PolyContext(degree: degree, moduli: [T(2)]) // arbitrary
            let rnsTool = try RnsTool(from: inputContext, to: outputContext)
            let q: OctoWidth<T> = inputModuli.product()
            let qBsk: OctoWidth<T> = rnsTool.qBskContext.moduli.product()
            let bSk: OctoWidth<T> = rnsTool.rnsConvertQToBSk.outputContext.moduli.product()

            let referenceX = (0..<degree).map { index in
                if index == 0 {
                    return qBsk - OctoWidth<T>(1)
                }
                if index == 1 {
                    return OctoWidth<T>(1)
                }
                return OctoWidth<T>.random(in: 0..<qBsk)
            }
            let data = referenceX.map { bigInt in TestUtils.crtDecompose(
                value: bigInt,
                moduli: rnsTool.qBskContext.moduli)
            }
            let inputData = Array2d(data: data).transposed()
            let input: PolyRq<T, Coeff> = PolyRq(context: rnsTool.qBskContext, data: inputData)
            let output = try rnsTool.approximateFloor(poly: input)

            for (coeffIndex, x) in referenceX.enumerated() {
                let outputCrt = output.rnsIndices(coeffIndex: coeffIndex).map { index in output.data[index] }
                // coeff = (floor(x/q) + a_x) % B_sk,/ where a_x \in [-(inputModuli.count - 1), inputModuli.count - 1]
                // try to recover the exact x
                let possibleX = (0..<inputModuli.count).flatMap { aX in
                    let aX = OctoWidth<T>(aX)
                    return [(x / q + aX) % bSk, (x / q + bSk - aX) % bSk]
                }
                #expect(possibleX.contains { possibleX in
                    let possibleXCrt = TestUtils.crtDecompose(value: possibleX, moduli: output.moduli)
                    return possibleXCrt == outputCrt
                })
            }
        }

        try runTestApproximateFloor(UInt32.self, degree: 4, significantBitCounts: [20, 20])
        try runTestApproximateFloor(UInt32.self, degree: 8, significantBitCounts: [25, 25, 25])
        try runTestApproximateFloor(UInt32.self, degree: 16, significantBitCounts: [27, 27, 27, 27])

        try runTestApproximateFloor(UInt64.self, degree: 4, significantBitCounts: [20, 20])
        try runTestApproximateFloor(UInt64.self, degree: 8, significantBitCounts: [30, 30, 30])
        try runTestApproximateFloor(UInt64.self, degree: 16, significantBitCounts: [40, 40, 40, 40])
    }

    @Test
    func convertApproximateBskToQ() throws {
        func runTestConvertApproximateBskToQ<T: ScalarType>(
            _: T.Type,
            degree: Int,
            significantBitCounts: [Int]) throws
        {
            let inputModuli = try T.generatePrimes(
                significantBitCounts: significantBitCounts,
                preferringSmall: true)
            let q: OctoWidth<T> = inputModuli.product()

            let inputContext = try PolyContext<T>(degree: degree, moduli: inputModuli)
            let outputContext = try PolyContext<T>(degree: degree, moduli: [2]) // Arbitrary
            let rnsTool = try RnsTool(from: inputContext, to: outputContext)
            let bskContext = rnsTool.rnsConvertQToBSk.outputContext
            let bskModuli = bskContext.moduli
            let bskProd: OctoWidth<T> = bskModuli.product()

            let referenceX = (0..<degree).map { _ in OctoWidth<T>.random(in: 0..<q) }
            let data = referenceX.map { bigInt in TestUtils.crtDecompose(value: bigInt, moduli: bskModuli) }
            let inputData = Array2d(data: data).transposed()

            let input = PolyRq<T, Coeff>(context: bskContext, data: inputData)
            let output = try rnsTool.convertApproximateBskToQ(poly: input)

            for (coeffIndex, x) in referenceX.enumerated() {
                // coeff = (x + a_x * q) % t, where a_x \in [0, num_in_moduli-1]
                let expected = if x > bskProd / 2 {
                    q - ((bskProd - x) % q)
                } else {
                    x % q
                }
                let expectedCrt = TestUtils.crtDecompose(value: expected, moduli: inputModuli)
                let outputCrt = output.rnsIndices(coeffIndex: coeffIndex).map { index in output.data[index] }
                #expect(outputCrt == expectedCrt)
            }
        }
        try runTestConvertApproximateBskToQ(UInt32.self, degree: 4, significantBitCounts: [20, 20])
        try runTestConvertApproximateBskToQ(UInt32.self, degree: 8, significantBitCounts: [25, 25, 25])

        try runTestConvertApproximateBskToQ(UInt64.self, degree: 4, significantBitCounts: [20, 20])
        try runTestConvertApproximateBskToQ(UInt64.self, degree: 8, significantBitCounts: [30, 30, 30])
    }
}
