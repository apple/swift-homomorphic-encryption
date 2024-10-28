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
import XCTest

class CoefficientPackingTests: XCTestCase {
    func testBytesRoundtrip() throws {
        func runTest<T: ScalarType>(_: T.Type) throws {
            let n = 512
            let log2t = Int.random(in: 1...(T.bitWidth - 1))
            let t = T(1) << T(log2t) + 1

            var bytes: [UInt8] = .init(repeating: 0, count: n)
            var rng = NistAes128Ctr()
            rng.fill(&bytes)

            let coeffs: [T] = try CoefficientPacking.bytesToCoefficients(
                bytes: bytes,
                bitsPerCoeff: log2t,
                decode: false)
            for coeff in coeffs {
                XCTAssertLessThan(coeff, t)
            }

            let decodedBytes: [UInt8] = try CoefficientPacking.coefficientsToBytes(
                coeffs: coeffs,
                bitsPerCoeff: log2t)
            XCTAssertEqual(decodedBytes[0..<bytes.count], bytes[...])
        }

        try runTest(UInt32.self)
        try runTest(UInt64.self)
    }

    func testCoeffsRoundtrip() throws {
        func runTest<T: ScalarType>(_: T.Type) throws {
            let n = 512
            let log2t = Int.random(in: 1...(T.bitWidth - 4))
            let t = T(1) << T(log2t) + 1

            var coeffs: [T] = .init(repeating: 0, count: n)
            var rng = NistAes128Ctr()
            let reduceModulus = ReduceModulus(modulus: T(t), bound: .SingleWord, variableTime: true)
            rng.fill(&coeffs)

            for coeffIndex in coeffs.indices {
                coeffs[coeffIndex] = reduceModulus.reduce(coeffs[coeffIndex])
            }

            for coeff in coeffs {
                XCTAssertLessThan(coeff, t)
            }

            let bytes = try CoefficientPacking.coefficientsToBytes(coeffs: coeffs, bitsPerCoeff: log2t + 1)
            let decodedCoeffs: [T] = try CoefficientPacking.bytesToCoefficients(
                bytes: bytes,
                bitsPerCoeff: log2t + 1,
                decode: true)

            XCTAssertEqual(decodedCoeffs[..<coeffs.count], coeffs[...], "log2t = \(log2t), T = \(T.self)")
        }

        try runTest(UInt32.self)
        try runTest(UInt64.self)
    }

    func testBytesToCoeffKAT() throws {
        struct BytesToCoeffKAT<T: ScalarType> {
            let bytes: [UInt8]
            let bitsPerCoeff: Int
            let skipLSBs: Int
            let decode: Bool
            let expectedCoefficients: [T]
        }

        func runTest<T: ScalarType>(_: T.Type) throws {
            let kats: [BytesToCoeffKAT<T>] = [
                BytesToCoeffKAT(
                    bytes: [3, 24, 95, 141, 179, 34, 113],
                    bitsPerCoeff: 4,
                    skipLSBs: 0,
                    decode: false,
                    expectedCoefficients: [0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1]),
                BytesToCoeffKAT(
                    bytes: [3, 24, 95, 141, 179, 34, 113],
                    bitsPerCoeff: 4,
                    skipLSBs: 0,
                    decode: true,
                    expectedCoefficients: [0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1]),
                BytesToCoeffKAT(
                    bytes: [4, 69, 230, 164, 150, 0],
                    bitsPerCoeff: 4,
                    skipLSBs: 1,
                    decode: true,
                    expectedCoefficients: [0, 2, 0, 8, 4, 14, 8, 12, 10, 2, 2, 2, 6, 0, 0, 0]),
                BytesToCoeffKAT(
                    bytes: [2, 123, 128, 64],
                    bitsPerCoeff: 4,
                    skipLSBs: 2,
                    decode: false,
                    expectedCoefficients: [0, 0, 0, 8, 4, 12, 8, 12, 8, 0, 0, 0, 4, 0, 0, 0]),
                BytesToCoeffKAT(
                    bytes: [2, 123, 128, 64],
                    bitsPerCoeff: 4,
                    skipLSBs: 2,
                    decode: true,
                    expectedCoefficients: [0, 0, 0, 8, 4, 12, 8, 12, 8, 0, 0, 0, 4, 0, 0, 0]),
                BytesToCoeffKAT(
                    bytes: [23, 128],
                    bitsPerCoeff: 4,
                    skipLSBs: 3,
                    decode: true,
                    expectedCoefficients: [0, 0, 0, 8, 0, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0]),
                BytesToCoeffKAT(
                    bytes: Array(0...255),
                    bitsPerCoeff: 8,
                    skipLSBs: 0,
                    decode: false,
                    expectedCoefficients: Array(0...255)),
            ]

            for kat in kats {
                let coeffs: [T] = try CoefficientPacking.bytesToCoefficients(
                    bytes: kat.bytes,
                    bitsPerCoeff: kat.bitsPerCoeff,
                    decode: kat.decode,
                    skipLSBs: kat.skipLSBs)
                XCTAssertEqual(coeffs, kat.expectedCoefficients)
            }
        }

        try runTest(UInt32.self)
        try runTest(UInt64.self)
    }

    func testCoeffsToBytesKAT() throws {
        struct CoeffsToBytesKAT<T: ScalarType> {
            let coeffs: [T]
            let bitsPerCoeff: Int
            let skipLSBs: Int
            let expectedBytes: [UInt8]
        }

        func runTest<T: ScalarType>(_: T.Type) throws {
            let kats: [CoeffsToBytesKAT<T>] = [
                CoeffsToBytesKAT(
                    coeffs: [0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1],
                    bitsPerCoeff: 4,
                    skipLSBs: 0,
                    expectedBytes: [3, 24, 95, 141, 179, 34, 113]),
                CoeffsToBytesKAT(
                    coeffs: [0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1],
                    bitsPerCoeff: 4,
                    skipLSBs: 1,
                    expectedBytes: [4, 69, 230, 164, 150, 0]),
                CoeffsToBytesKAT(
                    coeffs: [0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1],
                    bitsPerCoeff: 4,
                    skipLSBs: 2,
                    expectedBytes: [2, 123, 128, 64]),
                CoeffsToBytesKAT(
                    coeffs: [0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1],
                    bitsPerCoeff: 4,
                    skipLSBs: 3,
                    expectedBytes: [23, 128]),
                CoeffsToBytesKAT(
                    coeffs: [0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1],
                    bitsPerCoeff: 5,
                    skipLSBs: 0,
                    expectedBytes: [0, 194, 130, 189, 13, 88, 196, 35, 132]),
                CoeffsToBytesKAT(
                    coeffs: [19, 16, 21, 4, 0, 1, 15, 3, 10, 3],
                    bitsPerCoeff: 5,
                    skipLSBs: 1,
                    expectedBytes: [152, 162, 0, 113, 81]),
                CoeffsToBytesKAT(
                    coeffs: [19, 16, 21, 4, 0, 1, 15, 3, 10, 3],
                    bitsPerCoeff: 5,
                    skipLSBs: 2,
                    expectedBytes: [146, 144, 24, 64]),
                CoeffsToBytesKAT(
                    coeffs: Array(0...255),
                    bitsPerCoeff: 8,
                    skipLSBs: 0,
                    expectedBytes: Array(0...255).map { UInt8($0) }),
            ]

            for kat in kats {
                let bytes = try CoefficientPacking.coefficientsToBytes(
                    coeffs: kat.coeffs,
                    bitsPerCoeff: kat.bitsPerCoeff,
                    skipLSBs: kat.skipLSBs)
                XCTAssertEqual(bytes, kat.expectedBytes)
            }
        }

        try runTest(UInt32.self)
        try runTest(UInt64.self)
    }
}
