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

import HomomorphicEncryption
@testable import PrivateNearestNeighborsSearch
import TestUtilities
import XCTest

final class PlaintextMatrixTests: XCTestCase {
    func testMatrixDimensions() throws {
        XCTAssertThrowsError(try MatrixDimensions(rowCount: -1, columnCount: 1))
        let dims = try MatrixDimensions(rowCount: 2, columnCount: 3)
        XCTAssertEqual(dims.rowCount, 2)
        XCTAssertEqual(dims.columnCount, 3)
        XCTAssertEqual(dims.count, 6)
    }

    func testPlaintextMatrixError() throws {
        func runTest<Scheme: HeScheme>(rlweParams: PredefinedRlweParameters, _: Scheme.Type) throws {
            let encryptionParams = try EncryptionParameters<Scheme>(from: rlweParams)
            guard encryptionParams.supportsSimdEncoding else {
                return
            }
            let rowCount = encryptionParams.polyDegree
            let columnCount = 2
            let dims = try MatrixDimensions(rowCount: rowCount, columnCount: columnCount)
            let packing = PlaintextMatrixPacking.denseRow
            let context = try Context(encryptionParameters: encryptionParams)
            let values = TestUtils.getRandomPlaintextData(
                count: encryptionParams.polyDegree,
                in: 0..<encryptionParams.plaintextModulus)
            let plaintext: Plaintext<Scheme, Coeff> = try context.encode(
                values: values,
                format: EncodeFormat.coefficient)
            XCTAssertNoThrow(try PlaintextMatrix<Scheme, Coeff>(
                dimensions: dims,
                packing: packing,
                plaintexts: [plaintext, plaintext]))

            // Not enough plaintexts
            XCTAssertThrowsError(try PlaintextMatrix<Scheme, Coeff>(dimensions: dims, packing: packing, plaintexts: []))
            // Plaintexts from different contexts
            do {
                let diffRlweParams = rlweParams == PredefinedRlweParameters
                    .insecure_n_8_logq_5x18_logt_5 ? .n_4096_logq_27_28_28_logt_16 : PredefinedRlweParameters
                    .insecure_n_8_logq_5x18_logt_5
                let diffEncryptionParams = try EncryptionParameters<Scheme>(from: diffRlweParams)
                let diffContext = try Context(encryptionParameters: diffEncryptionParams)
                let diffValues = TestUtils.getRandomPlaintextData(
                    count: diffEncryptionParams.polyDegree,
                    in: 0..<diffEncryptionParams.plaintextModulus)
                let diffPlaintext: Scheme.CoeffPlaintext = try diffContext.encode(
                    values: diffValues,
                    format: EncodeFormat.coefficient)
                XCTAssertThrowsError(try PlaintextMatrix<Scheme, Coeff>(
                    dimensions: dims,
                    packing: packing,
                    plaintexts: [plaintext, diffPlaintext]))
            }
        }
        for rlweParams in PredefinedRlweParameters.allCases {
            try runTest(rlweParams: rlweParams, NoOpScheme.self)
            if rlweParams.supportsScalar(UInt32.self) {
                try runTest(rlweParams: rlweParams, Bfv<UInt32>.self)
            }
            try runTest(rlweParams: rlweParams, Bfv<UInt64>.self)
        }
    }

    func testPlaintextMatrixDenseRowError() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParams = try EncryptionParameters<Scheme>(from: rlweParams)
            let context = try Context(encryptionParameters: encryptionParams)
            let rowCount = encryptionParams.polyDegree
            let columnCount = 2
            let values = TestUtils.getRandomPlaintextData(
                count: encryptionParams.polyDegree,
                in: 0..<Scheme.Scalar(rowCount * columnCount))
            let packing = PlaintextMatrixPacking.denseRow

            // Wrong number of values
            do {
                let wrongDims = try MatrixDimensions(rowCount: rowCount, columnCount: columnCount + 1)
                XCTAssertThrowsError(try PlaintextMatrix<Scheme, Coeff>(
                    context: context,
                    dimensions: wrongDims,
                    packing: packing,
                    values: values))
            }
            // Too many columns
            do {
                let dims = try MatrixDimensions(rowCount: rowCount, columnCount: columnCount + 1)
                XCTAssertThrowsError(try PlaintextMatrix<Scheme, Coeff>(
                    context: context,
                    dimensions: dims,
                    packing: packing,
                    values: values))
            }
        }
        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt64>.self)
        try runTest(Bfv<UInt32>.self)
    }

    private func runPlaintextMatrixInitTest<Scheme: HeScheme>(
        context: Context<Scheme>,
        dimensions: MatrixDimensions,
        packing: PlaintextMatrixPacking,
        expected: [[Int]]) throws
    {
        guard context.supportsSimdEncoding else {
            return
        }
        let t = context.plaintextModulus
        let expected: [[Scheme.Scalar]] = expected.map { row in row.map { Scheme.Scalar($0) % t } }
        let encodeValues: [[Scheme.Scalar]] = (0..<dimensions.rowCount).map { rowIndex in
            (0..<dimensions.columnCount).map { columnIndex in
                let value = 1 + Scheme.Scalar(rowIndex * dimensions.columnCount + columnIndex)
                return value % t
            }
        }
        let plaintextMatrix = try PlaintextMatrix<Scheme, Coeff>(
            context: context,
            dimensions: dimensions,
            packing: packing,
            values: encodeValues.flatMap { $0 })
        XCTAssertEqual(plaintextMatrix.rowCount, dimensions.rowCount)
        XCTAssertEqual(plaintextMatrix.columnCount, dimensions.columnCount)
        XCTAssertEqual(plaintextMatrix.packing, packing)
        XCTAssertEqual(plaintextMatrix.context, context)
        // Test round-trip
        XCTAssertEqual(try plaintextMatrix.unpack(), encodeValues.flatMap { $0 })

        // Test representation
        XCTAssertEqual(plaintextMatrix.plaintexts.count, expected.count)
        for (plaintext, expected) in zip(plaintextMatrix.plaintexts, expected) {
            let decoded: [Scheme.Scalar] = try plaintext.decode(format: .simd)
            XCTAssertEqual(decoded, expected)
        }
    }

    func testPlaintextMatrixDenseColumn() throws {
        let kats: [((rowCount: Int, columnCount: Int), expected: [[Int]])] = [
            ((1, 1), [[1, 0, 0, 0, 0, 0, 0, 0]]),
            ((1, 2), [[1, 2, 0, 0, 0, 0, 0, 0]]),
            ((1, 3), [[1, 2, 3, 0, 0, 0, 0, 0]]),
            ((1, 4), [[1, 2, 3, 4, 0, 0, 0, 0]]),
            ((1, 5), [[1, 2, 3, 4, 5, 0, 0, 0]]),
            ((1, 6), [[1, 2, 3, 4, 5, 6, 0, 0]]),
            ((1, 7), [[1, 2, 3, 4, 5, 6, 7, 0]]),
            ((1, 8), [[1, 2, 3, 4, 5, 6, 7, 8]]),
            ((1, 9), [[1, 2, 3, 4, 5, 6, 7, 8],
                      [9, 0, 0, 0, 0, 0, 0, 0]]),
            ((2, 1), [[1, 2, 0, 0, 0, 0, 0, 0]]),
            ((2, 2), [[1, 3, 2, 4, 0, 0, 0, 0]]),
            // extra 0 prevents column from spanning multiple SIMD rows.
            ((2, 3), [[1, 4, 2, 5, 3, 6, 0, 0]]),
            ((2, 4), [[1, 5, 2, 6, 3, 7, 4, 8]]),
            ((2, 5), [[1, 6, 2, 7, 3, 8, 4, 9],
                      [5, 10, 0, 0, 0, 0, 0, 0]]),
            ((2, 6), [[1, 7, 2, 8, 3, 9, 4, 10],
                      [5, 11, 6, 12, 0, 0, 0, 0]]),
            ((2, 7), [[1, 8, 2, 9, 3, 10, 4, 11],
                      [5, 12, 6, 13, 7, 14, 0, 0]]),
            ((2, 8), [[1, 9, 2, 10, 3, 11, 4, 12],
                      [5, 13, 6, 14, 7, 15, 8, 16]]),
            ((2, 9), [[1, 10, 2, 11, 3, 12, 4, 13],
                      [5, 14, 6, 15, 7, 16, 8, 17],
                      [9, 18, 0, 0, 0, 0, 0, 0]]),
            ((3, 1), [[1, 2, 3, 0, 0, 0, 0, 0]]),
            // extra 0 prevents column from spanning multiple SIMD rows.
            ((3, 2), [[1, 3, 5, 0, 2, 4, 6, 0]]),
            // extra 0 prevents column from spanning multiple SIMD rows.
            ((3, 3), [[1, 4, 7, 0, 2, 5, 8, 0],
                      [3, 6, 9, 0, 0, 0, 0, 0]]),
            // extra 0 prevents column from spanning multiple SIMD rows.
            ((3, 4), [[1, 5, 9, 0, 2, 6, 10, 0],
                      [3, 7, 11, 0, 4, 8, 12, 0]]),
            ((4, 1), [[1, 2, 3, 4, 0, 0, 0, 0]]),
            ((4, 2), [[1, 3, 5, 7, 2, 4, 6, 8]]),
            ((4, 3), [[1, 4, 7, 10, 2, 5, 8, 11],
                      [3, 6, 9, 12, 0, 0, 0, 0]]),
            ((4, 4), [[1, 5, 9, 13, 2, 6, 10, 14],
                      [3, 7, 11, 15, 4, 8, 12, 16]]),
            ((4, 5), [[1, 6, 11, 16, 2, 7, 12, 17],
                      [3, 8, 13, 18, 4, 9, 14, 19],
                      [5, 10, 15, 20, 0, 0, 0, 0]]),
            ((4, 6), [[1, 7, 13, 19, 2, 8, 14, 20],
                      [3, 9, 15, 21, 4, 10, 16, 22],
                      [5, 11, 17, 23, 6, 12, 18, 24]]),
            ((5, 1), [[1, 2, 3, 4, 5, 0, 0, 0]]),
            ((5, 2), [[1, 3, 5, 7, 9, 0, 0, 0],
                      [2, 4, 6, 8, 10, 0, 0, 0]]),
            ((5, 3), [[1, 4, 7, 10, 13, 0, 0, 0],
                      [2, 5, 8, 11, 14, 0, 0, 0],
                      [3, 6, 9, 12, 15, 0, 0, 0]]),
            ((5, 4), [[1, 5, 9, 13, 17, 0, 0, 0],
                      [2, 6, 10, 14, 18, 0, 0, 0],
                      [3, 7, 11, 15, 19, 0, 0, 0],
                      [4, 8, 12, 16, 20, 0, 0, 0]]),
            ((5, 5), [[1, 6, 11, 16, 21, 0, 0, 0],
                      [2, 7, 12, 17, 22, 0, 0, 0],
                      [3, 8, 13, 18, 23, 0, 0, 0],
                      [4, 9, 14, 19, 24, 0, 0, 0],
                      [5, 10, 15, 20, 25, 0, 0, 0]]),
            ((10, 5), [[1, 6, 11, 16, 21, 26, 31, 36], [41, 46, 0, 0, 0, 0, 0, 0],
                       [2, 7, 12, 17, 22, 27, 32, 37], [42, 47, 0, 0, 0, 0, 0, 0],
                       [3, 8, 13, 18, 23, 28, 33, 38], [43, 48, 0, 0, 0, 0, 0, 0],
                       [4, 9, 14, 19, 24, 29, 34, 39], [44, 49, 0, 0, 0, 0, 0, 0],
                       [5, 10, 15, 20, 25, 30, 35, 40], [45, 50, 0, 0, 0, 0, 0, 0]]),
            ((10, 10), [[1, 11, 21, 31, 41, 51, 61, 71], [81, 91, 0, 0, 0, 0, 0, 0],
                        [2, 12, 22, 32, 42, 52, 62, 72], [82, 92, 0, 0, 0, 0, 0, 0],
                        [3, 13, 23, 33, 43, 53, 63, 73], [83, 93, 0, 0, 0, 0, 0, 0],
                        [4, 14, 24, 34, 44, 54, 64, 74], [84, 94, 0, 0, 0, 0, 0, 0],
                        [5, 15, 25, 35, 45, 55, 65, 75], [85, 95, 0, 0, 0, 0, 0, 0],
                        [6, 16, 26, 36, 46, 56, 66, 76], [86, 96, 0, 0, 0, 0, 0, 0],
                        [7, 17, 27, 37, 47, 57, 67, 77], [87, 97, 0, 0, 0, 0, 0, 0],
                        [8, 18, 28, 38, 48, 58, 68, 78], [88, 98, 0, 0, 0, 0, 0, 0],
                        [9, 19, 29, 39, 49, 59, 69, 79], [89, 99, 0, 0, 0, 0, 0, 0],
                        [10, 20, 30, 40, 50, 60, 70, 80], [90, 100, 0, 0, 0, 0, 0, 0]]),
        ]

        func runTest<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let encryptionParams = try EncryptionParameters<Scheme>(
                polyDegree: 8,
                plaintextModulus: 1153,
                coefficientModuli: Scheme.Scalar
                    .generatePrimes(
                        significantBitCounts: [25, 25],
                        preferringSmall: false,
                        nttDegree: 8),
                errorStdDev: .stdDev32,
                securityLevel: .unchecked)
            let context = try Context(encryptionParameters: encryptionParams)
            for ((rowCount, columnCount), expected) in kats {
                let dimensions = try MatrixDimensions(rowCount: rowCount, columnCount: columnCount)
                try runPlaintextMatrixInitTest(
                    context: context,
                    dimensions: dimensions,
                    packing: .denseColumn, expected: expected)
            }
        }
        try runTest(for: NoOpScheme.self)
        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }

    func testPlaintextMatrixDenseRow() throws {
        let kats: [((rowCount: Int, columnCount: Int), expected: [[Int]])] = [
            ((1, 1), [[1, 1, 1, 1, 1, 1, 1, 1]]),
            ((1, 2), [[1, 2, 1, 2, 1, 2, 1, 2]]),
            ((1, 3), [[1, 2, 3, 0, 1, 2, 3, 0]]),
            ((1, 4), [[1, 2, 3, 4, 1, 2, 3, 4]]),
            ((3, 1), [[1, 2, 3, 0, 1, 2, 3, 0]]),
            ((3, 2), [[1, 2, 3, 4, 5, 6, 5, 6]]),
            ((3, 3), [[1, 2, 3, 0, 4, 5, 6, 0], [7, 8, 9, 0, 7, 8, 9, 0]]),
            ((3, 4), [[1, 2, 3, 4, 5, 6, 7, 8], [9, 10, 11, 12, 9, 10, 11, 12]]),
            ((4, 1), [[1, 2, 3, 4, 1, 2, 3, 4]]),
            ((4, 2), [[1, 2, 3, 4, 5, 6, 7, 8]]),
            ((4, 3), [[1, 2, 3, 0, 4, 5, 6, 0], [7, 8, 9, 0, 10, 11, 12, 0]]),
            ((4, 4), [[1, 2, 3, 4, 5, 6, 7, 8], [9, 10, 11, 12, 13, 14, 15, 16]]),
            ((5, 1), [[1, 2, 3, 4, 5, 5, 5, 5]]),
            ((5, 2), [[1, 2, 3, 4, 5, 6, 7, 8], [9, 10, 9, 10, 9, 10, 9, 10]]),
            ((5, 3), [[1, 2, 3, 0, 4, 5, 6, 0],
                      [7, 8, 9, 0, 10, 11, 12, 0],
                      [13, 14, 15, 0, 13, 14, 15, 0]]),
            ((5, 4), [[1, 2, 3, 4, 5, 6, 7, 8],
                      [9, 10, 11, 12, 13, 14, 15, 16],
                      [17, 18, 19, 20, 17, 18, 19, 20]]),
            ((6, 1), [[1, 2, 3, 4, 5, 6, 5, 6]]),
            ((6, 2), [[1, 2, 3, 4, 5, 6, 7, 8], [9, 10, 11, 12, 9, 10, 11, 12]]),
            ((6, 3), [[1, 2, 3, 0, 4, 5, 6, 0], [7, 8, 9, 0, 10, 11, 12, 0], [13, 14, 15, 0, 16, 17, 18, 0]]),
            ((6, 4), [[1, 2, 3, 4, 5, 6, 7, 8],
                      [9, 10, 11, 12, 13, 14, 15, 16],
                      [17, 18, 19, 20, 21, 22, 23, 24]]),
            // Note, last value is 0, because not all rows stored in the SIMD row can be repeated
            ((7, 1), [[1, 2, 3, 4, 5, 6, 7, 0]]),
            ((7, 2), [[1, 2, 3, 4, 5, 6, 7, 8], [9, 10, 11, 12, 13, 14, 13, 14]]),
            ((7, 3), [[1, 2, 3, 0, 4, 5, 6, 0],
                      [7, 8, 9, 0, 10, 11, 12, 0],
                      [13, 14, 15, 0, 16, 17, 18, 0],
                      [19, 20, 21, 0, 19, 20, 21, 0]]),
            ((7, 4), [[1, 2, 3, 4, 5, 6, 7, 8],
                      [9, 10, 11, 12, 13, 14, 15, 16],
                      [17, 18, 19, 20, 21, 22, 23, 24],
                      [25, 26, 27, 28, 25, 26, 27, 28]]),
            ((8, 1), [[1, 2, 3, 4, 5, 6, 7, 8]]),
            ((8, 2), [[1, 2, 3, 4, 5, 6, 7, 8], [9, 10, 11, 12, 13, 14, 15, 16]]),
            ((8, 3), [[1, 2, 3, 0, 4, 5, 6, 0],
                      [7, 8, 9, 0, 10, 11, 12, 0],
                      [13, 14, 15, 0, 16, 17, 18, 0],
                      [19, 20, 21, 0, 22, 23, 24, 0]]),
            ((8, 4), [[1, 2, 3, 4, 5, 6, 7, 8],
                      [9, 10, 11, 12, 13, 14, 15, 16],
                      [17, 18, 19, 20, 21, 22, 23, 24],
                      [25, 26, 27, 28, 29, 30, 31, 32]]),
            ((9, 1), [[1, 2, 3, 4, 5, 6, 7, 8], [9, 9, 9, 9, 9, 9, 9, 9]]),
            ((9, 2), [[1, 2, 3, 4, 5, 6, 7, 8],
                      [9, 10, 11, 12, 13, 14, 15, 16],
                      [17, 18, 17, 18, 17, 18, 17, 18]]),
            ((9, 3), [[1, 2, 3, 0, 4, 5, 6, 0],
                      [7, 8, 9, 0, 10, 11, 12, 0],
                      [13, 14, 15, 0, 16, 17, 18, 0],
                      [19, 20, 21, 0, 22, 23, 24, 0],
                      [25, 26, 27, 0, 25, 26, 27, 0]]),
            ((9, 4), [[1, 2, 3, 4, 5, 6, 7, 8],
                      [9, 10, 11, 12, 13, 14, 15, 16],
                      [17, 18, 19, 20, 21, 22, 23, 24],
                      [25, 26, 27, 28, 29, 30, 31, 32],
                      [33, 34, 35, 36, 33, 34, 35, 36]]),
        ]

        func runTest<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParams = try EncryptionParameters<Scheme>(from: rlweParams)
            let context = try Context(encryptionParameters: encryptionParams)
            for ((rowCount, columnCount), expected) in kats {
                let dimensions = try MatrixDimensions(rowCount: rowCount, columnCount: columnCount)
                try runPlaintextMatrixInitTest(
                    context: context,
                    dimensions: dimensions,
                    packing: .denseRow,
                    expected: expected)
            }
        }
        try runTest(for: NoOpScheme.self)
        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }

    func testPlaintextMatrixConversion() throws {
        func runTest<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParams = try EncryptionParameters<Scheme>(from: rlweParams)
            XCTAssert(encryptionParams.supportsSimdEncoding)
            let context = try Context<Scheme>(encryptionParameters: encryptionParams)
            let dimensions = try MatrixDimensions(rowCount: 10, columnCount: 4)
            let encodeValues: [[Scheme.Scalar]] = (0..<dimensions.rowCount).map { rowIndex in
                (0..<dimensions.columnCount).map { columnIndex in
                    let value = 1 + Scheme.Scalar(rowIndex * dimensions.columnCount + columnIndex)
                    return value % context.plaintextModulus
                }
            }
            let plaintextMatrix = try PlaintextMatrix<Scheme, Coeff>(
                context: context,
                dimensions: dimensions,
                packing: .denseRow,
                values: encodeValues.flatMap { $0 })

            let evalMatrix = try plaintextMatrix.convertToEvalFormat()
            let coeffMatrixRoundtrip = try evalMatrix.convertToCoeffFormat()
            XCTAssertEqual(coeffMatrixRoundtrip, plaintextMatrix)
        }
        try runTest(for: NoOpScheme.self)
        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }
}
