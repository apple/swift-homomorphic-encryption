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

    func testPlaintextMatrixDenseRow() throws {
        func runTest<Scheme: HeScheme>(
            context: Context<Scheme>,
            dimensions: MatrixDimensions,
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
            let packing = PlaintextMatrixPacking.denseRow

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
                try runTest(context: context, dimensions: dimensions, expected: expected)
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
