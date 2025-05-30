// Copyright 2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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
import ModularArithmetic
import PrivateNearestNeighborSearch
import Testing

extension PrivateNearestNeighborSearchUtil {
    /// Testing `PlaintextMatrix`.
    public enum PlaintextMatrixTests {
        /// Testing `MatrixDimensions`.
        public static func matrixDimensions() throws {
            #expect(throws: (any Error).self) { try MatrixDimensions(rowCount: -1, columnCount: 1) }
            let dims = try MatrixDimensions(rowCount: 2, columnCount: 3)
            #expect(dims.rowCount == 2)
            #expect(dims.columnCount == 3)
            #expect(dims.count == 6)
        }

        /// Error cases.
        @inlinable
        public static func plaintextMatrixError<Scheme: HeScheme>(for _: Scheme.Type) throws {
            func runTest(rlweParams: PredefinedRlweParameters) throws {
                let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: rlweParams)
                // Parameters with large polyDegree are slow in debug mode
                guard encryptionParameters.supportsSimdEncoding, encryptionParameters.polyDegree <= 16 else {
                    return
                }
                let dims = try MatrixDimensions(rowCount: encryptionParameters.polyDegree, columnCount: 2)
                let packing = MatrixPacking.denseRow
                let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
                let values = TestUtils.getRandomPlaintextData(
                    count: encryptionParameters.polyDegree,
                    in: 0..<encryptionParameters.plaintextModulus)
                let plaintext: Plaintext<Scheme, Coeff> = try context.encode(
                    values: values,
                    format: EncodeFormat.coefficient)
                #expect(throws: Never.self) { try PlaintextMatrix<Scheme, Coeff>(
                    dimensions: dims,
                    packing: packing,
                    plaintexts: [plaintext, plaintext]) }

                // Not enough plaintexts
                #expect(throws: (any Error).self) { try PlaintextMatrix<Scheme, Coeff>(
                    dimensions: dims,
                    packing: packing,
                    plaintexts: []) }
                // Plaintexts from different contexts
                do {
                    let diffRlweParams = rlweParams == PredefinedRlweParameters
                        .insecure_n_8_logq_5x18_logt_5 ? .n_4096_logq_27_28_28_logt_16 : PredefinedRlweParameters
                        .insecure_n_8_logq_5x18_logt_5
                    let diffEncryptionParams = try EncryptionParameters<Scheme.Scalar>(from: diffRlweParams)
                    let diffContext = try Context<Scheme>(encryptionParameters: diffEncryptionParams)
                    let diffValues = TestUtils.getRandomPlaintextData(
                        count: diffEncryptionParams.polyDegree,
                        in: 0..<diffEncryptionParams.plaintextModulus)
                    let diffPlaintext: Scheme.CoeffPlaintext = try diffContext.encode(
                        values: diffValues,
                        format: EncodeFormat.coefficient)
                    #expect(throws: (any Error).self) { try PlaintextMatrix<Scheme, Coeff>(
                        dimensions: dims,
                        packing: packing,
                        plaintexts: [plaintext, diffPlaintext]) }
                }
            }
            for rlweParams in PredefinedRlweParameters.allCases where rlweParams.supportsScalar(Scheme.Scalar.self) {
                try runTest(rlweParams: rlweParams)
            }
        }

        /// Errors for `denseRow` packing.
        @inlinable
        public static func plaintextMatrixDenseRowError<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: rlweParams)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
            let rowCount = encryptionParameters.polyDegree
            let columnCount = 2
            let values = TestUtils.getRandomPlaintextData(
                count: encryptionParameters.polyDegree,
                in: 0..<Scheme.Scalar(rowCount * columnCount))
            let packing = MatrixPacking.denseRow

            // Wrong number of values
            do {
                let wrongDims = try MatrixDimensions((rowCount, columnCount + 1))
                #expect(throws: (any Error).self) { try PlaintextMatrix<Scheme, Coeff>(
                    context: context,
                    dimensions: wrongDims,
                    packing: packing,
                    values: values) }
            }
            // Too many columns
            do {
                let dims = try MatrixDimensions((rowCount, columnCount + 1))
                #expect(throws: (any Error).self) { try PlaintextMatrix<Scheme, Coeff>(
                    context: context,
                    dimensions: dims,
                    packing: packing,
                    values: values) }
            }
        }

        @inlinable
        static func runPlaintextMatrixInitTest<Scheme: HeScheme>(
            context: Context<Scheme>,
            dimensions: MatrixDimensions,
            packing: MatrixPacking,
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
                values: encodeValues.flatMap(\.self))
            #expect(plaintextMatrix.rowCount == dimensions.rowCount)
            #expect(plaintextMatrix.columnCount == dimensions.columnCount)
            #expect(plaintextMatrix.packing == packing)
            #expect(plaintextMatrix.context == context)
            // Test round-trip
            #expect(try plaintextMatrix.unpack() == encodeValues.flatMap(\.self))

            // Test representation
            #expect(plaintextMatrix.plaintexts.count == expected.count)
            for (plaintext, expected) in zip(plaintextMatrix.plaintexts, expected) {
                let decoded: [Scheme.Scalar] = try plaintext.decode(format: .simd)
                #expect(decoded == expected)
            }

            // Test signed encoding/decoding
            let signedValues: [Scheme.SignedScalar] = try plaintextMatrix.unpack()
            let signedMatrix = try PlaintextMatrix<Scheme, Coeff>(
                context: context,
                dimensions: dimensions,
                packing: packing,
                signedValues: signedValues)
            let signedRoundtrip: [Scheme.SignedScalar] = try signedMatrix.unpack()
            #expect(signedRoundtrip == signedValues)

            // Test modular reduction
            let largerValues = encodeValues.flatMap(\.self).map { $0 + t }
            let largerSignedValues = signedValues.enumerated().map { index, value in
                if index.isMultiple(of: 2) {
                    value + Scheme.SignedScalar(t)
                } else {
                    value - Scheme.SignedScalar(t)
                }
            }

            let largerPlaintextMatrix = try PlaintextMatrix<Scheme, Coeff>(
                context: context,
                dimensions: dimensions,
                packing: packing,
                values: largerValues,
                reduce: true)
            #expect(largerPlaintextMatrix == plaintextMatrix)

            let largerSignedMatrix = try PlaintextMatrix<Scheme, Coeff>(
                context: context,
                dimensions: dimensions,
                packing: packing,
                signedValues: largerSignedValues,
                reduce: true)
            #expect(largerSignedMatrix == signedMatrix)
        }

        /// Errors for `denseColumn` packing.
        @inlinable
        public static func plaintextMatrixDenseColumn<Scheme: HeScheme>(for _: Scheme.Type) throws {
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

            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
                polyDegree: 8,
                plaintextModulus: 1153,
                coefficientModuli: Scheme.Scalar.generatePrimes(
                    significantBitCounts: [25, 25],
                    preferringSmall: false,
                    nttDegree: 8),
                errorStdDev: .stdDev32,
                securityLevel: .unchecked)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
            for ((rowCount, columnCount), expected) in kats {
                let dimensions = try MatrixDimensions((rowCount, columnCount))
                try Self.runPlaintextMatrixInitTest(
                    context: context,
                    dimensions: dimensions,
                    packing: .denseColumn, expected: expected)
            }
        }

        /// Testing `.denseRow` format.
        @inlinable
        public static func plaintextMatrixDenseRow<Scheme: HeScheme>(for _: Scheme.Type) throws {
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

            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: rlweParams)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
            for ((rowCount, columnCount), expected) in kats {
                let dimensions = try MatrixDimensions((rowCount, columnCount))
                try Self.runPlaintextMatrixInitTest(
                    context: context,
                    dimensions: dimensions,
                    packing: .denseRow,
                    expected: expected)
            }
        }

        /// Testing `.diagonal` format.
        @inlinable
        public static func plaintextMatrixDiagonal<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let kats: [((rowCount: Int, columnCount: Int), expected: [[Int]])] = [
                ((1, 3), [
                    [1, 0, 0, 0, 0, 0, 0, 0],
                    [2, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 3, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0, 0, 0, 0],
                ]),
                ((2, 3), [
                    [1, 5, 0, 0, 0, 0, 0, 0],
                    [2, 6, 0, 0, 0, 0, 0, 0],
                    [0, 0, 3, 0, 0, 0, 0, 0],
                    [0, 0, 0, 4, 0, 0, 0, 0],
                ]),
                ((3, 3), [
                    [1, 5, 9, 0, 0, 0, 0, 0],
                    [2, 6, 0, 0, 0, 0, 0, 0],
                    [7, 0, 3, 0, 0, 0, 0, 0],
                    [8, 0, 0, 4, 0, 0, 0, 0],
                ]),
                ((4, 3), [
                    [1, 5, 9, 0, 0, 0, 0, 0],
                    [2, 6, 0, 10, 0, 0, 0, 0],
                    [7, 11, 3, 0, 0, 0, 0, 0],
                    [8, 12, 0, 4, 0, 0, 0, 0],
                ]),
                ((7, 3), [
                    [1, 5, 9, 0, 13, 17, 21, 0],
                    [2, 6, 0, 10, 14, 18, 0, 0],
                    [7, 11, 3, 0, 19, 0, 15, 0],
                    [8, 12, 0, 4, 20, 0, 0, 16],
                ]),
                ((10, 3), [
                    [1, 5, 9, 0, 13, 17, 21, 0],
                    [25, 29, 0, 0, 0, 0, 0, 0],
                    [2, 6, 0, 10, 14, 18, 0, 22],
                    [26, 30, 0, 0, 0, 0, 0, 0],
                    [7, 11, 3, 0, 19, 23, 15, 0],
                    [0, 0, 27, 0, 0, 0, 0, 0],
                    [8, 12, 0, 4, 20, 24, 0, 16],
                    [0, 0, 0, 28, 0, 0, 0, 0],
                ]),
                ((1, 4), [[1, 0, 0, 0, 0, 0, 0, 0],
                          [2, 0, 0, 0, 0, 0, 0, 0],
                          [0, 0, 3, 0, 0, 0, 0, 0],
                          [0, 0, 4, 0, 0, 0, 0, 0]]),
                ((2, 4), [[1, 6, 0, 0, 0, 0, 0, 0],
                          [2, 7, 0, 0, 0, 0, 0, 0],
                          [0, 0, 3, 8, 0, 0, 0, 0],
                          [0, 0, 4, 5, 0, 0, 0, 0]]),
                ((3, 4), [[1, 6, 11, 0, 0, 0, 0, 0],
                          [2, 7, 12, 0, 0, 0, 0, 0],
                          [9, 0, 3, 8, 0, 0, 0, 0],
                          [10, 0, 4, 5, 0, 0, 0, 0]]),
                ((4, 4), [[1, 6, 11, 16, 0, 0, 0, 0],
                          [2, 7, 12, 13, 0, 0, 0, 0],
                          [9, 14, 3, 8, 0, 0, 0, 0],
                          [10, 15, 4, 5, 0, 0, 0, 0]]),
                ((7, 4), [[1, 6, 11, 16, 17, 22, 27, 0],
                          [2, 7, 12, 13, 18, 23, 28, 0],
                          [9, 14, 3, 8, 25, 0, 19, 24],
                          [10, 15, 4, 5, 26, 0, 20, 21]]),
                ((8, 4), [[1, 6, 11, 16, 17, 22, 27, 32],
                          [2, 7, 12, 13, 18, 23, 28, 29],
                          [9, 14, 3, 8, 25, 30, 19, 24],
                          [10, 15, 4, 5, 26, 31, 20, 21]]),
                ((9, 4), [[1, 6, 11, 16, 17, 22, 27, 32],
                          [33, 0, 0, 0, 0, 0, 0, 0],
                          [2, 7, 12, 13, 18, 23, 28, 29],
                          [34, 0, 0, 0, 0, 0, 0, 0],
                          [9, 14, 3, 8, 25, 30, 19, 24],
                          [0, 0, 35, 0, 0, 0, 0, 0],
                          [10, 15, 4, 5, 26, 31, 20, 21],
                          [0, 0, 36, 0, 0, 0, 0, 0]]),
            ]

            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
                polyDegree: 8,
                plaintextModulus: 1153,
                coefficientModuli: Scheme.Scalar.generatePrimes(
                    significantBitCounts: [25, 25],
                    preferringSmall: false,
                    nttDegree: 8),
                errorStdDev: ErrorStdDev.stdDev32,
                securityLevel: SecurityLevel.unchecked)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
            for ((rowCount, columnCount), expected) in kats {
                let dimensions = try MatrixDimensions((rowCount, columnCount))
                let bsgs = BabyStepGiantStep(vectorDimension: dimensions.columnCount.nextPowerOfTwo)
                try Self.runPlaintextMatrixInitTest(
                    context: context,
                    dimensions: dimensions,
                    packing: .diagonal(babyStepGiantStep: bsgs),
                    expected: expected)
            }
        }

        /// Testing `.diagonal` format.
        @inlinable
        public static func diagonalRotation<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
                polyDegree: 16,
                plaintextModulus: 1153,
                coefficientModuli: Scheme.Scalar.generatePrimes(
                    significantBitCounts: [25, 25],
                    preferringSmall: false,
                    nttDegree: 16),
                errorStdDev: ErrorStdDev.stdDev32,
                securityLevel: SecurityLevel.unchecked)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)

            let dimensions = try MatrixDimensions(rowCount: 4, columnCount: 5)
            let bsgs = BabyStepGiantStep(vectorDimension: dimensions.columnCount)

            let values: [[Scheme.Scalar]] = increasingData(
                dimensions: dimensions,
                modulus: encryptionParameters.plaintextModulus)
            let rotatedDiagonalPrefixes: [[Scheme.Scalar]] = [[1, 7, 13, 19],
                                                              [2, 8, 14, 20],
                                                              [3, 9, 15, 0],
                                                              [0, 0, 0, 4, 10],
                                                              [0, 0, 0, 5],
                                                              [0, 0, 0, 0, 0, 0, 16],
                                                              [11, 17],
                                                              [12, 18, 0, 0, 0, 0, 0, 6]]

            let expected: [[Scheme.Scalar]] = rotatedDiagonalPrefixes.map { diagonal in
                diagonal + Array(repeating: 0, count: encryptionParameters.polyDegree - diagonal.count)
            }

            let plaintextMatrix = try PlaintextMatrix<Scheme, Coeff>(
                context: context,
                dimensions: dimensions,
                packing: .diagonal(babyStepGiantStep: bsgs),
                values: values.flatMap(\.self))

            for (plaintext, expected) in zip(plaintextMatrix.plaintexts, expected) {
                let decoded: [Scheme.Scalar] = try plaintext.decode(format: .simd)
                #expect(decoded == expected)
            }
        }

        /// Testing format conversion.
        @inlinable
        public static func plaintextMatrixConversion<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: rlweParams)
            #expect(encryptionParameters.supportsSimdEncoding)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
            let dimensions = try MatrixDimensions(rowCount: 10, columnCount: 4)
            let encodeValues: [[Scheme.Scalar]] = increasingData(
                dimensions: dimensions,
                modulus: context.plaintextModulus)
            let plaintextMatrix = try PlaintextMatrix<Scheme, Coeff>(
                context: context,
                dimensions: dimensions,
                packing: .denseRow,
                values: encodeValues.flatMap(\.self))

            let evalMatrix = try plaintextMatrix.convertToEvalFormat()
            let coeffMatrixRoundtrip = try evalMatrix.convertToCoeffFormat()
            #expect(coeffMatrixRoundtrip == plaintextMatrix)
        }
    }
}
