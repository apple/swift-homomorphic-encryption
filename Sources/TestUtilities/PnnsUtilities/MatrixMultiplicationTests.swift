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

extension Array where Element: Collection, Element.Element: ScalarType, Element.Index == Int {
    @usableFromInline typealias BaseElement = Element.Element

    @inlinable
    func mul(_ vector: [BaseElement], modulus: BaseElement) throws -> [BaseElement] {
        map { row in
            precondition(row.count == vector.count)
            return zip(row, vector).reduce(0) { sum, multiplicands in
                let product = multiplicands.0.multiplyMod(multiplicands.1, modulus: modulus, variableTime: true)
                return sum.addMod(product, modulus: modulus)
            }
        }
    }

    @inlinable
    func mulTranspose(_ matrix: [[BaseElement]], modulus: BaseElement) throws -> [BaseElement] {
        var result: [BaseElement] = []
        for vector in matrix {
            result += try mul(vector, modulus: modulus)
        }
        let resultMatrix = Array2d(data: result, rowCount: matrix.count, columnCount: count).transposed()
        return resultMatrix.data
    }
}

extension PrivateNearestNeighborSearchUtil {
    /// Matrix multiplication tests.
    public enum MatrixMultiplicationTests {
        /// Testing matrix-vector multiplication.
        @inlinable
        public static func mulVector<Scheme: HeScheme>(for _: Scheme.Type) throws {
            func checkProduct(
                _: Scheme.Type,
                _ plaintextRows: [[Scheme.Scalar]],
                _ plaintextMatrixDimensions: MatrixDimensions,
                _ queryValues: [Scheme.Scalar]) throws
            {
                let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: .n_4096_logq_27_28_28_logt_16)
                let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
                let secretKey = try context.generateSecretKey()

                var expected: [Scheme.Scalar] = try plaintextRows.mul(
                    queryValues,
                    modulus: encryptionParameters.plaintextModulus)

                let n = encryptionParameters.polyDegree
                if expected.count % n > 0 {
                    expected += Array(repeating: 0, count: n - (expected.count % n))
                }

                let babyStepGiantStep = BabyStepGiantStep(vectorDimension: queryValues.count)
                let plaintextMatrix = try PlaintextMatrix(
                    context: context,
                    dimensions: plaintextMatrixDimensions,
                    packing: .diagonal(babyStepGiantStep: babyStepGiantStep),
                    values: plaintextRows.flatMap(\.self))

                let evaluationKeyConfig = try EvaluationKeyConfig(galoisElements: [
                    GaloisElement.rotatingColumns(
                        by: -1,
                        degree: encryptionParameters.polyDegree),
                    GaloisElement.rotatingColumns(
                        by: -babyStepGiantStep.babyStep,
                        degree: encryptionParameters.polyDegree),
                ], hasRelinearizationKey: false)

                let evaluationKey = try context.generateEvaluationKey(
                    config: evaluationKeyConfig,
                    using: secretKey)

                // Query ciphertext matrix
                let ciphertextDimensions = try MatrixDimensions(rowCount: 1, columnCount: queryValues.count)
                let ciphertextVector = try PlaintextMatrix(
                    context: context,
                    dimensions: ciphertextDimensions,
                    packing: .denseRow,
                    values: queryValues).encrypt(using: secretKey)

                let dotProduct = try plaintextMatrix.mulTranspose(vector: ciphertextVector, using: evaluationKey)
                let expectedCiphertextsCount = plaintextMatrixDimensions.rowCount.dividingCeil(
                    encryptionParameters.polyDegree,
                    variableTime: true)
                #expect(dotProduct.count == expectedCiphertextsCount)
                var resultValues: [Scheme.Scalar] = []
                for ciphertext in dotProduct {
                    let decrypted = try ciphertext.decrypt(using: secretKey)
                    let decoded: [Scheme.Scalar] = try decrypted.decode(format: .simd)
                    resultValues += decoded
                }
                #expect(resultValues == expected)
            }

            // 6x6
            var values: [[Scheme.Scalar]] = []
            for i in Scheme.Scalar(1)...6 {
                values.append(Array(repeating: i, count: 6))
            }
            var dimensions = try MatrixDimensions(rowCount: 6, columnCount: 6)
            var queryValues: [Scheme.Scalar] = Array(repeating: 2, count: 6)
            try checkProduct(Scheme.self, values, dimensions, queryValues)

            // Tall - 64x16
            dimensions = try MatrixDimensions(rowCount: 64, columnCount: 16)
            values = increasingData(dimensions: dimensions, modulus: Scheme.Scalar(17))
            queryValues = Array(1...16)
            try checkProduct(Scheme.self, values, dimensions, queryValues)

            // Broad - 16x64
            dimensions = try MatrixDimensions(rowCount: 16, columnCount: 64)
            values = increasingData(dimensions: dimensions, modulus: Scheme.Scalar(70))
            queryValues = Array(1...64)
            queryValues.reverse()
            try checkProduct(Scheme.self, values, dimensions, queryValues)

            // Multiple result ciphertexts. 10240x4
            dimensions = try MatrixDimensions(rowCount: 10240, columnCount: 4)
            values = increasingData(dimensions: dimensions, modulus: Scheme.Scalar(17))
            queryValues = Array(1...4)
            try checkProduct(Scheme.self, values, dimensions, queryValues)
        }

        @inlinable
        package static func matrixMulRunner<Scheme: HeScheme>(
            context: Context<Scheme>,
            plaintextValues: [[Scheme.Scalar]],
            queryValues: [[Scheme.Scalar]]) throws
        {
            let encryptionParameters = context.encryptionParameters
            let secretKey = try context.generateSecretKey()
            let expected = try plaintextValues.mulTranspose(queryValues, modulus: context.plaintextModulus)
            // Query matrix
            let queryDimensions = try MatrixDimensions(rowCount: queryValues.count, columnCount: queryValues[0].count)
            let ciphertextMatrix = try PlaintextMatrix(
                context: context,
                dimensions: queryDimensions,
                packing: .denseRow,
                values: queryValues.flatMap(\.self)).encrypt(using: secretKey)

            let babyStepGiantStep = BabyStepGiantStep(vectorDimension: plaintextValues[0].count)
            let plaintextDimensions = try MatrixDimensions(
                rowCount: plaintextValues.count,
                columnCount: plaintextValues[0].count)
            let plaintextMatrix = try PlaintextMatrix(
                context: context,
                dimensions: plaintextDimensions,
                packing: .diagonal(babyStepGiantStep: babyStepGiantStep),
                values: plaintextValues.flatMap(\.self))

            let evaluationKeyConfig: EvaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
                plaintextMatrixDimensions: plaintextDimensions,
                maxQueryCount: queryDimensions.rowCount,
                encryptionParameters: encryptionParameters,
                scheme: Scheme.self)
            let evaluationKey = try context.generateEvaluationKey(config: evaluationKeyConfig, using: secretKey)
            let decryptedValues: [Scheme.Scalar] = try plaintextMatrix.mulTranspose(
                matrix: ciphertextMatrix,
                using: evaluationKey)
                .decrypt(using: secretKey).unpack()

            #expect(decryptedValues == expected, "incorrect decrypted values")
        }

        /// Testing matrix multiplication for large dimensions.
        @inlinable
        public static func matrixMulLargeDimensions<Scheme: HeScheme>(for _: Scheme.Type) throws {
            func testOnRandomData(
                plaintextRows: Int,
                plaintextCols: Int,
                ciphertextRows: Int,
                context: Context<Scheme>) throws
            {
                let plaintextMatrixDimensions = try MatrixDimensions(
                    rowCount: plaintextRows,
                    columnCount: plaintextCols)
                let ciphertextMatrixDimensions = try MatrixDimensions(
                    rowCount: ciphertextRows,
                    columnCount: plaintextCols)
                let plaintextValues: [[Scheme.Scalar]] = randomData(
                    dimensions: plaintextMatrixDimensions,
                    modulus: context.encryptionParameters.plaintextModulus)
                let queryValues: [[Scheme.Scalar]] = randomData(
                    dimensions: ciphertextMatrixDimensions,
                    modulus: context.encryptionParameters.plaintextModulus)
                try Self.matrixMulRunner(
                    context: context,
                    plaintextValues: plaintextValues,
                    queryValues: queryValues)
            }
            let degree = 2048
            let coefficientModuli = try Scheme.Scalar.generatePrimes(
                significantBitCounts: [29, 29, 29, 29],
                preferringSmall: false,
                nttDegree: degree)
            let plaintextModulus = try Scheme.Scalar.generatePrimes(
                significantBitCounts: [16],
                preferringSmall: true,
                nttDegree: degree)[0]
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
                polyDegree: degree,
                plaintextModulus: plaintextModulus,
                coefficientModuli: coefficientModuli,
                errorStdDev: ErrorStdDev.stdDev32,
                securityLevel: SecurityLevel.unchecked)

            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
            do {
                // Tall
                try testOnRandomData(plaintextRows: degree / 2, plaintextCols: 128, ciphertextRows: 3, context: context)
                try testOnRandomData(plaintextRows: degree / 2, plaintextCols: 384, ciphertextRows: 3, context: context)
                try testOnRandomData(
                    plaintextRows: 3 * degree / 4,
                    plaintextCols: 128,
                    ciphertextRows: 3,
                    context: context)
                try testOnRandomData(plaintextRows: degree, plaintextCols: 128, ciphertextRows: 1, context: context)
                try testOnRandomData(plaintextRows: 2 * degree, plaintextCols: 128, ciphertextRows: 2, context: context)
                try testOnRandomData(plaintextRows: 3 * degree, plaintextCols: 128, ciphertextRows: 3, context: context)
            }

            do {
                // Short, power-of-two ncols
                try testOnRandomData(plaintextRows: 160, plaintextCols: 128, ciphertextRows: 1, context: context)
                try testOnRandomData(plaintextRows: 160, plaintextCols: 128, ciphertextRows: 2, context: context)
                try testOnRandomData(plaintextRows: 160, plaintextCols: 128, ciphertextRows: 16, context: context)
                try testOnRandomData(plaintextRows: 160, plaintextCols: 128, ciphertextRows: 32, context: context)
            }

            do {
                // Short, non-power-of-two ncols
                try testOnRandomData(plaintextRows: 160, plaintextCols: 384, ciphertextRows: 1, context: context)
                try testOnRandomData(plaintextRows: 160, plaintextCols: 384, ciphertextRows: 2, context: context)
                try testOnRandomData(plaintextRows: 160, plaintextCols: 384, ciphertextRows: 16, context: context)
                try testOnRandomData(plaintextRows: 160, plaintextCols: 384, ciphertextRows: 32, context: context)
            }

            do {
                // Short, power-of-two ncols
                try testOnRandomData(plaintextRows: 160, plaintextCols: 128, ciphertextRows: 1, context: context)
                try testOnRandomData(plaintextRows: 160, plaintextCols: 128, ciphertextRows: 2, context: context)
                try testOnRandomData(plaintextRows: 160, plaintextCols: 128, ciphertextRows: 16, context: context)
                try testOnRandomData(plaintextRows: 160, plaintextCols: 128, ciphertextRows: 32, context: context)
            }

            do {
                // Wide columns
                var columnCount = degree / 4
                try testOnRandomData(
                    plaintextRows: 512,
                    plaintextCols: columnCount,
                    ciphertextRows: 1,
                    context: context)
                try testOnRandomData(
                    plaintextRows: 512,
                    plaintextCols: columnCount,
                    ciphertextRows: 2,
                    context: context)
                try testOnRandomData(
                    plaintextRows: 512,
                    plaintextCols: columnCount,
                    ciphertextRows: 5,
                    context: context)

                columnCount = degree / 2
                try testOnRandomData(
                    plaintextRows: 512,
                    plaintextCols: columnCount,
                    ciphertextRows: 1,
                    context: context)
                try testOnRandomData(
                    plaintextRows: 512,
                    plaintextCols: columnCount,
                    ciphertextRows: 2,
                    context: context)
                try testOnRandomData(
                    plaintextRows: 512,
                    plaintextCols: columnCount,
                    ciphertextRows: 5,
                    context: context)
            }
        }

        /// Testing matrix multiplication for small dimensions
        @inlinable
        public static func matrixMulSmallDimensions<Scheme: HeScheme>(for _: Scheme.Type) throws {
            func testOnIncreasingData(
                plaintextDimensions: MatrixDimensions,
                queryDimensions: MatrixDimensions,
                context: Context<Scheme>) throws
            {
                let plaintextModulus = context.encryptionParameters.plaintextModulus
                let plaintextValues: [[Scheme.Scalar]] = increasingData(
                    dimensions: plaintextDimensions,
                    modulus: plaintextModulus)
                let queryValues: [[Scheme.Scalar]] = increasingData(
                    dimensions: queryDimensions,
                    modulus: plaintextModulus)
                try Self.matrixMulRunner(
                    context: context,
                    plaintextValues: plaintextValues,
                    queryValues: queryValues)
            }

            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: .insecure_n_8_logq_5x18_logt_5)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
            do {
                // 8x4x2
                let plaintextDimensions = try MatrixDimensions(rowCount: 8, columnCount: 4)
                let queryDimensions = try MatrixDimensions(rowCount: 2, columnCount: 4)
                try testOnIncreasingData(
                    plaintextDimensions: plaintextDimensions,
                    queryDimensions: queryDimensions,
                    context: context)
            }
            do {
                // 7x2x4
                let plaintextDimensions = try MatrixDimensions(rowCount: 7, columnCount: 2)
                let queryDimensions = try MatrixDimensions(rowCount: 4, columnCount: 2)
                try testOnIncreasingData(
                    plaintextDimensions: plaintextDimensions,
                    queryDimensions: queryDimensions,
                    context: context)
            }
            do {
                // 6x1x2
                let plaintextDimensions = try MatrixDimensions(rowCount: 6, columnCount: 1)
                let queryDimensions = try MatrixDimensions(rowCount: 2, columnCount: 1)
                try testOnIncreasingData(
                    plaintextDimensions: plaintextDimensions,
                    queryDimensions: queryDimensions,
                    context: context)
            }

            do {
                // Non-power of 2 ncols
                let plaintextDimensions = try MatrixDimensions(rowCount: 5, columnCount: 3)
                let queryDimensions = try MatrixDimensions(rowCount: 2, columnCount: 3)
                try testOnIncreasingData(
                    plaintextDimensions: plaintextDimensions,
                    queryDimensions: queryDimensions,
                    context: context)
            }
            do {
                // Tall, plaintext rows in [N/4, N/2]
                let plaintextDimensions = try MatrixDimensions(rowCount: 200, columnCount: 4)
                let queryDimensions = try MatrixDimensions(rowCount: 5, columnCount: 4)
                try testOnIncreasingData(
                    plaintextDimensions: plaintextDimensions,
                    queryDimensions: queryDimensions,
                    context: context)
            }
            do {
                // Tall, plaintext rows > N
                let plaintextDimensions = try MatrixDimensions(rowCount: 10, columnCount: 4)
                let queryDimensions = try MatrixDimensions(rowCount: 5, columnCount: 4)
                try testOnIncreasingData(
                    plaintextDimensions: plaintextDimensions,
                    queryDimensions: queryDimensions,
                    context: context)
            }
        }

        /// Testing evaluation key configuration containment.
        public static func evaluationKeyContainment<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: .n_4096_logq_27_28_28_logt_16)
            let columnCount = 20
            let plaintextDims = try MatrixDimensions(rowCount: 100, columnCount: columnCount)
            for maxQueryCount in 1..<(columnCount + 1) {
                let maxQueryCountConfig = try MatrixMultiplication.evaluationKeyConfig(
                    plaintextMatrixDimensions: plaintextDims,
                    maxQueryCount: maxQueryCount,
                    encryptionParameters: encryptionParameters,
                    scheme: Scheme.self)
                for queryCount in 1..<maxQueryCount {
                    let config = try MatrixMultiplication.evaluationKeyConfig(
                        plaintextMatrixDimensions: plaintextDims,
                        maxQueryCount: queryCount,
                        encryptionParameters: encryptionParameters,
                        scheme: Scheme.self)
                    #expect(maxQueryCountConfig.contains(config))
                }
            }
            let hasRelinKey = EvaluationKeyConfig(galoisElements: [], hasRelinearizationKey: true)
            let noRelinKey = EvaluationKeyConfig(galoisElements: [], hasRelinearizationKey: false)
            #expect(hasRelinKey.contains(noRelinKey))
            #expect(hasRelinKey.contains(hasRelinKey))
            #expect(noRelinKey.contains(noRelinKey))
            #expect(!noRelinKey.contains(hasRelinKey))
        }
    }
}
