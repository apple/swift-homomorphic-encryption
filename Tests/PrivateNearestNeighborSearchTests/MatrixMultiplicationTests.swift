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
import HomomorphicEncryption
@testable import PrivateNearestNeighborSearch
import Testing

extension Array where Element: Collection, Element.Element: ScalarType, Element.Index == Int {
    func mulTranspose(_ matrix: [[BaseElement]], modulus: BaseElement) throws -> [BaseElement] {
        var result: [BaseElement] = []
        for vector in matrix {
            result += try mul(vector, modulus: modulus)
        }
        let resultMatrix = Array2d(data: result, rowCount: matrix.count, columnCount: count).transposed()
        return resultMatrix.data
    }
}

@Suite
struct MatrixMultiplicationTests {
    @Test
    func mulVector() throws {
        func checkProduct<Scheme: HeScheme>(
            _: Scheme.Type,
            _ plaintextRows: [[Scheme.Scalar]],
            _ plaintextMatrixDimensions: MatrixDimensions,
            _ queryValues: [Scheme.Scalar]) throws
        {
            let encryptionParameters = try EncryptionParameters<Scheme>(from: .n_4096_logq_27_28_28_logt_16)
            let context = try Context(encryptionParameters: encryptionParameters)
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
                values: plaintextRows.flatMap { $0 })

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

        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
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

        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    private func matrixMulRunner<Scheme: HeScheme>(
        encryptionParameters: EncryptionParameters<Scheme>,
        plaintextValues: [[Scheme.Scalar]],
        queryValues: [[Scheme.Scalar]]) throws
    {
        let context = try Context(encryptionParameters: encryptionParameters)
        let secretKey = try context.generateSecretKey()
        let expected = try plaintextValues.mulTranspose(queryValues, modulus: context.plaintextModulus)
        // Query matrix
        let queryDimensions = try MatrixDimensions(rowCount: queryValues.count, columnCount: queryValues[0].count)
        let ciphertextMatrix = try PlaintextMatrix(
            context: context,
            dimensions: queryDimensions,
            packing: .denseRow,
            values: queryValues.flatMap { $0 }).encrypt(using: secretKey)

        let babyStepGiantStep = BabyStepGiantStep(vectorDimension: plaintextValues[0].count)
        let plaintextDimensions = try MatrixDimensions(
            rowCount: plaintextValues.count,
            columnCount: plaintextValues[0].count)
        let plaintextMatrix = try PlaintextMatrix(
            context: context,
            dimensions: plaintextDimensions,
            packing: .diagonal(babyStepGiantStep: babyStepGiantStep),
            values: plaintextValues.flatMap { $0 })

        let evaluationKeyConfig: EvaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: plaintextDimensions,
            encryptionParameters: encryptionParameters,
            maxQueryCount: queryDimensions.rowCount)
        let evaluationKey = try context.generateEvaluationKey(config: evaluationKeyConfig, using: secretKey)
        let decryptedValues: [Scheme.Scalar] = try plaintextMatrix.mulTranspose(
            matrix: ciphertextMatrix,
            using: evaluationKey)
            .decrypt(using: secretKey).unpack()

        #expect(decryptedValues == expected)
    }

    @Test
    func matrixMulLargeParameters() throws {
        func testOnRandomData<Scheme: HeScheme>(
            plaintextRows: Int,
            plaintextCols: Int,
            ciphertextRows: Int,
            encryptionParameters: EncryptionParameters<Scheme>) throws
        {
            let plaintextMatrixDimensions = try MatrixDimensions(rowCount: plaintextRows, columnCount: plaintextCols)
            let ciphertextMatrixDimensions = try MatrixDimensions(rowCount: ciphertextRows, columnCount: plaintextCols)
            let plaintextValues: [[Scheme.Scalar]] = randomData(
                dimensions: plaintextMatrixDimensions,
                modulus: encryptionParameters.plaintextModulus)
            let queryValues: [[Scheme.Scalar]] = randomData(
                dimensions: ciphertextMatrixDimensions,
                modulus: encryptionParameters.plaintextModulus)
            try matrixMulRunner(
                encryptionParameters: encryptionParameters,
                plaintextValues: plaintextValues,
                queryValues: queryValues)
        }

        let encryptionParameters = try EncryptionParameters<Bfv<UInt64>>(from: .n_8192_logq_3x55_logt_29)
        let degree = encryptionParameters.polyDegree

        do {
            // Tall
            try testOnRandomData(
                plaintextRows: degree / 2,
                plaintextCols: 128,
                ciphertextRows: 3,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: degree / 2,
                plaintextCols: 384,
                ciphertextRows: 3,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 3 * degree / 4,
                plaintextCols: 128,
                ciphertextRows: 3,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: degree,
                plaintextCols: 128,
                ciphertextRows: 1,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 2 * degree,
                plaintextCols: 128,
                ciphertextRows: 2,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 3 * degree,
                plaintextCols: 128,
                ciphertextRows: 3,
                encryptionParameters: encryptionParameters)
        }

        do {
            // Short, power-of-two ncols
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 128,
                ciphertextRows: 1,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 128,
                ciphertextRows: 2,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 128,
                ciphertextRows: 16,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 128,
                ciphertextRows: 32,
                encryptionParameters: encryptionParameters)
        }

        do {
            // Short, non-power-of-two ncols
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 384,
                ciphertextRows: 1,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 384,
                ciphertextRows: 2,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 384,
                ciphertextRows: 16,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 384,
                ciphertextRows: 32,
                encryptionParameters: encryptionParameters)
        }

        do {
            // Short, power-of-two ncols
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 128,
                ciphertextRows: 1,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 128,
                ciphertextRows: 2,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 128,
                ciphertextRows: 16,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 160,
                plaintextCols: 128,
                ciphertextRows: 32,
                encryptionParameters: encryptionParameters)
        }

        do {
            // Wide columns
            var columnCount = degree / 4
            try testOnRandomData(
                plaintextRows: 512,
                plaintextCols: columnCount,
                ciphertextRows: 1,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 512,
                plaintextCols: columnCount,
                ciphertextRows: 2,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 512,
                plaintextCols: columnCount,
                ciphertextRows: 5,
                encryptionParameters: encryptionParameters)

            columnCount = degree / 2
            try testOnRandomData(
                plaintextRows: 512,
                plaintextCols: columnCount,
                ciphertextRows: 1,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 512,
                plaintextCols: columnCount,
                ciphertextRows: 2,
                encryptionParameters: encryptionParameters)
            try testOnRandomData(
                plaintextRows: 512,
                plaintextCols: columnCount,
                ciphertextRows: 5,
                encryptionParameters: encryptionParameters)
        }
    }

    @Test
    func matrixMulSmallParameters() throws {
        func testOnIncreasingData<Scheme: HeScheme>(
            plaintextDimensions: MatrixDimensions,
            queryDimensions: MatrixDimensions,
            encryptionParameters: EncryptionParameters<Scheme>) throws
        {
            let plaintextValues: [[Scheme.Scalar]] = increasingData(
                dimensions: plaintextDimensions,
                modulus: encryptionParameters.plaintextModulus)
            let queryValues: [[Scheme.Scalar]] = increasingData(
                dimensions: queryDimensions,
                modulus: encryptionParameters.plaintextModulus)
            try matrixMulRunner(
                encryptionParameters: encryptionParameters,
                plaintextValues: plaintextValues,
                queryValues: queryValues)
        }

        let encryptionParameters = try EncryptionParameters<Bfv<UInt64>>(from: .insecure_n_512_logq_4x60_logt_20)
        do {
            // 8x4x2
            let plaintextDimensions = try MatrixDimensions(rowCount: 8, columnCount: 4)
            let queryDimensions = try MatrixDimensions(rowCount: 2, columnCount: 4)
            try testOnIncreasingData(
                plaintextDimensions: plaintextDimensions,
                queryDimensions: queryDimensions,
                encryptionParameters: encryptionParameters)
        }

        do {
            // 7x2x4
            let plaintextDimensions = try MatrixDimensions(rowCount: 7, columnCount: 2)
            let queryDimensions = try MatrixDimensions(rowCount: 4, columnCount: 2)
            try testOnIncreasingData(
                plaintextDimensions: plaintextDimensions,
                queryDimensions: queryDimensions,
                encryptionParameters: encryptionParameters)
        }

        do {
            // 6x1x2
            let plaintextDimensions = try MatrixDimensions(rowCount: 6, columnCount: 1)
            let queryDimensions = try MatrixDimensions(rowCount: 2, columnCount: 1)
            try testOnIncreasingData(
                plaintextDimensions: plaintextDimensions,
                queryDimensions: queryDimensions,
                encryptionParameters: encryptionParameters)
        }

        do {
            // Non-power of 2 ncols
            let plaintextDimensions = try MatrixDimensions(rowCount: 5, columnCount: 3)
            let queryDimensions = try MatrixDimensions(rowCount: 2, columnCount: 3)
            try testOnIncreasingData(
                plaintextDimensions: plaintextDimensions,
                queryDimensions: queryDimensions,
                encryptionParameters: encryptionParameters)
        }

        do {
            // Tall, plaintext rows in [N/4, N/2]
            let plaintextDimensions = try MatrixDimensions(rowCount: 200, columnCount: 4)
            let queryDimensions = try MatrixDimensions(rowCount: 5, columnCount: 4)
            try testOnIncreasingData(
                plaintextDimensions: plaintextDimensions,
                queryDimensions: queryDimensions,
                encryptionParameters: encryptionParameters)
        }

        do {
            // Tall, plaintext rows > N
            let encryptionParameters = try EncryptionParameters<Bfv<UInt64>>(from: .insecure_n_8_logq_5x18_logt_5)
            let plaintextDimensions = try MatrixDimensions(rowCount: 10, columnCount: 4)
            let queryDimensions = try MatrixDimensions(rowCount: 5, columnCount: 4)
            try testOnIncreasingData(
                plaintextDimensions: plaintextDimensions,
                queryDimensions: queryDimensions,
                encryptionParameters: encryptionParameters)
        }
    }

    @Test
    func evaluationKeyContainment() throws {
        let encryptionParameters = try EncryptionParameters<Bfv<UInt64>>(from: .insecure_n_512_logq_4x60_logt_20)
        let columnCount = 20
        let plaintextDims = try MatrixDimensions(rowCount: 100, columnCount: columnCount)
        for maxQueryCount in 1..<(columnCount + 1) {
            let maxQueryCountConfig = try MatrixMultiplication.evaluationKeyConfig(
                plaintextMatrixDimensions: plaintextDims,
                encryptionParameters: encryptionParameters,
                maxQueryCount: maxQueryCount)
            for queryCount in 1..<maxQueryCount {
                let config = try MatrixMultiplication.evaluationKeyConfig(
                    plaintextMatrixDimensions: plaintextDims,
                    encryptionParameters: encryptionParameters,
                    maxQueryCount: queryCount)
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
