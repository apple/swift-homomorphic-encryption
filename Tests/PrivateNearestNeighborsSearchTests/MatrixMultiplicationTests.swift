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

final class MatrixMultiplicationTests: XCTestCase {
    func testMulVector() throws {
        func checkProduct<Scheme: HeScheme>(
            _: Scheme.Type,
            _ plaintextRows: [[Scheme.Scalar]],
            _ plaintextMatrixDimensions: MatrixDimensions,
            _ queryValues: [Scheme.Scalar]) throws
        {
            let encryptionParameters = try EncryptionParameters<Scheme>(from: .n_4096_logq_27_28_28_logt_16)
            let context = try Context(encryptionParameters: encryptionParameters)
            let secretKey = try context.generateSecretKey()
            let queryCount = queryValues.count / plaintextMatrixDimensions.columnCount

            let expected: [Scheme.Scalar] = try plaintextRows.mul(
                queryValues,
                modulus: encryptionParameters.plaintextModulus)

            let babyStepGiantStep = BabyStepGiantStep(vectorDimension: queryValues.count)
            let plaintextMatrix = try PlaintextMatrix(
                context: context,
                dimensions: plaintextMatrixDimensions,
                packing: .diagonal(babyStepGiantStep: babyStepGiantStep),
                values: plaintextRows.flatMap { $0 })

            let evaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
                plaintextMatrixDimensions: plaintextMatrixDimensions,
                encryptionParameters: encryptionParameters)
            let evaluationKey = try context.generateEvaluationKey(
                configuration: evaluationKeyConfig,
                using: secretKey)

            // Query ciphertext matrix
            let ciphertextDimensions = try MatrixDimensions(rowCount: queryValues.count, columnCount: 1)
            let ciphertextVector = try PlaintextMatrix(
                context: context,
                dimensions: ciphertextDimensions,
                packing: .denseRow,
                values: queryValues).encrypt(using: secretKey)

            let dotProduct = try plaintextMatrix.mul(ciphertextVector: ciphertextVector, using: evaluationKey)
            let expectedCiphertextsCount = plaintextMatrixDimensions.rowCount.dividingCeil(
                encryptionParameters.polyDegree,
                variableTime: true)
            XCTAssertEqual(dotProduct.ciphertexts.count, expectedCiphertextsCount)
            XCTAssertEqual(
                dotProduct.dimensions,
                try MatrixDimensions(
                    rowCount: plaintextMatrixDimensions.rowCount,
                    columnCount: queryCount))

            let resultMatrix = try dotProduct.decrypt(using: secretKey)
            let resultValues: [Scheme.Scalar] = try resultMatrix.unpack()
            XCTAssertEqual(resultValues, expected)
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
            // values = Array(1...1024).map { $0 % 17 }
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
}
