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

import HomomorphicEncryption
@testable import PrivateNearestNeighborSearch
import Testing
import TestUtilities

func increasingData<T: ScalarType>(dimensions: MatrixDimensions, modulus: T) -> [[T]] {
    (0..<dimensions.rowCount).map { rowIndex in
        (0..<dimensions.columnCount).map { columnIndex in
            let value = 1 + T(rowIndex * dimensions.columnCount + columnIndex)
            return value % modulus
        }
    }
}

func randomData<T: ScalarType>(dimensions: MatrixDimensions, modulus: T) -> [[T]] {
    (0..<dimensions.rowCount).map { _ in
        (0..<dimensions.columnCount).map { _ in T.random(in: 0..<modulus) }
    }
}

@Suite("Ciphertext Matrix Tests")
struct CiphertextMatrixTests {
    @Test("Encrypt/Decrypt Round Trip")
    func encryptDecryptRoundTrip() throws {
        func runTest<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParameters = try EncryptionParameters<Scheme>(from: rlweParams)
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
                values: encodeValues.flatMap { $0 })
            let secretKey = try context.generateSecretKey()
            var ciphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)
            let plaintextMatrixRoundTrip = try ciphertextMatrix.decrypt(using: secretKey)
            #expect(plaintextMatrixRoundTrip == plaintextMatrix)

            // modSwitchDownToSingle
            do {
                try ciphertextMatrix.modSwitchDownToSingle()
                let plaintextMatrixRoundTrip = try ciphertextMatrix.decrypt(using: secretKey)
                #expect(plaintextMatrixRoundTrip == plaintextMatrix)
            }
        }
        try runTest(for: NoOpScheme.self)
        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }

    @Test("Convert Round Trip")
    func convertRoundTrip() throws {
        func runTest<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParameters = try EncryptionParameters<Scheme>(from: rlweParams)
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
                values: encodeValues.flatMap { $0 })
            let secretKey = try context.generateSecretKey()
            let ciphertextCoeffMatrix: CiphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)
            let ciphertextEvalMatrix = try ciphertextCoeffMatrix.convertToEvalFormat()
            let ciphertextMatrixRoundTrip = try ciphertextEvalMatrix.convertToCoeffFormat()
            let decoded = try ciphertextMatrixRoundTrip.decrypt(using: secretKey)
            #expect(plaintextMatrix == decoded)
        }
        try runTest(for: NoOpScheme.self)
        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }

    @Test("Extract Dense Row")
    func extractDenseRow() throws {
        func runTest<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let degree = 16
            let plaintextModulus = try Scheme.Scalar.generatePrimes(
                significantBitCounts: [9],
                preferringSmall: true,
                nttDegree: degree)[0]
            let coefficientModuli = try Scheme.Scalar.generatePrimes(
                significantBitCounts: Array(
                    repeating: Scheme.Scalar.bitWidth - 4,
                    count: 2),
                preferringSmall: false,
                nttDegree: degree)
            let encryptionParameters = try EncryptionParameters<Scheme>(
                polyDegree: degree,
                plaintextModulus: plaintextModulus,
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .unchecked)
            #expect(encryptionParameters.supportsSimdEncoding)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)

            for rowCount in 1..<(2 * degree) {
                for columnCount in 1..<degree / 2 {
                    let dimensions = try MatrixDimensions((rowCount, columnCount))
                    let encodeValues: [[Scheme.Scalar]] = increasingData(
                        dimensions: dimensions,
                        modulus: plaintextModulus)

                    let plaintextMatrix = try PlaintextMatrix<Scheme, Coeff>(
                        context: context,
                        dimensions: dimensions,
                        packing: .denseRow,
                        values: encodeValues.flatMap { $0 })
                    let secretKey = try context.generateSecretKey()
                    let ciphertextMatrix: CiphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)

                    let evaluationKeyConfig = try CiphertextMatrix<Scheme, Coeff>.extractDenseRowConfig(
                        for: encryptionParameters,
                        dimensions: dimensions)
                    let evaluationKey = try context.generateEvaluationKey(
                        config: evaluationKeyConfig,
                        using: secretKey)

                    for rowIndex in 0..<rowCount {
                        let extractedRow = try ciphertextMatrix.extractDenseRow(
                            rowIndex: rowIndex,
                            evaluationKey: evaluationKey)

                        let expectedDimensions = try MatrixDimensions(
                            rowCount: 1,
                            columnCount: columnCount)
                        #expect(extractedRow.dimensions == expectedDimensions)

                        // Check unpacking
                        let decrypted = try extractedRow.decrypt(using: secretKey)
                        let unpacked: [Scheme.Scalar] = try decrypted.unpack()
                        #expect(unpacked == encodeValues[rowIndex])

                        // Check encoded values
                        var row = encodeValues[rowIndex]
                        row += Array(repeating: 0, count: row.count.nextPowerOfTwo - row.count)
                        let expectedRow = Array(repeating: row, count: degree / row.count).flatMap { $0 }
                        let decoded: [Scheme.Scalar] = try decrypted.plaintexts[0].decode(format: .simd)
                        #expect(decoded == expectedRow)
                    }
                }
            }
        }
        try runTest(for: NoOpScheme.self)
        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }
}
