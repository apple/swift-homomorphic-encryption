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

final class CiphertextMatrixTests: XCTestCase {
    func testEncryptDecryptRoundTrip() throws {
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
            let secretKey = try context.generateSecretKey()
            let ciphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)
            let plaintextMatrixroundTrip = try ciphertextMatrix.decrypt(using: secretKey)
            XCTAssertEqual(plaintextMatrixroundTrip, plaintextMatrix)
        }
        try runTest(for: NoOpScheme.self)
        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }

    func testConvertRoundTrip() throws {
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
            let secretKey = try context.generateSecretKey()
            let ciphertextCoeffMatrix: CiphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)
            let ciphertextEvalMatrix = try ciphertextCoeffMatrix.convertToEvalFormat()
            let ciphertextMatrixRoundTrip = try ciphertextEvalMatrix.convertToCoeffFormat()
            let decoded = try ciphertextMatrixRoundTrip.decrypt(using: secretKey)
            XCTAssertEqual(plaintextMatrix, decoded)
        }
        try runTest(for: NoOpScheme.self)
        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }
}
