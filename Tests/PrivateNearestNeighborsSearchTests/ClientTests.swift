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

final class ClientTests: XCTestCase {
    func testClientConfig() throws {
        func runTest<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let plaintextModuli = try [
                PredefinedRlweParameters.n_4096_logq_27_28_28_logt_16,
                PredefinedRlweParameters.n_4096_logq_27_28_28_logt_17,
            ].map { rlweParams in
                try EncryptionParameters<Scheme>(from: rlweParams).plaintextModulus
            }
            // Check scaling factor increases as we add plaintext moduli.
            let maxScalingFactor1 = ClientConfig<Scheme>.maxScalingFactor(
                vectorDimension: 128,
                distanceMetric: .cosineSimilarity,
                plaintextModuli: Array(plaintextModuli.prefix(1)))
            let maxScalingFactor2 = ClientConfig<Scheme>.maxScalingFactor(
                vectorDimension: 128,
                distanceMetric: .cosineSimilarity,
                plaintextModuli: plaintextModuli)
            XCTAssertGreaterThan(maxScalingFactor2, maxScalingFactor1)

            XCTAssertNoThrow(
                try ClientConfig<Scheme>(
                    encryptionParams: EncryptionParameters(from: PredefinedRlweParameters.n_4096_logq_27_28_28_logt_17),
                    scalingFactor: maxScalingFactor2,
                    queryPacking: .denseRow,
                    vectorDimension: 128,
                    evaluationKeyConfig: EvaluationKeyConfiguration(),
                    distanceMetric: .cosineSimilarity,
                    extraPlaintextModuli: [plaintextModuli[1]]))
        }

        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }

    func testNormalizeRowsAndScale() throws {
        struct TestCase<T: SignedScalarType> {
            let scalingFactor: Float
            let norm: Array2d<Float>.Norm
            let input: [[Float]]
            let normalized: [[Float]]
            let scaled: [[Float]]
            let rounded: [[T]]
        }

        func runTestCase<T: SignedScalarType>(testCase: TestCase<T>) throws {
            let floatMatrix = Array2d<Float>(data: testCase.input)
            let normalized = floatMatrix.normalizedRows(norm: testCase.norm)
            for (normalized, expected) in zip(normalized.data, testCase.normalized.flatMap { $0 }) {
                XCTAssertIsClose(normalized, expected)
            }

            let scaled = normalized.scaled(by: testCase.scalingFactor)
            for (scaled, expected) in zip(scaled.data, testCase.scaled.flatMap { $0 }) {
                XCTAssertIsClose(scaled, expected)
            }
            let rounded: Array2d<T> = scaled.rounded()
            XCTAssertEqual(rounded.data, testCase.rounded.flatMap { $0 })
        }

        let testCases: [TestCase<Int32>] = [
            TestCase(scalingFactor: 10.0,
                     norm: Array2d<Float>.Norm.Lp(p: 1.0),
                     input: [[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]],
                     normalized: [[1.0 / 3.0, 2.0 / 3.0], [3.0 / 7.0, 4.0 / 7.0], [5.0 / 11.0, 6.0 / 11.0]],
                     scaled: [[10.0 / 3.0, 20.0 / 3.0], [30.0 / 7.0, 40.0 / 7.0], [50.0 / 11.0, 60.0 / 11.0]],
                     rounded: [[3, 7], [4, 6], [5, 5]]),
            TestCase(scalingFactor: 100.0,
                     norm: Array2d<Float>.Norm.Lp(p: 2.0),
                     input: [[3.0, 4.0], [-5.0, 12.0]],
                     normalized: [[3.0 / 5.0, 4.0 / 5.0], [-5.0 / 13.0, 12.0 / 13.0]],
                     scaled: [[300.0 / 5.0, 400.0 / 5.0], [-500.0 / 13.0, 1200.0 / 13.0]],
                     rounded: [[60, 80], [-38, 92]]),
        ]
        for testCase in testCases {
            try runTestCase(testCase: testCase)
        }
    }

    func testQuery() throws {
        func runTest<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let degree = 512
            let encryptionParams = try EncryptionParameters<Scheme>(
                polyDegree: degree,
                plaintextModulus: Scheme.Scalar.generatePrimes(
                    significantBitCounts: [16],
                    preferringSmall: true,
                    nttDegree: degree)[0],
                coefficientModuli: Scheme.Scalar.generatePrimes(
                    significantBitCounts: [27, 28, 28],
                    preferringSmall: false,
                    nttDegree: degree),
                errorStdDev: .stdDev32,
                securityLevel: .unchecked)
            XCTAssert(encryptionParams.supportsSimdEncoding)
            let context = try Context<Scheme>(encryptionParameters: encryptionParams)
            let vectorDimension = 32
            let queryDimensions = try MatrixDimensions(rowCount: 1, columnCount: vectorDimension)

            let encodeValues: [[Scheme.Scalar]] = increasingData(
                dimensions: queryDimensions,
                modulus: context.plaintextModulus)
            let queryValues: Array2d<Float> = Array2d(data: encodeValues).map { value in Float(value) }
            let secretKey = try context.generateSecretKey()
            let scalingFactor = 100

            for extraPlaintextModuli in try [[], Scheme.Scalar.generatePrimes(
                significantBitCounts: [17],
                preferringSmall: true, nttDegree: degree)]
            {
                let config = ClientConfig(
                    encryptionParams: encryptionParams,
                    scalingFactor: scalingFactor,
                    queryPacking: .denseRow,
                    vectorDimension: vectorDimension,
                    evaluationKeyConfig: EvaluationKeyConfiguration(),
                    distanceMetric: .cosineSimilarity,
                    extraPlaintextModuli: extraPlaintextModuli)
                let client = try Client(config: config)
                let query = try client.generateQuery(vectors: queryValues, using: secretKey)
                XCTAssertEqual(query.ciphertextMatrices.count, config.plaintextModuli.count)

                let entryIds = [UInt64(42)]
                let entryMetadatas = [42.littleEndianBytes]
                let response = Response(
                    ciphertextMatrices: query.ciphertextMatrices,
                    entryIds: entryIds, entryMetadatas: entryMetadatas)
                let databaseDistances = try client.decrypt(response: response, using: secretKey)
                XCTAssertEqual(databaseDistances.entryIds, entryIds)
                XCTAssertEqual(databaseDistances.entryMetadatas, entryMetadatas)

                let scaledQuery: Array2d<Scheme.SignedScalar> = queryValues
                    .normalizedRows(norm: Array2d<Float>.Norm.Lp(p: 2.0)).scaled(by: Float(config.scalingFactor))
                    .rounded()
                // Cosine similarity response returns result scaled by scalingFactor^2
                let expectedDistances = scaledQuery.map { value in
                    Float(value) / Float(config.scalingFactor * config.scalingFactor)
                }
                XCTAssertEqual(databaseDistances.distances, expectedDistances)
            }
        }
        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }
}
