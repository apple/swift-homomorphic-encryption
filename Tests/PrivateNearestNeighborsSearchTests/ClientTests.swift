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
                distanceMetric: .cosineSimilarity,
                vectorDimension: 128,
                plaintextModuli: Array(plaintextModuli.prefix(1)))
            let maxScalingFactor2 = ClientConfig<Scheme>.maxScalingFactor(
                distanceMetric: .cosineSimilarity,
                vectorDimension: 128,
                plaintextModuli: plaintextModuli)
            XCTAssertGreaterThan(maxScalingFactor2, maxScalingFactor1)

            XCTAssertNoThrow(
                try ClientConfig<Scheme>(
                    encryptionParams: EncryptionParameters(from: PredefinedRlweParameters.n_4096_logq_27_28_28_logt_17),
                    scalingFactor: maxScalingFactor2,
                    queryPacking: .denseRow,
                    vectorDimension: 128,
                    evaluationKeyConfig: EvaluationKeyConfig(),
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

            if testCase.norm == Array2d<Float>.Norm.Lp(p: 2.0) {
                let normalizedScaledAndRounded: Array2d<T> = floatMatrix.normalizedScaledAndRounded(
                    scalingFactor: testCase.scalingFactor)
                XCTAssertEqual(normalizedScaledAndRounded.data, testCase.rounded.flatMap { $0 })
            }
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

    func testQueryAsResponse() throws {
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
                let config = try ClientConfig(
                    encryptionParams: encryptionParams,
                    scalingFactor: scalingFactor,
                    queryPacking: .denseRow,
                    vectorDimension: vectorDimension,
                    evaluationKeyConfig: EvaluationKeyConfig(),
                    distanceMetric: .cosineSimilarity,
                    extraPlaintextModuli: extraPlaintextModuli)
                let client = try Client(config: config)
                let query = try client.generateQuery(for: queryValues, using: secretKey)
                XCTAssertEqual(query.ciphertextMatrices.count, config.plaintextModuli.count)

                let entryIds = [UInt64(42)]
                let entryMetadatas = [42.littleEndianBytes]
                // Treat the query as a response
                let response = Response(
                    ciphertextMatrices: query.ciphertextMatrices,
                    entryIds: entryIds, entryMetadatas: entryMetadatas)
                let databaseDistances = try client.decrypt(response: response, using: secretKey)
                XCTAssertEqual(databaseDistances.entryIds, entryIds)
                XCTAssertEqual(databaseDistances.entryMetadatas, entryMetadatas)

                let scaledQuery: Array2d<Scheme.SignedScalar> = queryValues
                    .normalizedScaledAndRounded(scalingFactor: Float(config.scalingFactor))
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

    func testClientServer() throws {
        func runSingleTest<Scheme: HeScheme>(
            encryptionParams: EncryptionParameters<Scheme>,
            dimensions: MatrixDimensions,
            plaintextModuli: [Scheme.Scalar],
            queryCount: Int) throws
        {
            let vectorDimension = dimensions.columnCount
            let scalingFactor = ClientConfig<Scheme>.maxScalingFactor(
                distanceMetric: .cosineSimilarity,
                vectorDimension: vectorDimension,
                plaintextModuli: plaintextModuli)
            let evaluatonKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
                plaintextMatrixDimensions: dimensions,
                encryptionParameters: encryptionParams)
            let clientConfig = try ClientConfig<Scheme>(
                encryptionParams: encryptionParams,
                scalingFactor: scalingFactor,
                queryPacking: .denseRow,
                vectorDimension: vectorDimension,
                evaluationKeyConfig: evaluatonKeyConfig,
                distanceMetric: .cosineSimilarity,
                extraPlaintextModuli: Array(plaintextModuli[1...]))
            let serverConfig = ServerConfig(
                clientConfig: clientConfig,
                databasePacking: .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))

            let database = getDatabaseForTesting(config: DatabaseConfig(
                rowCount: dimensions.rowCount,
                vectorDimension: dimensions.columnCount))
            let processed = try database.process(config: serverConfig)

            let client = try Client(config: clientConfig, contexts: processed.contexts)
            let server = try Server(database: processed)

            // We query exact matches from rows in the database
            let queryVectors = Array2d(data: database.rows.prefix(queryCount).map { row in row.vector })
            let secretKey = try client.generateSecretKey()
            let query = try client.generateQuery(for: queryVectors, using: secretKey)
            let evaluationKey = try client.generateEvaluationKey(using: secretKey)

            let response = try server.computeResponse(to: query, using: evaluationKey)
            let noiseBudget = try response.noiseBudget(using: secretKey, variableTime: true)
            XCTAssertGreaterThan(noiseBudget, 0)
            let decrypted = try client.decrypt(response: response, using: secretKey)

            XCTAssertEqual(decrypted.entryIds, processed.entryIds)
            XCTAssertEqual(decrypted.entryMetadatas, processed.entryMetadatas)

            let vectors = Array2d<Float>(data: database.rows.map { row in row.vector })
            let modulus: UInt64 = client.config.plaintextModuli.map { UInt64($0) }.reduce(1, *)
            let expected = try vectors.fixedPointCosineSimilarity(
                queryVectors.transposed(),
                modulus: modulus,
                scalingFactor: Float(scalingFactor))
            XCTAssertEqual(decrypted.distances, expected)
        }

        func runTest<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let degree = 64
            let maxPlaintextModuliCount = 2
            let plaintextModuli = try Scheme.Scalar.generatePrimes(
                significantBitCounts: Array(repeating: 10, count: maxPlaintextModuliCount),
                preferringSmall: true,
                nttDegree: degree)
            let coefficientModuli = try Scheme.Scalar.generatePrimes(
                significantBitCounts: Array(
                    repeating: Scheme.Scalar.bitWidth - 4,
                    count: 3),
                preferringSmall: false,
                nttDegree: degree)
            let encryptionParams = try EncryptionParameters<Scheme>(
                polyDegree: degree,
                plaintextModulus: plaintextModuli[0],
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .unchecked)
            XCTAssert(encryptionParams.supportsSimdEncoding)

            let queryCount = 1
            for rowCount in [degree / 2, degree, degree + 1, 3 * degree] {
                for dimensions in try [MatrixDimensions(rowCount: rowCount, columnCount: 16)] {
                    for plaintextModuliCount in 1...maxPlaintextModuliCount {
                        try runSingleTest(
                            encryptionParams: encryptionParams,
                            dimensions: dimensions,
                            plaintextModuli: Array(plaintextModuli.prefix(plaintextModuliCount)),
                            queryCount: queryCount)
                    }
                }
            }
        }

        try runTest(for: Bfv<UInt32>.self)
        try runTest(for: Bfv<UInt64>.self)
    }
}
