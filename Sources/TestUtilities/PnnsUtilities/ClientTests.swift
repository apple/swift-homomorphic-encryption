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
import PrivateNearestNeighborSearch
import Testing

extension PrivateNearestNeighborSearchUtil {
    /// Client tests.
    public enum ClientTests {
        /// Testing client configuration.
        public static func clientConfig<Scheme: HeScheme>(for _: Scheme.Type) throws {
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
            #expect(maxScalingFactor2 > maxScalingFactor1)

            #expect(throws: Never.self) {
                try ClientConfig<Scheme>(
                    encryptionParameters: EncryptionParameters(from: PredefinedRlweParameters
                        .n_4096_logq_27_28_28_logt_17),
                    scalingFactor: maxScalingFactor2,
                    queryPacking: .denseRow,
                    vectorDimension: 128,
                    evaluationKeyConfig: EvaluationKeyConfig(),
                    distanceMetric: .cosineSimilarity,
                    extraPlaintextModuli: [plaintextModuli[1]])
            }
        }

        /// Testing normalization and scaling.
        public static func normalizeRowsAndScale() throws {
            // swiftlint:disable:next nesting
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
                for (normalized, expected) in zip(normalized.data, testCase.normalized.flatMap(\.self)) {
                    #expect(normalized.isClose(to: expected))
                }

                let scaled = normalized.scaled(by: testCase.scalingFactor)
                for (scaled, expected) in zip(scaled.data, testCase.scaled.flatMap(\.self)) {
                    #expect(scaled.isClose(to: expected))
                }
                let rounded: Array2d<T> = scaled.rounded()
                #expect(rounded.data == testCase.rounded.flatMap(\.self))

                if testCase.norm == Array2d<Float>.Norm.Lp(p: 2.0) {
                    let normalizedScaledAndRounded: Array2d<T> = floatMatrix.normalizedScaledAndRounded(
                        scalingFactor: testCase.scalingFactor)
                    #expect(normalizedScaledAndRounded.data == testCase.rounded.flatMap(\.self))
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

        /// Testing round trip with the query as the response.
        @inlinable
        public static func queryAsResponse<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let degree = 512
            let encryptionParameters = try EncryptionParameters<Scheme>(
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
            #expect(encryptionParameters.supportsSimdEncoding)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
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
                    encryptionParameters: encryptionParameters,
                    scalingFactor: scalingFactor,
                    queryPacking: .denseRow,
                    vectorDimension: vectorDimension,
                    evaluationKeyConfig: EvaluationKeyConfig(),
                    distanceMetric: .cosineSimilarity,
                    extraPlaintextModuli: extraPlaintextModuli)
                let client = try Client(config: config)
                let query = try client.generateQuery(for: queryValues, using: secretKey)
                #expect(query.ciphertextMatrices.count == config.plaintextModuli.count)

                let entryIds = [UInt64(42)]
                let entryMetadatas = [42.littleEndianBytes]
                // Treat the query as a response
                let response = Response(
                    ciphertextMatrices: query.ciphertextMatrices,
                    entryIds: entryIds, entryMetadatas: entryMetadatas)
                let databaseDistances = try client.decrypt(response: response, using: secretKey)
                #expect(databaseDistances.entryIds == entryIds)
                #expect(databaseDistances.entryMetadatas == entryMetadatas)

                let scaledQuery: Array2d<Scheme.SignedScalar> = queryValues
                    .normalizedScaledAndRounded(scalingFactor: Float(config.scalingFactor))
                // Cosine similarity response returns result scaled by scalingFactor^2
                let expectedDistances = scaledQuery.map { value in
                    Float(value) / Float(config.scalingFactor * config.scalingFactor)
                }
                #expect(databaseDistances.distances == expectedDistances)
            }
        }

        /// Testing client-server round-trip functionality.
        @inlinable
        public static func clientServer<Scheme: HeScheme>(for _: Scheme.Type) throws {
            func runSingleTest(
                encryptionParameters: EncryptionParameters<Scheme>,
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
                    encryptionParameters: encryptionParameters,
                    maxQueryCount: queryCount)
                let clientConfig = try ClientConfig<Scheme>(
                    encryptionParameters: encryptionParameters,
                    scalingFactor: scalingFactor,
                    queryPacking: .denseRow,
                    vectorDimension: vectorDimension,
                    evaluationKeyConfig: evaluatonKeyConfig,
                    distanceMetric: .cosineSimilarity,
                    extraPlaintextModuli: Array(plaintextModuli[1...]))
                let serverConfig = ServerConfig(
                    clientConfig: clientConfig,
                    databasePacking: .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))

                let database = PrivateNearestNeighborSearchUtil.getDatabaseForTesting(config: DatabaseConfig(
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
                #expect(noiseBudget > 0)
                let decrypted = try client.decrypt(response: response, using: secretKey)

                #expect(decrypted.entryIds == processed.entryIds)
                #expect(decrypted.entryMetadatas == processed.entryMetadatas)

                let vectors = Array2d<Float>(data: database.rows.map { row in row.vector })
                let modulus: UInt64 = client.config.plaintextModuli.map { UInt64($0) }.reduce(1, *)
                let expected = try vectors.fixedPointCosineSimilarity(
                    queryVectors.transposed(),
                    modulus: modulus,
                    scalingFactor: Float(scalingFactor))
                #expect(decrypted.distances == expected)
            }

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
            let encryptionParameters = try EncryptionParameters<Scheme>(
                polyDegree: degree,
                plaintextModulus: plaintextModuli[0],
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .unchecked)
            #expect(encryptionParameters.supportsSimdEncoding)

            let queryCount = 1
            for rowCount in [degree / 2, degree, degree + 1, 3 * degree] {
                for dimensions in try [MatrixDimensions(rowCount: rowCount, columnCount: 16)] {
                    for plaintextModuliCount in 1...maxPlaintextModuliCount {
                        try runSingleTest(
                            encryptionParameters: encryptionParameters,
                            dimensions: dimensions,
                            plaintextModuli: Array(plaintextModuli.prefix(plaintextModuliCount)),
                            queryCount: queryCount)
                    }
                }
            }
        }
    }
}
