// Copyright 2025-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

import Foundation
import HomomorphicEncryption
@testable import PrivateNearestNeighborSearch
import Testing

/// Validates that dotProduct mode produces correct results through the full HE pipeline,
/// and that two-server vector splitting with dotProduct reconstructs cosine similarity.
struct DotProductTests {
    /// Helper: L2-normalize each row of a 2D float array.
    private static func normalizeRows(_ vectors: [[Float]]) -> [[Float]] {
        vectors.map { row in
            let norm = row.map { $0 * $0 }.reduce(0, +).squareRoot()
            guard norm > 0 else {
                return row
            }
            return row.map { $0 / norm }
        }
    }

    /// Helper: compute dot product of two vectors.
    private static func dot(_ a: [Float], _ b: [Float]) -> Float {
        zip(a, b).map(*).reduce(0, +)
    }

    /// Helper: centered modulo — maps x into [-t/2, t/2).
    private static func centeredMod(_ x: Int64, _ t: Int64) -> Int64 {
        let r = x % t
        let pos = r >= 0 ? r : r + t // ensure positive
        return pos >= (t + 1) / 2 ? pos - t : pos
    }

    /// Test 1: dotProduct mode on pre-normalized vectors should match cosineSimilarity mode.
    /// This validates that skipping normalization in Database.process() works correctly
    /// when vectors are already unit-normalized.
    @Test
    func dotProductMatchesCosine() async throws {
        try await runDotProductMatchesCosine(for: Bfv<UInt64>.self)
    }

    @inlinable
    func runDotProductMatchesCosine<Scheme: HeScheme>(for _: Scheme.Type) async throws {
        let degree = 64
        let vectorDimension = 16
        let rowCount = degree

        let plaintextModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: [10, 10],
            preferringSmall: true,
            nttDegree: degree)
        let coefficientModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: Array(repeating: Scheme.Scalar.bitWidth - 4, count: 3),
            preferringSmall: false,
            nttDegree: degree)
        let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
            polyDegree: degree,
            plaintextModulus: plaintextModuli[0],
            coefficientModuli: coefficientModuli,
            errorStdDev: .stdDev32,
            securityLevel: .unchecked)

        // Create test database with non-unit vectors
        let rawVectors: [[Float]] = (0..<rowCount).map { rowIndex in
            (0..<vectorDimension).map { colIndex in
                Float(colIndex + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1)
            }
        }
        let normalizedVectors = Self.normalizeRows(rawVectors)

        let scalingFactor = ClientConfig<Scheme>.maxScalingFactor(
            distanceMetric: .cosineSimilarity,
            vectorDimension: vectorDimension,
            plaintextModuli: plaintextModuli)

        // --- Cosine similarity baseline ---
        let cosineRows = rawVectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        }
        let cosineDB = Database(rows: cosineRows)

        let evaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: MatrixDimensions(rowCount: rowCount, columnCount: vectorDimension),
            maxQueryCount: 1,
            encryptionParameters: encryptionParameters,
            scheme: Scheme.self)

        let cosineClientConfig = try ClientConfig<Scheme>(
            encryptionParameters: encryptionParameters,
            scalingFactor: scalingFactor,
            queryPacking: .denseRow,
            vectorDimension: vectorDimension,
            evaluationKeyConfig: evaluationKeyConfig,
            distanceMetric: .cosineSimilarity,
            extraPlaintextModuli: Array(plaintextModuli[1...]))
        let cosineServerConfig = ServerConfig(
            clientConfig: cosineClientConfig,
            databasePacking: .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))

        let cosineProcessed = try await cosineDB.process(config: cosineServerConfig)
        let cosineClient = try Client(config: cosineClientConfig, contexts: cosineProcessed.contexts)
        let cosineServer = try Server(database: cosineProcessed)

        // --- dotProduct with pre-normalized vectors ---
        let dotRows = normalizedVectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        }
        let dotDB = Database(rows: dotRows)

        let dotClientConfig = try ClientConfig<Scheme>(
            encryptionParameters: encryptionParameters,
            scalingFactor: scalingFactor,
            queryPacking: .denseRow,
            vectorDimension: vectorDimension,
            evaluationKeyConfig: evaluationKeyConfig,
            distanceMetric: .dotProduct,
            extraPlaintextModuli: Array(plaintextModuli[1...]))
        let dotServerConfig = ServerConfig(
            clientConfig: dotClientConfig,
            databasePacking: .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))

        let dotProcessed = try await dotDB.process(config: dotServerConfig)
        let dotClient = try Client(config: dotClientConfig, contexts: dotProcessed.contexts)
        let dotServer = try Server(database: dotProcessed)

        // Query with first row
        let queryVectors = Array2d(data: [rawVectors[0]])
        // Pre-normalize query for dotProduct path (dotProduct skips normalization)
        let normalizedQueryVectors = Array2d(data: Self.normalizeRows([rawVectors[0]]))
        let secretKey = try cosineClient.generateSecretKey()

        // Cosine path (auto-normalizes query internally)
        let cosineQuery = try cosineClient.generateQuery(for: queryVectors, using: secretKey)
        let cosineEvalKey = try cosineClient.generateEvaluationKey(using: secretKey)
        let cosineResponse = try await cosineServer.computeResponse(to: cosineQuery, using: cosineEvalKey)
        let cosineDistances = try cosineClient.decrypt(response: cosineResponse, using: secretKey)

        // dotProduct path (caller must pre-normalize query)
        let dotQuery = try dotClient.generateQuery(for: normalizedQueryVectors, using: secretKey)
        let dotEvalKey = try dotClient.generateEvaluationKey(using: secretKey)
        let dotResponse = try await dotServer.computeResponse(to: dotQuery, using: dotEvalKey)
        let dotDistances = try dotClient.decrypt(response: dotResponse, using: secretKey)

        // Compare: both should produce the same distances
        #expect(cosineDistances.distances.rowCount == dotDistances.distances.rowCount)
        #expect(cosineDistances.distances.columnCount == dotDistances.distances.columnCount)
        for i in 0..<cosineDistances.distances.data.count {
            let diff = abs(cosineDistances.distances.data[i] - dotDistances.distances.data[i])
            #expect(
                diff < 0.05,
                Comment(
                    rawValue: "Distance mismatch at \(i): " +
                        "cosine=\(cosineDistances.distances.data[i]), dot=\(dotDistances.distances.data[i])"))
        }
    }

    /// Test 2: Two-server vector splitting.
    /// Split each normalized DB vector v into v1 = v - r, v2 = r (random unit vector).
    /// Process v1 and v2 as separate dotProduct databases.
    /// Sum of decrypted scores should equal cosine similarity.
    @Test
    func twoServerVectorSplit() async throws {
        try await runTwoServerVectorSplit(for: Bfv<UInt64>.self)
    }

    @inlinable
    func runTwoServerVectorSplit<Scheme: HeScheme>(for _: Scheme.Type) async throws {
        let degree = 64
        let vectorDimension = 16
        let rowCount = degree

        let plaintextModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: [10, 10],
            preferringSmall: true,
            nttDegree: degree)
        let coefficientModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: Array(repeating: Scheme.Scalar.bitWidth - 4, count: 3),
            preferringSmall: false,
            nttDegree: degree)
        let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
            polyDegree: degree,
            plaintextModulus: plaintextModuli[0],
            coefficientModuli: coefficientModuli,
            errorStdDev: .stdDev32,
            securityLevel: .unchecked)

        // Create and normalize database vectors
        let rawVectors: [[Float]] = (0..<rowCount).map { rowIndex in
            (0..<vectorDimension).map { colIndex in
                Float(colIndex + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1)
            }
        }
        let normalizedVectors = Self.normalizeRows(rawVectors)

        // Generate random unit vectors for splitting
        // Use a simple deterministic "random" for reproducibility
        let randomVectors = Self.normalizeRows((0..<rowCount).map { rowIndex in
            (0..<vectorDimension).map { colIndex in
                // Deterministic pseudo-random using sin
                Float(sin(Double(rowIndex * vectorDimension + colIndex) * 1.618033988749895))
            }
        })

        // Split: v1 = v_normalized - r, v2 = r
        let v1Vectors: [[Float]] = zip(normalizedVectors, randomVectors).map { v, r in
            zip(v, r).map { $0 - $1 }
        }
        let v2Vectors = randomVectors

        let scalingFactor = ClientConfig<Scheme>.maxScalingFactor(
            distanceMetric: .dotProduct,
            vectorDimension: vectorDimension,
            plaintextModuli: plaintextModuli)

        let evaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: MatrixDimensions(rowCount: rowCount, columnCount: vectorDimension),
            maxQueryCount: 1,
            encryptionParameters: encryptionParameters,
            scheme: Scheme.self)

        // Both servers use dotProduct (no normalization)
        let clientConfig = try ClientConfig<Scheme>(
            encryptionParameters: encryptionParameters,
            scalingFactor: scalingFactor,
            queryPacking: .denseRow,
            vectorDimension: vectorDimension,
            evaluationKeyConfig: evaluationKeyConfig,
            distanceMetric: .dotProduct,
            extraPlaintextModuli: Array(plaintextModuli[1...]))
        let serverConfig = ServerConfig(
            clientConfig: clientConfig,
            databasePacking: .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))

        // Server A: holds v1 shares
        let dbA = Database(rows: v1Vectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })
        let processedA = try await dbA.process(config: serverConfig)
        let serverA = try Server(database: processedA)

        // Server B: holds v2 shares (random unit vectors)
        let dbB = Database(rows: v2Vectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })
        let processedB = try await dbB.process(config: serverConfig)
        let serverB = try Server<Scheme>(database: processedB)

        // Client queries both servers with the same pre-normalized query
        let client = try Client(config: clientConfig, contexts: processedA.contexts)
        let normalizedQuery = Self.normalizeRows([rawVectors[0]])
        let queryVectors = Array2d(data: normalizedQuery)
        let secretKey = try client.generateSecretKey()
        let query = try client.generateQuery(for: queryVectors, using: secretKey)
        let evalKey = try client.generateEvaluationKey(using: secretKey)

        let responseA = try await serverA.computeResponse(to: query, using: evalKey)
        let responseB = try await serverB.computeResponse(to: query, using: evalKey)

        let distancesA = try client.decrypt(response: responseA, using: secretKey)
        let distancesB = try client.decrypt(response: responseB, using: secretKey)

        // Sum scores from both servers
        let combinedScores = zip(distancesA.distances.data, distancesB.distances.data).map(+)

        // Compute ground truth cosine similarity
        let queryNormalized = Self.normalizeRows([rawVectors[0]])[0]
        let groundTruth = normalizedVectors.map { Self.dot(queryNormalized, $0) }

        // Verify combined scores match ground truth within quantization tolerance
        for i in 0..<groundTruth.count {
            let diff = abs(combinedScores[i] - groundTruth[i])
            #expect(
                diff < 0.1,
                Comment(
                    rawValue: "Score mismatch at \(i): " +
                        "combined=\(combinedScores[i]), expected=\(groundTruth[i]), diff=\(diff)"))
        }

        // Verify ranking: top result for querying row 0 should be row 0 itself
        let topIndex = combinedScores.indices.max { combinedScores[$0] < combinedScores[$1] } ?? -1
        #expect(
            topIndex == 0,
            Comment(rawValue: "Expected top result to be entry 0 (self-match), got entry \(topIndex)"))
    }

    /// Test 3: HE-addition of responses before decryption.
    /// Instead of decrypt(A) + decrypt(B), compute decrypt(A + B) in the encrypted domain.
    /// Should produce the same result (BFV addition is exact).
    @Test
    func heAdditionBeforeDecrypt() async throws {
        try await runHeAdditionBeforeDecrypt(for: Bfv<UInt64>.self)
    }

    @inlinable
    func runHeAdditionBeforeDecrypt<Scheme: HeScheme>(for _: Scheme.Type) async throws {
        let degree = 64
        let vectorDimension = 16
        let rowCount = degree

        let plaintextModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: [10, 10],
            preferringSmall: true,
            nttDegree: degree)
        let coefficientModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: Array(repeating: Scheme.Scalar.bitWidth - 4, count: 3),
            preferringSmall: false,
            nttDegree: degree)
        let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
            polyDegree: degree,
            plaintextModulus: plaintextModuli[0],
            coefficientModuli: coefficientModuli,
            errorStdDev: .stdDev32,
            securityLevel: .unchecked)

        let rawVectors: [[Float]] = (0..<rowCount).map { rowIndex in
            (0..<vectorDimension).map { colIndex in
                Float(colIndex + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1)
            }
        }
        let normalizedVectors = Self.normalizeRows(rawVectors)

        // Split: v1 = v_hat - r, v2 = r
        let randomVectors = Self.normalizeRows((0..<rowCount).map { rowIndex in
            (0..<vectorDimension).map { colIndex in
                Float(sin(Double(rowIndex * vectorDimension + colIndex) * 1.618033988749895))
            }
        })
        let v1Vectors: [[Float]] = zip(normalizedVectors, randomVectors).map { v, r in
            zip(v, r).map { $0 - $1 }
        }
        let v2Vectors = randomVectors

        let scalingFactor = ClientConfig<Scheme>.maxScalingFactor(
            distanceMetric: .dotProduct,
            vectorDimension: vectorDimension,
            plaintextModuli: plaintextModuli)

        let evaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: MatrixDimensions(rowCount: rowCount, columnCount: vectorDimension),
            maxQueryCount: 1,
            encryptionParameters: encryptionParameters,
            scheme: Scheme.self)

        let clientConfig = try ClientConfig<Scheme>(
            encryptionParameters: encryptionParameters,
            scalingFactor: scalingFactor,
            queryPacking: .denseRow,
            vectorDimension: vectorDimension,
            evaluationKeyConfig: evaluationKeyConfig,
            distanceMetric: .dotProduct,
            extraPlaintextModuli: Array(plaintextModuli[1...]))
        let serverConfig = ServerConfig(
            clientConfig: clientConfig,
            databasePacking: .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))

        // Server A and B
        let dbA = Database(rows: v1Vectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })
        let processedA = try await dbA.process(config: serverConfig)
        let serverA = try Server(database: processedA)

        let dbB = Database(rows: v2Vectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })
        let processedB = try await dbB.process(config: serverConfig)
        let serverB = try Server<Scheme>(database: processedB)

        let client = try Client(config: clientConfig, contexts: processedA.contexts)
        let normalizedQuery = Self.normalizeRows([rawVectors[0]])
        let queryVectors = Array2d(data: normalizedQuery)
        let secretKey = try client.generateSecretKey()
        let query = try client.generateQuery(for: queryVectors, using: secretKey)
        let evalKey = try client.generateEvaluationKey(using: secretKey)

        let responseA = try await serverA.computeResponse(to: query, using: evalKey)
        let responseB = try await serverB.computeResponse(to: query, using: evalKey)

        // --- Method 1: Decrypt separately, then add (existing approach) ---
        let distancesA = try client.decrypt(response: responseA, using: secretKey)
        let distancesB = try client.decrypt(response: responseB, using: secretKey)
        let separateScores = zip(distancesA.distances.data, distancesB.distances.data).map(+)

        // --- Method 2: HE-add ciphertext matrices, then decrypt once ---
        var combinedMatrices: [CiphertextMatrix<Scheme, Coeff>] = []
        for (matA, matB) in zip(responseA.ciphertextMatrices, responseB.ciphertextMatrices) {
            // Add corresponding ciphertexts element-wise
            var sumCiphertexts: [Ciphertext<Scheme, Coeff>] = []
            for (ctA, ctB) in zip(matA.ciphertexts, matB.ciphertexts) {
                let sumCt = try await ctA + ctB
                sumCiphertexts.append(sumCt)
            }
            let sumMatrix = try CiphertextMatrix<Scheme, Coeff>(
                dimensions: matA.dimensions,
                packing: matA.packing,
                ciphertexts: sumCiphertexts)
            combinedMatrices.append(sumMatrix)
        }
        let combinedResponse = Response(
            ciphertextMatrices: combinedMatrices,
            entryIds: responseA.entryIds,
            entryMetadatas: responseA.entryMetadatas)

        // Check noise budget of combined response
        let noiseBudget = try combinedResponse.noiseBudget(using: secretKey, variableTime: true)
        #expect(noiseBudget > 0, Comment(rawValue: "Noise budget exhausted after HE addition: \(noiseBudget)"))

        let heAddDistances = try client.decrypt(response: combinedResponse, using: secretKey)
        let heAddScores = heAddDistances.distances.data

        // --- Compare both methods ---
        // They should be very close (possibly identical for BFV)
        var maxDiff: Float = 0
        for i in 0..<separateScores.count {
            let diff = abs(separateScores[i] - heAddScores[i])
            maxDiff = max(maxDiff, diff)
            #expect(
                diff < 0.01,
                Comment(
                    rawValue: "HE-add vs separate mismatch at \(i): " +
                        "heAdd=\(heAddScores[i]), separate=\(separateScores[i])"))
        }

        // Compare HE-add scores against ground truth
        let queryNormalized = Self.normalizeRows([rawVectors[0]])[0]
        let groundTruth = normalizedVectors.map { Self.dot(queryNormalized, $0) }
        for i in 0..<groundTruth.count {
            let diff = abs(heAddScores[i] - groundTruth[i])
            #expect(
                diff < 0.1,
                Comment(
                    rawValue: "HE-add mismatch at \(i): " +
                        "heAdd=\(heAddScores[i]), expected=\(groundTruth[i])"))
        }

        // Verify ranking
        let topIndex = heAddScores.indices.max { heAddScores[$0] < heAddScores[$1] } ?? -1
        #expect(
            topIndex == 0,
            Comment(rawValue: "Expected top result to be entry 0 (self-match), got entry \(topIndex)"))
    }

    /// Test 4: Dimension splitting (small).
    @Test
    func dimensionSplit() async throws {
        try await runDimensionSplit(for: Bfv<UInt64>.self, degree: 64, vectorDimension: 16)
    }

    /// Test 5: Dimension splitting at larger scale.
    @Test
    func dimensionSplitLarge() async throws {
        try await runDimensionSplit(for: Bfv<UInt64>.self, degree: 4096, vectorDimension: 128)
    }

    @inlinable
    func runDimensionSplit<Scheme: HeScheme>(for _: Scheme.Type, degree: Int, vectorDimension: Int) async throws {
        let fullDimension = vectorDimension
        let halfDimension = fullDimension / 2
        let rowCount = degree // fill one polynomial's worth of rows

        // For small degrees, use small bit widths; for large, use production-like params
        let plaintextBitWidth = degree >= 4096 ? 20 : 10
        let coeffBitWidth = degree >= 4096 ? 50 : Scheme.Scalar.bitWidth - 4

        let plaintextModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: Array(repeating: plaintextBitWidth, count: 2),
            preferringSmall: true,
            nttDegree: degree)
        let coefficientModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: Array(repeating: coeffBitWidth, count: 3),
            preferringSmall: false,
            nttDegree: degree)
        let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
            polyDegree: degree,
            plaintextModulus: plaintextModuli[0],
            coefficientModuli: coefficientModuli,
            errorStdDev: .stdDev32,
            securityLevel: .unchecked)

        // Create and globally normalize vectors (full dimension)
        let rawVectors: [[Float]] = (0..<rowCount).map { rowIndex in
            (0..<fullDimension).map { colIndex in
                Float(colIndex + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1)
            }
        }
        let normalizedVectors = Self.normalizeRows(rawVectors)

        // Split by dimension
        let topVectors = normalizedVectors.map { Array($0.prefix(halfDimension)) }
        let botVectors = normalizedVectors.map { Array($0.suffix(halfDimension)) }

        // Halves are NOT unit vectors — need dotProduct mode
        // Max norm of a half: bounded by 1.0 (full vector is unit)
        let scalingFactor = ClientConfig<Scheme>.maxScalingFactor(
            distanceMetric: .dotProduct,
            vectorDimension: halfDimension,
            plaintextModuli: plaintextModuli,
            maxVectorNorm: 1.0) // each half has norm ≤ 1

        let evaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: MatrixDimensions(rowCount: rowCount, columnCount: halfDimension),
            maxQueryCount: 1,
            encryptionParameters: encryptionParameters,
            scheme: Scheme.self)

        let clientConfig = try ClientConfig<Scheme>(
            encryptionParameters: encryptionParameters,
            scalingFactor: scalingFactor,
            queryPacking: .denseRow,
            vectorDimension: halfDimension,
            evaluationKeyConfig: evaluationKeyConfig,
            distanceMetric: .dotProduct,
            extraPlaintextModuli: Array(plaintextModuli[1...]))
        let serverConfig = ServerConfig(
            clientConfig: clientConfig,
            databasePacking: .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: halfDimension)))

        // Server A: top halves
        let dbTop = Database(rows: topVectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })
        let processedTop = try await dbTop.process(config: serverConfig)
        let serverTop = try Server(database: processedTop)

        // Server B: bottom halves
        let dbBot = Database(rows: botVectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })
        let processedBot = try await dbBot.process(config: serverConfig)
        let serverBot = try Server<Scheme>(database: processedBot)

        // Client: split query the same way (pre-normalized globally, then split)
        let normalizedQuery = Self.normalizeRows([rawVectors[0]])[0]
        let queryTop = Array2d(data: [Array(normalizedQuery.prefix(halfDimension))])
        let queryBot = Array2d(data: [Array(normalizedQuery.suffix(halfDimension))])

        let client = try Client(config: clientConfig, contexts: processedTop.contexts)
        let secretKey = try client.generateSecretKey()
        let evalKey = try client.generateEvaluationKey(using: secretKey)

        // Send different query halves to different servers
        let queryForTop = try client.generateQuery(for: queryTop, using: secretKey)
        let queryForBot = try client.generateQuery(for: queryBot, using: secretKey)

        let responseTop = try await serverTop.computeResponse(to: queryForTop, using: evalKey)
        let responseBot = try await serverBot.computeResponse(to: queryForBot, using: evalKey)

        // HE-add the two responses, then decrypt once
        var combinedMatrices: [CiphertextMatrix<Scheme, Coeff>] = []
        for (matT, matB) in zip(responseTop.ciphertextMatrices, responseBot.ciphertextMatrices) {
            var sumCiphertexts: [Ciphertext<Scheme, Coeff>] = []
            for (ctT, ctB) in zip(matT.ciphertexts, matB.ciphertexts) {
                let sumCt = try await ctT + ctB
                sumCiphertexts.append(sumCt)
            }
            let sumMatrix = try CiphertextMatrix<Scheme, Coeff>(
                dimensions: matT.dimensions,
                packing: matT.packing,
                ciphertexts: sumCiphertexts)
            combinedMatrices.append(sumMatrix)
        }
        let combinedResponse = Response(
            ciphertextMatrices: combinedMatrices,
            entryIds: responseTop.entryIds,
            entryMetadatas: responseTop.entryMetadatas)

        let noiseBudget = try combinedResponse.noiseBudget(using: secretKey, variableTime: true)
        #expect(noiseBudget > 0, Comment(rawValue: "Noise budget exhausted: \(noiseBudget)"))

        let distances = try client.decrypt(response: combinedResponse, using: secretKey)

        // Ground truth: cosine similarity on full vectors
        let groundTruth = normalizedVectors.map { Self.dot(normalizedQuery, $0) }

        for i in 0..<groundTruth.count {
            let diff = abs(distances.distances.data[i] - groundTruth[i])
            #expect(
                diff < 0.1,
                Comment(
                    rawValue: "Dim-split mismatch at \(i): " +
                        "got=\(distances.distances.data[i]), expected=\(groundTruth[i])"))
        }

        // Self-match should be top result
        let topResult = distances.distances.data.indices
            .max { distances.distances.data[$0] < distances.distances.data[$1] } ?? -1
        #expect(topResult == 0, Comment(rawValue: "Expected self-match at 0, got \(topResult)"))
    }

    // MARK: - Modular integer split

    /// Test 6: Modular integer split (information-theoretically secure).
    /// Split quantized integers mod t: share_A = (v_int - r) mod t, share_B = r.
    /// Both shares are uniform mod t (one-time pad). Zero additional quantization error.
    @Test
    func modularIntegerSplit() async throws {
        try await runModularIntegerSplit(for: Bfv<UInt64>.self)
    }

    @inlinable
    func runModularIntegerSplit<Scheme: HeScheme>(for _: Scheme.Type) async throws {
        let degree = 64
        let vectorDimension = 16
        let rowCount = degree

        // Single plaintext modulus (no CRT) for simplicity
        let plaintextModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: [10],
            preferringSmall: true,
            nttDegree: degree)
        let coefficientModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: Array(repeating: Scheme.Scalar.bitWidth - 4, count: 3),
            preferringSmall: false,
            nttDegree: degree)
        let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
            polyDegree: degree,
            plaintextModulus: plaintextModuli[0],
            coefficientModuli: coefficientModuli,
            errorStdDev: .stdDev32,
            securityLevel: .unchecked)

        let t = Int64(encryptionParameters.plaintextModulus)

        // Create and normalize vectors
        let rawVectors: [[Float]] = (0..<rowCount).map { rowIndex in
            (0..<vectorDimension).map { colIndex in
                Float(colIndex + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1)
            }
        }
        let normalizedVectors = Self.normalizeRows(rawVectors)

        let scalingFactor = ClientConfig<Scheme>.maxScalingFactor(
            distanceMetric: .cosineSimilarity,
            vectorDimension: vectorDimension,
            plaintextModuli: plaintextModuli)
        let sf = Float(scalingFactor)

        // Step 1: Quantize — same as what the library does internally
        let quantizedVectors: [[Int64]] = normalizedVectors.map { row in
            row.map { Int64(($0 * sf).rounded()) }
        }

        // Step 2: Generate random integers mod t
        var rng = SystemRandomNumberGenerator()
        let randomInts: [[Int64]] = (0..<rowCount).map { _ in
            (0..<vectorDimension).map { _ in
                Int64.random(in: 0..<t, using: &rng)
            }
        }

        // Step 3: Modular split
        let shareAInts: [[Int64]] = zip(quantizedVectors, randomInts).map { vRow, rRow in
            zip(vRow, rRow).map { vVal, rVal in
                Self.centeredMod(vVal - rVal, t)
            }
        }
        let shareBInts: [[Int64]] = randomInts.map { rRow in
            rRow.map { Self.centeredMod($0, t) }
        }

        // Verify reconstruction: (share_A + share_B) mod t == v_int mod t
        for i in 0..<rowCount {
            for j in 0..<vectorDimension {
                let reconstructed = Self.centeredMod(shareAInts[i][j] + shareBInts[i][j], t)
                let original = Self.centeredMod(quantizedVectors[i][j], t)
                #expect(reconstructed == original,
                        Comment(rawValue: "Reconstruction failed at [\(i)][\(j)]: \(reconstructed) != \(original)"))
            }
        }

        // Step 4: Convert shares to floats (÷ sf so the library's ×sf recovers the integers)
        let shareAFloats: [[Float]] = shareAInts.map { row in row.map { Float($0) / sf } }
        let shareBFloats: [[Float]] = shareBInts.map { row in row.map { Float($0) / sf } }

        // Step 5: Feed through the standard dotProduct pipeline
        let evaluationKeyConfig = try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: MatrixDimensions(rowCount: rowCount, columnCount: vectorDimension),
            maxQueryCount: 1,
            encryptionParameters: encryptionParameters,
            scheme: Scheme.self)

        let clientConfig = try ClientConfig<Scheme>(
            encryptionParameters: encryptionParameters,
            scalingFactor: scalingFactor,
            queryPacking: .denseRow,
            vectorDimension: vectorDimension,
            evaluationKeyConfig: evaluationKeyConfig,
            distanceMetric: .dotProduct)
        let serverConfig = ServerConfig(
            clientConfig: clientConfig,
            databasePacking: .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))

        // Server A: share_A
        let dbA = Database(rows: shareAFloats.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })
        let processedA = try await dbA.process(config: serverConfig)
        let serverA = try Server(database: processedA)

        // Server B: share_B
        let dbB = Database(rows: shareBFloats.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })
        let processedB = try await dbB.process(config: serverConfig)
        let serverB = try Server<Scheme>(database: processedB)

        // Query (pre-normalized since dotProduct mode doesn't normalize)
        let normalizedQuery = Self.normalizeRows([rawVectors[0]])
        let queryVectors = Array2d(data: normalizedQuery)

        let client = try Client(config: clientConfig, contexts: processedA.contexts)
        let secretKey = try client.generateSecretKey()
        let query = try client.generateQuery(for: queryVectors, using: secretKey)
        let evalKey = try client.generateEvaluationKey(using: secretKey)

        let responseA = try await serverA.computeResponse(to: query, using: evalKey)
        let responseB = try await serverB.computeResponse(to: query, using: evalKey)

        // HE-add before decrypt
        var combinedMatrices: [CiphertextMatrix<Scheme, Coeff>] = []
        for (matA, matB) in zip(responseA.ciphertextMatrices, responseB.ciphertextMatrices) {
            var sumCiphertexts: [Ciphertext<Scheme, Coeff>] = []
            for (ctA, ctB) in zip(matA.ciphertexts, matB.ciphertexts) {
                try await sumCiphertexts.append(ctA + ctB)
            }
            try combinedMatrices.append(CiphertextMatrix<Scheme, Coeff>(
                dimensions: matA.dimensions,
                packing: matA.packing,
                ciphertexts: sumCiphertexts))
        }
        let combinedResponse = Response(
            ciphertextMatrices: combinedMatrices,
            entryIds: responseA.entryIds,
            entryMetadatas: responseA.entryMetadatas)

        let noiseBudget = try combinedResponse.noiseBudget(using: secretKey, variableTime: true)
        #expect(noiseBudget > 0, Comment(rawValue: "Noise budget exhausted: \(noiseBudget)"))

        let modularDistances = try client.decrypt(response: combinedResponse, using: secretKey)

        // Also compute baseline (no split) for comparison
        let baselineDB = Database(rows: normalizedVectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })
        let baselineProcessed = try await baselineDB.process(config: serverConfig)
        let baselineServer = try Server<Scheme>(database: baselineProcessed)
        let baselineResponse = try await baselineServer.computeResponse(to: query, using: evalKey)
        let baselineDistances = try client.decrypt(response: baselineResponse, using: secretKey)

        // The modular split should produce IDENTICAL results to baseline
        for i in 0..<baselineDistances.distances.data.count {
            let diff = abs(modularDistances.distances.data[i] - baselineDistances.distances.data[i])
            #expect(diff == 0,
                    Comment(
                        rawValue: "Modular split differs at \(i): " +
                            "modular=\(modularDistances.distances.data[i]), " +
                            "baseline=\(baselineDistances.distances.data[i])"))
        }

        // Also check against ground truth cosine similarity
        let queryNorm = Self.normalizeRows([rawVectors[0]])[0]
        let groundTruth = normalizedVectors.map { Self.dot(queryNorm, $0) }
        for i in 0..<groundTruth.count {
            let diff = abs(modularDistances.distances.data[i] - groundTruth[i])
            #expect(
                diff < 0.1,
                Comment(
                    rawValue: "Ground truth mismatch at \(i): " +
                        "got=\(modularDistances.distances.data[i]), expected=\(groundTruth[i])"))
        }

        let topResult = modularDistances.distances.data.indices
            .max { modularDistances.distances.data[$0] < modularDistances.distances.data[$1] } ?? -1
        #expect(topResult == 0, Comment(rawValue: "Expected self-match at 0, got \(topResult)"))
    }
}
