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

struct FastEncoderTests {
    /// Validate that FastPlaintextEncoder produces identical PlaintextMatrix to the standard pipeline.
    @Test
    func fastEncoderMatchesStandard() async throws {
        try await runFastEncoderTest(for: Bfv<UInt64>.self, degree: 64, vectorDimension: 16)
    }

    @Test
    func fastEncoderMatchesStandardLarge() async throws {
        try await runFastEncoderTest(for: Bfv<UInt64>.self, degree: 4096, vectorDimension: 128)
    }

    @inlinable
    func runFastEncoderTest<Scheme: HeScheme>(
        for _: Scheme.Type, degree: Int, vectorDimension: Int) async throws
    {
        let rowCount = degree

        let plaintextBitWidth = degree >= 4096 ? 20 : 10
        let coeffBitWidth = degree >= 4096 ? 50 : Scheme.Scalar.bitWidth - 4

        let plaintextModuli = try Scheme.Scalar.generatePrimes(
            significantBitCounts: [plaintextBitWidth],
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
            distanceMetric: .dotProduct)
        let serverConfig = ServerConfig(
            clientConfig: clientConfig,
            databasePacking: .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))

        let context = try Scheme.Context(encryptionParameters: encryptionParameters)

        // Generate test vectors
        let rawVectors: [[Float]] = (0..<rowCount).map { rowIndex in
            (0..<vectorDimension).map { colIndex in
                let norm = (0..<vectorDimension).map { c in
                    Float(c + rowIndex) * Float(c + rowIndex)
                }.reduce(0, +).squareRoot()
                return Float(colIndex + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1) / max(norm, 1)
            }
        }

        // Quantize
        let sf = Float(scalingFactor)
        let signedValues: [Scheme.SignedScalar] = rawVectors.flatMap { row in
            row.map { Scheme.SignedScalar(($0 * sf).rounded()) }
        }

        // === Standard pipeline ===
        let clock = ContinuousClock()

        let database = Database(rows: rawVectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })

        var standardProcessed: ProcessedDatabase<Scheme>?
        let standardTime = try await clock.measure {
            standardProcessed = try await database.process(config: serverConfig, contexts: [context])
        }
        let unwrappedStandard = try #require(standardProcessed)
        let standardMatrices = unwrappedStandard.plaintextMatrices
        print("  Standard pipeline: \(standardTime)")

        // === Fast encoder ===

        let setupTime = try clock.measure {
            _ = try FastPlaintextEncoder<Scheme>(config: serverConfig, context: context, rowCount: rowCount)
        }

        let encoder = try FastPlaintextEncoder<Scheme>(config: serverConfig, context: context, rowCount: rowCount)

        var fastMatrix: PlaintextMatrix<Scheme, Eval>?
        let encodeTime = try clock.measure {
            fastMatrix = try encoder.encode(signedValues: signedValues, context: context)
        }
        let unwrappedFastMatrix = try #require(fastMatrix)

        print("  Setup (one-time): \(setupTime)")
        print("  Fast encode: \(encodeTime)")
        print("  Mappings count: \(encoder.mappings.count)")
        print("  Plaintext count: \(encoder.plaintextCount)")

        // === Compare: decrypt both and check values match ===
        // The PlaintextMatrix plaintexts should produce identical results when
        // used in a query. Let's do a full round-trip comparison.
        let client = try Client<Scheme>(config: clientConfig, contexts: [context])
        let secretKey = try client.generateSecretKey()
        let evalKey = try client.generateEvaluationKey(using: secretKey)

        let queryRow = rawVectors[0].map(\.self) // query = first row
        let queryVectors = Array2d(data: [queryRow])
        let query = try client.generateQuery(for: queryVectors, using: secretKey)

        // Standard pipeline response
        let standardServer = try Server(database: standardProcessed)
        let standardResponse = try await standardServer.computeResponse(to: query, using: evalKey)
        let standardDistances = try client.decrypt(response: standardResponse, using: secretKey)

        // Fast encoder response
        let fastProcessed = try ProcessedDatabase<Scheme>(
            contexts: [context],
            plaintextMatrices: [unwrappedFastMatrix],
            entryIds: (0..<UInt64(rowCount)).map(\.self),
            entryMetadatas: [],
            serverConfig: serverConfig)
        let fastServer = try Server(database: fastProcessed)
        let fastResponse = try await fastServer.computeResponse(to: query, using: evalKey)
        let fastDistances = try client.decrypt(response: fastResponse, using: secretKey)

        // Compare distances
        #expect(standardDistances.distances.data.count == fastDistances.distances.data.count)
        var maxDiff: Float = 0
        for i in 0..<standardDistances.distances.data.count {
            let diff = abs(standardDistances.distances.data[i] - fastDistances.distances.data[i])
            maxDiff = max(maxDiff, diff)
        }
        print("  Max difference (standard vs fast): \(maxDiff)")

        // They should be identical (same integer values, same encoding)
        #expect(maxDiff == 0, Comment(rawValue: "Fast encoder differs from standard: maxDiff=\(maxDiff)"))
    }

    /// Validate the full ORAM-friendly flow:
    /// Database → QuantizedDatabase → serialize → deserialize → FastPlaintextEncoder → query
    @Test
    func quantizedDatabaseRoundTrip() async throws {
        try await runQuantizedRoundTrip(for: Bfv<UInt64>.self)
    }

    @inlinable
    func runQuantizedRoundTrip<Scheme: HeScheme>(for _: Scheme.Type) async throws {
        let degree = 64
        let vectorDimension = 16
        let rowCount = degree

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
            distanceMetric: .dotProduct)
        let serverConfig = ServerConfig(
            clientConfig: clientConfig,
            databasePacking: .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))
        let context = try Scheme.Context(encryptionParameters: encryptionParameters)

        // Create test database
        let rawVectors: [[Float]] = (0..<rowCount).map { rowIndex in
            (0..<vectorDimension).map { colIndex in
                let norm = (0..<vectorDimension).map { c in
                    Float(c + rowIndex) * Float(c + rowIndex)
                }.reduce(0, +).squareRoot()
                return Float(colIndex + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1) / max(norm, 1)
            }
        }
        let database = Database(rows: rawVectors.enumerated().map { i, vec in
            DatabaseRow(entryId: UInt64(i), entryMetadata: [], vector: vec)
        })

        // Step 1: Quantize
        let quantized = QuantizedDatabase<Scheme>(database: database, config: serverConfig)
        print("  Quantized: \(quantized.rowCount) rows × \(quantized.vectorDimension) dims")
        print("  Vector data size: \(quantized.vectorDataByteCount) bytes")

        // Step 2: Serialize (this is what goes into ORAM)
        let bytes = quantized.serializeVectors()
        print("  Serialized size: \(bytes.count) bytes")

        // Step 3: Deserialize (proxy reads from ORAM)
        let restored = QuantizedDatabase<Scheme>.deserializeVectors(
            from: bytes,
            rowCount: quantized.rowCount,
            vectorDimension: quantized.vectorDimension,
            entryIds: quantized.entryIds,
            entryMetadatas: quantized.entryMetadatas)

        // Verify round-trip
        #expect(restored.signedValues == quantized.signedValues)
        #expect(restored.entryIds == quantized.entryIds)

        // Step 4: Fast encode
        let encoder = try FastPlaintextEncoder<Scheme>(
            config: serverConfig, context: context, rowCount: rowCount)
        let processed = try encoder.encodeDatabase(restored, context: context)

        // Step 5: Query and verify
        let client = try Client<Scheme>(config: clientConfig, contexts: [context])
        let secretKey = try client.generateSecretKey()
        let evalKey = try client.generateEvaluationKey(using: secretKey)
        let queryVectors = Array2d(data: [rawVectors[0]])
        let query = try client.generateQuery(for: queryVectors, using: secretKey)

        let server = try Server(database: processed)
        let response = try await server.computeResponse(to: query, using: evalKey)
        let distances = try client.decrypt(response: response, using: secretKey)

        // Verify against standard pipeline
        let standardProcessed = try await database.process(config: serverConfig, contexts: [context])
        let standardServer = try Server(database: standardProcessed)
        let standardResponse = try await standardServer.computeResponse(to: query, using: evalKey)
        let standardDistances = try client.decrypt(response: standardResponse, using: secretKey)

        var maxDiff: Float = 0
        for i in 0..<distances.distances.data.count {
            let diff = abs(distances.distances.data[i] - standardDistances.distances.data[i])
            maxDiff = max(maxDiff, diff)
        }
        print("  Max difference (quantized round-trip vs standard): \(maxDiff)")
        #expect(maxDiff == 0, Comment(rawValue: "Round-trip differs: maxDiff=\(maxDiff)"))

        // Compare sizes
        // Each plaintext matrix stores polyDegree × moduliCount × scalarSize bytes per plaintext
        let scalarSize = MemoryLayout<Scheme.Scalar>.size
        let approxProcessedSize = encoder.plaintextCount * degree * 3 * scalarSize // 3 moduli
        print("  Approx ProcessedDatabase size: \(approxProcessedSize) bytes (\(approxProcessedSize / 1024)KB)")
        print("  QuantizedDatabase vectors only: \(bytes.count) bytes (\(bytes.count / 1024)KB)")
        print("  Size ratio: \(Float(approxProcessedSize) / Float(bytes.count))x smaller in ORAM")
    }
}
