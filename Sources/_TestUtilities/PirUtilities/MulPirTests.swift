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

public import HomomorphicEncryption
public import PrivateInformationRetrieval
public import Testing

extension PirTestUtils {
    @usableFromInline
    struct UnevenTestVector {
        @usableFromInline let entryCount: Int
        @usableFromInline let batchSize: Int
        @usableFromInline let evenDims: [Int]
        @usableFromInline let unevenDimsForBfv: [Int]
        @usableFromInline
        init(entryCount: Int, batchSize: Int, evenDims: [Int], unevenDimsForBfv: [Int]) {
            self.entryCount = entryCount
            self.batchSize = batchSize
            self.evenDims = evenDims
            self.unevenDimsForBfv = unevenDimsForBfv
        }
    }

    /// MulPir tests.
    public enum MulPirTests {
        /// Tests evaluation key configuration.
        @inlinable
        public static func evaluationKeyConfig<Scheme: HeScheme>(scheme _: Scheme.Type) throws {
            func runTest(queryCount: Int, degree: Int, _ keyCompression: PirKeyCompressionStrategy, expected: [Int]) {
                let evalKeyConfig = MulPir<Scheme>.evaluationKeyConfig(
                    expandedQueryCount: queryCount,
                    degree: degree,
                    keyCompression: keyCompression)
                #expect(evalKeyConfig.galoisElements == expected)
            }
            // noCompression
            do {
                let compression = PirKeyCompressionStrategy.noCompression
                runTest(queryCount: 2, degree: 4096, compression, expected: [4097])
                runTest(queryCount: 2, degree: 8192, compression, expected: [8193])
                runTest(queryCount: 32, degree: 4096, compression, expected: [257, 513, 1025, 2049, 4097])
                runTest(queryCount: 32, degree: 8192, compression, expected: [513, 1025, 2049, 4097, 8193])
                runTest(
                    queryCount: 1024,
                    degree: 4096,
                    compression,
                    expected: [9, 17, 33, 65, 129, 257, 513, 1025, 2049, 4097])
                runTest(
                    queryCount: 1024,
                    degree: 8192,
                    compression,
                    expected: [17, 33, 65, 129, 257, 513, 1025, 2049, 4097, 8193])
            }
            // hybridCompression
            do {
                let compression = PirKeyCompressionStrategy.hybridCompression
                runTest(queryCount: 2, degree: 4096, compression, expected: [4097])
                runTest(queryCount: 2, degree: 8192, compression, expected: [8193])
                runTest(queryCount: 32, degree: 4096, compression, expected: [257, 1025])
                runTest(queryCount: 32, degree: 8192, compression, expected: [513, 2049])
                runTest(queryCount: 1024, degree: 4096, compression, expected: [9, 17, 33, 65, 129, 1025])
                runTest(queryCount: 1024, degree: 8192, compression, expected: [17, 33, 65, 129, 1025])
            }
            // maxCompression
            do {
                let compression = PirKeyCompressionStrategy.maxCompression
                runTest(queryCount: 2, degree: 4096, compression, expected: [4097])
                runTest(queryCount: 2, degree: 8192, compression, expected: [8193])
                runTest(queryCount: 32, degree: 4096, compression, expected: [257])
                runTest(queryCount: 32, degree: 8192, compression, expected: [513])
                runTest(queryCount: 1024, degree: 4096, compression, expected: [9, 17, 33, 65, 129])
                runTest(queryCount: 1024, degree: 8192, compression, expected: [17, 33, 65, 129])
            }
        }

        /// Tests query generation.
        @inlinable
        public static func queryGenerationTest<PirUtil: PirUtilProtocol>(
            pirUtil _: PirUtil.Type,
            _ keyCompression: PirKeyCompressionStrategy) async throws
        {
            let entryCount = 200
            let entrySizeInBytes = 16
            let context: PirUtil.Scheme.Context = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let parameter = try PirTestUtils.getTestParameter(
                pir: MulPir<PirUtil.Scheme>.self,
                with: context,
                entryCount: entryCount,
                entrySizeInBytes: entrySizeInBytes, keyCompression: keyCompression)
            let client = MulPirClient<PirUtil>(parameter: parameter, context: context)

            let evaluationKey = try client.generateEvaluationKey(using: secretKey)
            for _ in 0..<3 {
                var indices = Array(0..<parameter.entryCount)
                indices.shuffle()
                let batchSize = Int.random(in: 1...parameter.batchSize)
                let queryIndices = Array(indices.prefix(batchSize))
                let query = try client.generateQuery(at: queryIndices, using: secretKey)
                let outputCount = parameter.expandedQueryCount * batchSize
                let expandedQuery: [PirUtil.Scheme.CanonicalCiphertext] = try await PirUtil.expand(ciphertexts:
                    query.ciphertexts,
                    outputCount: outputCount,
                    using: evaluationKey)
                let decodedQuery: [[PirUtil.Scheme.Scalar]] = try expandedQuery.map { ciphertext in
                    try ciphertext.decrypt(using: secretKey).decode(format: .coefficient)
                }

                let expandedList: [Bool] = decodedQuery.map { decodedCiphertext in
                    // first is either zero or one
                    #expect(decodedCiphertext[0] == 0 || decodedCiphertext[0] == 1)
                    // the rest are all zero
                    #expect(decodedCiphertext.dropFirst().allSatisfy { $0 == 0 })
                    return decodedCiphertext[0] == 1
                }
                #expect(expandedList.count == outputCount)
                // right number of set ciphertexts
                #expect(expandedList.count { $0 } == batchSize * parameter.dimensionCount)

                // right coordinates are set
                var offset = 0
                for queryIndex in queryIndices {
                    let coordinates = try client.computeCoordinates(at: queryIndex)
                    for (coord, dimension) in zip(coordinates, parameter.dimensions) {
                        #expect(expandedList[offset + coord])
                        offset += dimension
                    }
                }
            }
        }

        /// Tests client computing query coordinates.
        @inlinable
        public static func computeCoordinates<PirUtil: PirUtilProtocol>(pirUtil _: PirUtil.Type) throws {
            let context: PirUtil.Scheme.Context = try TestUtils.getTestContext()
            let evalKeyConfig = EvaluationKeyConfig()
            // two dimensional case
            for encodingEntrySize in [false, true] {
                let parameter = IndexPirParameter(
                    entryCount: 100,
                    entrySizeInBytes: 16,
                    dimensions: [10, 10],
                    batchSize: 1,
                    evaluationKeyConfig: evalKeyConfig,
                    encodingEntrySize: encodingEntrySize)
                let client = MulPirClient<PirUtil>(parameter: parameter, context: context)

                let vectors = [
                    (0, [0, 0]),
                    (1, [0, 1]),
                    (2, [0, 2]),
                    (10, [1, 0]),
                    (11, [1, 1]),
                    (12, [1, 2]),
                    (98, [9, 8]),
                    (99, [9, 9]),
                ]
                for vector in vectors {
                    #expect(try client.computeCoordinates(at: vector.0) == vector.1)
                }
            }

            // three dimensional case
            for encodingEntrySize in [false, true] {
                let parameter = IndexPirParameter(
                    entryCount: 30,
                    entrySizeInBytes: 16,
                    dimensions: [5, 3, 2],
                    batchSize: 1,
                    evaluationKeyConfig: evalKeyConfig,
                    encodingEntrySize: encodingEntrySize)
                let client = MulPirClient<PirUtil>(parameter: parameter, context: context)

                let vectors = [
                    (0, [0, 0, 0]),
                    (1, [0, 0, 1]),
                    (2, [0, 1, 0]),
                    (10, [1, 2, 0]),
                    (11, [1, 2, 1]),
                    (12, [2, 0, 0]),
                    (27, [4, 1, 1]),
                    (28, [4, 2, 0]),
                    (29, [4, 2, 1]),
                ]
                for vector in vectors {
                    #expect(try client.computeCoordinates(at: vector.0) == vector.1)
                }
            }
        }

        /// Tests that `unevenDimensions` produces exact expected dimensions for known inputs.
        @inlinable
        public static func unevenDimensionVectorsTest<Scheme: HeScheme>(scheme _: Scheme.Type) throws {
            // entrySizeInBytes=21 > bytesPerPlaintext=20 for test context (polyDegree=16, plaintextModulus=1153),
            // so perChunkPlaintextCount == entryCount for all vectors.
            let vectors: [UnevenTestVector] = [
                // perfect square: floor(sqrt(9))=3 → [3,3]; unevenLimit=nextPow2(6)=8 → [5,2]
                UnevenTestVector(entryCount: 9, batchSize: 1, evenDims: [3, 3], unevenDimsForBfv: [5, 2]),
                // non-square needing one bump: floor(sqrt(20))=4 → [5,4]; unevenLimit=nextPow2(9)=16 → [10,2]
                UnevenTestVector(entryCount: 20, batchSize: 1, evenDims: [5, 4], unevenDimsForBfv: [10, 2]),
                // floor(sqrt(100))=10 → [10,10]; unevenLimit=nextPow2(20)=32 → [25,4]
                UnevenTestVector(entryCount: 100, batchSize: 1, evenDims: [10, 10], unevenDimsForBfv: [25, 4]),
                // floor(sqrt(72))=8 → [9,8]; unevenLimit=nextPow2(17)=32 → [24,3]
                UnevenTestVector(entryCount: 72, batchSize: 1, evenDims: [9, 8], unevenDimsForBfv: [24, 3]),
                // batchSize=3: even→[10,10]; unevenLimit=nextPow2(60)=64 → [13,8]
                UnevenTestVector(entryCount: 100, batchSize: 3, evenDims: [10, 10], unevenDimsForBfv: [13, 8]),
            ]
            let context: Scheme.Context = try TestUtils.getTestContext()
            for vector in vectors {
                for unevenDimensions in [false, true] {
                    let config = try IndexPirConfig(
                        entryCount: vector.entryCount,
                        entrySizeInBytes: 21,
                        dimensionCount: 2,
                        batchSize: vector.batchSize,
                        unevenDimensions: unevenDimensions,
                        keyCompression: .noCompression,
                        encodingEntrySize: false)
                    let param = MulPir<Scheme>.generateParameter(config: config, with: context)
                    let expected = (unevenDimensions && Scheme.cryptosystem == .bfv)
                        ? vector.unevenDimsForBfv
                        : vector.evenDims
                    #expect(param.dimensions == expected)
                }
            }
        }

        /// Tests that `unevenDimensions` produces the expected dimension layout.
        @inlinable
        public static func unevenDimensionsTest<Scheme: HeScheme>(scheme _: Scheme.Type) throws {
            let context: Scheme.Context = try TestUtils.getTestContext()
            let entryCount = 100

            let unevenConfig = try IndexPirConfig(
                entryCount: entryCount,
                entrySizeInBytes: 1,
                dimensionCount: 2,
                batchSize: 1,
                unevenDimensions: true,
                keyCompression: .noCompression,
                encodingEntrySize: false)
            let unevenParam = MulPir<Scheme>.generateParameter(config: unevenConfig, with: context)

            let evenConfig = try IndexPirConfig(
                entryCount: entryCount,
                entrySizeInBytes: 1,
                dimensionCount: 2,
                batchSize: 1,
                unevenDimensions: false,
                keyCompression: .noCompression,
                encodingEntrySize: false)
            let evenParam = MulPir<Scheme>.generateParameter(config: evenConfig, with: context)

            if Scheme.cryptosystem == .bfv {
                #expect(unevenParam.dimensions[0] > unevenParam.dimensions[1])
                #expect(abs(evenParam.dimensions[0] - evenParam.dimensions[1]) <= 1)
                #expect(unevenParam.dimensions != evenParam.dimensions)
            } else {
                // unevenDimensions only applies to BFV; other schemes currently produce identical dims
                #expect(unevenParam.dimensions == evenParam.dimensions)
            }
        }
    }
}
