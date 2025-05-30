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
import PrivateInformationRetrieval
import Testing

extension PirTestUtils {
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
        public static func queryGenerationTest<Scheme: HeScheme>(
            scheme _: Scheme.Type,
            _ keyCompression: PirKeyCompressionStrategy) throws
        {
            let entryCount = 200
            let entrySizeInBytes = 16
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let parameter = try PirTestUtils.getTestParameter(
                pir: MulPir<Scheme>.self,
                with: context,
                entryCount: entryCount,
                entrySizeInBytes: entrySizeInBytes, keyCompression: keyCompression)
            let client = MulPirClient(parameter: parameter, context: context)

            let evaluationKey = try client.generateEvaluationKey(using: secretKey)
            for _ in 0..<3 {
                var indices = Array(0..<parameter.entryCount)
                indices.shuffle()
                let batchSize = Int.random(in: 1...parameter.batchSize)
                let queryIndices = Array(indices.prefix(batchSize))
                let query = try client.generateQuery(at: queryIndices, using: secretKey)
                let outputCount = parameter.expandedQueryCount * batchSize
                let expandedQuery: [Scheme.CanonicalCiphertext] = try PirUtil.expandCiphertexts(
                    query.ciphertexts,
                    outputCount: outputCount,
                    using: evaluationKey)
                let decodedQuery: [[Scheme.Scalar]] = try expandedQuery.map { ciphertext in
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
        public static func computeCoordinates<Scheme: HeScheme>(scheme _: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let evalKeyConfig = EvaluationKeyConfig()
            // two dimensional case
            do {
                let parameter = IndexPirParameter(
                    entryCount: 100,
                    entrySizeInBytes: 16,
                    dimensions: [10, 10],
                    batchSize: 1,
                    evaluationKeyConfig: evalKeyConfig)
                let client = MulPirClient(parameter: parameter, context: context)

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
            do {
                let parameter = IndexPirParameter(
                    entryCount: 30,
                    entrySizeInBytes: 16,
                    dimensions: [5, 3, 2],
                    batchSize: 1,
                    evaluationKeyConfig: evalKeyConfig)
                let client = MulPirClient(parameter: parameter, context: context)

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
    }
}
