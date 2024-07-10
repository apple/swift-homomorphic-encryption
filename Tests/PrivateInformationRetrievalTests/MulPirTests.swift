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
@testable import PrivateInformationRetrieval
import TestUtilities
import XCTest

class MulPirTests: XCTestCase {
    private func queryGenerationTest<Scheme: HeScheme>(scheme _: Scheme.Type) throws {
        let entryCount = 100
        let entrySizeInBytes = 16
        let context: Context<Scheme> = try TestUtils.getTestContext()
        let secretKey = try context.generateSecretKey()
        let parameter = try PirTestUtils.getTestParameter(
            pir: MulPir<Scheme>.self,
            with: context,
            entryCount: entryCount,
            entrySizeInBytes: entrySizeInBytes)
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
                XCTAssert(decodedCiphertext[0] == 0 || decodedCiphertext[0] == 1)
                // the rest are all zero
                XCTAssert(decodedCiphertext.dropFirst().allSatisfy { $0 == 0 })
                return decodedCiphertext[0] == 1
            }
            XCTAssertEqual(expandedList.count, outputCount)
            // right number of set ciphertexts
            XCTAssertEqual(expandedList.count { $0 }, batchSize * parameter.dimensionCount)

            // right coordinates are set
            var offset = 0
            for queryIndex in queryIndices {
                let coordinates = try client.computeCoordinates(at: queryIndex)
                for (coord, dimension) in zip(coordinates, parameter.dimensions) {
                    XCTAssert(expandedList[offset + coord])
                    offset += dimension
                }
            }
        }
    }

    func testQueryGeneration() throws {
        try queryGenerationTest(scheme: NoOpScheme.self)
        try queryGenerationTest(scheme: Bfv<UInt32>.self)
        try queryGenerationTest(scheme: Bfv<UInt64>.self)
    }

    private func getDatabaseForTesting(
        entryCount: Int,
        entrySizeInBytes: Int) -> [[UInt8]]
    {
        (0..<entryCount).map { _ in
            (0..<entrySizeInBytes).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
        }
    }

    private func queryAndResponseTest<Scheme: HeScheme>(scheme _: Scheme.Type) throws {
        let context: Context<Scheme> = try TestUtils.getTestContext()
        let entryCount = 1000
        let entrySize = 16
        let database: [[UInt8]] = getDatabaseForTesting(
            entryCount: entryCount,
            entrySizeInBytes: entrySize)
        let parameter = try PirTestUtils.getTestParameter(
            pir: MulPir<Scheme>.self,
            with: context,
            entryCount: entryCount,
            entrySizeInBytes: entrySize)
        let client = MulPirClient(parameter: parameter, context: context)

        let secretKey = try context.generateSecretKey()
        let evaluationKey = try client.generateEvaluationKey(using: secretKey)

        let processedDatabase = try MulPirServer<Scheme>.process(
            database: database,
            with: context,
            using: parameter)
        let server = try MulPirServer(parameter: parameter, context: context, database: processedDatabase)

        for _ in 0..<3 {
            var indices = Array(0..<parameter.entryCount)
            indices.shuffle()
            let batchSize = Int.random(in: 1...parameter.batchSize)
            let queryIndices = Array(indices.prefix(batchSize))
            let query = try client.generateQuery(at: queryIndices, using: secretKey)
            let response = try server.computeResponse(to: query, using: evaluationKey)
            let decoded = try client.decrypt(response: response, at: queryIndices, using: secretKey)
            for index in queryIndices.indices {
                XCTAssertEqual(decoded[index], database[queryIndices[index]])
            }
        }
    }

    func testQueryAndResponse() throws {
        try queryAndResponseTest(scheme: NoOpScheme.self)
        try queryAndResponseTest(scheme: Bfv<UInt32>.self)
        try queryAndResponseTest(scheme: Bfv<UInt64>.self)
    }

    func testComputeCoordinates() throws {
        let context: Context<NoOpScheme> = try TestUtils.getTestContext()
        // two dimensional case
        do {
            let parameter = IndexPirParameter(entryCount: 100, entrySizeInBytes: 16, dimensions: [10, 10], batchSize: 1)
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
                XCTAssertEqual(try client.computeCoordinates(at: vector.0), vector.1)
            }
        }

        // three dimensional case
        do {
            let parameter = IndexPirParameter(entryCount: 30, entrySizeInBytes: 16, dimensions: [5, 3, 2], batchSize: 1)
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
                XCTAssertEqual(try client.computeCoordinates(at: vector.0), vector.1)
            }
        }
    }
}
