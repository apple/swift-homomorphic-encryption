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

final class DatabaseTests: XCTestCase {
    func testSerializedProcessedDatabase() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let encryptionParams = try EncryptionParameters<Scheme>(from: .insecure_n_8_logq_5x18_logt_5)
            let vectorDimension = 4

            let rows = (0...10).map { rowIndex in
                DatabaseRow(
                    entryId: rowIndex,
                    entryMetadata: rowIndex.littleEndianBytes,
                    vector: Array(repeating: Float(rowIndex), count: vectorDimension))
            }
            let database = Database(rows: rows)

            let clientConfig = try ClientConfig<Scheme>(
                encryptionParams: encryptionParams,
                scalingFactor: 123,
                queryPacking: .denseRow,
                vectorDimension: vectorDimension,
                evaluationKeyConfig: EvaluationKeyConfiguration(galoisElements: [3]),
                distanceMetric: .cosineSimilarity,
                extraPlaintextModuli: Scheme.Scalar
                    .generatePrimes(
                        significantBitCounts: [7],
                        preferringSmall: true,
                        nttDegree: encryptionParams.polyDegree))
            let serverConfig = ServerConfig<Scheme>(
                clientConfig: clientConfig,
                databasePacking: MatrixPacking
                    .diagonal(
                        babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))

            let processed = try database.process(config: serverConfig)
            let serialized = try processed.serialize()
            let deserialized = try ProcessedDatabase(from: serialized, contexts: processed.contexts)
            XCTAssertEqual(deserialized, processed)
        }
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }
}
