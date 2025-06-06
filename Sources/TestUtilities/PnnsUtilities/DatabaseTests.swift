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
    /// Database tests.
    public enum DatabaseTests {
        /// Test serialization.
        @inlinable
        public static func serializedProcessedDatabase<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: .insecure_n_8_logq_5x18_logt_5)
            let vectorDimension = 4

            let rows = (0...10).map { rowIndex in
                DatabaseRow(
                    entryId: rowIndex,
                    entryMetadata: rowIndex.littleEndianBytes,
                    vector: Array(repeating: Float(rowIndex), count: vectorDimension))
            }
            let database = Database(rows: rows)

            let extraPlaintextModuli = try Scheme.Scalar.generatePrimes(
                significantBitCounts: [7],
                preferringSmall: true,
                nttDegree: encryptionParameters.polyDegree)
            let clientConfig = try ClientConfig<Scheme>(
                encryptionParameters: encryptionParameters,
                scalingFactor: 123,
                queryPacking: .denseRow,
                vectorDimension: vectorDimension,
                evaluationKeyConfig: EvaluationKeyConfig(galoisElements: [3]),
                distanceMetric: .cosineSimilarity,
                extraPlaintextModuli: extraPlaintextModuli)
            let databasePacking = MatrixPacking
                .diagonal(babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension))
            let serverConfig = ServerConfig<Scheme>(clientConfig: clientConfig, databasePacking: databasePacking)

            let processed: ProcessedDatabase<Scheme> = try database.process(config: serverConfig)
            let serialized = try processed.serialize()
            let deserialized = try ProcessedDatabase<Scheme>(from: serialized, contexts: processed.contexts)
            #expect(deserialized == processed)
        }
    }
}
