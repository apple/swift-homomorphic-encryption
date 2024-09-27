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

@testable import HomomorphicEncryption
@testable import PrivateNearestNeighborSearch
import PrivateNearestNeighborSearchProtobuf

import XCTest

func increasingData<T: ScalarType>(dimensions: MatrixDimensions, modulus: T) -> [[T]] {
    (0..<dimensions.rowCount).map { rowIndex in
        (0..<dimensions.columnCount).map { columnIndex in
            let value = 1 + T(rowIndex * dimensions.columnCount + columnIndex)
            return value % modulus
        }
    }
}

class ConversionTests: XCTestCase {
    func testDistanceMetric() throws {
        for metric in DistanceMetric.allCases {
            XCTAssertEqual(try metric.proto().native(), metric)
        }
    }

    func testPacking() throws {
        XCTAssertEqual(
            try MatrixPacking.denseColumn.proto().native(),
            MatrixPacking.denseColumn)
        XCTAssertEqual(
            try MatrixPacking.denseRow.proto().native(),
            MatrixPacking.denseRow)
        let bsgs = BabyStepGiantStep(vectorDimension: 128)
        XCTAssertEqual(bsgs.proto().native(), bsgs)

        XCTAssertEqual(
            try MatrixPacking
                .diagonal(babyStepGiantStep: bsgs)
                .proto()
                .native(),
            MatrixPacking.diagonal(babyStepGiantStep: bsgs))
    }

    func testClientAndServerConfig() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let vectorDimension = 4
            let clientConfig = try ClientConfig<Scheme>(
                encryptionParameters: EncryptionParameters(
                    from: .insecure_n_8_logq_5x18_logt_5),
                scalingFactor: 123,
                queryPacking: .denseRow,
                vectorDimension: vectorDimension,
                evaluationKeyConfig: EvaluationKeyConfig(galoisElements: [3]),
                distanceMetric: .cosineSimilarity,
                extraPlaintextModuli: Scheme.Scalar.generatePrimes(
                    significantBitCounts: [15],
                    preferringSmall: true,
                    nttDegree: 8))
            XCTAssertEqual(try clientConfig.proto().native(), clientConfig)

            let serverConfig = ServerConfig<Scheme>(
                clientConfig: clientConfig,
                databasePacking: MatrixPacking
                    .diagonal(
                        babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))
            XCTAssertEqual(try serverConfig.proto().native(), serverConfig)
        }

        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    func testDatabase() throws {
        let rows = (0...10).map { rowIndex in
            DatabaseRow(
                entryId: rowIndex,
                entryMetadata: rowIndex.littleEndianBytes,
                vector: [Float(rowIndex)])
        }
        for row in rows {
            XCTAssertEqual(row.proto().native(), row)
        }
        let database = Database(rows: rows)
        XCTAssertEqual(database.proto().native(), database)
    }

    func testSerializedPlaintextMatrix() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let encryptionParameters = try EncryptionParameters<Scheme>(from: .insecure_n_8_logq_5x18_logt_5)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)

            let dimensions = try MatrixDimensions(rowCount: 5, columnCount: 4)
            let scalars: [[Scheme.Scalar]] = increasingData(
                dimensions: dimensions,
                modulus: encryptionParameters.plaintextModulus)
            let plaintextMatrix = try PlaintextMatrix(
                context: context,
                dimensions: dimensions,
                packing: .denseColumn,
                values: scalars.flatMap { $0 })
            let serialized = try plaintextMatrix.serialize()
            XCTAssertEqual(try serialized.proto().native(), serialized)
            let deserialized = try PlaintextMatrix(deserialize: serialized, context: context)
            XCTAssertEqual(deserialized, plaintextMatrix)

            for moduliCount in 1..<encryptionParameters.coefficientModuli.count {
                let evalPlaintextMatrix = try plaintextMatrix.convertToEvalFormat(moduliCount: moduliCount)
                let serialized = try evalPlaintextMatrix.serialize()
                XCTAssertEqual(try serialized.proto().native(), serialized)
                let deserialized = try PlaintextMatrix(
                    deserialize: serialized,
                    context: context,
                    moduliCount: moduliCount)
                XCTAssertEqual(deserialized, evalPlaintextMatrix)
            }
        }

        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    func testSerializedCiphertextMatrix() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let encryptionParameters = try EncryptionParameters<Scheme>(from: .insecure_n_8_logq_5x18_logt_5)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
            let secretKey = try context.generateSecretKey()

            let dimensions = try MatrixDimensions(rowCount: 5, columnCount: 4)
            let scalars: [[Scheme.Scalar]] = increasingData(
                dimensions: dimensions,
                modulus: encryptionParameters.plaintextModulus)
            let plaintextMatrix = try PlaintextMatrix(
                context: context,
                dimensions: dimensions,
                packing: .denseColumn,
                values: scalars.flatMap { $0 })
            // Check Canonical Format
            do {
                let ciphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)
                let serialized = try ciphertextMatrix.serialize()
                let serializedProto = try serialized.proto()
                XCTAssertEqual(try serializedProto.native(), serialized)
            }
            // Check Evaluation format
            do {
                let ciphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)
                let evalCiphertextMatrix = try ciphertextMatrix.convertToEvalFormat()
                let serialized = try evalCiphertextMatrix.serialize()
                XCTAssertEqual(try serialized.proto().native(), serialized)
                let deserialized = try CiphertextMatrix<Scheme, Eval>(
                    deserialize: serialized,
                    context: context)
                XCTAssertEqual(deserialized, evalCiphertextMatrix)
            }
            // Check serializeForDecryption
            do {
                var ciphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)
                try ciphertextMatrix.modSwitchDownToSingle()
                let serializedForDecryption = try ciphertextMatrix.serialize(forDecryption: true)
                let serializedForDecryptionSize = try serializedForDecryption.proto().serializedData().count

                let serialized = try ciphertextMatrix.serialize()
                let serializedProto = try serialized.proto()
                let serializedSize = try serializedProto.serializedData().count

                XCTAssertLessThan(serializedForDecryptionSize, serializedSize)
                let deserialized = try CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat>(
                    deserialize: serializedForDecryption,
                    context: context, moduliCount: 1)
                let decrypted = try deserialized.decrypt(using: secretKey)
                XCTAssertEqual(decrypted, plaintextMatrix)
            }
        }

        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    func testQuery() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let encryptionParameters = try EncryptionParameters<Scheme>(from: .insecure_n_8_logq_5x18_logt_5)
            let context = try Context<Scheme>(encryptionParameters: encryptionParameters)
            let secretKey = try context.generateSecretKey()

            let dimensions = try MatrixDimensions(rowCount: 5, columnCount: 4)
            let scalars: [[Scheme.Scalar]] = increasingData(
                dimensions: dimensions,
                modulus: encryptionParameters.plaintextModulus)
            let plaintextMatrix = try PlaintextMatrix(
                context: context,
                dimensions: dimensions,
                packing: .denseColumn,
                values: scalars.flatMap { $0 })
            let ciphertextMatrices = try (0...3).map { _ in
                try plaintextMatrix.encrypt(using: secretKey).convertToCoeffFormat()
            }

            let query = Query(ciphertextMatrices: ciphertextMatrices)
            let roundtrip = try query.proto().native(context: context)
            XCTAssertEqual(roundtrip, query)
        }
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    func testSerializedProcessedDatabase() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let encryptionParameters = try EncryptionParameters<Scheme>(from: .insecure_n_8_logq_5x18_logt_5)
            let vectorDimension = 4

            let rows = (0...10).map { rowIndex in
                DatabaseRow(
                    entryId: rowIndex,
                    entryMetadata: rowIndex.littleEndianBytes,
                    vector: Array(repeating: Float(rowIndex), count: vectorDimension))
            }
            for row in rows {
                XCTAssertEqual(row.proto().native(), row)
            }
            let database = Database(rows: rows)

            let clientConfig = try ClientConfig<Scheme>(
                encryptionParameters: encryptionParameters,
                scalingFactor: 123,
                queryPacking: .denseRow,
                vectorDimension: vectorDimension,
                evaluationKeyConfig: EvaluationKeyConfig(galoisElements: [3]),
                distanceMetric: .cosineSimilarity,
                extraPlaintextModuli: Scheme.Scalar
                    .generatePrimes(
                        significantBitCounts: [7],
                        preferringSmall: true,
                        nttDegree: encryptionParameters.polyDegree))
            let serverConfig = ServerConfig<Scheme>(
                clientConfig: clientConfig,
                databasePacking: MatrixPacking
                    .diagonal(
                        babyStepGiantStep: BabyStepGiantStep(vectorDimension: vectorDimension)))

            let processed = try database.process(config: serverConfig)
            let serialized = try processed.serialize()
            XCTAssertEqual(try serialized.proto().native(), serialized)
        }
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }
}
