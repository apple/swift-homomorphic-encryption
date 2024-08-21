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
@testable import PrivateNearestNeighborsSearch
import PrivateNearestNeighborsSearchProtobuf

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
                encryptionParams: EncryptionParameters(
                    from: .insecure_n_8_logq_5x18_logt_5),
                scalingFactor: 123,
                queryPacking: .denseRow,
                vectorDimension: vectorDimension,
                evaluationKeyConfig: EvaluationKeyConfiguration(galoisElements: [3]),
                distanceMetric: .cosineSimilarity,
                extraPlaintextModuli: [536_903_681])
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
                entryID: rowIndex,
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
            let encryptionParams = try EncryptionParameters<Scheme>(from: .insecure_n_8_logq_5x18_logt_5)
            let context = try Context<Scheme>(encryptionParameters: encryptionParams)

            let dimensions = try MatrixDimensions(rowCount: 5, columnCount: 4)
            let scalars: [[Scheme.Scalar]] = increasingData(
                dimensions: dimensions,
                modulus: encryptionParams.plaintextModulus)
            let plaintextMatrix = try PlaintextMatrix(
                context: context,
                dimensions: dimensions,
                packing: .denseColumn,
                values: scalars.flatMap { $0 })
            let serialized = try plaintextMatrix.serialize()
            XCTAssertEqual(try serialized.proto().native(), serialized)
        }

        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    func testSerializedCiphertextMatrix() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let encryptionParams = try EncryptionParameters<Scheme>(from: .insecure_n_8_logq_5x18_logt_5)
            let context = try Context<Scheme>(encryptionParameters: encryptionParams)
            let secretKey = try context.generateSecretKey()

            let dimensions = try MatrixDimensions(rowCount: 5, columnCount: 4)
            let scalars: [[Scheme.Scalar]] = increasingData(
                dimensions: dimensions,
                modulus: encryptionParams.plaintextModulus)
            let plaintextMatrix = try PlaintextMatrix(
                context: context,
                dimensions: dimensions,
                packing: .denseColumn,
                values: scalars.flatMap { $0 })
            let ciphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)
            let serialized = try ciphertextMatrix.serialize()
            let serializedProto = try serialized.proto()
            XCTAssertEqual(try serializedProto.native(), serialized)
            let serializedSize = try serializedProto.serializedData().count

            // TODO: test deserialization
            let serializedForDecryption = try ciphertextMatrix.serialize(forDecryption: true)
            let serializedForDecryptionSize = try serializedForDecryption.proto().serializedData().count
            XCTAssertLessThanOrEqual(serializedForDecryptionSize, serializedSize)
        }

        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }
}
