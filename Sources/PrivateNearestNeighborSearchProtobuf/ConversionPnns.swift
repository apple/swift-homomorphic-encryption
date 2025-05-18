// Copyright 2024-2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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
import PrivateNearestNeighborSearch

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_DistanceMetric {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon unsupported object.
    public func native() throws -> DistanceMetric {
        switch self {
        case .cosineSimilarity:
            .cosineSimilarity
        case let .UNRECOGNIZED(value):
            throw ConversionError.unrecognizedEnumValue(enum: Self.self, value: value)
        }
    }
}

extension DistanceMetric {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pnns_V1_DistanceMetric {
        switch self {
        case .cosineSimilarity:
            Apple_SwiftHomomorphicEncryption_Pnns_V1_DistanceMetric.cosineSimilarity
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_BabyStepGiantStep {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon unsupported object.
    public func native() -> BabyStepGiantStep {
        BabyStepGiantStep(
            vectorDimension: Int(vectorDimension),
            babyStep: Int(babyStep),
            giantStep: Int(giantStep))
    }
}

extension BabyStepGiantStep {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pnns_V1_BabyStepGiantStep {
        Apple_SwiftHomomorphicEncryption_Pnns_V1_BabyStepGiantStep.with { babyStepGiantStep in
            babyStepGiantStep.vectorDimension = UInt32(vectorDimension)
            babyStepGiantStep.babyStep = UInt32(babyStep)
            babyStepGiantStep.giantStep = UInt32(giantStep)
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon unsupported object.
    public func native() throws -> MatrixPacking {
        guard let matrixPackingType else {
            throw ConversionError.unsetOneof(oneof: Self.self, field: \Self.matrixPackingType)
        }
        switch matrixPackingType {
        case .denseColumn:
            return MatrixPacking.denseColumn
        case .denseRow:
            return MatrixPacking.denseRow
        case let .diagonal(diagonal):
            guard diagonal.hasBabyStepGiantStep else {
                throw ConversionError.unsetField(\Self.diagonal.babyStepGiantStep, in: Self.self)
            }
            let bsgs = diagonal.babyStepGiantStep.native()
            return MatrixPacking.diagonal(babyStepGiantStep: bsgs)
        }
    }
}

extension MatrixPacking {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking {
        Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking.with { packing in
            switch self {
            case .denseColumn:
                let protoDenseColumn = Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPackingDenseColumn()
                packing.matrixPackingType = .denseColumn(protoDenseColumn)
            case .denseRow:
                let protoDenseRow = Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPackingDenseRow()
                packing.matrixPackingType = .denseRow(protoDenseRow)
            case let .diagonal(babyStepGiantStep):
                let diagonal = Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPackingDiagonal.with { diagonalPacking in
                    diagonalPacking.babyStepGiantStep = babyStepGiantStep.proto()
                }
                packing.matrixPackingType = .diagonal(diagonal)
            }
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_ClientConfig {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon unsupported object.
    public func native<Scheme: HeScheme>() throws -> ClientConfig<Scheme> {
        guard hasEncryptionParameters else {
            throw ConversionError.unsetField(\Self.encryptionParameters, in: Self.self)
        }
        return try ClientConfig<Scheme>(
            encryptionParameters: encryptionParameters.native(),
            scalingFactor: Int(scalingFactor),
            queryPacking: queryPacking.native(),
            vectorDimension: Int(vectorDimension),
            evaluationKeyConfig: EvaluationKeyConfig(galoisElements: galoisElements.map { Int($0) }),
            distanceMetric: distanceMetric.native(),
            extraPlaintextModuli: extraPlaintextModuli.map { Scheme.Scalar($0) })
    }
}

extension ClientConfig {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> Apple_SwiftHomomorphicEncryption_Pnns_V1_ClientConfig {
        try Apple_SwiftHomomorphicEncryption_Pnns_V1_ClientConfig.with { config in
            config.encryptionParameters = try encryptionParameters[0].proto(scheme: Scheme.self)
            config.scalingFactor = UInt64(scalingFactor)
            config.queryPacking = try queryPacking.proto()
            config.vectorDimension = UInt32(vectorDimension)
            config.galoisElements = evaluationKeyConfig.galoisElements.map { UInt32($0) }
            config.distanceMetric = distanceMetric.proto()
            config.extraPlaintextModuli = extraPlaintextModuli.map { UInt64($0) }
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_ServerConfig {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon unsupported object.
    public func native<Scheme: HeScheme>() throws -> ServerConfig<Scheme> {
        guard hasClientConfig else {
            throw ConversionError.unsetField(\Self.clientConfig, in: Self.self)
        }
        return try ServerConfig(
            clientConfig: clientConfig.native(),
            databasePacking: databasePacking.native())
    }
}

extension ServerConfig {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> Apple_SwiftHomomorphicEncryption_Pnns_V1_ServerConfig {
        try Apple_SwiftHomomorphicEncryption_Pnns_V1_ServerConfig
            .with { config in
                config.clientConfig = try clientConfig.proto()
                config.databasePacking = try databasePacking.proto()
            }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_DatabaseRow {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() -> DatabaseRow {
        DatabaseRow(
            entryId: entryID,
            entryMetadata: Array(entryMetadata),
            vector: vector)
    }
}

extension DatabaseRow {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pnns_V1_DatabaseRow {
        Apple_SwiftHomomorphicEncryption_Pnns_V1_DatabaseRow.with { row in
            row.entryID = entryId
            row.entryMetadata = Data(entryMetadata)
            row.vector = vector
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_Database {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() -> Database {
        Database(rows: rows.map { row in row.native() })
    }
}

extension Database {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pnns_V1_Database {
        Apple_SwiftHomomorphicEncryption_Pnns_V1_Database.with { database in
            database.rows = rows.map { row in row.proto() }
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedPlaintextMatrix {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native() throws -> SerializedPlaintextMatrix {
        let dimensions = try MatrixDimensions(
            rowCount: Int(numRows),
            columnCount: Int(numColumns))
        return try SerializedPlaintextMatrix(
            dimensions: dimensions,
            packing: packing.native(),
            plaintexts: plaintexts.map { plaintext in plaintext.native() })
    }
}

extension SerializedPlaintextMatrix {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedPlaintextMatrix {
        try Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedPlaintextMatrix.with { protoMatrix in
            protoMatrix.numRows = UInt32(dimensions.rowCount)
            protoMatrix.numColumns = UInt32(dimensions.columnCount)
            protoMatrix.plaintexts = plaintexts.map { plaintext in plaintext.proto() }
            protoMatrix.packing = try packing.proto()
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedCiphertextMatrix {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native<T: ScalarType>() throws -> SerializedCiphertextMatrix<T> {
        let dimensions = try MatrixDimensions(
            rowCount: Int(numRows),
            columnCount: Int(numColumns))
        return try SerializedCiphertextMatrix<T>(
            dimensions: dimensions,
            packing: packing.native(),
            ciphertexts: ciphertexts.map { ciphertext in try ciphertext.native() })
    }
}

extension SerializedCiphertextMatrix {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedCiphertextMatrix {
        try Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedCiphertextMatrix.with { protoMatrix in
            protoMatrix.numRows = UInt32(dimensions.rowCount)
            protoMatrix.numColumns = UInt32(dimensions.columnCount)
            protoMatrix.ciphertexts = ciphertexts.map { ciphertext in ciphertext.proto() }
            protoMatrix.packing = try packing.proto()
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedProcessedDatabase {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native<Scheme: HeScheme>() throws -> SerializedProcessedDatabase<Scheme> {
        try SerializedProcessedDatabase(
            plaintextMatrices: plaintextMatrices.map { matrix in try matrix.native() },
            entryIds: entryIds,
            entryMetadatas: entryMetadatas.map { metadata in Array(metadata) },
            serverConfig: serverConfig.native())
    }
}

extension SerializedProcessedDatabase {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedProcessedDatabase {
        try Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedProcessedDatabase
            .with { protoDatabase in
                protoDatabase.plaintextMatrices = try plaintextMatrices.map { matrix in try matrix.proto() }
                protoDatabase.entryIds = entryIds
                protoDatabase.entryMetadatas = entryMetadatas.map { metadata in Data(metadata) }
                protoDatabase.serverConfig = try serverConfig.proto()
            }
    }
}

extension Query {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> [Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedCiphertextMatrix] {
        try ciphertextMatrices.map { matrix in try matrix.serialize().proto() }
    }
}

extension [Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedCiphertextMatrix] {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func native<Scheme: HeScheme>(context: Context<Scheme.Scalar>) throws -> Query<Scheme> {
        let matrices: [CiphertextMatrix<Scheme, Coeff>] = try map { matrix in
            let native: SerializedCiphertextMatrix<Scheme.Scalar> = try matrix.native()
            return try CiphertextMatrix(deserialize: native, context: context)
        }
        return Query(ciphertextMatrices: matrices)
    }
}

extension Query {
    package func size() throws -> Int {
        try proto().map { matrix in try matrix.serializedData().count }.sum()
    }
}

extension Response {
    package func size() throws -> Int {
        try proto().serializedData().count
    }
}

extension EvaluationKey {
    package func size() throws -> Int {
        try serialize().proto().serializedData().count
    }
}
