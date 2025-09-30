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

import _CryptoExtras
import Crypto
import Foundation
import HomomorphicEncryption
import PrivateInformationRetrieval
import SwiftProtobuf

extension Apple_SwiftHomomorphicEncryption_Pir_V1_EncryptedIndices {
    /// Converts the protobuf object to a native type.
    /// - Parameter context: Context to associate with the native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon invalid protobuf object.
    public func native<Scheme: HeScheme>(context: Context<Scheme>) throws -> Query<Scheme> {
        let ciphertexts: [Scheme.CanonicalCiphertext] = try ciphertexts.map { ciphertext in
            let serializedCiphertext: SerializedCiphertext<Scheme.Scalar> = try ciphertext.native()
            return try Ciphertext(
                deserialize: serializedCiphertext,
                context: context)
        }
        return Query(ciphertexts: ciphertexts, indicesCount: Int(numPirCalls))
    }
}

extension Query {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> Apple_SwiftHomomorphicEncryption_Pir_V1_EncryptedIndices {
        try Apple_SwiftHomomorphicEncryption_Pir_V1_EncryptedIndices.with { encryptedIndices in
            encryptedIndices.ciphertexts = try ciphertexts.map { ciphertext in
                try ciphertext.serialize().proto()
            }
            encryptedIndices.numPirCalls = UInt64(indicesCount)
        }
    }
}

extension ProcessedDatabaseWithParameters {
    /// Converts the native processed database with parameters into protobuf object that contains only the parameters.
    /// - Parameter context: The context that was used to create processed database.
    /// - Returns: The PIR parameters protobuf object.
    /// - Throws: Error when the parameters cannot be represented as a protobuf object.
    public func proto(context: Context<Scheme>) throws -> Apple_SwiftHomomorphicEncryption_Pir_V1_PirParameters {
        let encryptionParameters = context.encryptionParameters
        return try Apple_SwiftHomomorphicEncryption_Pir_V1_PirParameters.with { params in
            params.encryptionParameters = try encryptionParameters.proto(scheme: Scheme.self)
            params.numEntries = UInt64(pirParameter.entryCount)
            params.entrySize = UInt64(pirParameter.entrySizeInBytes)
            params.dimensions = pirParameter.dimensions.map(UInt64.init)
            if let keywordPirParameter {
                params.keywordPirParams = keywordPirParameter.proto()
            }
            params.algorithm = algorithm.proto()
            params.batchSize = UInt64(pirParameter.batchSize)
            params.evaluationKeyConfig = try evaluationKeyConfig
                .proto(encryptionParameters: encryptionParameters, scheme: Scheme.self)
            params.keyCompressionStrategy = .unspecified
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordPirParameters {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error when the parameters cannot be represented as a protobuf object.
    public func native() throws -> KeywordPirParameter {
        let symmetricPirClientConfig = hasSymmetricPirClientConfig ? try symmetricPirClientConfig.native() : nil
        return KeywordPirParameter(
            hashFunctionCount: Int(numHashFunctions),
            shardingFunction: shardingFunction.native(),
            symmetricPirClientConfig: symmetricPirClientConfig)
    }
}

extension KeywordPirParameter {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordPirParameters {
        Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordPirParameters.with { params in
            params.numHashFunctions = UInt64(hashFunctionCount)
            params.shardingFunction = shardingFunction.proto()
            if let symmetricPirClientConfig {
                params.symmetricPirClientConfig = symmetricPirClientConfig.proto()
            }
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pir_V1_PIRShardingFunction {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() -> ShardingFunction {
        switch function {
        case .sha256:
            .sha256
        case let .doubleMod(doubleMod):
            .doubleMod(otherShardCount: Int(doubleMod.otherShardCount))
        case .none:
            .sha256
        }
    }
}

extension ShardingFunction {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pir_V1_PIRShardingFunction {
        Apple_SwiftHomomorphicEncryption_Pir_V1_PIRShardingFunction.with { shardingFunction in
            shardingFunction.function = switch self.function {
            case .sha256:
                .sha256(Apple_SwiftHomomorphicEncryption_Pir_V1_PIRShardingFunctionSHA256())
            case let .doubleMod(otherShardCount: otherShardCount):
                .doubleMod(Apple_SwiftHomomorphicEncryption_Pir_V1_PIRShardingFunctionDoubleMod.with { doubleMod in
                    doubleMod.otherShardCount = UInt32(otherShardCount)
                })
            }
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pir_V1_SymmetricPirClientConfig {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() throws -> SymmetricPirClientConfig {
        switch configType {
        case .unspecified:
            throw ConversionError
                .unspecifiedEnumValue(enum: Apple_SwiftHomomorphicEncryption_Pir_V1_SymmetricPirConfigType.self)
        case .oprfP384AesGcm192Nonce96Tag128:
            return SymmetricPirClientConfig(
                serverPublicKey: [UInt8](serverPublicKey),
                configType: .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128)
        case let .UNRECOGNIZED(value):
            throw ConversionError.unrecognizedEnumValue(
                enum: Apple_SwiftHomomorphicEncryption_Pir_V1_SymmetricPirConfigType.self,
                value: value)
        }
    }
}

extension SymmetricPirClientConfig {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pir_V1_SymmetricPirClientConfig {
        Apple_SwiftHomomorphicEncryption_Pir_V1_SymmetricPirClientConfig.with { config in
            config.serverPublicKey = Data(serverPublicKey)
            switch configType {
            case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128:
                config.configType = .oprfP384AesGcm192Nonce96Tag128
            }
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pir_V1_PirParameters {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() -> IndexPirParameter {
        IndexPirParameter(
            entryCount: Int(numEntries),
            entrySizeInBytes: Int(entrySize),
            dimensions: dimensions.map(Int.init),
            batchSize: Int(batchSize),
            evaluationKeyConfig: evaluationKeyConfig.native())
    }

    /// Converts the protobuf object into a native type.
    /// - Parameter database: The database  to use.
    /// - Returns: A database with parameters.
    /// - Throws: Error when the protobuf object cannot be represented.
    public func native<Scheme: HeScheme>(database: ProcessedDatabase<Scheme>) throws
        -> ProcessedDatabaseWithParameters<Scheme>
    {
        try ProcessedDatabaseWithParameters(
            database: database,
            algorithm: algorithm.native(),
            evaluationKeyConfig: evaluationKeyConfig.native(),
            pirParameter: native(),
            keywordPirParameter: hasKeywordPirParams ? keywordPirParams.native() : nil)
    }
}

extension Apple_SwiftHomomorphicEncryption_Pir_V1_PirAlgorithm {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() throws -> PirAlgorithm {
        switch self {
        case .aclsPir: PirAlgorithm.aclsPir
        case .mulPir: PirAlgorithm.mulPir
        case let .UNRECOGNIZED(value):
            throw ConversionError.unrecognizedEnumValue(enum: Self.self, value: value)
        }
    }
}

extension PirAlgorithm {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pir_V1_PirAlgorithm {
        switch self {
        case .aclsPir: Apple_SwiftHomomorphicEncryption_Pir_V1_PirAlgorithm.aclsPir
        case .mulPir: Apple_SwiftHomomorphicEncryption_Pir_V1_PirAlgorithm.mulPir
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pir_V1_KeyCompressionStrategy {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() throws -> PirKeyCompressionStrategy {
        switch self {
        case .unspecified: PirKeyCompressionStrategy.noCompression
        case .hybridCompression: PirKeyCompressionStrategy.hybridCompression
        case .maximumCompression: PirKeyCompressionStrategy.maxCompression
        case let .UNRECOGNIZED(value):
            throw ConversionError.unrecognizedEnumValue(enum: Self.self, value: value)
        }
    }
}

extension PirKeyCompressionStrategy {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pir_V1_KeyCompressionStrategy {
        switch self {
        case .noCompression: Apple_SwiftHomomorphicEncryption_Pir_V1_KeyCompressionStrategy.unspecified
        case .hybridCompression: Apple_SwiftHomomorphicEncryption_Pir_V1_KeyCompressionStrategy.hybridCompression
        case .maxCompression: Apple_SwiftHomomorphicEncryption_Pir_V1_KeyCompressionStrategy.maximumCompression
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabaseRow {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() -> KeywordValuePair {
        KeywordValuePair(keyword: Array(keyword), value: Array(value))
    }
}

extension KeywordValuePair {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabaseRow {
        Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabaseRow.with { row in
            row.keyword = Data(keyword)
            row.value = Data(value)
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() -> [KeywordValuePair] {
        rows.map { row in row.native() }
    }
}

extension [KeywordValuePair] {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase {
        Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase.with { database in
            database.rows = self.map { $0.proto() }
        }
    }
}

extension [KeywordValuePair.Keyword: KeywordValuePair.Value] {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase {
        Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase.with { database in
            database.rows = self.map { row in KeywordValuePair(keyword: row.key, value: row.value).proto() }
        }
    }
}

extension Query {
    package func size() throws -> Int {
        try proto().serializedData().count
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

extension OprfQuery {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFRequest {
        Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFRequest.with { request in
            request.queryElement = oprfRepresentation
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFRequest {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error when the protobuf object cannot be represented.
    public func native() throws -> OprfQuery {
        try OprfQuery(oprfRepresentation: queryElement)
    }
}

extension OprfResponse {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFResponse {
        Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFResponse.with { response in
            response.evaluatedElement = evaluatedElement.oprfRepresentation
            response.proof = proof.rawRepresentation
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFResponse {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error when the protobuf object cannot be represented.
    public func native() throws -> OprfResponse {
        try OprfResponse(rawRepresentation: evaluatedElement + proof)
    }
}
