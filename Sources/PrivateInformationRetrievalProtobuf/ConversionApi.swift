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
import HomomorphicEncryptionProtobuf
import PrivateInformationRetrieval

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRResponse {
    /// Converts the protobuf object to a native type.
    /// - Parameter context: Context to associate with the native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon invalid protobuf object.
    public func native<Scheme: HeScheme>(context: Context<Scheme>) throws -> Response<Scheme> {
        let ciphertexts: [[Scheme.CoeffCiphertext]] = try replies.map { reply in
            let serializedCiphertexts: [SerializedCiphertext<Scheme.Scalar>] = try reply.native()
            return try serializedCiphertexts.map { serialized in
                try Scheme.CoeffCiphertext(deserialize: serialized, context: context, moduliCount: 1)
            }
        }
        return Response(ciphertexts: ciphertexts)
    }
}

extension Response {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRResponse {
        try Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRResponse.with { pirResponse in
            pirResponse.replies = try ciphertexts.map { reply in
                try reply.map { try $0.serialize(forDecryption: true) }.proto()
            }
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRShardConfig {
    /// Converts the protobuf object to a native type.
    /// - Parameters:
    ///   - batchSize: Number of queries in a batch.
    ///   - evaluationKeyConfig: Evaluation key configuration
    /// - Returns: The converted native type.
    public func native(batchSize: Int, evaluationKeyConfig: EvaluationKeyConfig) -> IndexPirParameter {
        IndexPirParameter(
            entryCount: Int(numEntries),
            entrySizeInBytes: Int(entrySize),
            dimensions: dimensions.map(Int.init),
            batchSize: batchSize,
            evaluationKeyConfig: evaluationKeyConfig)
    }
}

extension IndexPirParameter {
    /// Converts the native object into a protobuf object.
    /// - Parameter shardID: Optional identifier to associate with the shard
    /// - Returns: The converted protobuf object.
    public func proto(shardID: String = "") -> Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRShardConfig {
        Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRShardConfig.with { shardConfig in
            shardConfig.numEntries = UInt64(entryCount)
            shardConfig.entrySize = UInt64(entrySizeInBytes)
            shardConfig.dimensions = dimensions.map(UInt64.init)
            shardConfig.shardID = shardID
        }
    }
}
