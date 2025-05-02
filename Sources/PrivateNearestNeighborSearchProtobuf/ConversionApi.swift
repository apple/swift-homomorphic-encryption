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
import HomomorphicEncryptionProtobuf
import PrivateNearestNeighborSearch

extension Apple_SwiftHomomorphicEncryption_Api_Pnns_V1_PNNSShardResponse {
    /// Converts the protobuf object to a native type.
    /// - Parameter contexts: Contexts to associate with the native type; one context per plaintext modulus.
    /// - Returns: The converted native type.
    /// - Throws: Error upon invalid protobuf object.
    public func native<Scheme: HeScheme>(contexts: [Scheme.Context]) throws -> Response<Scheme> {
        precondition(contexts.count == reply.count)
        let matrices: [CiphertextMatrix<Scheme, Coeff>] = try zip(reply, contexts).map { matrix, context in
            let serialized: SerializedCiphertextMatrix<Scheme.Scalar> = try matrix.native()
            return try CiphertextMatrix(deserialize: serialized, context: context, moduliCount: 1)
        }
        return Response(
            ciphertextMatrices: matrices,
            entryIds: entryIds,
            entryMetadatas: entryMetadatas.map { metadata in Array(metadata) })
    }
}

extension Response {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> Apple_SwiftHomomorphicEncryption_Api_Pnns_V1_PNNSShardResponse {
        try Apple_SwiftHomomorphicEncryption_Api_Pnns_V1_PNNSShardResponse.with { pnnsResponse in
            pnnsResponse.reply = try ciphertextMatrices.map { matrix in
                try matrix.serialize(forDecryption: true).proto()
            }
            pnnsResponse.entryIds = entryIds
            pnnsResponse.entryMetadatas = entryMetadatas.map { bytes in Data(bytes) }
        }
    }
}
