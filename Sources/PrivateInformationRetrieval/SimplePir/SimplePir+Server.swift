// Copyright 2025-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

public import HomomorphicEncryption
import Foundation
import ModularArithmetic

public struct SimplePirServer<Scalar: ScalarType>: SimplePirServerProtocol {
    public typealias ProcessedDatabase = Array2d<Scalar>
    public let processedDatabase: ProcessedDatabase
    public let hint: Hint
    public let params: SimplePirParameters

    public init(processedDatabase: ProcessedDatabase, hint: Hint, params: SimplePirParameters) async throws {
        self.processedDatabase = processedDatabase
        self.hint = hint
        self.params = params
    }

    public func computeResponse(to requests: Requests) async throws -> Responses {
        let mask: Scalar = params.encryptionParams.getCiphertextMask()
        let result = try await processedDatabase.multiply(transposing: requests, mask: mask)
        // Compute response using multiply(transposing:) to avoid transposing the query client-side.
        // This produces (columnSize × chunksPerEntry), but client expects (chunksPerEntry × columnSize),
        // so we transpose the result.
        return await result.transposed()
    }
}
