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

/// A nearest neighbor search query.
struct Query<Scheme: HeScheme>: Sendable {
    // Encrypted query; one matrix per plaintext CRT modulus
    let ciphertextMatrices: [CiphertextMatrix<Scheme, Coeff>]
}

/// A nearest neighbor search response.
struct Response<Scheme: HeScheme>: Sendable {
    // Encrypted response; one matrix per plaintext CRT modulus
    let ciphertextMatrices: [CiphertextMatrix<Scheme, Coeff>]
    // A list of entry identifiers the server computed similarities for
    let entryIDs: [UInt64]
    // Metadata for each entry in the database
    let entryMetadatas: [[UInt8]]
}

/// Distances from one or more query vector to the database rows.
struct DatabaseDistances: Sendable {
    /// The distance from each query vector (outer dimension) to each database row (inner dimension).
    let distances: Array2d<Float>
    // Identifier for each entry in the database.
    let entryIDs: [UInt64]
    // Metadata for each entry in the database.
    let entryMetadatas: [[UInt8]]
}
