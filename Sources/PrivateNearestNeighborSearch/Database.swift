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

/// One row in a nearest-neighbor search database.
public struct DatabaseRow: Codable, Equatable, Hashable, Sendable {
    /// Unique identifier for the database entry.
    public let entryId: UInt64

    /// Metadata associated with the entry.
    public let entryMetadata: [UInt8]

    /// Vector for use in nearest neighbor search.
    public let vector: [Float]

    /// Creates a new ``DatabaseRow``.
    /// - Parameters:
    ///   - entryId: Unique identifier for the database entry.
    ///   - entryMetadata: Metadata associated with the entry.
    ///   - vector: Vector for use in nearest neighbor search.
    public init(entryId: UInt64, entryMetadata: [UInt8], vector: [Float]) {
        self.entryId = entryId
        self.entryMetadata = entryMetadata
        self.vector = vector
    }
}

/// Database for nearest neighbor search.
public struct Database: Codable, Equatable, Hashable, Sendable {
    /// Rows in the database.
    public let rows: [DatabaseRow]

    /// Creates a new ``Database``.
    /// - Parameter rows: Rows in the database.
    public init(rows: [DatabaseRow]) {
        self.rows = rows
    }
}
