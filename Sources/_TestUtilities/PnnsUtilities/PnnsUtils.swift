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
public import PrivateNearestNeighborSearch

/// Testing utilities for PrivateNearestNeighborSearch.
public enum PrivateNearestNeighborSearchUtil {}

extension PrivateNearestNeighborSearchUtil {
    @usableFromInline
    package struct DatabaseConfig {
        @usableFromInline let rowCount: Int
        @usableFromInline let vectorDimension: Int
        @usableFromInline let metadataCount: Int

        @inlinable
        init(rowCount: Int, vectorDimension: Int, metadataCount: Int = 0) {
            self.rowCount = rowCount
            self.vectorDimension = vectorDimension
            self.metadataCount = metadataCount
        }
    }

    @inlinable
    package static func getDatabaseForTesting(config: DatabaseConfig) -> Database {
        let rows = (0..<config.rowCount).map { rowIndex in
            let vector = (0..<config.vectorDimension)
                .map { Float($0 + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1) }
            let metadata = Array(repeating: UInt8(rowIndex % Int(UInt8.max)), count: config.metadataCount)
            return DatabaseRow(
                entryId: UInt64(rowIndex),
                entryMetadata: metadata,
                vector: vector)
        }
        return Database(rows: rows)
    }
}
