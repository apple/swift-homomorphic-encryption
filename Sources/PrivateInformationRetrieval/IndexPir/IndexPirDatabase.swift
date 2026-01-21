// Copyright 2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

/// Type of value in an ``IndexDatabase``.
public typealias IndexDatabaseRowValue = [UInt8]

/// A row in an ``IndexDatabase``
public struct IndexDatabaseRow {
    /// Index of the row in the database.
    public let index: Int
    /// Value of the row.
    public let value: IndexDatabaseRowValue

    ///  Creates a new ``IndexDatabaseRow``.
    /// - Parameters:
    ///   - index: Index of the row in the database.
    ///   - value: Value of the row.
    public init(index: Int, value: IndexDatabaseRowValue) {
        self.index = index
        self.value = value
    }
}

/// A shard of an ``IndexDatabase``.
public struct IndexDatabaseShard: Hashable, Codable, Sendable {
    /// Identifier for the shard.
    public let shardID: String
    /// Rows in the database.
    public var rows: [IndexDatabaseRowValue]
    /// Whether or not the database is empty, i.e., has no rows.
    public var isEmpty: Bool {
        rows.isEmpty
    }

    /// Initializes an ``IndexDatabaseShard``.
    /// - Parameters:
    ///   - shardID: Identifier for the database shard.
    ///   - rows: Rows in the database.
    @inlinable
    public init(
        shardID: String,
        rows: some Collection<IndexDatabaseRowValue>)
    {
        self.shardID = shardID
        self.rows = [IndexDatabaseRowValue](rows)
    }
}

extension IndexDatabaseShard: Collection {
    public typealias Index = Int
    public typealias Element = IndexDatabaseRowValue

    public var startIndex: Index { rows.startIndex }

    public var endIndex: Index { rows.endIndex }

    public func index(after i: Index) -> Index {
        rows.index(after: i)
    }

    public subscript(index: Index) -> Iterator.Element {
        rows[index]
    }
}

/// Configuration for an ``IndexDatabase``.
public struct IndexDatabaseConfig: Hashable, Codable, Sendable {
    public let sharding: Sharding
    public let indexPirConfig: IndexPirConfig

    /// Initializes an ``IndexDatabaseConfig``.
    /// - Parameters:
    ///   - sharding: Sharding to use for the database.
    ///   - keywordPirConfig: Index PIR configuration.
    public init(
        sharding: Sharding,
        indexPirConfig: IndexPirConfig)
    {
        self.sharding = sharding
        self.indexPirConfig = indexPirConfig
    }
}

/// Database of index pairs, divided into shards.
public struct IndexDatabase {
    /// Shards of the database.
    ///
    /// Each keyword-value pair is in exactly one shard.
    public let shards: [String: IndexDatabaseShard]

    /// Initializes an ``IndexDatabase``.
    /// - Parameters:
    ///   - rows: Rows in the database.
    ///   - sharding: How to shard the database.
    /// - Throws: Error upon failure to initialize the database.
    public init(
        rows: some Collection<IndexDatabaseRowValue>,
        sharding: Sharding) throws
    {
        let database = rows
        let shardCount = switch sharding {
        case let .shardCount(shardCount): shardCount
        case let .entryCountPerShard(entryCountPerShard):
            // Flooring divide ensures `entryCountPerShard` for privacy
            max(rows.count / entryCountPerShard, 1)
        }

        var shards: [String: IndexDatabaseShard] = [:]
        for (index, row) in database.enumerated() {
            let shardID = String(index % shardCount)
            shards[shardID, default: IndexDatabaseShard(shardID: shardID, rows: [])].rows.append(row)
        }
        self.shards = shards
    }
}
