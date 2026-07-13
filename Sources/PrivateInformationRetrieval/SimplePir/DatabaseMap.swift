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
import Algorithms

/// A map that tracks the layout of database entries across multiple shards.
///
/// `DatabaseMap` provides a way to locate and reconstruct database entries that have been
/// split into chunks and distributed across multiple shards. Each entry maintains
/// information about its original size and the locations of all its constituent chunks.
public struct DatabaseMap: Codable, Hashable, Sendable {
    /// A location of a database entry chunk.
    public struct ChunkLocation: Codable, Hashable, Sendable {
        /// The index of the shard that contains the chunk.
        public let shardIndex: Int
        /// The index of the chunk within the shard.
        public let index: Int

        /// Creates a new chunk location.
        /// - Parameters:
        ///   - shardIndex: The index of the shard that contains the chunk.
        ///   - index: The index of the chunk within the shard.
        public init(shardIndex: Int, index: Int) {
            self.shardIndex = shardIndex
            self.index = index
        }
    }

    /// A database entry.
    public struct Entry: Codable, Hashable, Sendable {
        /// The original index of the entry within the original dataset.
        public let originalIndex: Int
        /// The size of the entry in bytes.
        public let size: Int
        /// The locations of all the chunks that make up the entry.
        public let chunks: [ChunkLocation]

        /// Creates a new database entry.
        /// - Parameters:
        ///   - originalIndex: The original index of the entry within the original dataset.
        ///   - size: The size of the entry in bytes.
        ///   - chunks: The locations of all the chunks that make up the entry.
        public init(originalIndex: Int, size: Int, chunks: [ChunkLocation]) {
            self.originalIndex = originalIndex
            self.size = size
            self.chunks = chunks
        }
    }

    /// The collection of all database entries tracked by this map.
    public let entries: [Entry]
    /// The size of each chunk in bytes.
    public let chunkSize: Int

    /// Creates a new database map.
    /// - Parameter entries: The collection of all database entries tracked by this map.
    /// - Parameter chunkSize: The size of each chunk in bytes.
    public init(entries: [Entry], chunkSize: Int) {
        self.entries = entries
        self.chunkSize = chunkSize
    }

    /// Shard a database.
    /// - Parameters:
    ///   - rawEntries: The collection of raw entries, where each entry is a tuple containing the original index and
    /// a value.
    ///   - shardCount: The number of shards to use.
    ///   - chunkSize: The number of bytes per chunk.
    /// - Returns: A database map and a list of shards.
    public static func shardDatabase(
        entries rawEntries: some Sequence<(originalIndex: Int, value: [UInt8])>,
        shardCount: Int,
        chunkSize: Int) -> (databaseMap: DatabaseMap, shards: [Array2d<UInt8>])
    {
        var entries: [DatabaseMap.Entry] = []
        var shards: [[[UInt8]]] = .init(repeating: [], count: shardCount)

        for (originalIndex, value) in rawEntries {
            var chunks: [DatabaseMap.ChunkLocation] = []
            let randomShards = Array(0..<shardCount).shuffled()
            for (chunkIndex, chunk) in value.chunks(ofCount: chunkSize).enumerated() {
                var paddedChunk = chunk
                if chunk.count < chunkSize {
                    paddedChunk.append(contentsOf: repeatElement(0, count: chunkSize - chunk.count))
                }

                let shardIndex = randomShards[chunkIndex % shardCount]
                chunks.append(.init(shardIndex: shardIndex, index: shards[shardIndex].count))
                shards[shardIndex].append(Array(paddedChunk))
            }
            entries.append(DatabaseMap.Entry(originalIndex: originalIndex, size: value.count, chunks: chunks))
        }

        let compactShards = shards.map { shard in
            Array2d(data: shard.flatMap(\.self), rowCount: shard.count, columnCount: chunkSize)
        }
        return (DatabaseMap(entries: entries, chunkSize: chunkSize), compactShards)
    }
}
