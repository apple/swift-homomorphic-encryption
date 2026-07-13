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

public struct ShardMap: Sendable {
    /// From `originalIndex` to `EntryResult`.
    let mapping: [Int: DatabaseMap.Entry]
    let shardCount: Int
    let maximumChunkCount: Int
    let chunkSize: Int
    public let chunksPerShard: Int

    public init(databaseMap: DatabaseMap) {
        self.mapping = databaseMap.entries.reduce(into: [:]) { result, entry in
            result[entry.originalIndex] = entry
        }

        // compute shard count
        var shards: Set<Int> = []
        for value in mapping.values {
            shards.formUnion(value.chunks.map(\.shardIndex))
        }
        self.shardCount = shards.count
        self.maximumChunkCount = mapping.values.map(\.chunks.count).max() ?? 0
        self.chunkSize = databaseMap.chunkSize
        self.chunksPerShard = maximumChunkCount.dividingCeil(shardCount, variableTime: true)
    }

    subscript(_ originalIndex: Int) -> DatabaseMap.Entry? {
        mapping[originalIndex]
    }
}

public struct SimplePirClientForAllShards<Generator: QueryGenerator>: SimplePirProtocol {
    public typealias Scalar = Generator.Scalar
    public typealias Client = SimplePirClient<Generator>

    let shardMap: ShardMap
    var clients: [Client]
    public var queriesPerShard: Int {
        shardMap.chunksPerShard
    }

    public init(databaseMap: DatabaseMap, clients: [Client]) throws {
        let shardMap = ShardMap(databaseMap: databaseMap)
        try self.init(shardMap: shardMap, clients: clients)
    }

    public init(shardMap: ShardMap, clients: [Client]) throws {
        self.shardMap = shardMap
        self.clients = clients
        guard shardMap.shardCount == clients.count else {
            throw PirError.validationError(
                "Mismatching shard count \(shardMap.shardCount) and number of clients \(clients.count)")
        }
    }

    public func query(for index: Int) async throws -> [[PrecomputedQueries<Scalar>.WithQueryIndices]]? {
        // Build query indices for all shards
        var queryIndices: [[Int]] = Array(repeating: [], count: clients.count)

        // Add real queries first (if entry exists)
        if let entry = shardMap[index] {
            for chunk in entry.chunks {
                queryIndices[chunk.shardIndex].append(chunk.index)
            }
        }

        // Fill remaining slots with fake queries to index 0
        for shardIndex in 0..<clients.count {
            while queryIndices[shardIndex].count < shardMap.chunksPerShard {
                queryIndices[shardIndex].append(0)
            }
        }

        var queriesForAllShards: [[PrecomputedQueries<Scalar>.WithQueryIndices]] = []
        for shardIndex in 0..<clients.count {
            var queriesForThisShard = [PrecomputedQueries<Scalar>.WithQueryIndices]()
            let indicesToQuery = queryIndices[shardIndex]
            for queryIndex in indicesToQuery {
                try await queriesForThisShard.append(clients[shardIndex].query(at: queryIndex))
            }
            queriesForAllShards.append(queriesForThisShard)
        }
        return queriesForAllShards
    }

    public func decrypt(
        responses: [[Responses]],
        for index: Int,
        with queries: [[PrecomputedQueries<Scalar>.WithQueryIndices]]) async throws -> [UInt8]?
    {
        // Validate that responses and queries have matching structure
        guard responses.count == clients.count else {
            throw PirError.validationError(
                "Response count \(responses.count) does not match client count \(clients.count)")
        }
        guard queries.count == clients.count else {
            throw PirError.validationError(
                "Query count \(queries.count) does not match client count \(clients.count)")
        }

        var decryptedResults: [[[UInt8]]] = []
        for shardIndex in 0..<clients.count {
            guard responses[shardIndex].count == queries[shardIndex].count else {
                throw PirError.validationError(
                    """
                    Response count \(responses[shardIndex].count) for shard \(shardIndex) \
                    does not match query count \(queries[shardIndex].count)
                    """)
            }

            var shardResults: [[UInt8]] = []
            for queryIndex in 0..<queries[shardIndex].count {
                let queryUsed = queries[shardIndex][queryIndex]
                let preparedResponse = queryUsed.prepareResponse()
                let decrypted = try await clients[shardIndex].decrypt(
                    responses: responses[shardIndex][queryIndex],
                    with: preparedResponse,
                    at: queryUsed.index)
                shardResults.append(decrypted)
            }
            decryptedResults.append(shardResults)
        }

        let entry = shardMap[index]
        let chunks: [DatabaseMap.ChunkLocation] = if let entry {
            entry.chunks
        } else {
            []
        }

        var result = [UInt8]()
        for chunkIndex in 0..<shardMap.maximumChunkCount {
            let isRealChunk = chunkIndex < chunks.count

            // Always compute both paths
            let realChunk = isRealChunk ? chunks[chunkIndex] : DatabaseMap.ChunkLocation(shardIndex: 0, index: 0)
            let fakeShardIndex = 0
            let fakeIndex = 0

            // Select in constant-time using ternaries
            let shardIndex = isRealChunk ? realChunk.shardIndex : fakeShardIndex
            let targetIndex = isRealChunk ? realChunk.index : fakeIndex

            var searchIndex = 0
            for (idx, query) in queries[shardIndex].enumerated() {
                let matches = query.index == targetIndex
                searchIndex = matches ? idx : searchIndex
            }
            result += decryptedResults[shardIndex][searchIndex].prefix(shardMap.chunkSize)
        }

        // To ensure constant-time execution, we keep this check at the end of the function
        guard let entry else {
            return nil
        }
        return Array(result.prefix(entry.size))
    }
}

extension SimplePirClientForAllShards: CustomDebugStringConvertible {
    public var debugDescription: String {
        """
        Shard Map {
          entryCount: \(shardMap.mapping.count)
          shardCount: \(shardMap.shardCount)
          maximumChunks: \(shardMap.maximumChunkCount)
          chunkSize: \(shardMap.chunkSize)
          chunksPerShard: \(shardMap.chunksPerShard)
        }
        Client Count: \(clients.count)
        """
    }
}
