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

import ArgumentParser
import PrivateInformationRetrieval
import PrivateInformationRetrievalProtobuf

extension KeywordDatabaseShard {
    func save(to path: String) throws {
        try rows.proto().save(to: path)
    }
}

enum ShardingOption: String, CaseIterable, ExpressibleByArgument {
    case entryCountPerShard
    case shardCount
}

struct ShardingArguments: ParsableArguments {
    @Option var sharding: ShardingOption
    @Option(help: "A positive integer")
    var shardingCount: Int
}

extension Sharding {
    init?(from arguments: ShardingArguments) {
        switch arguments.sharding {
        case .entryCountPerShard:
            self.init(entryCountPerShard: arguments.shardingCount)
        case .shardCount:
            self.init(shardCount: arguments.shardingCount)
        }
    }
}

extension String {
    func validateProtoFilename(descriptor: String) throws {
        guard hasSuffix(".txtpb") || hasSuffix(".binpb") else {
            throw ValidationError("'\(descriptor)' must contain have extension '.txtpb' or '.binpb', found \(self)")
        }
    }
}

let discussion =
    """
    This executable allows one to divide a database into disjoint shards. \
    Each resulting shard is suitable for processing with the `PIRProcessDatabase` executable.
    """

@main
struct ProcessCommand: ParsableCommand {
    static let configuration: CommandConfiguration = .init(
        commandName: "PIRShardDatabase", discussion: discussion)

    @Option(help: "path to input PIR database file. Must have extension '.txtpb' or '.binpb'")
    var inputDatabase: String

    @Option(help: "path to output PIR database file. Must contain 'SHARD_ID' and have extension '.txtpb' or '.binpb'")
    var outputDatabase: String

    @OptionGroup var sharding: ShardingArguments

    func validate() throws {
        try inputDatabase.validateProtoFilename(descriptor: "inputDatabase")
        try outputDatabase.validateProtoFilename(descriptor: "outputDatabase")
        guard outputDatabase.contains("SHARD_ID") else {
            throw ValidationError("'outputDatabase' must contain 'SHARD_ID', found \(outputDatabase)")
        }
        guard Sharding(from: sharding) != nil else {
            throw ValidationError("Invalid sharding \(sharding)")
        }
    }

    mutating func run() throws {
        guard let sharding = Sharding(from: sharding) else {
            throw ValidationError("Invalid sharding \(sharding)")
        }
        let database: [KeywordValuePair] =
            try Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase(from: inputDatabase).native()
        let sharded = try KeywordDatabase(rows: database, sharding: sharding)
        for (shardID, shard) in sharded.shards {
            let outputDatabaseFilename = outputDatabase.replacingOccurrences(
                of: "SHARD_ID",
                with: String(shardID))
            if !shard.isEmpty {
                try shard.save(to: outputDatabaseFilename)
            }
        }
    }
}
