// Copyright 2024-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

import ApplicationProtobuf
public import ArgumentParser
import HomomorphicEncryption
import PrivateInformationRetrieval

extension KeywordDatabaseShard {
    func save(to path: String) throws {
        try rows.proto().save(to: path)
    }
}

enum ShardingOption: String, CaseIterable, ExpressibleByArgument {
    case entryCountPerShard
    case shardCount
}

enum ShardingFunctionOption: String, CaseIterable, ExpressibleByArgument {
    case doubleMod
    case sha256
}

struct ShardingArguments: ParsableArguments {
    @Option var sharding: ShardingOption
    @Option(help: "A positive integer")
    var shardingCount: Int

    @Option var shardingFunction: ShardingFunctionOption = .sha256

    @Option(help: "Shards in the other usecase")
    var otherShardCount: Int?
}

struct SymmetricPirArguments: ParsableArguments {
    @Option(
        help: """
            path to file containing key for encrypting server database as a
            hexadecimal key string, without leading '0x'.
            """)
    var databaseEncryptionKeyPath: String?
    @Option(help: """
        config type for symmetric pir; default is nil, unless --database-encryption-key-path \
        is specified, in which case the default is \
        \(SymmetricPirConfigType.OPRF_P384_AES_GCM_192_NONCE_96_TAG_128.rawValue)
        """)
    var symmetricPirConfigType: SymmetricPirConfigType?
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

extension ShardingFunction {
    init(from arguments: ShardingArguments) throws {
        switch arguments.shardingFunction {
        case .doubleMod:
            guard let otherShardCount = arguments.otherShardCount else {
                throw ValidationError("Must specify 'otherShardCount' when using 'doubleMod' sharding function.")
            }
            self = .doubleMod(otherShardCount: otherShardCount)
        case .sha256:
            self = .sha256
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

extension SymmetricPirConfigType: ExpressibleByArgument {}

let discussion =
    """
    This executable allows one to divide a database into disjoint shards. \
    Each resulting shard is suitable for processing with the `PIRProcessDatabase` executable.
    """

@main
struct ProcessCommand: ParsableCommand {
    static let configuration: CommandConfiguration = .init(
        commandName: "PIRShardDatabase", discussion: discussion, version: Version.current.description)

    @Option(help: "path to input PIR database file. Must have extension '.txtpb' or '.binpb'")
    var inputDatabase: String

    @Option(help: "path to output PIR database file. Must contain 'SHARD_ID' and have extension '.txtpb' or '.binpb'")
    var outputDatabase: String

    @OptionGroup var sharding: ShardingArguments
    @OptionGroup var symmetricPirArguments: SymmetricPirArguments

    func validate() throws {
        try inputDatabase.validateProtoFilename(descriptor: "inputDatabase")
        try outputDatabase.validateProtoFilename(descriptor: "outputDatabase")
        guard outputDatabase.contains("SHARD_ID") else {
            throw ValidationError("'outputDatabase' must contain 'SHARD_ID', found \(outputDatabase)")
        }
        guard Sharding(from: sharding) != nil else {
            throw ValidationError("Invalid sharding \(sharding)")
        }
        if symmetricPirArguments.symmetricPirConfigType != nil {
            guard symmetricPirArguments.databaseEncryptionKeyPath != nil else {
                throw ValidationError("Missing databaseEncryptionKeyPath.")
            }
        }
    }

    mutating func run() throws {
        guard let sharding = Sharding(from: sharding) else {
            throw ValidationError("Invalid sharding \(sharding)")
        }
        let shardingFunction = try ShardingFunction(from: self.sharding)
        let database: [KeywordValuePair] =
            try Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase(from: inputDatabase).native()
        let symmetricPirConfig = try symmetricPirArguments.databaseEncryptionKeyPath.map { filePath in
            let configType = symmetricPirArguments.symmetricPirConfigType ?? .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128
            do {
                let secretKeyString = try String(contentsOfFile: filePath, encoding: .utf8)
                guard let secretKey = Array(hexEncoded: secretKeyString) else {
                    throw PirError.invalidOPRFHexSecretKey
                }
                try configType.validateEncryptionKey(secretKey)
                return try SymmetricPirConfig(oprfSecretKey: Secret(value: secretKey), configType: configType)
            } catch {
                throw PirError.failedToLoadOPRFKey(underlyingError: "\(error)", filePath: filePath)
            }
        }
        let sharded = try KeywordDatabase(rows: database,
                                          sharding: sharding,
                                          shardingFunction: shardingFunction,
                                          symmetricPirConfig: symmetricPirConfig)
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
