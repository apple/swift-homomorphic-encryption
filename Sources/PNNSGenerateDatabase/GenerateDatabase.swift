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

import ArgumentParser
import Foundation
import HomomorphicEncryption
import PrivateNearestNeighborSearch
import PrivateNearestNeighborSearchProtobuf

enum VectorTypeArguments: String, CaseIterable, ExpressibleByArgument {
    /// Each vector's entry is uniform random from `[-1.0, 1.0]`
    case random
    /// The vector of the i'th row is all 0s except a 1 at index `i % vectorDimension`.
    case unit
}

@main
struct GenerateDatabaseCommand: ParsableCommand {
    static let configuration: CommandConfiguration = .init(
        commandName: "PNNSGenerateDatabase", version: Version.current.description)

    @Option(help: "Path to output database. Must end in '.txtpb' or '.binpb'.")
    var outputDatabase: String

    @Option(help: "Number of rows in the database.")
    var rowCount: Int

    @Option(help: "Number of entries in each row's vector.")
    var vectorDimension: Int

    @Option(help: "Number of bytes of metadata for each row.")
    var metadataSize: Int

    @Option var vectorType: VectorTypeArguments

    mutating func run() throws {
        let rows: [DatabaseRow] = (0..<rowCount).map { rowIndex in
            var vector: [Float]
            switch vectorType {
            case .unit:
                vector = Array(repeating: Float(0), count: vectorDimension)
                vector[rowIndex % vectorDimension] = Float(1)
            case .random:
                vector = (0..<vectorDimension).map { _ in Float.random(in: -1.0...1.0) }
            }

            let rowString = String(rowIndex)
            let repeatCount = metadataSize.dividingCeil(rowString.count, variableTime: true)
            let metadata = Array([[UInt8]](repeating: Array(rowString.utf8), count: repeatCount).flatMap(\.self)
                .prefix(metadataSize))
            return DatabaseRow(
                entryId: UInt64(rowIndex),
                entryMetadata: metadata,
                vector: vector)
        }
        let database = Database(rows: rows)
        try database.proto().save(to: outputDatabase)
    }
}
