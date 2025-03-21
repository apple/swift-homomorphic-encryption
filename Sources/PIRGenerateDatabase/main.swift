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
import PrivateInformationRetrieval
import PrivateInformationRetrievalProtobuf

enum ValueTypeArguments: String, CaseIterable, ExpressibleByArgument {
    case random
    /// Repeats the keyword
    case repeated
}

// This executable is used in tests, which breaks `swift test -c release` when used with `@main`.
// So we avoid using `@main` here.
struct ValueSizeArguments: ExpressibleByArgument {
    let range: Range<Int>

    init?(argument: String) {
        let parsedOpen = argument.split(separator: "..<")
        if parsedOpen.count == 2, let lower = Int(parsedOpen[0]), let upper = Int(parsedOpen[1]), lower < upper,
           lower > 0, upper > 0
        {
            self.range = lower..<upper
        } else {
            let parsedClosed = argument.split(separator: "...")
            if parsedClosed.count == 2, let lower = Int(parsedClosed[0]), let upper = Int(parsedClosed[1]),
               lower <= upper, lower > 0, upper > 0
            {
                self.range = lower..<(upper + 1)
            } else if parsedClosed.count == 1, let size = Int(parsedClosed[0]), size > 0 {
                self.range = size..<(size + 1)
            } else {
                return nil
            }
        }
    }
}

extension [UInt8] {
    @inlinable
    init(randomByteCount: Int) {
        self = .init(repeating: 0, count: randomByteCount)
        var rng = SystemRandomNumberGenerator()
        rng.fill(&self)
    }
}

struct GenerateDatabaseCommand: ParsableCommand {
    static let configuration: CommandConfiguration = .init(
        commandName: "PIRGenerateDatabase", version: Version.current.description)

    @Option(help: "Path to output database. Must end in '.txtpb' or '.binpb'")
    var outputDatabase: String

    @Option(help: "Number of rows in the database")
    var rowCount: Int

    @Option(help: "Number of bytes in each row. Must be of the form 'x', 'x..<y', or 'x...y'")
    var valueSize: ValueSizeArguments

    @Option var valueType: ValueTypeArguments

    @Option(help: "The first keyword")
    var firstKeyword: Int = 0

    mutating func run() throws {
        let databaseRows = (0..<rowCount)
            .map { rowIndex in
                let keyword = [UInt8](String(firstKeyword + rowIndex).utf8)
                guard let valueSize = valueSize.range.randomElement() else {
                    preconditionFailure("Could not sample valueSize from range \(valueSize.range)")
                }

                let value: [UInt8]
                switch valueType {
                case .random:
                    value = [UInt8](randomByteCount: valueSize)
                case .repeated:
                    let repeatCount = valueSize.dividingCeil(keyword.count, variableTime: true)
                    value = Array([[UInt8]](repeating: keyword, count: repeatCount).flatMap { $0 }.prefix(valueSize))
                }
                return KeywordValuePair(keyword: keyword, value: value)
            }
        try databaseRows.proto().save(to: outputDatabase)
    }
}

GenerateDatabaseCommand.main()
