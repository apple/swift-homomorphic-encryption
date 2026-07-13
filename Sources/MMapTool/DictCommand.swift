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

import ApplicationProtobuf
import ArgumentParser
import Foundation
import MemoryMapping

extension Data {
    /// stream Data to file in chunks.
    /// - Parameters:
    ///   - url: File URL to write to
    ///   - chunkSize: Size of each chunk in bytes (default 1 MiB)
    /// - Throws: Any errors during file writing
    func stream(to url: URL, chunkSize: Int = 1024 * 1024) throws {
        // Create/overwrite the file
        FileManager.default.createFile(atPath: url.path, contents: nil, attributes: nil)

        guard let fileHandle = try? FileHandle(forWritingTo: url) else {
            preconditionFailure("Cannot open file handle")
        }

        defer { try? fileHandle.close() }

        var offset = 0
        while offset < count {
            let end = Swift.min(offset + chunkSize, count)
            let slice = self[offset..<end]
            try fileHandle.write(contentsOf: slice)
            offset = end
        }
    }
}

extension [UInt8] {
    var printable: String {
        if let keyString = String(bytes: self, encoding: .utf8) {
            keyString
        } else {
            "<converted to hex> \(hexString)"
        }
    }
}

extension Data {
    var printable: String {
        if let keyString = String(bytes: self, encoding: .utf8) {
            keyString
        } else {
            "<converted to hex> \(Array(self).hexString)"
        }
    }
}

struct DictCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "dict",
        abstract: "Memory-mapped dictionary operations",
        subcommands: [
            CreateCommand.self,
            CreateFromCommand.self,
            InfoCommand.self,
            LookupCommand.self,
            KeysCommand.self,
        ])
}

// MARK: - Create Command

extension DictCommand {
    struct CreateCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "create",
            abstract: "Create a new memory-mapped dictionary from key-value pairs")

        @Argument(help: "Path to the output .bin file")
        var output: String

        @Option(help: "Load factor (0.0 to 1.0)")
        var loadFactor: Double = MMapDictionary.defaultLoadFactor

        @Flag(help: "Read key-value pairs from stdin (format: key=value, one per line)")
        var stdin: Bool = false

        @Argument(help: "Key-value pairs in format key=value")
        var pairs: [String] = []

        func run() throws {
            var builder = MMapDictionary.Builder()

            if stdin {
                // Read from stdin
                while let line = readLine() {
                    try parsePair(line, into: &builder)
                }
            } else if pairs.isEmpty {
                throw ValidationError("No key-value pairs provided. Use --stdin or provide pairs as arguments.")
            } else {
                // Read from arguments
                for pair in pairs {
                    try parsePair(pair, into: &builder)
                }
            }

            try builder.write(to: output, loadFactor: loadFactor)
            print("Created dictionary at: \(output)")
        }

        private func parsePair(_ pair: String, into builder: inout MMapDictionary.Builder) throws {
            // Split the string by the first '='.
            // maxSplits: 1 ensures it only splits at the first '='.
            // omittingEmptySubsequences: false is crucial to handle cases like "key=" correctly,
            // where the value part is an empty string.
            let components = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)

            // Validate that we got exactly two components (key and value).
            // This handles cases like "keyvalue" (no '=') or malformed strings.
            guard components.count == 2 else {
                throw ValidationError("Invalid format '\(pair)'. Expected key=value")
            }

            let key = String(components[0])
            let valueString = String(components[1])
            builder.insert(key: key, value: Array(valueString.utf8))
        }
    }
}

// MARK: - Create From Command

extension DictCommand {
    struct CreateFromCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "create-from",
            abstract: "Create from a keyword database")

        @Argument(help: "Path to the keyword database protobuf file")
        var databasePath: String

        @Option(help: "Output path (default: input file with .bin extension)")
        var output: String?

        @Option(help: "Load factor (0.0 to 1.0)")
        var loadFactor: Double = MMapDictionary.defaultLoadFactor

        func run() throws {
            let url = URL(fileURLWithPath: databasePath)
            let protobuf = try Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase(from: databasePath)

            let destination: URL = if let output {
                URL(fileURLWithPath: output)
            } else {
                url.deletingPathExtension().appendingPathExtension("bin")
            }

            var builder = MMapDictionary.Builder()
            for row in protobuf.rows {
                builder.insert(key: row.keyword.bytes, value: row.value.bytes)
            }
            let data = try builder.build(loadFactor: loadFactor)
            try data.stream(to: destination)
            try validateMMapDictionary(path: destination.path(), protobuf: protobuf)
            print("Successfully converted \(databasePath) to \(destination.path())")
        }

        private func validateMMapDictionary(
            path: String,
            protobuf: Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase) throws
        {
            let mmapDictionary = try MMapDictionary(path: path)
            for row in protobuf.rows {
                let value = row.value
                let validateValue: (RawSpan) throws -> Void = { span in
                    // Compare without copying: check length first, then compare bytes
                    guard span.byteCount == value.count else {
                        throw ValidationError(
                            "MMapped dictionary has different length for key \(row.keyword.printable)")
                    }

                    // Use withUnsafeBytes for zero-copy comparison
                    let isMatch = value.withUnsafeBytes { valueBytes in
                        span.withUnsafeBytes { spanBytes in
                            if value.isEmpty, span.isEmpty {
                                return true
                            }
                            // swiftlint:disable:next force_unwrapping
                            return memcmp(valueBytes.baseAddress!, spanBytes.baseAddress!, span.byteCount) == 0
                        }
                    }

                    guard isMatch else {
                        throw ValidationError(
                            "MMapped dictionary has different values for key \(row.keyword.printable)")
                    }
                }

                guard try mmapDictionary.withValue(forKey: row.keyword.bytes, validateValue) != nil else {
                    throw ValidationError("Value not found for key \(row.keyword.printable)")
                }
            }
        }
    }
}

// MARK: - Info Command

extension DictCommand {
    struct InfoCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "info",
            abstract: "Display information about a memory-mapped dictionary")

        @Argument(help: "Path to the .bin file")
        var path: String

        func run() throws {
            let dict = try MMapDictionary(path: path)
            let count = try dict.count()
            let buckets = dict.bucketCount
            let longestRun = try dict.longestProbeRun()
            let loadFactor = Double(count) / Double(buckets)

            // Get size breakdown from the dictionary
            let fileSize = dict.fileSize
            let bucketsSize = dict.bucketsSize
            let keysAndValuesSize = dict.keysAndValuesSize

            // Create formatter for byte counts
            let formatter = ByteCountFormatter()
            formatter.allowedUnits = [.useAll]
            formatter.countStyle = .file

            let bucketsPercent = String(format: "%.2f%%", Double(bucketsSize) / Double(fileSize) * 100)
            let keysValuesPercent = String(
                format: "%.2f%%",
                Double(keysAndValuesSize) / Double(fileSize) * 100)

            print("""
                Dictionary Info:
                  Path: \(path)
                  Entries: \(count)
                  Buckets: \(buckets)
                  Load Factor: \(String(format: "%.2f%%", loadFactor * 100))
                  Longest Probe Run: \(longestRun)

                Size Breakdown:
                  Total File Size: \(formatter.string(fromByteCount: Int64(fileSize))) (\(fileSize) bytes)
                  Header Size: \(formatter.string(fromByteCount: Int64(MMapDictionary.headerSize))) \
                (\(MMapDictionary.headerSize) bytes)
                  Buckets Size: \(formatter.string(fromByteCount: Int64(bucketsSize))) (\(bucketsPercent))
                  Keys & Values Size: \(formatter.string(fromByteCount: Int64(keysAndValuesSize))) \
                (\(keysValuesPercent))
                """)
        }
    }
}

// MARK: - Lookup Command

extension DictCommand {
    struct LookupCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "lookup",
            abstract: "Lookup values for specific keys in a memory-mapped dictionary")

        @Argument(help: "Path to the .bin file")
        var path: String

        @Argument(help: "Keys to look up")
        var keys: [String]

        @Flag(help: "Display values as hex instead of UTF-8")
        var hex: Bool = false

        func run() throws {
            let dict = try MMapDictionary(path: path)

            for key in keys {
                if let value = try dict[key] {
                    if hex {
                        print("\(key): \(value.hexString)")
                    } else {
                        print("\(key): \(value.printable)")
                    }
                } else {
                    print("\(key): <not found>")
                }
            }
        }
    }
}

// MARK: - Keys Command

extension DictCommand {
    struct KeysCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "keys",
            abstract: "Print keys in a memory-mapped dictionary")

        @Argument(help: "Path to the .bin file")
        var path: String

        @Option(help: "Maximum number of keys to print")
        var count: Int?

        func run() throws {
            let dict = try MMapDictionary(path: path)
            let keys = try dict.keys(count: count)

            for key in keys {
                print(key.printable)
            }

            if let count, keys.count > count {
                print("... and \(keys.count - count) more keys")
            }
        }
    }
}
