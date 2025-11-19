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

import Foundation
public import SwiftProtobuf

extension Message {
    /// Initializes a `Message` from a file.
    ///
    /// The serialized message should be in protocol buffer text format or binary format.
    /// - Parameter path: Filepath with a serialized message. If the message is in text format, `path` should have
    /// `.txtpb` extension.
    /// - Throws: Error upon failure to initialize message.
    public init(from path: String) throws {
        if path.hasSuffix(".txtpb") {
            try self.init(textFormatString: String(contentsOfFile: path, encoding: .utf8))
        } else {
            let serializedData = try Data(contentsOf: URL(fileURLWithPath: path))
            try self.init(serializedBytes: serializedData)
        }
    }

    /// Saves a `Message` to a file.
    ///
    /// - Parameter path: Filepath to save the serialized message. The message will be serialized with protocol buffer
    /// text format if the path has `.txtpb` extension, and protocol buffer binary format otherwise.
    /// - Throws: Error upon failure to save the message.
    public func save(to path: String) throws {
        if path.hasSuffix(".txtpb") {
            let textFormat = textFormatString()
            try textFormat.write(toFile: path, atomically: true, encoding: .utf8)
        } else {
            let data = try serializedData()
            try data.write(to: URL(fileURLWithPath: path))
        }
    }
}
