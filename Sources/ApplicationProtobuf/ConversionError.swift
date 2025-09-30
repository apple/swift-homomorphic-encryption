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
import SwiftProtobuf

/// Error type when converting between protobuf and native objects.
public enum ConversionError: Error {
    case unrecognizedEnumValue(enum: any Enum.Type, value: Int)
    case unsetField(field: String, message: any Message.Type)
    case unsetOneof(oneof: any Message.Type, field: String)
    case unspecifiedEnumValue(enum: any Enum.Type)
}

extension ConversionError {
    static func unsetOneof(oneof: any Message.Type, field: AnyKeyPath) -> Self {
        .unsetOneof(oneof: oneof, field: String(reflecting: field))
    }

    static func unsetField(_ field: AnyKeyPath, in message: any Message.Type) -> Self {
        .unsetField(field: String(reflecting: field), message: message)
    }
}

extension ConversionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .unrecognizedEnumValue(enum: enumeration, value):
            "Unrecognized value \(value) in enum \(enumeration)"
        case let .unsetField(field, message):
            "Unset field \(field) in message \(message)"
        case let .unsetOneof(oneof, field):
            "Unset oneof in message \(oneof) for field \(field)"
        case let .unspecifiedEnumValue(enum: enumeration):
            "Unspecified value for enum \(enumeration)"
        }
    }
}
