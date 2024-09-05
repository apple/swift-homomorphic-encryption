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
    case invalidScheme
    case unimplementedScheme(scheme: String)
    case unrecognizedEnumValue(enum: any Enum.Type, value: Int)
    case unsetOneof(oneof: any Message.Type, field: String)
}

extension ConversionError {
    static func unsetOneof(oneof: any Message.Type, field: AnyKeyPath) -> Self {
        .unsetOneof(oneof: oneof, field: String(reflecting: field))
    }
}

extension ConversionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidScheme:
            "Invalid HE scheme"
        case let .unimplementedScheme(scheme: scheme):
            "Unimplemented encryption scheme: \(scheme)"
        case let .unrecognizedEnumValue(enum: enumeration, value: value):
            "Unrecognized value \(value) in enum \(enumeration)"
        case let .unsetOneof(oneof: oneof, field: field):
            "Unset oneof in message \(oneof) for field \(field)"
        }
    }
}
