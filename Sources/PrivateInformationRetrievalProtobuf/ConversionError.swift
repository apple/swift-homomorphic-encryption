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

enum ConversionError: Error {
    case unrecognizedEnumValue(enum: any Enum.Type, value: Int)
    case unspecifiedEnumValue(enum: any Enum.Type)
}

extension ConversionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .unrecognizedEnumValue(enum: enume, value: value):
            "Unrecognized value \(value) in enum \(enume)"
        case let .unspecifiedEnumValue(enum: enume):
            "Unspecified value for enum \(enume)"
        }
    }
}
