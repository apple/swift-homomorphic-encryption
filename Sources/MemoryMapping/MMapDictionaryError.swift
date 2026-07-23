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

public import Foundation

/// Errors that can occur when working with memory-mapped dictionaries
public enum MMapDictionaryError: Error {
    case corruptedData(String)
    case invalidFormat(String)
    case invalidLoadFactor(String)
    case tooManyCollisions(String)
}

extension MMapDictionaryError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .corruptedData(message):
            "Corrupted data: \(message)"
        case let .invalidFormat(message):
            "Invalid format: \(message)"
        case let .invalidLoadFactor(message):
            "Invalid load factor: \(message)"
        case let .tooManyCollisions(message):
            "Too many collisions: \(message)"
        }
    }
}

extension MMapDictionaryError: CustomStringConvertible {
    public var description: String {
        switch self {
        case let .corruptedData(message):
            "MMapDictionaryError.corruptedData: \(message)"
        case let .invalidFormat(message):
            "MMapDictionaryError.invalidFormat: \(message)"
        case let .invalidLoadFactor(message):
            "MMapDictionaryError.invalidLoadFactor: \(message)"
        case let .tooManyCollisions(message):
            "MMapDictionaryError.tooManyCollisions: \(message)"
        }
    }
}
