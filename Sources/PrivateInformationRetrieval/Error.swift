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

import Foundation

/// PIR error type.
public enum PirError: Error, Hashable, Codable {
    case corruptedData(_ description: String)
    case emptyDatabase
    case failedToConstructCuckooTable(_ description: String)
    case invalidBatchSize(queryCount: Int, databaseCount: Int)
    case invalidCuckooConfig(config: CuckooTableConfig)
    case invalidDatabaseDuplicateKeyword(keyword: KeywordValuePair.Keyword,
                                         oldValue: KeywordValuePair.Value,
                                         newValue: KeywordValuePair.Value)
    case invalidDatabaseEntryCount(entryCount: Int, expected: Int)
    case invalidDatabaseEntrySize(maximumEntrySize: Int, expected: Int)
    case invalidDatabasePlaintextCount(plaintextCount: Int, expected: Int)
    case invalidDatabaseSerializationPlaintextTag(tag: UInt8)
    case invalidDatabaseSerializationVersion(serializationVersion: Int, expected: Int)
    case invalidDimensionCount(dimensionCount: Int, expected: [Int])
    case invalidHashBucketEntryValueSize(maxSize: Int)
    case invalidHashBucketSlotCount(maxCount: Int)
    case invalidIndex(index: Int, numberOfEntries: Int)
    case invalidPirAlgorithm(_ pirAlgorithm: PirAlgorithm)
    case invalidReply(ciphertextCount: Int, expected: Int)
    case invalidResponse(replyCount: Int, expected: Int)
    case invalidSharding(_ description: String)
    case validationError(_ description: String)
}

extension PirError {
    @inlinable
    static func invalidSharding(_ sharding: Sharding,
                                message: String? = nil) -> Self
    {
        let message = message.map { " \($0)" } ?? ""
        return .invalidSharding("Invalid sharding: \(sharding) \(message)")
    }
}

extension PirError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .corruptedData(description):
            "Data is corrupted \(description)"
        case .emptyDatabase:
            "Empty database"
        case let .failedToConstructCuckooTable(description):
            "Failed to construct Cuckoo table: \(description)"
        case let .invalidBatchSize(queryCount, databaseCount):
            """
            Mismatching batch size: getting \(queryCount) queries for \(databaseCount) tables. \
            Query count shouldn't exceed table count.
            """
        case let .invalidCuckooConfig(config):
            "Cuckoo table config is invalid \(config)"
        case let .invalidDatabaseEntryCount(entryCount, expected):
            "Invalid database: Database has \(entryCount) entries, expected \(expected)"
        case let .invalidDatabaseEntrySize(maximumEntrySize, expected):
            """
            Invalid database: Database has entry with size \(maximumEntrySize) plaintexts, \
            expected all entry sizes to be <= \(expected)
            """
        case let .invalidDatabaseDuplicateKeyword(keyword, oldValue, newValue):
            """
            Invalid database: Duplicate values \(oldValue), \(newValue) \
            for keyword \(keyword)
            """
        case let .invalidDatabasePlaintextCount(plaintextCount, expected):
            "Invalid database: Database has \(plaintextCount) plaintexts, expected \(expected)"
        case let .invalidDatabaseSerializationPlaintextTag(tag):
            "Invalid database serialization plaintext tag: \(tag)"
        case let .invalidDatabaseSerializationVersion(serializationVersion, expected):
            "Invalid database: Invalid serialization version number \(serializationVersion), expected \(expected)"
        case let .invalidDimensionCount(dimensionCount, expected):
            """
            Invalid database dimension count: Dimension count is set to \
            \(dimensionCount) should be in \(expected)
            """
        case let .invalidHashBucketEntryValueSize(maxSize):
            "Invalid hash bucket entry value size; maximum is \(maxSize)"
        case let .invalidHashBucketSlotCount(maxCount):
            "Invalid hash bucket slot count; maximum is \(maxCount)"
        case let .invalidIndex(index, numberOfEntries):
            "Index \(index) should between 0 and \(numberOfEntries)"
        case let .invalidPirAlgorithm(pirAlgorithm):
            "Invalid PIR algorithm: \(pirAlgorithm)"
        case let .invalidReply(ciphertextCount, expected):
            "Reply has \(ciphertextCount) ciphertexts, expected \(expected)"
        case let .invalidResponse(replyCount, expected):
            "Response has \(replyCount) replies, expected \(expected)"
        case let .invalidSharding(description):
            "Invalid sharding \(description)"
        case let .validationError(description):
            "Validation error \(description)"
        }
    }
}
