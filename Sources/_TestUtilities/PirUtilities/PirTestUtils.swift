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

public import HomomorphicEncryption
public import PrivateInformationRetrieval

/// Testing utilities for PrivateInformationRetrieval.
public enum PirTestUtils {
    /// Creates test parameters.
    public static func getTestParameter<Pir: IndexPirProtocol>(
        pir _: Pir.Type,
        with context: Pir.Scheme.Context,
        entryCount: Int,
        entrySizeInBytes: Int,
        keyCompression: PirKeyCompressionStrategy,
        batchSize: Int = 10,
        encodingEntrySize: Bool = false) throws -> IndexPirParameter
    {
        let config = try IndexPirConfig(
            entryCount: entryCount,
            entrySizeInBytes: entrySizeInBytes,
            dimensionCount: 2,
            batchSize: batchSize,
            unevenDimensions: true,
            keyCompression: keyCompression,
            encodingEntrySize: encodingEntrySize)
        return Pir.generateParameter(config: config, with: context)
    }

    /// Generates a database of random entries
    /// - Parameters:
    ///   - entryCount: Number of entries in the database.
    ///   - entrySizeInBytes: Byte size of each entry.
    /// - Returns: An array of entries in the database.
    public static func randomIndexPirDatabase(entryCount: Int, entrySizeInBytes: Int) -> [[UInt8]] {
        (0..<entryCount).map { _ in (0..<entrySizeInBytes)
            .map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
        }
    }

    /// Generates a database of random entries
    /// - Parameters:
    ///   - entryCount: Number of entries in the database.
    ///   - entrySizeInBytes: Range of possible byte sizes of each entry.
    /// - Returns: An array of entries in the database.
    public static func randomIndexPirDatabase(entryCount: Int, entrySizeInBytes: ClosedRange<Int>) -> [[UInt8]] {
        (0..<entryCount).map { _ in
            let entrySize = Int.random(in: entrySizeInBytes)
            return (0..<entrySize).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
        }
    }

    ///  Generates a random KeywordPir database.
    /// - Parameters:
    ///   - rowCount: Number of rows in the database.
    ///   - valueSize: Number of values in the database.
    /// - Returns: A list of keyword-value pairs in the database.
    public static func randomKeywordPirDatabase(rowCount: Int, valueSize: Int) -> [KeywordValuePair] {
        var rng = SystemRandomNumberGenerator()
        return randomKeywordPirDatabase(rowCount: rowCount, valueSize: valueSize, using: &rng)
    }

    ///  Generates a random KeywordPir database.
    /// - Parameters:
    ///   - rowCount: Number of rows in the database.
    ///   - valueSize: Number of values in the database.
    /// - Returns: A list of keyword-value pairs in the database.
    public static func randomKeywordPirDatabase(
        rowCount: Int,
        valueSize: Int,
        using rng: inout some PseudoRandomNumberGenerator,
        keywordSize: Int = 30) -> [KeywordValuePair]
    {
        precondition(rowCount > 0)
        var keywords: Set<KeywordValuePair.Keyword> = []
        var rows: [KeywordValuePair] = []
        rows.reserveCapacity(rowCount)
        repeat {
            let keyword = Self.generateRandomBytes(size: keywordSize, using: &rng)
            if keywords.contains(keyword) {
                continue
            }
            keywords.insert(keyword)
            let value = Self.generateRandomBytes(size: valueSize, using: &rng)
            rows.append(KeywordValuePair(keyword: keyword, value: value))
        } while rows.count < rowCount
        return rows
    }

    @inlinable
    package static func generateRandomBytes(size: Int) -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        return generateRandomBytes(size: size, using: &rng)
    }

    @inlinable
    static func generateRandomBytes(size: Int, using rng: inout some PseudoRandomNumberGenerator) -> [UInt8] {
        var data = [UInt8](repeating: 0, count: size)
        rng.fill(&data)
        return data
    }

    /// Generates a cuckoo table configuration for testing
    /// - Parameter maxSerializedBucketSize: maximum serialized bucket size.
    /// - Throws: Error upon failure to create a cuckoo table configuration.
    /// - Returns: The cuckoo table configuration.
    @inlinable
    public static func testCuckooTableConfig(maxSerializedBucketSize: Int) throws -> CuckooTableConfig {
        let defaultConfig: CuckooTableConfig = .defaultKeywordPir(
            maxSerializedBucketSize: maxSerializedBucketSize)
        return try CuckooTableConfig(
            hashFunctionCount: defaultConfig.hashFunctionCount,
            maxEvictionCount: defaultConfig.maxEvictionCount,
            maxSerializedBucketSize: defaultConfig.maxSerializedBucketSize,
            bucketCount: defaultConfig.bucketCount)
    }
}

extension Response {
    /// Whether or not all the ciphertexts are transparent.
    @inlinable
    public func isTransparent() -> Bool {
        ciphertexts.flatMap(\.self).allSatisfy
            { ciphertext in ciphertext.isTransparent() }
    }
}
