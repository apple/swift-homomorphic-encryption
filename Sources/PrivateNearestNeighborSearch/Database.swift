// Copyright 2024-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

/// One row in a nearest-neighbor search database.
public struct DatabaseRow: Codable, Equatable, Hashable, Sendable {
    /// Unique identifier for the database entry.
    public let entryId: UInt64

    /// Metadata associated with the entry.
    public let entryMetadata: [UInt8]

    /// Vector for use in nearest neighbor search.
    public let vector: [Float]

    /// Creates a new ``DatabaseRow``.
    /// - Parameters:
    ///   - entryId: Unique identifier for the database entry.
    ///   - entryMetadata: Metadata associated with the entry.
    ///   - vector: Vector for use in nearest neighbor search.
    public init(entryId: UInt64, entryMetadata: [UInt8], vector: [Float]) {
        self.entryId = entryId
        self.entryMetadata = entryMetadata
        self.vector = vector
    }
}

/// Database for nearest neighbor search.
public struct Database: Codable, Equatable, Hashable, Sendable {
    /// Rows in the database.
    public let rows: [DatabaseRow]

    /// Creates a new ``Database``.
    /// - Parameter rows: Rows in the database.
    public init(rows: [DatabaseRow]) {
        self.rows = rows
    }
}

/// Compact quantized database for use with ``FastPlaintextEncoder``.
///
/// Stores only the quantized integer vectors, entry IDs, and metadata — no HE encoding.
/// Suitable for ORAM storage where the full ``ProcessedDatabase`` (~27MB) is too large
/// and the ``FastPlaintextEncoder`` reconstructs the ``PlaintextMatrix`` on the fly.
public struct QuantizedDatabase<Scheme: HeScheme>: Sendable {
    /// Quantized integer vectors in row-major order (one row per database entry).
    public let signedValues: [Scheme.SignedScalar]

    /// Number of rows (database entries).
    public let rowCount: Int

    /// Number of columns (vector dimension).
    public let vectorDimension: Int

    /// Unique identifier for each database entry.
    public let entryIds: [UInt64]

    /// Metadata associated with each database entry.
    public let entryMetadatas: [[UInt8]]

    /// Size in bytes of the quantized data (vectors only, excluding IDs/metadata).
    public var vectorDataByteCount: Int {
        signedValues.count * MemoryLayout<Scheme.SignedScalar>.size
    }

    /// Creates a ``QuantizedDatabase`` by quantizing a ``Database``.
    ///
    /// Applies normalization (for cosine) or raw scaling (for dotProduct),
    /// then rounds to integers — the same quantization as ``Database/process(config:contexts:)``.
    ///
    /// - Parameters:
    ///   - database: The source database.
    ///   - config: Server configuration (determines scaling factor and distance metric).
    /// - Returns: The quantized database.
    public init(database: Database, config: ServerConfig<Scheme>) {
        let vectors = Array2d(data: database.rows.map { row in row.vector })
        let roundedVectors: Array2d<Scheme.SignedScalar> = switch config.distanceMetric {
        case .cosineSimilarity:
            vectors.normalizedScaledAndRounded(
                scalingFactor: Float(config.scalingFactor))
        case .dotProduct:
            vectors.scaled(by: Float(config.scalingFactor)).rounded()
        }

        self.signedValues = roundedVectors.data
        self.rowCount = database.rows.count
        self.vectorDimension = config.vectorDimension
        self.entryIds = database.rows.map(\.entryId)
        let hasMetadata = database.rows.contains { !$0.entryMetadata.isEmpty }
        self.entryMetadatas = hasMetadata ? database.rows.map(\.entryMetadata) : []
    }

    /// Creates a ``QuantizedDatabase`` from pre-quantized values.
    public init(
        signedValues: [Scheme.SignedScalar],
        rowCount: Int,
        vectorDimension: Int,
        entryIds: [UInt64],
        entryMetadatas: [[UInt8]] = [])
    {
        precondition(signedValues.count == rowCount * vectorDimension)
        precondition(entryIds.count == rowCount)
        self.signedValues = signedValues
        self.rowCount = rowCount
        self.vectorDimension = vectorDimension
        self.entryIds = entryIds
        self.entryMetadatas = entryMetadatas
    }

    /// Deserializes quantized vectors from a byte buffer.
    ///
    /// - Parameters:
    ///   - bytes: Raw bytes from ``serializeVectors()``.
    ///   - rowCount: Number of vectors.
    ///   - vectorDimension: Dimension of each vector.
    ///   - entryIds: Entry identifiers.
    ///   - entryMetadatas: Entry metadata.
    /// - Returns: The deserialized quantized database.
    public static func deserializeVectors(
        from bytes: [UInt8],
        rowCount: Int,
        vectorDimension: Int,
        entryIds: [UInt64],
        entryMetadatas: [[UInt8]] = []) -> QuantizedDatabase
    {
        let values: [Scheme.SignedScalar] = bytes.withUnsafeBufferPointer { buffer in
            buffer.withMemoryRebound(to: Scheme.SignedScalar.self) { signedBuffer in
                Array(signedBuffer)
            }
        }
        return QuantizedDatabase(
            signedValues: values,
            rowCount: rowCount,
            vectorDimension: vectorDimension,
            entryIds: entryIds,
            entryMetadatas: entryMetadatas)
    }

    /// Serializes the quantized vectors to a compact byte buffer.
    ///
    /// Format: raw little-endian signed integers, row-major.
    /// Use ``deserializeVectors(from:rowCount:vectorDimension:)`` to read back.
    public func serializeVectors() -> [UInt8] {
        signedValues.withUnsafeBufferPointer { buffer in
            buffer.withMemoryRebound(to: UInt8.self) { bytes in
                Array(bytes)
            }
        }
    }
}
