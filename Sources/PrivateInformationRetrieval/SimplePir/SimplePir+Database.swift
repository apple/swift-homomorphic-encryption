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
public import HomomorphicEncryption
public import ModularArithmetic

extension Array2d where Element: ScalarType {
    typealias Scalar = Element

    /// At most 64MB (8 million UInt64s) per chunk when dealing with files.
    static var fileChunkSize: Int {
        8_000_000
    }

    /// At most 16 billion elements (128GB in UInt64) in database.
    static var maxDatabaseSize: Int {
        16_000_000_000
    }

    /// Initializes an `Array2d` from a file.
    /// - Parameters:
    ///   - path: Filepath with a serialized database.
    /// - Throws: Error upon failure to load the database.
    public init(from path: String) throws {
        let url = URL(fileURLWithPath: path)
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        let uint32Size = MemoryLayout<UInt32>.size

        // Helper: read exactly N bytes
        func readExactly(_ n: Int) throws -> Data {
            var data = Data()
            while data.count < n {
                guard let chunk = try handle.read(upToCount: n - data.count), !chunk.isEmpty else {
                    throw PirError.corruptedData("Unexpected EOF")
                }
                data.append(chunk)
            }
            return data
        }

        let header = try readExactly(2 * uint32Size)
        let rowCount = header.withUnsafeBytes { value in
            Int(value.loadUnaligned(as: UInt32.self).littleEndian)
        }
        let columnCount = header.withUnsafeBytes { value in
            Int(value.loadUnaligned(fromByteOffset: uint32Size, as: UInt32.self).littleEndian)
        }
        let totalCount = rowCount * columnCount
        if totalCount >= Self.maxDatabaseSize {
            throw PirError.corruptedData("Database is unreasonably large: \(rowCount) x \(columnCount)")
        }
        var data = [Scalar](repeating: 0, count: totalCount)

        var index = 0
        while index < totalCount {
            let thisChunkSize = min(Self.fileChunkSize, totalCount - index)
            let thisChunkBytes = thisChunkSize * MemoryLayout<Scalar>.stride
            let chunkData = try readExactly(thisChunkBytes)

            data.withUnsafeMutableBytes { destPtr in
                let offset = index * MemoryLayout<Scalar>.stride
                // swiftlint:disable:next force_unwrapping
                let destSlice = destPtr.baseAddress!.advanced(by: offset)
                chunkData.withUnsafeBytes { srcPtr in
                    // swiftlint:disable:next force_unwrapping
                    destSlice.copyMemory(from: srcPtr.baseAddress!, byteCount: thisChunkBytes)
                }
            }
            index += thisChunkSize
        }
        self.init(data: data, rowCount: rowCount, columnCount: columnCount)
    }

    /// Saves the 2-dimension array  to a file.
    /// - Parameters:
    ///   - path: Filepath to save the serialized database.
    /// - Throws: Error upon failure to save the database.
    public func save(to path: String) throws {
        let url = URL(fileURLWithPath: path)
        let fm = FileManager.default

        // create/truncate the file first
        if fm.fileExists(atPath: path) {
            try fm.removeItem(at: url)
        }
        guard fm.createFile(atPath: path, contents: nil) else {
            throw PirError.failedToCreateFile(path)
        }
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }

        var header = Data()
        withUnsafeBytes(of: UInt32(rowCount).littleEndian) { header.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt32(columnCount).littleEndian) { header.append(contentsOf: $0) }
        try handle.write(contentsOf: header)

        var index = 0
        while index < data.count {
            let end = min(data.count, index + Self.fileChunkSize)
            let slice = data[index..<end]
            try slice.withUnsafeBytes { sliceBytes in
                try handle.write(contentsOf: Data(sliceBytes))
            }
            index = end
        }
        handle.synchronizeFile()
    }
}

/// Processed database for SimplePir.
public struct SimplePirDatabase<Scalar: ScalarType>: Sendable, Equatable {
    /// The processed database.
    public let database: Array2d<Scalar>

    /// Creates a SimplePir database.
    /// - Parameters:
    ///   - database: The processed database data.
    @inlinable
    public init(database: Array2d<Scalar>) {
        self.database = database
    }

    /// Load a database from a file.
    /// - Parameters:
    ///   - path: Filepath with a serialized database.
    /// - Throws: Error upon failure to load the database.
    public init(from path: String) throws {
        self.database = try Array2d(from: path)
    }

    public func save(to path: String) throws {
        try database.save(to: path)
    }
}

/// Processed database with hint.
///
/// This is the result of processing a database with hint generation.
public struct SimplePIRProcessDatabaseResults<Scalar: ScalarType> {
    /// Processed database, this is the part that is required for answering PIR queries.
    public let database: SimplePirDatabase<Scalar>
    /// The hint that should be distributed to clients.
    public let hint: Array2d<Scalar>
    /// The parameters that should be distributed to clients.
    public let params: SimplePirParameters

    @inlinable
    init(database: SimplePirDatabase<Scalar>, hint: Array2d<Scalar>, params: SimplePirParameters) {
        self.database = database
        self.hint = hint
        self.params = params
    }
}

extension SimplePirParameters {
    @usableFromInline var aPolyCount: Int {
        databaseColumns.dividingCeil(latticeDimension, variableTime: true)
    }
}

extension SimplePirContext {
    /// Generate the polynomials used to construct the A matrix.
    /// - Returns: An array of polynomials.
    public func generateAPolynomials() throws -> [PolyRq<Scalar, Coeff>] {
        var rng = try NistAes128Ctr(seed: seed)
        return (0..<aPolyCount).map { _ in PolyRq.random(context: extraContext, using: &rng) }
    }

    /// Materialize the A matrix.
    /// - Parameter aPolynomials: The polynomials that are expanded to negacyclic matrices and then concatenated.
    /// - Returns: Negacyclic matrix A.
    public func materializeAMatrix(aPolynomials: [PolyRq<Scalar, Coeff>]) throws -> Array2d<Scalar> {
        var aMatrix: Array2d<Scalar> = .init(data: [], rowCount: 0, columnCount: latticeDimension)
        for poly in aPolynomials {
            let negacyclicMatrix = try poly.negacyclicMatrix().collect().transposed()
            assert(aMatrix.columnCount == negacyclicMatrix.columnCount)
            if aMatrix.rowCount + negacyclicMatrix.rowCount < databaseColumns {
                aMatrix.data.append(contentsOf: negacyclicMatrix.data)
                aMatrix.rowCount += negacyclicMatrix.rowCount
            } else {
                let missingRows = databaseColumns - aMatrix.rowCount
                aMatrix.data.append(contentsOf: negacyclicMatrix.data.prefix(missingRows * latticeDimension))
                aMatrix.rowCount += missingRows
            }
        }
        assert(aMatrix.rowCount == databaseColumns)
        assert(aMatrix.columnCount == latticeDimension)
        assert(aMatrix.data.count == databaseColumns * latticeDimension)
        return aMatrix
    }
}

extension SimplePirServerProtocol {
    @inlinable
    static func computingParams(encryptionParams: SimplePirEncryptionParams, entryCount: Int,
                                entrySizeInBytes: Int,
                                seed: [UInt8]? = nil) throws -> SimplePirParameters
    {
        let entrySizeInScalar = CoefficientPacking.bytesToCoefficientsCoeffCount(
            byteCount: entrySizeInBytes,
            bitsPerCoeff: encryptionParams.plaintextModulusBits,
            decode: false)
        let databaseSize = entryCount * entrySizeInScalar
        // Round sqrt(databaseSize) to the nearest integer
        var idealColumnSize = Int(sqrt(Double(databaseSize)).rounded())
        // If idealColumnSize is larger than entrySizeInScalar, set idealColumnSize to entrySizeInScalar
        if idealColumnSize > entrySizeInScalar {
            idealColumnSize = entrySizeInScalar
        }
        // Get ideal entry count per column.
        let idealEntriesPerColumn = Int((Double(idealColumnSize) / Double(entrySizeInScalar)).rounded())
        // At least 1 entry per column
        let entriesPerColumn = max(idealEntriesPerColumn, 1)
        // Get ideal chunk count for each entry
        let idealChunksPerEntry = Int(Double(entrySizeInScalar) / Double(idealColumnSize).rounded())
        // At least 1 chunk per entry
        let chunksPerEntry = max(idealChunksPerEntry, 1)
        let databaseColumns = if entriesPerColumn == 1 {
            entryCount * chunksPerEntry
        } else {
            max(entryCount.dividingCeil(entriesPerColumn, variableTime: true), 1)
        }
        return SimplePirParameters(encryptionParams: encryptionParams,
                                   entrySizeInBytes: entrySizeInBytes,
                                   entriesPerColumn: entriesPerColumn,
                                   chunksPerEntry: chunksPerEntry,
                                   databaseColumns: databaseColumns,
                                   seed: seed ?? .init(randomByteCount: NistAes128Ctr.SeedCount))
    }

    /// Process a database so it can be used with Simple PIR server.
    /// - Parameters:
    ///   - database: The database to process.
    ///   - encryptionParams: The security parameters.
    ///   - seed: The seed to use for generating the random matrix. If `nil`, a random seed is generated.
    /// - Returns: Processed database with hint.
    @inlinable
    public static func process(database: RawDatabase,
                               encryptionParams: SimplePirEncryptionParams,
                               seed: [UInt8]? = nil) async throws
        -> SimplePIRProcessDatabaseResults<Scalar>
    {
        let params = try computingParams(
            encryptionParams: encryptionParams,
            entryCount: database.rowCount,
            entrySizeInBytes: database.columnCount,
            seed: seed)
        let paddedEntrySize = if params.chunksPerEntry == 1 {
            params.entrySizeInScalar
        } else {
            params.entrySizeInScalar.nextMultiple(of: params.chunksPerEntry, variableTime: true)
        }
        // at least one of  `entriesPerColumn` and `chunksPerEntry` is 1
        let columnSize = paddedEntrySize * params.entriesPerColumn / params.chunksPerEntry

        var processedDatabase = Array2d<Scalar>.zero(
            rowCount: params.databaseColumns,
            columnCount: columnSize)
        try (0..<database.rowCount).forEach { entryIndex in
            try CoefficientPacking.bytesToCoefficientsInplace(
                bytes: database.row(entryIndex),
                coeffs: &processedDatabase
                    .data[entryIndex * paddedEntrySize..<entryIndex * paddedEntrySize + params.entrySizeInScalar],
                bitsPerCoeff: encryptionParams.plaintextModulusBits)
        }
        processedDatabase = await processedDatabase.transposed()

        let context: SimplePirContext<Scalar> = try .init(params: params)
        let matrixA: Array2d<Scalar> = try context.materializeAMatrix(aPolynomials: context.generateAPolynomials())
        let hint = await processedDatabase.multiply(matrixA, modulus: context.nttFriendlyMod)

        return SimplePIRProcessDatabaseResults(
            database: SimplePirDatabase(database: processedDatabase),
            hint: hint,
            params: params)
    }
}
