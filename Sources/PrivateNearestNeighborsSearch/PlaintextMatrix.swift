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

import HomomorphicEncryption

/// Different algorithms for packing a matrix of scalar values into plaintexts.
enum PlaintextMatrixPacking: Equatable {
    /// As many rows of data are packed sequentially into each SIMD plaintext
    /// row as possible, such that no data row is split across multiple SIMD rows, and
    /// each data row is zero-padded to the next power of two length.
    /// The rows in the final plaintext are repeated as many times as possible within the plaintext,
    /// with the constraint that either all or none of the entries stored within the last plaintext
    /// row are repeated.
    case denseRow
}

/// The dimensions of a matrix, a 2d array.
struct MatrixDimensions: Equatable {
    /// Number of rows in the data.
    @usableFromInline let rowCount: Int
    /// Number of columns in the data.
    @usableFromInline let columnCount: Int

    /// Number of data values stored in the plaintext matrix.
    @usableFromInline var count: Int {
        rowCount * columnCount
    }

    /// Initializes a ``MatrixDimensions``.
    /// - Parameters:
    ///   - rowCount: Number of rows; must be positive.
    ///   - columnCount: Number of columns; must be positive.
    /// - Throws: Error upon failure to initialize the dimensions.
    @inlinable
    init(rowCount: Int, columnCount: Int) throws {
        self.rowCount = rowCount
        self.columnCount = columnCount
        guard rowCount > 0, columnCount > 0 else {
            throw PNNSError.invalidMatrixDimensions(self)
        }
    }
}

/// Stores a matrix of scalars as plaintexts.
struct PlaintextMatrix<Scheme: HeScheme> {
    typealias Packing = PlaintextMatrixPacking
    typealias Dimensions = MatrixDimensions

    /// Dimensions of the scalars.
    @usableFromInline let dimensions: Dimensions

    /// The row and column count of a SIMD-encoded plaintext.
    let simdDimensions: (rowCount: Int, columnCount: Int)

    /// Plaintext packing with which the data is stored.
    @usableFromInline let packing: Packing

    /// Plaintexts encoding the scalars.
    let plaintexts: [Scheme.CoeffPlaintext]

    /// The parameter context.
    @usableFromInline var context: Context<Scheme> {
        precondition(!plaintexts.isEmpty, "Plaintext array cannot be empty")
        return plaintexts[0].context
    }

    /// The number of rows in SIMD-encoded plaintext.
    @usableFromInline var simdRowCount: Int { simdDimensions.rowCount }

    /// The number of columns SIMD-encoded plaintext.
    @usableFromInline var simdColumnCount: Int { simdDimensions.columnCount }

    /// The number of data values stored in the plaintext matrix.
    @usableFromInline var count: Int { dimensions.count }

    /// The number of rows in the stored data.
    @usableFromInline var rowCount: Int { dimensions.rowCount }

    /// The number of columns in the stored data.
    @usableFromInline var columnCount: Int { dimensions.columnCount }

    /// Creates a new plaintext matrix.
    /// - Parameters:
    ///   - dimensions: Plaintext matrix dimensions
    ///   - packing: The plaintext packing with which the data is stored
    ///   - plaintexts: Plaintexts encoding the data; must not be empty.
    /// - Throws: Error upon failure to initialize the plaintext matrix.
    @inlinable
    init(dimensions: Dimensions, packing: Packing, plaintexts: [Scheme.CoeffPlaintext]) throws {
        guard !plaintexts.isEmpty else {
            throw PNNSError.emptyPlaintextArray
        }
        let context = plaintexts[0].context
        let encryptionParams = context.encryptionParameters
        guard let simdDimensions = encryptionParams.simdDimensions else {
            throw PNNSError.simdEncodingNotSupported(for: encryptionParams)
        }
        let expectedPlaintextCount = try PlaintextMatrix.plaintextCount(
            encryptionParameters: encryptionParams,
            dimensions: dimensions,
            packing: packing)
        guard plaintexts.count == expectedPlaintextCount else {
            throw PNNSError.wrongPlaintextCount(got: plaintexts.count, expected: expectedPlaintextCount)
        }
        for plaintext in plaintexts {
            guard plaintext.context == context else {
                throw PNNSError.wrongContext(got: plaintext.context, expected: context)
            }
        }

        self.simdDimensions = simdDimensions
        self.dimensions = dimensions
        self.packing = packing
        self.plaintexts = plaintexts
    }

    /// Creates a new plaintext matrix.
    /// - Parameters:
    ///   - context: Parameter context to encode the data with.
    ///   - dimensions: Plaintext matrix dimensions.
    ///   - packing: The plaintext packing with which the data is stored.
    ///   - values: The data values to store in the plaintext matrix; stored in row-major format.
    /// - Throws: Error upon failure to create the plaitnext matrix.
    @inlinable
    init(context: Context<Scheme>, dimensions: Dimensions, packing: Packing, values: [some ScalarType]) throws {
        guard values.count == dimensions.count, !values.isEmpty else {
            throw PNNSError.wrongEncodingValuesCount(got: values.count, expected: values.count)
        }
        switch packing {
        case .denseRow:
            let plaintexts = try PlaintextMatrix.denseRowPlaintexts(
                context: context,
                dimensions: dimensions,
                values: values)
            try self.init(dimensions: dimensions, packing: packing, plaintexts: plaintexts)
        }
    }

    /// Returns the number of plaintexts required to encode a data matrix.
    /// - Parameters:
    ///   - encryptionParameters: Encryption parameters to encode the data with.
    ///   - dimensions: Plaintext matrix dimensions.
    ///   - packing: The plaintext packing with which the data is stored.
    /// - Returns: The number of plaintexts.
    /// - Throws: Error upon failure to compute the plaintext count.
    @inlinable
    static func plaintextCount(
        encryptionParameters: EncryptionParameters<Scheme>,
        dimensions: PlaintextMatrix.Dimensions,
        packing: PlaintextMatrix.Packing) throws -> Int
    {
        guard let (simdRowCount, simdColumnCount) = encryptionParameters.simdDimensions else {
            throw PNNSError.simdEncodingNotSupported(for: encryptionParameters)
        }
        switch packing {
        case .denseRow:
            guard dimensions.columnCount <= simdColumnCount else {
                throw PNNSError.invalidMatrixDimensions(dimensions)
            }
            let rowsPerPlaintextCount = simdRowCount * (simdColumnCount / dimensions.columnCount.nextPowerOfTwo)
            return dimensions.rowCount.dividingCeil(rowsPerPlaintextCount, variableTime: true)
        }
    }

    /// Computes the plaintexts for denseRow packing.
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - dimensions: Plaintext matrix dimensions.
    ///   - values: The data values to store in the plaintext matrix; stored in row-major format.
    /// - Returns: The plaintexts for denseRow packing.
    /// - Throws: Error upon failure to compute the plaintexts.
    @inlinable
    static func denseRowPlaintexts<V: ScalarType>(
        context: Context<Scheme>,
        dimensions: Dimensions,
        values: [V]) throws -> [Scheme.CoeffPlaintext]
    {
        let encryptionParameters = context.encryptionParameters
        guard let (simdRowCount, simdColumnCount) = context.simdDimensions else {
            throw PNNSError.simdEncodingNotSupported(for: encryptionParameters)
        }
        precondition(simdRowCount == 2)
        guard dimensions.columnCount <= simdColumnCount else {
            throw PNNSError.invalidMatrixDimensions(dimensions)
        }

        var plaintexts: [Scheme.CoeffPlaintext] = []
        let expectedPlaintextCount = try PlaintextMatrix.plaintextCount(
            encryptionParameters: encryptionParameters,
            dimensions: dimensions,
            packing: .denseRow)
        plaintexts.reserveCapacity(expectedPlaintextCount)

        // Pad number of columns to next power of two
        let padColCount = dimensions.columnCount.nextPowerOfTwo - dimensions.columnCount
        let padValues = [V](repeating: 0, count: padColCount)

        var packedValues: [V] = []
        packedValues.reserveCapacity(context.degree)
        var valuesIdx = 0
        for _ in 0..<dimensions.rowCount {
            for _ in 0..<dimensions.columnCount {
                packedValues.append(values[valuesIdx])
                valuesIdx += 1
            }
            packedValues.append(contentsOf: padValues)
            // Ensure next data row does not split across multiple SIMD rows
            if packedValues.count < simdColumnCount, packedValues.count + dimensions.columnCount > simdColumnCount {
                packedValues += repeatElement(0, count: simdColumnCount - packedValues.count)
            }
            if packedValues.count + dimensions.columnCount > context.degree {
                let plaintext = try context.encode(values: packedValues, format: .simd)
                packedValues.removeAll(keepingCapacity: true)
                plaintexts.append(plaintext)
            }
        }
        if !packedValues.isEmpty {
            // Repeat rows in final plaintext if possible
            let colOffset = packedValues.count % simdColumnCount
            let padCount = colOffset == 0 ? 0 : (colOffset.nextPowerOfTwo - colOffset)
            packedValues += repeatElement(0, count: padCount)
            let repeatValues = if packedValues.count <= simdColumnCount {
                packedValues[...]
            } else {
                packedValues[simdColumnCount...]
            }
            while packedValues.count < context.degree {
                packedValues += repeatValues
            }
            try plaintexts.append(context.encode(values: packedValues, format: .simd))
        }
        return plaintexts
    }

    /// Unpacks the plaintext matrix.
    /// - Returns: The stored data values in row-major format.
    /// - Throws: Error upon failure to unpack the matrix.
    @inlinable
    func unpack<V: ScalarType>() throws -> [V] {
        switch packing {
        case .denseRow:
            return try unpackDenseRow()
        }
    }

    /// Unpacks a plaintext matrix with `denseRow` packing.
    /// - Returns: The stored data values in row-major format.
    /// - Throws: Error upon failure to unpack the matrix.
    @inlinable
    func unpackDenseRow<V: ScalarType>() throws -> [V] {
        guard case packing = .denseRow else {
            throw PNNSError.wrongPlaintextMatrixPacking(got: packing, expected: Packing.denseRow)
        }
        let simdColumnCount = simdDimensions.columnCount

        // zero-pad each row to next power of two length
        let columnCountPerSimdRow = (simdColumnCount / columnCount.nextPowerOfTwo)
        let columnPadCount = columnCount.nextPowerOfTwo - columnCount
        var values: [V] = []
        values.reserveCapacity(count)
        for plaintext in plaintexts {
            let decoded: [V] = try plaintext.decode(format: .simd)
            for simdRowIndex in 0..<simdRowCount {
                for columnIndex in 0..<columnCountPerSimdRow {
                    let decodeStartIndex = (simdRowIndex * simdColumnCount) + columnIndex * columnCount +
                        columnIndex * columnPadCount
                    let decodeEndIndex = decodeStartIndex + min(columnCount, count - values.count)
                    values += decoded[decodeStartIndex..<decodeEndIndex]
                    if values.count == count {
                        return values
                    }
                }
            }
        }
        guard values.count == count else {
            throw PNNSError.wrongEncodingValuesCount(got: values.count, expected: count)
        }
        return values
    }
}
