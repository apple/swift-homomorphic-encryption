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

import Algorithms
import HomomorphicEncryption

/// Different algorithms for packing a matrix of scalar values into plaintexts / ciphertexts.
public enum MatrixPacking: Codable, Equatable, Hashable, Sendable {
    /// As many columns of data are packed sequentially into each plaintext SIMD row as possible, such that no SIMD row
    /// contains data from multiple columns.
    case denseColumn

    /// As many rows of data are packed sequentially into each SIMD plaintext
    /// row as possible, such that no data row is split across multiple SIMD rows, and
    /// each data row is zero-padded to the next power of two length.
    /// The rows in the final plaintext are repeated as many times as possible within the plaintext,
    /// with the constraint that either all or none of the entries stored within the last plaintext
    /// row are repeated.
    case denseRow
    /// Packs the values using a generalized diagonal packing.
    ///
    /// Includes modifications for the baby-step, giant-step algorithm from Section 6.3 of
    /// <https://eprint.iacr.org/2018/244.pdf>.
    case diagonal(babyStepGiantStep: BabyStepGiantStep)
}

/// The dimensions of a matrix, a 2d array.
public struct MatrixDimensions: Equatable, Sendable {
    /// Number of rows in the data.
    public let rowCount: Int
    /// Number of columns in the data.
    public let columnCount: Int

    /// Number of data values stored in the plaintext matrix.
    public var count: Int {
        rowCount * columnCount
    }

    /// Initializes a ``MatrixDimensions``.
    /// - Parameters:
    ///   - rowCount: Number of rows; must be positive.
    ///   - columnCount: Number of columns; must be positive.
    /// - Throws: Error upon failure to initialize the dimensions.
    @inlinable
    public init(rowCount: Int, columnCount: Int) throws {
        self.rowCount = rowCount
        self.columnCount = columnCount
        guard rowCount > 0, columnCount > 0 else {
            throw PnnsError.invalidMatrixDimensions(self)
        }
    }
}

/// Stores a matrix of scalars as plaintexts.
public struct PlaintextMatrix<Scheme: HeScheme, Format: PolyFormat>: Equatable, Sendable {
    /// Dimensions of the matrix.
    @usableFromInline let dimensions: MatrixDimensions

    /// Dimensions of the scalar matrix in a SIMD-encoded plaintext.
    @usableFromInline let simdDimensions: SimdEncodingDimensions

    /// Plaintext packing with which the data is stored.
    @usableFromInline let packing: MatrixPacking

    /// Plaintexts encoding the scalars.
    @usableFromInline let plaintexts: [Plaintext<Scheme, Format>]

    /// The parameter context.
    @usableFromInline var context: Context<Scheme> {
        precondition(!plaintexts.isEmpty, "Plaintext array cannot be empty")
        return plaintexts[0].context
    }

    /// Number of rows in SIMD-encoded plaintext.
    @usableFromInline var simdRowCount: Int { simdDimensions.rowCount }

    /// Number of columns SIMD-encoded plaintext.
    @usableFromInline var simdColumnCount: Int { simdDimensions.columnCount }

    /// Number of data values stored in the plaintext matrix.
    @usableFromInline var count: Int { dimensions.count }

    /// Number of rows in the stored data.
    @usableFromInline var rowCount: Int { dimensions.rowCount }

    /// Number of columns in the stored data.
    @usableFromInline var columnCount: Int { dimensions.columnCount }

    /// Creates a new plaintext matrix.
    /// - Parameters:
    ///   - dimensions: Plaintext matrix dimensions.
    ///   - packing: The packing with which the data is stored.
    ///   - plaintexts: Plaintexts encoding the data; must not be empty.
    /// - Throws: Error upon failure to initialize the plaintext matrix.
    @inlinable
    init(dimensions: MatrixDimensions, packing: MatrixPacking, plaintexts: [Plaintext<Scheme, Format>]) throws {
        guard !plaintexts.isEmpty else {
            throw PnnsError.emptyPlaintextArray
        }
        let context = plaintexts[0].context
        let encryptionParams = context.encryptionParameters
        guard let simdDimensions = encryptionParams.simdDimensions else {
            throw PnnsError.simdEncodingNotSupported(for: encryptionParams)
        }
        let expectedPlaintextCount = try PlaintextMatrix.plaintextCount(
            encryptionParameters: encryptionParams,
            dimensions: dimensions,
            packing: packing)
        guard plaintexts.count == expectedPlaintextCount else {
            throw PnnsError.wrongPlaintextCount(got: plaintexts.count, expected: expectedPlaintextCount)
        }
        for plaintext in plaintexts {
            guard plaintext.context == context else {
                throw PnnsError.wrongContext(got: plaintext.context, expected: context)
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
    ///   - packing: The packing with which the data is stored.
    ///   - values: The data values to store in the plaintext matrix; stored in row-major format.
    /// - Throws: Error upon failure to create the plaitnext matrix.
    @inlinable
    public init(
        context: Context<Scheme>,
        dimensions: MatrixDimensions,
        packing: MatrixPacking,
        values: [some ScalarType]) throws
        where Format == Coeff
    {
        guard values.count == dimensions.count, !values.isEmpty else {
            throw PnnsError.wrongEncodingValuesCount(got: values.count, expected: values.count)
        }
        switch packing {
        case .denseColumn:
            let plaintexts = try PlaintextMatrix.denseColumnPlaintexts(
                context: context,
                dimensions: dimensions,
                values: values)
            try self.init(dimensions: dimensions, packing: packing, plaintexts: plaintexts)
        case .denseRow:
            let plaintexts = try PlaintextMatrix.denseRowPlaintexts(
                context: context,
                dimensions: dimensions,
                values: values)
            try self.init(dimensions: dimensions, packing: packing, plaintexts: plaintexts)
        case .diagonal:
            let plaintexts = try PlaintextMatrix.diagonalPlaintexts(
                context: context,
                dimensions: dimensions,
                packing: packing,
                values: values)
            try self.init(dimensions: dimensions, packing: packing, plaintexts: plaintexts)
        }
    }

    /// Returns the number of plaintexts required to encode a data matrix.
    /// - Parameters:
    ///   - encryptionParameters: Encryption parameters to encode the data with.
    ///   - dimensions: Plaintext matrix dimensions.
    ///   - packing: The packing with which the data is stored.
    /// - Returns: The number of plaintexts.
    /// - Throws: Error upon failure to compute the plaintext count.
    @inlinable
    static func plaintextCount(
        encryptionParameters: EncryptionParameters<Scheme>,
        dimensions: MatrixDimensions,
        packing: MatrixPacking) throws -> Int
    {
        guard let simdDimensions = encryptionParameters.simdDimensions else {
            throw PnnsError.simdEncodingNotSupported(for: encryptionParameters)
        }
        switch packing {
        case .denseColumn:
            let columnsPerPlaintextCount = simdDimensions.rowCount * (simdDimensions.columnCount / dimensions.rowCount)
            if columnsPerPlaintextCount > 1 {
                return dimensions.columnCount.dividingCeil(columnsPerPlaintextCount, variableTime: true)
            }
            return dimensions.columnCount * dimensions.rowCount
                .dividingCeil(encryptionParameters.polyDegree, variableTime: true)
        case .denseRow:
            guard dimensions.columnCount <= simdDimensions.columnCount else {
                throw PnnsError.invalidMatrixDimensions(dimensions)
            }
            let rowsPerPlaintextCount = simdDimensions.rowCount * (
                simdDimensions.columnCount / dimensions.columnCount.nextPowerOfTwo)
            return dimensions.rowCount.dividingCeil(rowsPerPlaintextCount, variableTime: true)
        case .diagonal:
            let plaintextsPerColumnCount = dimensions.rowCount.dividingCeil(
                encryptionParameters.polyDegree,
                variableTime: true)
            return dimensions.columnCount.nextPowerOfTwo * plaintextsPerColumnCount
        }
    }

    /// Computes the plaintexts for `denseColumn`` packing.
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - dimensions: Plaintext matrix dimensions.
    ///   - values: The data values to store in the plaintext matrix; stored in row-major format.
    /// - Returns: The plaintexts for `denseColumn` packing.
    /// - Throws: Error upon plaintext to compute the plaintexts.
    @inlinable
    static func denseColumnPlaintexts<V: ScalarType>(context: Context<Scheme>, dimensions: MatrixDimensions,
                                                     values: [V]) throws -> [Scheme.CoeffPlaintext]
    {
        let degree = context.degree
        guard let simdColumnCount = context.simdDimensions?.columnCount else {
            throw PnnsError.simdEncodingNotSupported(for: context.encryptionParameters)
        }

        let encryptionParams = context.encryptionParameters
        let expectedPlaintextCount = try PlaintextMatrix.plaintextCount(
            encryptionParameters: encryptionParams,
            dimensions: dimensions,
            packing: .denseColumn)
        var plaintexts: [Scheme.CoeffPlaintext] = []
        plaintexts.reserveCapacity(expectedPlaintextCount)

        var packedValues: [V] = []
        packedValues.reserveCapacity(degree)
        for colIndex in 0..<dimensions.columnCount {
            for rowIndex in 0..<dimensions.rowCount {
                let valueIndex = rowIndex * dimensions.columnCount + colIndex
                let value = values[valueIndex]
                packedValues.append(value)
                if packedValues.count == degree {
                    try plaintexts.append(context.encode(values: packedValues, format: .simd))
                    packedValues.removeAll(keepingCapacity: true)
                }
            }
            let nextColumnCount = packedValues.count + dimensions.rowCount
            // Ensure data column is contained within single SIMD row, if possible
            if packedValues.count < simdColumnCount, (simdColumnCount + 1...degree).contains(nextColumnCount) {
                // Next data column fits in next SIMD row; pad 0s to this SIMD row
                let padCount = (context.degree - packedValues.count) % simdColumnCount
                packedValues += [V](repeating: 0, count: padCount)
            } else if nextColumnCount > degree {
                // Next data column requires new plaintext
                try plaintexts.append(context.encode(values: packedValues, format: .simd))
                packedValues.removeAll(keepingCapacity: true)
            }
        }
        if !packedValues.isEmpty {
            try plaintexts.append(context.encode(values: packedValues, format: .simd))
        }
        precondition(plaintexts.count == expectedPlaintextCount)

        return plaintexts
    }

    /// Computes the plaintexts for `denseRow` packing.
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - dimensions: Plaintext matrix dimensions.
    ///   - values: The data values to store in the plaintext matrix; stored in row-major format.
    /// - Returns: The plaintexts for `denseRow` packing.
    /// - Throws: Error upon failure to compute the plaintexts.
    @inlinable
    static func denseRowPlaintexts<V: ScalarType>(
        context: Context<Scheme>,
        dimensions: MatrixDimensions,
        values: [V]) throws -> [Plaintext<Scheme, Coeff>]
    {
        let encryptionParameters = context.encryptionParameters
        guard let simdDimensions = context.simdDimensions else {
            throw PnnsError.simdEncodingNotSupported(for: encryptionParameters)
        }
        precondition(simdDimensions.rowCount == 2, "SIMD row count must be 2")
        let simdColumnCount = simdDimensions.columnCount
        guard dimensions.columnCount <= simdColumnCount else {
            throw PnnsError.invalidMatrixDimensions(dimensions)
        }

        var plaintexts: [Plaintext<Scheme, Coeff>] = []
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
                let plaintext: Plaintext<Scheme, Coeff> = try context.encode(values: packedValues, format: .simd)
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
        precondition(plaintexts.count == expectedPlaintextCount)

        return plaintexts
    }

    /// Computes the plaintexts for diagonal packing.
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - dimensions: Plaintext matrix dimensions.
    ///   - packing: Plaintext packing; must be `.diagonal`.
    ///   - values: The data values to store in the plaintext matrix; stored in row-major format.
    /// - Returns: The plaintexts for diagonal packing.
    /// - Throws: Error upon failure to compute the plaintexts.
    @inlinable
    static func diagonalPlaintexts<V: ScalarType>(
        context: Context<Scheme>,
        dimensions: MatrixDimensions,
        packing: MatrixPacking,
        values: [V]) throws -> [Scheme.CoeffPlaintext]
    {
        let encryptionParameters = context.encryptionParameters
        guard let simdDimensions = context.simdDimensions else {
            throw PnnsError.simdEncodingNotSupported(for: encryptionParameters)
        }
        let simdColumnCount = simdDimensions.columnCount
        let simdRowCount = simdDimensions.rowCount
        precondition(simdRowCount == 2, "simdRowCount must be 2")
        guard dimensions.columnCount <= simdColumnCount else {
            throw PnnsError.invalidMatrixDimensions(dimensions)
        }
        guard case let .diagonal(bsgs) = packing else {
            let expectedBsgs = BabyStepGiantStep(vectorDimension: dimensions.columnCount)
            throw PnnsError.wrongMatrixPacking(got: packing, expected: .diagonal(babyStepGiantStep: expectedBsgs))
        }

        let data = Array2d(data: values, rowCount: dimensions.rowCount, columnCount: dimensions.columnCount)
        // Transposed from original shape, with extra zero columns.
        // Encode diagonals
        var packedValues = Array2d<V>.zero(
            rowCount: dimensions.columnCount.nextPowerOfTwo,
            columnCount: dimensions.rowCount)
        for rowIndex in 0..<packedValues.rowCount {
            for columnIndex in 0..<packedValues.columnCount {
                let paddedColumnIndex = (columnIndex &+ rowIndex) % packedValues.rowCount
                if paddedColumnIndex < dimensions.columnCount {
                    packedValues[rowIndex, columnIndex] =
                        data[columnIndex, paddedColumnIndex]
                }
            }
        }

        var plaintexts: [Scheme.CoeffPlaintext] = []
        let expectedPlaintextCount = try PlaintextMatrix.plaintextCount(
            encryptionParameters: encryptionParameters,
            dimensions: dimensions,
            packing: packing)
        plaintexts.reserveCapacity(expectedPlaintextCount)
        let plaintextsPerColumn = expectedPlaintextCount / packedValues.rowCount

        // Perform baby-step giant-step rotations.
        // See Section 6.3 of <https://eprint.iacr.org/2018/244.pdf>.
        let n = context.degree
        for rowIndex in 0..<packedValues.rowCount {
            let row = packedValues.row(row: rowIndex)
            for (chunkIndex, var chunk) in row.chunks(ofCount: n).enumerated() {
                chunk += repeatElement(0, count: n - chunk.count)
                let i = (plaintexts.count - chunkIndex) / plaintextsPerColumn
                let rotationStep = i.previousMultiple(of: bsgs.babyStep, variableTime: true)
                let middle = min(chunk.endIndex, chunk.startIndex + n / 2)
                chunk[chunk.startIndex..<middle].rotate(toStartAt: chunk.startIndex + rotationStep)
                chunk[middle...].rotate(toStartAt: middle + rotationStep)

                let plaintext = try context.encode(values: Array(chunk), format: .simd)
                plaintexts.append(plaintext)
            }
        }
        precondition(plaintexts.count == expectedPlaintextCount)

        return plaintexts
    }

    /// Unpacks the plaintext matrix.
    /// - Returns: The stored data values in row-major format.
    /// - Throws: Error upon failure to unpack the matrix.
    @inlinable
    func unpack<V: ScalarType>() throws -> [V] where Format == Coeff {
        switch packing {
        case .denseColumn:
            return try unpackDenseColumn()
        case .denseRow:
            return try unpackDenseRow()
        case .diagonal:
            // TODO: Implement
            preconditionFailure("Unpacking diagonal plaintext matrix not supported")
        }
    }

    /// Unpacks a plaintext matrix with `denseColumn` packing.
    /// - Returns: The stored data values in row-major format.
    /// - Throws: Error upon failure to unpack the matrix.
    @inlinable
    func unpackDenseColumn<V: ScalarType>() throws -> [V] where Format == Coeff {
        guard case packing = .denseColumn else {
            throw PnnsError.wrongMatrixPacking(got: packing, expected: .denseColumn)
        }
        let simdColumnCount = simdDimensions.columnCount
        let simdRowCount = simdDimensions.rowCount
        precondition(simdRowCount == 2, "SIMD row count must be 2")
        let columnsPerPlaintextCount = simdRowCount * (simdColumnCount / rowCount)

        var valuesColumnMajor: [V] = []
        valuesColumnMajor.reserveCapacity(count)
        for plaintext in plaintexts {
            let decoded: [V] = try plaintext.decode(format: .simd)
            if columnsPerPlaintextCount > 1 {
                let valsPerSimdRowCount = rowCount * (simdColumnCount / rowCount)
                // Ignore padding at the end of each SIMD row
                var remainingDecodeCount = count - valuesColumnMajor.count
                let simdRow1DecodedCount = min(valsPerSimdRowCount, remainingDecodeCount)
                valuesColumnMajor += decoded[0..<simdRow1DecodedCount]

                remainingDecodeCount = count - valuesColumnMajor.count
                let simdRow2DecodedCount = min(valsPerSimdRowCount, remainingDecodeCount)
                valuesColumnMajor += decoded[simdColumnCount..<simdColumnCount + simdRow2DecodedCount]
            } else {
                let valuesInRowCount = valuesColumnMajor.count % rowCount
                let decodedEndIndex = min(decoded.count, rowCount - valuesInRowCount)
                valuesColumnMajor += decoded[0..<decodedEndIndex]
            }
        }
        guard valuesColumnMajor.count == count else {
            throw PnnsError.wrongEncodingValuesCount(got: valuesColumnMajor.count, expected: count)
        }
        // transpose from column-major to row-major
        let arrayColumnMajor = Array2d(
            data: valuesColumnMajor,
            rowCount: columnCount,
            columnCount: rowCount)
        return arrayColumnMajor.transposed().data
    }

    /// Unpacks a plaintext matrix with `denseRow` packing.
    /// - Returns: The stored data values in row-major format.
    /// - Throws: Error upon failure to unpack the matrix.
    @inlinable
    func unpackDenseRow<V: ScalarType>() throws -> [V] where Format == Coeff {
        guard case packing = .denseRow else {
            throw PnnsError.wrongMatrixPacking(got: packing, expected: MatrixPacking.denseRow)
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
            throw PnnsError.wrongEncodingValuesCount(got: values.count, expected: count)
        }
        return values
    }

    /// Symmetric secret key encryption of the plaintext matrix.
    /// - Parameter secretKey: Secret key to encrypt with.
    /// - Returns: A ciphertext encrypting the plaintext matrix.
    /// - Throws: Error upon failure to encrypt the plaintext matrix.
    @inlinable
    public func encrypt(using secretKey: SecretKey<Scheme>) throws
        -> CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat> where Format == Coeff
    {
        let ciphertexts = try plaintexts.map { plaintext in try plaintext.encrypt(using: secretKey) }
        return try CiphertextMatrix(dimensions: dimensions, packing: packing, ciphertexts: ciphertexts)
    }
}

// MARK: format conversion

extension PlaintextMatrix {
    /// Converts the plaintext matrix to ``Eval`` format.
    ///
    /// This makes the plaintext matrix suitable for operations with ciphertexts in ``Eval`` format, with `moduliCount`
    /// moduli.
    /// - Parameter moduliCount: Number of coefficient moduli in the context.
    /// - Returns: The converted plaintext matrix.
    /// - Throws: Error upon failure to convert the plaintext matrix.
    @inlinable
    public func convertToEvalFormat(moduliCount: Int? = nil) throws -> PlaintextMatrix<Scheme, Eval> {
        if Format.self == Eval.self {
            // swiftlint:disable:next force_cast
            return self as! PlaintextMatrix<Scheme, Eval>
        }
        let plaintexts = try plaintexts.map { plaintext in try plaintext.convertToEvalFormat(moduliCount: moduliCount) }
        return try PlaintextMatrix<Scheme, Eval>(dimensions: dimensions, packing: packing, plaintexts: plaintexts)
    }

    /// Converts the plaintext matrix to ``Coeff`` format.
    /// - Returns: The converted plaintext matrix.
    /// - Throws: Error upon failure to convert the plaintext matrix.
    @inlinable
    public func convertToCoeffFormat() throws -> PlaintextMatrix<Scheme, Coeff> {
        if Format.self == Coeff.self {
            // swiftlint:disable:next force_cast
            return self as! PlaintextMatrix<Scheme, Coeff>
        }
        let plaintexts = try plaintexts.map { plaintext in try plaintext.convertToCoeffFormat() }
        return try PlaintextMatrix<Scheme, Coeff>(dimensions: dimensions, packing: packing, plaintexts: plaintexts)
    }
}
