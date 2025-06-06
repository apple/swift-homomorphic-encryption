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

import HomomorphicEncryption
import ModularArithmetic

/// Stores a matrix of scalars as ciphertexts.
public struct CiphertextMatrix<Scheme: HeScheme, Format: PolyFormat>: Equatable, Sendable {
    public typealias Scalar = Scheme.Scalar

    /// Dimensions of the matrix.
    @usableFromInline package let dimensions: MatrixDimensions

    /// Dimensions of the scalar matrix in a SIMD-encoded plaintext.
    @usableFromInline let simdDimensions: SimdEncodingDimensions

    /// Plaintext packing with which the data is stored.
    @usableFromInline let packing: MatrixPacking

    /// Encrypted data.
    @usableFromInline package var ciphertexts: [Ciphertext<Scheme, Format>]

    /// The parameter context.
    @usableFromInline var context: Context<Scheme> {
        precondition(!ciphertexts.isEmpty, "Ciphertext array cannot be empty")
        return ciphertexts[0].context
    }

    /// Number of rows in SIMD-encoded plaintext.
    @usableFromInline var simdRowCount: Int { simdDimensions.rowCount }

    /// Number of columns SIMD-encoded plaintext.
    @usableFromInline var simdColumnCount: Int { simdDimensions.columnCount }

    /// Number of data values stored in the ciphertexts matrix.
    @usableFromInline var count: Int { dimensions.count }

    /// Number of rows in the stored data.
    @usableFromInline var rowCount: Int { dimensions.rowCount }

    /// Number of columns in the stored data.
    @usableFromInline var columnCount: Int { dimensions.columnCount }

    /// Creates a new ciphertexts matrix.
    /// - Parameters:
    ///   - dimensions: Ciphertext matrix dimensions.
    ///   - packing: The packing with which the data is stored.
    ///   - ciphertexts: Ciphertexts encrypting the data; must not be empty.
    /// - Throws: Error upon failure to initialize the ciphertext matrix.
    @inlinable
    public init(dimensions: MatrixDimensions, packing: MatrixPacking,
                ciphertexts: [Ciphertext<Scheme, Format>]) throws
    {
        guard let context = ciphertexts.first?.context else {
            throw PnnsError.emptyCiphertextArray
        }
        let encryptionParameters = context.encryptionParameters
        guard let simdDimensions = context.simdDimensions else {
            throw PnnsError.simdEncodingNotSupported(for: encryptionParameters)
        }
        let expectedCiphertextCount = try PlaintextMatrix<Scheme, Format>.plaintextCount(
            encryptionParameters: encryptionParameters,
            dimensions: dimensions,
            packing: packing)
        guard ciphertexts.count == expectedCiphertextCount else {
            throw PnnsError.wrongCiphertextCount(got: ciphertexts.count, expected: expectedCiphertextCount)
        }
        for ciphertext in ciphertexts {
            guard ciphertext.context == context else {
                throw PnnsError.wrongContext(got: ciphertext.context, expected: context)
            }
        }

        self.simdDimensions = simdDimensions
        self.dimensions = dimensions
        self.packing = packing
        self.ciphertexts = ciphertexts
    }

    @inlinable
    package func decrypt(using secretKey: SecretKey<Scheme>) throws -> PlaintextMatrix<Scheme, Coeff> {
        let plaintexts = try ciphertexts.map { ciphertext in try ciphertext.decrypt(using: secretKey) }
        return try PlaintextMatrix(dimensions: dimensions, packing: packing, plaintexts: plaintexts)
    }
}

// MARK: format conversion

extension CiphertextMatrix {
    /// Converts the ciphertext matrix to `Eval` format.
    /// - Returns: The converted ciphertext matrix.
    /// - Throws: Error upon failure to convert the ciphertext matrix.
    @inlinable
    public func convertToEvalFormat() throws -> CiphertextMatrix<Scheme, Eval> {
        if Format.self == Eval.self {
            // swiftlint:disable:next force_cast
            return self as! CiphertextMatrix<Scheme, Eval>
        }
        let evalCiphertexts = try ciphertexts.map { ciphertext in try ciphertext.convertToEvalFormat() }
        return try CiphertextMatrix<Scheme, Eval>(
            dimensions: dimensions,
            packing: packing,
            ciphertexts: evalCiphertexts)
    }

    /// Converts the ciphertext matrix to `Coeff` format.
    /// - Returns: The converted ciphertext matrix.
    /// - Throws: Error upon failure to convert the ciphertext matrix.
    @inlinable
    public func convertToCoeffFormat() throws -> CiphertextMatrix<Scheme, Coeff> {
        if Format.self == Coeff.self {
            // swiftlint:disable:next force_cast
            return self as! CiphertextMatrix<Scheme, Coeff>
        }
        let coeffCiphertexts = try ciphertexts.map { ciphertexts in try ciphertexts.convertToCoeffFormat() }
        return try CiphertextMatrix<Scheme, Coeff>(
            dimensions: dimensions,
            packing: packing,
            ciphertexts: coeffCiphertexts)
    }

    /// Converts the ciphertext matrix to canonical format.
    /// - Returns: The converted ciphertext matrix.
    /// - Throws: Error upon failure to convert the ciphertext matrix.
    @inlinable
    public func convertToCanonicalFormat() throws -> CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat> {
        if Scheme.CanonicalCiphertextFormat.self == Coeff.self {
            // swiftlint:disable:next force_cast
            return try convertToCoeffFormat() as! CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat>
        }
        if Scheme.CanonicalCiphertextFormat.self == Eval.self {
            // swiftlint:disable:next force_cast
            return try convertToEvalFormat() as! CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat>
        }
        fatalError("Unsupported Format \(Format.description)")
    }

    /// Performs modulus switching to a single modulus.
    ///
    /// If the ciphertexts already have a single modulus, this is a no-op.
    /// - Throws: Error upon failure to modulus switch.
    @inlinable
    public mutating func modSwitchDownToSingle() throws where Format == Scheme.CanonicalCiphertextFormat {
        for index in 0..<ciphertexts.count {
            try ciphertexts[index].modSwitchDownToSingle()
        }
    }
}

extension CiphertextMatrix {
    /// Computes the evaluation key configuration for calling `extractDenseRow`.
    /// - Parameters:
    ///   - encryptionParameters: Encryption parameters; must support `.simd` encoding.
    ///   - dimensions: Dimensions of the matrix to call `extractDenseRow` on.
    /// - Returns: The evaluation key configuration.
    /// - Throws: Error upon failure to generate the evaluation key configuration.
    @inlinable
    package static func extractDenseRowConfig(for encryptionParameters: EncryptionParameters<Scheme.Scalar>,
                                              dimensions: MatrixDimensions) throws -> EvaluationKeyConfig
    {
        if dimensions.rowCount == 1 {
            // extractDenseRow is a No-op, so no evaluation key required
            return EvaluationKeyConfig()
        }
        guard let simdDimensions = encryptionParameters.simdDimensions(for: Scheme.self) else {
            throw PnnsError.simdEncodingNotSupported(for: encryptionParameters)
        }
        let degree = encryptionParameters.polyDegree
        var galoisElements = [GaloisElement.swappingRows(degree: degree)]
        let columnCountPowerOfTwo = dimensions.columnCount.nextPowerOfTwo
        if columnCountPowerOfTwo != simdDimensions.columnCount {
            try galoisElements.append(GaloisElement.rotatingColumns(by: columnCountPowerOfTwo, degree: degree))
        }
        return EvaluationKeyConfig(galoisElements: galoisElements)
    }

    /// Extracts a ciphertext matrix with a single row and `.denseRow` packing.
    /// - Parameters:
    ///   - rowIndex: Row index to extract
    ///   - evaluationKey: Evaluation key; must have `CiphertextMatrix/extractDenseRow` configuration
    /// - Returns: A ciphertext matrix in `.denseRow` format with 1 row
    /// - Throws: Error upon failure to extract the row.
    @inlinable
    package func extractDenseRow(rowIndex: Int, evaluationKey: EvaluationKey<Scheme>) throws -> Self
        where Format == Scheme.CanonicalCiphertextFormat
    {
        precondition((0..<dimensions.rowCount).contains(rowIndex))
        guard packing == .denseRow else {
            throw PnnsError.wrongMatrixPacking(got: packing, expected: .denseRow)
        }
        guard simdDimensions.rowCount == 2 else {
            throw PnnsError.incorrectSimdRowsCount(got: simdDimensions.rowCount, expected: 2)
        }

        let columnCountPowerOfTwo = dimensions.columnCount.nextPowerOfTwo
        let degree = context.degree.nextPowerOfTwo
        let rowsPerSimdRow = simdDimensions.columnCount / columnCountPowerOfTwo
        let rowsPerCiphertext = rowsPerSimdRow * simdDimensions.rowCount
        let ciphertextIndex = rowIndex / rowsPerCiphertext
        if rowCount == 1 {
            return self
        }

        // Suppose, e.g., N=16, columnCount = 2, and the ciphertext data encrypts 2 rows: [1, 2] and [3, 4].
        // These rows are packed in the ciphertext SIMD simd rows as
        // [[1, 2, 3, 4, 1, 2, 3, 4],
        //  [1, 2, 3, 4, 1, 2, 3, 4]].
        // Suppose ciphertextRowIndex == 1, i.e., we want to return an encryption of
        // [[3, 4, 3, 4, 3, 4, 3, 4], [3, 4, 3, 4, 3, 4, 3, 4]]

        //  Returns the SIMD slot indices for the `rowIndex`'th row of the ciphertext matrix.
        func simdSlotIndices(rowIndex: Int) -> Range<Int> {
            precondition((0..<dimensions.rowCount).contains(rowIndex))
            let ciphertextRowIndex = rowIndex % rowsPerCiphertext
            let batchStart = ciphertextRowIndex * columnCountPowerOfTwo
            var batchIndices = (batchStart..<batchStart + columnCountPowerOfTwo)
            // Ensure no repeated values span multiple SIMD rows
            let overflowsSimdRow = batchIndices.contains(simdDimensions.columnCount)
            if overflowsSimdRow {
                batchIndices = (simdDimensions.columnCount..<simdDimensions.columnCount + columnCountPowerOfTwo)
            } else if batchIndices.upperBound > simdDimensions.columnCount {
                let padding = simdColumnCount % columnCountPowerOfTwo
                batchIndices = (batchIndices.startIndex + padding..<batchIndices.endIndex + padding)
            }
            // The last ciphertext pads until the end of the ciphertext.
            if ciphertextIndex == ciphertexts.indices.last {
                let upperBound = batchIndices.endIndex.nextMultiple(of: simdDimensions.columnCount, variableTime: true)
                batchIndices = batchIndices.startIndex..<upperBound
            }
            return batchIndices
        }
        let batchIndices = simdSlotIndices(rowIndex: rowIndex)

        // The number of rows in covered by `batchIndices`
        let rowCountInBatch = {
            var lastRowIndexInBatch = rowIndex + 1
            while lastRowIndexInBatch < dimensions.rowCount,
                  simdSlotIndices(rowIndex: lastRowIndexInBatch).upperBound == batchIndices.upperBound
            {
                lastRowIndexInBatch += 1
            }
            var firstRowIndexInBatch = rowIndex > 0 ? rowIndex - 1 : 0
            while firstRowIndexInBatch > 0,
                  simdSlotIndices(rowIndex: firstRowIndexInBatch).upperBound == batchIndices.upperBound
            {
                firstRowIndexInBatch -= 1
            }
            return lastRowIndexInBatch - firstRowIndexInBatch
        }()

        // First, we mask out just the ciphertext data row vector e.g.,
        // plaintextMask = [[0, 0, 1, 1, 0, 0, 1, 1],
        //                  [0, 0, 0, 0, 0, 0, 0, 0]]
        let (plaintextMask, copiesInMask) = try {
            var repeatMask = Array(repeating: Scalar(1), count: columnCountPowerOfTwo)
            repeatMask += Array(repeating: 0, count: columnCountPowerOfTwo * (rowCountInBatch - 1))
            // pad to next power of two
            repeatMask += Array(repeating: 0, count: repeatMask.count.nextPowerOfTwo - repeatMask.count)

            var mask = Array(repeating: Scalar(0), count: batchIndices.lowerBound)
            var repeatCountInMask = 0
            while mask.count < batchIndices.upperBound {
                mask += repeatMask
                repeatCountInMask += 1
            }
            mask = Array(mask.prefix(degree))
            let plaintext: Plaintext<Scheme, Eval> = try context.encode(values: mask, format: .simd)
            return (plaintext, repeatCountInMask)
        }()

        var ciphertextEval = try ciphertexts[ciphertextIndex].convertToEvalFormat()
        try ciphertextEval *= plaintextMask
        var ciphertext = try ciphertextEval.convertToCanonicalFormat()
        // e.g., `ciphertext` now encrypts
        // [[0, 0, 3, 4, 0, 0, 3, 4],
        //  [0, 0, 0, 0, 0, 0, 0, 0]]

        // Replicate the values across one SIMD row by rotating and adding.
        let rotateCount = simdColumnCount / (copiesInMask * columnCountPowerOfTwo) - 1
        var ciphertextCopyRight = ciphertext
        for _ in 0..<rotateCount {
            try ciphertextCopyRight.rotateColumns(by: columnCountPowerOfTwo, using: evaluationKey)
            try ciphertext += ciphertextCopyRight
        }
        // e.g., `ciphertext` now encrypts
        // [[3, 4, 3, 4, 3, 4, 3, 4],
        //  [0, 0, 0, 0, 0, 0, 0, 0]]

        // Duplicate values to both SIMD rows
        var ciphertextCopy = ciphertext
        try ciphertextCopy.swapRows(using: evaluationKey)
        try ciphertext += ciphertextCopy
        // e.g., `ciphertext` now encrypts
        // [[3, 4, 3, 4, 3, 4, 3, 4],
        //  [3, 4, 3, 4, 3, 4, 3, 4]]

        return try CiphertextMatrix(
            dimensions: MatrixDimensions(rowCount: 1, columnCount: columnCount),
            packing: packing,
            ciphertexts: [ciphertext])
    }

    /// Computes the noise budget of the ciphertext matrix.
    ///
    /// The *noise budget* of the each ciphertext in the matrix decreases throughout HE operations. Once a
    /// ciphertext's noise budget is
    /// below
    /// `HeScheme/minNoiseBudget`, decryption may yield inaccurate plaintexts.
    /// - Parameters:
    ///   - secretKey: Secret key.
    ///   - variableTime: If `true`, indicates the secret key coefficients may be leaked through timing.
    /// - Returns: The noise budget.
    /// - Throws: Error upon failure to compute the noise budget.
    /// - Warning: Leaks `secretKey` through timing. Should be used for testing only.
    /// - Warning: The noise budget depends on the encrypted message, which is impractical to know apriori. So this
    /// function should be treated only as a rough proxy for correct decryption, rather than a source of truth.
    ///   See Section 2 of <https://eprint.iacr.org/2016/510.pdf> for more details.
    @inlinable
    func noiseBudget(using secretKey: Scheme.SecretKey, variableTime: Bool) throws -> Double {
        try ciphertexts.map { ciphertext in
            try ciphertext.noiseBudget(using: secretKey, variableTime: variableTime)
        }.min() ?? -Double.infinity
    }
}
