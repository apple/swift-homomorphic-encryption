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

import _HomomorphicEncryptionExtras
import Algorithms
import Foundation
import HomomorphicEncryption
import ModularArithmetic

/// Pre-computed values for matrix-vector multiplication using baby-step, giant-step algorithm.
///
/// - seealso: Section 6.3 of <https://eprint.iacr.org/2018/244.pdf>.
public struct BabyStepGiantStep: Codable, Equatable, Hashable, Sendable {
    /// Dimension of the vector; "D" in the reference.
    public let vectorDimension: Int
    /// Baby step; "g" in the reference.
    public let babyStep: Int
    /// Giant step; "h" in the reference.
    public let giantStep: Int

    public init(vectorDimension: Int, babyStep: Int, giantStep: Int) {
        self.vectorDimension = vectorDimension
        self.babyStep = babyStep
        self.giantStep = giantStep
    }

    @inlinable
    public init(vectorDimension: Int, babyStep: Int) {
        let dimension = vectorDimension.nextPowerOfTwo
        let giantStep = dimension.dividingCeil(babyStep, variableTime: true)
        self.init(
            vectorDimension: vectorDimension,
            babyStep: babyStep,
            giantStep: giantStep)
    }

    @inlinable
    public init(vectorDimension: Int) {
        let dimension = vectorDimension.nextPowerOfTwo
        let babyStep = Int(Double(dimension).squareRoot().rounded(.up))
        self.init(vectorDimension: dimension, babyStep: babyStep)
    }
}

/// Utilities for matrix multiplication.
public enum MatrixMultiplication {
    /// Computes the evaluation key configuration for matrix multiplication.
    /// - Parameters:
    ///   - plaintextMatrixDimensions: Dimensions of the plaintext matrix.
    ///   - maxQueryCount: Maximum number of queries in one batch. The returned`EvaluationKeyConfig` will support all
    ///   - encryptionParameters: Encryption paramterss
    ///   - scheme: The metatype of the generic parameter `Scheme`.
    /// batch sizes up to and including `maxQueryCount`.
    /// - Returns: The evaluation key configuration.
    /// - Throws: Error upon failure to compute the configuration.
    @inlinable
    package static func evaluationKeyConfig<Scheme: HeScheme>(
        plaintextMatrixDimensions: MatrixDimensions,
        maxQueryCount: Int,
        encryptionParameters: EncryptionParameters<Scheme.Scalar>,
        scheme _: Scheme.Type) throws -> EvaluationKeyConfig
    {
        guard let simdColumnCount = encryptionParameters.simdDimensions(for: Scheme.self)?.columnCount else {
            throw PnnsError.simdEncodingNotSupported(for: encryptionParameters)
        }
        let degree = encryptionParameters.polyDegree
        let babyStepGiantStep = BabyStepGiantStep(vectorDimension: plaintextMatrixDimensions.columnCount)
        var galoisElements = try [
            GaloisElement.rotatingColumns(
                by: -1,
                degree: degree),
            GaloisElement.rotatingColumns(
                by: -babyStepGiantStep.babyStep,
                degree: degree),
            GaloisElement.swappingRows(degree: degree),
        ]

        let resultColumnsPerRowCount = simdColumnCount / plaintextMatrixDimensions.rowCount
        if resultColumnsPerRowCount > 1 {
            try galoisElements.append(GaloisElement.rotatingColumns(by: 1, degree: degree))
            if simdColumnCount > 16 {
                try galoisElements.append(GaloisElement.rotatingColumns(by: 16, degree: degree))
            }
            if simdColumnCount > 256 {
                try galoisElements.append(GaloisElement.rotatingColumns(by: 256, degree: degree))
            }
        }
        let multiplicationConfig = EvaluationKeyConfig(
            galoisElements: galoisElements,
            hasRelinearizationKey: false)

        let ciphertextMatrixDimensions = try MatrixDimensions(
            rowCount: maxQueryCount,
            columnCount: plaintextMatrixDimensions.columnCount)
        let denseRowConfig: EvaluationKeyConfig = try CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat>
            .extractDenseRowConfig(
                for: encryptionParameters,
                dimensions: ciphertextMatrixDimensions)

        return [multiplicationConfig, denseRowConfig].union()
    }
}

extension PlaintextMatrix {
    /// Computes matrix product between the `PlaintextMatrix` and transpose of row vector encrypted in `vector`.
    /// - Parameters:
    ///   - ciphertextVector: Encrypted dense-row packed vector.
    ///   - evaluationKey: Evaluation key to perform BabyStepGiantStep rotations.
    /// - Returns: Encrypted dense-column packed vector containing dot products.
    /// - Throws: Error upon failure to compute the inner product.
    @inlinable
    package func mulTranspose(
        vector ciphertextVector: CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat>,
        using evaluationKey: EvaluationKey<Scheme>) throws -> [Scheme.CanonicalCiphertext]
    {
        guard case .diagonal = packing else {
            let expectedBsgs = BabyStepGiantStep(vectorDimension: dimensions.columnCount)
            throw PnnsError.wrongMatrixPacking(got: packing, expected: .diagonal(babyStepGiantStep: expectedBsgs))
        }
        guard ciphertextVector.packing == .denseRow else {
            throw PnnsError.wrongMatrixPacking(got: ciphertextVector.packing, expected: .denseRow)
        }
        guard ciphertextVector.context == context else {
            throw PnnsError.wrongContext(got: ciphertextVector.context, expected: context)
        }
        guard ciphertextVector.dimensions.columnCount == dimensions.columnCount else {
            throw PnnsError.invalidMatrixDimensions(ciphertextVector.dimensions)
        }
        guard ciphertextVector.rowCount == 1 else {
            throw PnnsError.invalidMatrixDimensions(ciphertextVector.dimensions)
        }
        guard ciphertextVector.ciphertexts.count == 1 else {
            throw PnnsError.wrongCiphertextCount(got: ciphertextVector.ciphertexts.count, expected: 1)
        }

        // If the plaintext data matrix is
        // [[1,  2,  3,  4],
        //  [5,  6,  7,  8],
        //  [9,  10, 11, 12],
        //  [13, 14, 15, 16]]
        // it can be packed diagonally as
        // [[1, 6, 11, 16],
        //  [2, 7, 12, 13],
        //  [3, 8, 9,  14],
        //  [4, 5, 10, 15]]
        // Then, performing a dot product with the encrypted vector [1, 2, 3, 4]
        // is done by a series of ciphertxt-plaintext multiplications, ciphertext
        // rotations, and ciphertext-ciphertext additions:
        // [1, 6, 11, 16] * [1, 2, 3, 4] => [1, 12, 33, 64] |
        // [2, 7, 12, 13] * [2, 3, 4, 1] => [4, 21, 48, 13] |
        // [3, 8, 9,  14] * [3, 4, 1, 2] => [9, 32, 9,  28] |
        // [4, 5, 10, 15] * [4, 1, 2, 3] => [16, 5, 20, 45] | - + -> [30, 70, 110, 150]
        // We extend this basic idea using baby-step giant-step logic from Section 6.3 of
        // https://eprint.iacr.org/2018/244.pdf.

        let babyStepGiantStep = BabyStepGiantStep(vectorDimension: dimensions.columnCount)

        // 1) Compute v_j = theta^j(v)
        var rotatedCiphertexts: [Scheme.EvalCiphertext] = []
        rotatedCiphertexts.reserveCapacity(babyStepGiantStep.babyStep)
        var state = ciphertextVector.ciphertexts[0]
        for step in 0..<babyStepGiantStep.babyStep {
            try rotatedCiphertexts.append(state.convertToEvalFormat())
            if step != babyStepGiantStep.babyStep - 1 {
                try state.rotateColumns(by: -1, using: evaluationKey)
            }
        }

        let resultCiphertextCount = dimensions.rowCount.dividingCeil(context.degree, variableTime: true)
        let zeroCiphertext: Scheme.CanonicalCiphertext = try Ciphertext.zero(context: context)
        var resultCiphertexts: [Scheme.CanonicalCiphertext] = Array(
            repeating: zeroCiphertext,
            count: resultCiphertextCount)

        for resultCiphertextIndex in 0..<resultCiphertextCount {
            for giantStepIndex in (0..<babyStepGiantStep.giantStep).reversed() {
                let plaintextCount = min(
                    rotatedCiphertexts.count,
                    babyStepGiantStep.vectorDimension - babyStepGiantStep.babyStep * giantStepIndex)
                let plaintextRows = try (0..<plaintextCount).map { j in
                    j + babyStepGiantStep.babyStep * giantStepIndex
                }.map { i in
                    let index = resultCiphertextCount * i + resultCiphertextIndex
                    return try plaintexts[index].convertToEvalFormat()
                }
                let ciphertexts = rotatedCiphertexts[0..<plaintextRows.count]

                // 2) Compute w_k
                let innerProduct = try Scheme.innerProduct(ciphertexts: ciphertexts, plaintexts: plaintextRows)
                    .convertToCanonicalFormat()

                // 3) Compute w incrementally
                try resultCiphertexts[resultCiphertextIndex].rotateColumns(
                    by: -babyStepGiantStep.babyStep,
                    using: evaluationKey)
                try resultCiphertexts[resultCiphertextIndex] += innerProduct
            }
        }
        return resultCiphertexts
    }

    /// Computes matrix product between the `PlaintextMatrix` and transpose of row vectors encrypted in `matrix`.
    /// - Parameters:
    ///   - ciphertextMatrix: Encrypted dense-row packed matrix.
    ///   - evaluationKey: Evaluation key to perform BabyStepGiantStep rotations, extracting dense column, and for
    /// packing ciphertexts.
    /// - Returns: Encrypted dense-column packed matrix.
    /// - Throws: Error upon failure to compute the product.
    @inlinable
    package func mulTranspose(
        matrix ciphertextMatrix: CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat>,
        using evaluationKey: EvaluationKey<Scheme>) throws
        -> CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat>
    {
        guard dimensions.columnCount == ciphertextMatrix.dimensions.columnCount else {
            throw PnnsError.invalidMatrixDimensions(ciphertextMatrix.dimensions)
        }
        guard ciphertextMatrix.context == context else {
            throw PnnsError.wrongContext(got: ciphertextMatrix.context, expected: context)
        }
        guard case .diagonal = packing else {
            let expectedBsgs = BabyStepGiantStep(vectorDimension: dimensions.columnCount)
            throw PnnsError.wrongMatrixPacking(got: packing, expected: .diagonal(babyStepGiantStep: expectedBsgs))
        }
        guard case .denseRow = ciphertextMatrix.packing else {
            throw PnnsError.wrongMatrixPacking(got: ciphertextMatrix.packing, expected: .denseRow)
        }
        guard simdDimensions.rowCount == 2 else {
            throw PnnsError.incorrectSimdRowsCount(got: simdDimensions.rowCount, expected: 2)
        }

        var innerProducts: [Scheme.CanonicalCiphertext] = try (0..<ciphertextMatrix.rowCount).map { rowIndex in
            let ciphertextRow = try ciphertextMatrix.extractDenseRow(rowIndex: rowIndex, evaluationKey: evaluationKey)
            return try mulTranspose(vector: ciphertextRow, using: evaluationKey)
        }.flatMap(\.self)

        // Pack resulting ciphertexts such that no two result ciphertexts span multiple simd rows.
        let columnsPerSimdRowCount = simdColumnCount / dimensions.rowCount
        if columnsPerSimdRowCount > 0 {
            let columnsPerCiphertextCount = simdRowCount * columnsPerSimdRowCount
            let packedCiphertexts = try innerProducts.chunks(ofCount: columnsPerCiphertextCount)
                .map { columnsForCiphertext in
                    var packedRows: [Scheme.CanonicalCiphertext] = try columnsForCiphertext
                        .chunks(ofCount: columnsPerSimdRowCount).map { columnsForRow in
                            guard var packedRow = columnsForRow.last else {
                                throw PnnsError.emptyCiphertextArray
                            }
                            for column in columnsForRow.dropLast().reversed() {
                                try packedRow.rotateColumnsMultiStep(by: dimensions.rowCount, using: evaluationKey)
                                try packedRow += column
                            }
                            return packedRow
                        }
                    if columnsForCiphertext.count > columnsPerSimdRowCount {
                        try packedRows[1].swapRows(using: evaluationKey)
                        return try packedRows[0] + packedRows[1]
                    }
                    return packedRows[0]
                }
            innerProducts = packedCiphertexts
        }
        let resultMatrixDimensions = try MatrixDimensions(
            rowCount: dimensions.rowCount,
            columnCount: ciphertextMatrix.rowCount)
        return try CiphertextMatrix(
            dimensions: resultMatrixDimensions,
            packing: .denseColumn,
            ciphertexts: innerProducts)
    }
}
