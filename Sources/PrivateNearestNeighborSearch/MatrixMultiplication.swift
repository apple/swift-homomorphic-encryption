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

public import _HomomorphicEncryptionExtras
public import Algorithms
public import AsyncAlgorithms
import Foundation
public import HomomorphicEncryption
public import ModularArithmetic

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
        // Ensure babyStep >= giantStep for correct algorithm behavior.
        // The baby-step giant-step algorithm requires this ordering.
        if babyStep >= giantStep {
            self.babyStep = babyStep
            self.giantStep = giantStep
        } else {
            self.babyStep = giantStep
            self.giantStep = babyStep
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let vectorDimension = try container.decode(Int.self, forKey: .vectorDimension)
        let babyStep = try container.decode(Int.self, forKey: .babyStep)
        let giantStep = try container.decode(Int.self, forKey: .giantStep)
        // Use the normalizing initializer
        self.init(vectorDimension: vectorDimension, babyStep: babyStep, giantStep: giantStep)
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
    // swiftformat:disable unusedArguments
    /// Computes the evaluation key configuration for matrix multiplication.
    /// - Parameters:
    ///   - plaintextMatrixDimensions: Dimensions of the plaintext matrix.
    ///   - encryptionParameters: Encryption paramterss
    ///   - maxQueryCount: Maximum number of queries in one batch. The returned`EvaluationKeyConfig` will support
    /// all batch sizes up to and including `maxQueryCount`.
    ///   - scheme: The metatype of the generic parameter `Scheme`.
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
        using evaluationKey: EvaluationKey<Scheme>) async throws -> [Scheme.CanonicalCiphertext]
    {
        // Extract BabyStepGiantStep from the packing to ensure consistency
        // between how data was packed and how it's accessed during multiplication
        guard case let .diagonal(babyStepGiantStep: babyStepGiantStep) = packing else {
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

        // 1) Compute v_j = theta^j(v)
        var rotatedStates: [Scheme.CanonicalCiphertext] = []
        rotatedStates.reserveCapacity(babyStepGiantStep.babyStep)

        var state = ciphertextVector.ciphertexts[0]
        for step in 0..<babyStepGiantStep.babyStep {
            rotatedStates.append(state)
            if step != babyStepGiantStep.babyStep - 1 {
                try await state.rotateColumns(by: -1, using: evaluationKey)
            }
        }
        let rotatedCiphertexts: [Scheme.EvalCiphertext] = try await .init(
            rotatedStates.async.map { state in
                try await state.convertToEvalFormat()
            })

        let resultCiphertextCount = dimensions.rowCount.dividingCeil(context.degree, variableTime: true)

        let generateInnerProduct: @Sendable (Int, Int) async throws
            -> Scheme.CanonicalCiphertext = { giantStepIndex, resultCiphertextIndex in
                let plaintextCount = min(
                    rotatedCiphertexts.count,
                    babyStepGiantStep.vectorDimension - babyStepGiantStep.babyStep * giantStepIndex)
                let plaintextRowIndices = (0..<plaintextCount).map { j in
                    resultCiphertextCount * (j + babyStepGiantStep.babyStep * giantStepIndex) + resultCiphertextIndex
                }
                let plaintextRows: [Plaintext<Scheme, Eval>] = try await .init(plaintextRowIndices.async.map { index in
                    try plaintexts[index].convertToEvalFormat()
                })

                let ciphertexts = rotatedCiphertexts[0..<plaintextRows.count]

                // 2) Compute w_k
                let innerProduct = try await ciphertexts.innerProduct(plaintexts: plaintextRows)
                return try await innerProduct.convertToCanonicalFormat()
            }

        return try await .init((0..<resultCiphertextCount).async
            .map { resultCiphertextIndex in
                let giantStepIndices = (0..<babyStepGiantStep.giantStep)
                let innerProductsToAdd: [Scheme.CanonicalCiphertext] = try await .init(giantStepIndices.async
                    .map { giantStepIndex in
                        try await generateInnerProduct(giantStepIndex, resultCiphertextIndex)
                    })
                return try await Scheme.rotateColumnsAndSumAsync(
                    innerProductsToAdd,
                    by: -babyStepGiantStep.babyStep,
                    using: evaluationKey)
            })
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
        using evaluationKey: EvaluationKey<Scheme>) async throws
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

        let innerProductsChunked: [[Scheme.CanonicalCiphertext]] = try await .init((0..<ciphertextMatrix.rowCount).async
            .map { rowIndex in
                let ciphertextRow = try await ciphertextMatrix.extractDenseRow(
                    rowIndex: rowIndex,
                    evaluationKey: evaluationKey)
                return try await mulTranspose(vector: ciphertextRow, using: evaluationKey)
            })
        var innerProducts: [Scheme.CanonicalCiphertext] = innerProductsChunked.flatMap(\.self)

        // Pack resulting ciphertexts such that no two result ciphertexts span multiple simd rows.
        let columnsPerSimdRowCount = simdColumnCount / dimensions.rowCount
        if columnsPerSimdRowCount > 0 {
            let columnsPerCiphertextCount = simdRowCount * columnsPerSimdRowCount
            let packedCiphertexts: [Scheme.CanonicalCiphertext] = try await .init(innerProducts
                .chunks(ofCount: columnsPerCiphertextCount).async
                .map { columnsForCiphertext in
                    let packedRows: [Scheme.CanonicalCiphertext] = try await .init(columnsForCiphertext
                        .chunks(ofCount: columnsPerSimdRowCount).async.map { columnsForRow in
                            try await Scheme.rotateColumnsAndSumAsync(
                                Array(columnsForRow),
                                by: dimensions.rowCount,
                                using: evaluationKey)
                        })
                    if columnsForCiphertext.count > columnsPerSimdRowCount {
                        return try await Scheme.swapRowsAndAddAsync(
                            swapping: packedRows[1],
                            addingTo: packedRows[0],
                            using: evaluationKey)
                    }
                    return packedRows[0]
                })
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
