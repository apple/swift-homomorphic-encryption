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
import HomomorphicEncryption

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

/// Helper function to compute evaluation key used in computing multiplication with a vector.
package enum MatrixMultiplication {
    @inlinable
    package static func evaluationKeyConfig(
        plaintextMatrixDimensions: MatrixDimensions,
        encryptionParameters: EncryptionParameters<some HeScheme>) throws -> EvaluationKeyConfig
    {
        let babyStepGiantStep = BabyStepGiantStep(vectorDimension: plaintextMatrixDimensions.columnCount)
        return try EvaluationKeyConfig(
            galoisElements: [
                GaloisElement.rotatingColumns(
                    by: -1,
                    degree: encryptionParameters.polyDegree),
                GaloisElement.rotatingColumns(
                    by: -babyStepGiantStep.babyStep,
                    degree: encryptionParameters.polyDegree),
            ],
            hasRelinearizationKey: false)
    }
}

extension PlaintextMatrix {
    /// Computes dot product of each row in the PlaintextMatrix with vector encrypted in `ciphertextVector`.
    ///
    /// - Parameters:
    ///   - ciphertextVector: Encrypted dense-row packed vector.
    ///   - evaluationKey: Evaluation key to perform BabyStepGiantStep rotations.
    /// - Returns: Encrypted dense-column packed vector containing dot products.
    /// - Throws: Error upon failure to compute the inner product.
    @inlinable
    func mul(
        ciphertextVector: CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat>,
        using evaluationKey: EvaluationKey<Scheme>) throws -> CiphertextMatrix<Scheme, Scheme.CanonicalCiphertextFormat>
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
        guard dimensions.columnCount == ciphertextVector.dimensions.rowCount else {
            throw PnnsError.invalidMatrixDimensions(ciphertextVector.dimensions)
        }
        guard ciphertextVector.columnCount == 1 else {
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
        let ciphertexMatrixDimensions = try MatrixDimensions(
            rowCount: dimensions.rowCount,
            columnCount: 1)
        return try CiphertextMatrix(
            dimensions: ciphertexMatrixDimensions,
            packing: .denseColumn,
            ciphertexts: resultCiphertexts)
    }
}
