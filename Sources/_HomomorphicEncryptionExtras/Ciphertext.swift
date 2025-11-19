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

public import HomomorphicEncryption

extension Ciphertext {
    /// Rotates the columns of the ciphertext by combining multiple rotation steps corresponding to Galois elements
    /// available in the `evaluationKey`.
    ///
    /// - Parameters:
    ///   - step: Number of slots to rotate. Negative values indicate a left rotation, and positive values indicate a
    /// right rotation. Must have absolute value in `[1, N / 2 - 1]` where `N` is the RLWE ring dimension, given by
    /// `EncryptionParameters/polyDegree`.
    ///   - evaluationKey: Evaluation key to use in the HE computation. Must contain Galois elements which can be
    /// combined for the desired rotation step.
    /// - Throws: Error upon failure to rotate ciphertext's columns.
    /// - seealso: `HeScheme/_rotateColumnsMultiStep(of:by:using:)` for an alternative API and more information.
    @inlinable
    public mutating func rotateColumnsMultiStep(by step: Int, using evaluationKey: EvaluationKey<Scheme>) throws
        where Format == Scheme.CanonicalCiphertextFormat
    {
        try Scheme.rotateColumnsMultiStep(of: &self, by: step, using: evaluationKey)
    }
}
