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

extension HeScheme {
    /// Rotates the columns of a ciphertext throw multiple steps in async way.
    /// - seealso: `HeScheme/rotateColumnsAsync(of:by:using:)` for the single-step API.
    @inlinable
    public static func rotateColumnsMultiStepAsync(
        of ciphertext: inout CanonicalCiphertext,
        by step: Int,
        using evaluationKey: EvaluationKey) async throws
    {
        if step == 0 {
            return
        }

        guard let galoisKey = evaluationKey._galoisKey else {
            throw HeError.missingGaloisKey
        }

        // Short-circuit to single rotation if possible.
        let degree = ciphertext.degree
        let galoisElement = try GaloisElement.rotatingColumns(by: step, degree: degree)
        if galoisKey._keys.keys.contains(galoisElement) {
            try await rotateColumnsAsync(of: &ciphertext, by: step, using: evaluationKey)
            return
        }

        let galoisElements = Array(galoisKey._keys.keys)
        let steps = GaloisElement.stepsFor(elements: galoisElements, degree: degree).values.compactMap(\.self)

        let positiveStep = if step < 0 {
            step + degree / 2
        } else {
            step
        }

        let plan = try GaloisElement._planMultiStep(supportedSteps: steps, step: positiveStep, degree: degree)
        guard let plan else {
            throw HeError.invalidRotationStep(step: step, degree: degree)
        }
        for (step, count) in plan {
            for _ in 0..<count {
                try await rotateColumnsAsync(of: &ciphertext, by: step, using: evaluationKey)
            }
        }
    }

    ///  Rotates the columns of a ciphertext through one or more rotations.
    /// - seealso: `HeScheme/rotateColumns(of:by:using:)` for the single-step API.
    @inlinable
    public static func rotateColumnsMultiStep(
        of ciphertext: inout CanonicalCiphertext,
        by step: Int,
        using evaluationKey: EvaluationKey) throws
    {
        if step == 0 {
            return
        }

        guard let galoisKey = evaluationKey._galoisKey else {
            throw HeError.missingGaloisKey
        }

        // Short-circuit to single rotation if possible.
        let degree = ciphertext.degree
        let galoisElement = try GaloisElement.rotatingColumns(by: step, degree: degree)
        if galoisKey._keys.keys.contains(galoisElement) {
            try ciphertext.rotateColumns(by: step, using: evaluationKey)
            return
        }

        let galoisElements = Array(galoisKey._keys.keys)
        let steps = GaloisElement.stepsFor(elements: galoisElements, degree: degree).values.compactMap(\.self)

        let positiveStep = if step < 0 {
            step + degree / 2
        } else {
            step
        }

        let plan = try GaloisElement._planMultiStep(supportedSteps: steps, step: positiveStep, degree: degree)
        guard let plan else {
            throw HeError.invalidRotationStep(step: step, degree: degree)
        }
        for (step, count) in plan {
            try (0..<count).forEach { _ in try ciphertext.rotateColumns(by: step, using: evaluationKey) }
        }
    }

    /// Sum up an array of ciphertexts after rotate their columns one-by-one.
    ///
    /// The i-th (starting from 0) ciphertext is rotated by i * `step` steps before adding up.
    /// - Parameters:
    ///  - ciphertexts: ciphertexts to be added up.
    ///  - step: the rotation steps for each ciphertext.
    /// - evaluationKey: the evaluation key for rotation.
    /// - Throws: Error upon failure to compute the inverse.
    @inlinable
    public static func rotateColumnsAndSumAsync(
        _ ciphertexts: consuming [CanonicalCiphertext],
        by step: Int,
        using evaluationKey: EvaluationKey) async throws -> CanonicalCiphertext
    {
        guard var accumulator = ciphertexts.popLast() else {
            preconditionFailure("No ciphertexts to sum up.")
        }
        if ciphertexts.isEmpty {
            return accumulator
        }

        for ciphertext in ciphertexts.reversed() {
            try await rotateColumnsMultiStepAsync(
                of: &accumulator,
                by: step,
                using: evaluationKey)
            try await addAssignAsync(&accumulator, ciphertext)
        }
        return accumulator
    }

    /// Sum up two ciphertexts after swap the row of second one.
    ///
    /// - Parameters:
    ///  - ciphertexts: ciphertexts to be added up.
    ///  - step: the rotation steps for each ciphertext.
    /// - evaluationKey: the evaluation key for rotation.
    /// - Throws: Error upon failure to compute the inverse.
    @inlinable
    public static func swapRowsAndAddAsync(
        swapping ciphertext0: consuming CanonicalCiphertext,
        addingTo ciphertext1: consuming CanonicalCiphertext,
        using evaluationKey: EvaluationKey) async throws -> CanonicalCiphertext
    {
        try await swapRowsAsync(of: &ciphertext0, using: evaluationKey)
        try await addAssignAsync(&ciphertext0, ciphertext1)
        return ciphertext0
    }
}
