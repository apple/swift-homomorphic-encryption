// Copyright 2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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

/// The functions in this extension are the default implementation of async methods of HE scheme.
extension HeScheme {
    // swiftlint:disable missing_docs
    @inlinable
    public static func rotateColumnsAsync(
        of ciphertext: inout CanonicalCiphertext,
        by step: Int,
        using evaluationKey: EvaluationKey) async throws
    {
        try rotateColumns(of: &ciphertext, by: step, using: evaluationKey)
    }

    @inlinable
    public static func swapRowsAsync(
        of ciphertext: inout CanonicalCiphertext,
        using evaluationKey: EvaluationKey) async throws
    {
        try swapRows(of: &ciphertext, using: evaluationKey)
    }

    @inlinable
    public static func addAssignAsync(_ lhs: inout CoeffPlaintext, _ rhs: CoeffPlaintext) async throws {
        try addAssign(&lhs, rhs)
    }

    @inlinable
    public static func addAssignAsync(_ lhs: inout EvalPlaintext, _ rhs: EvalPlaintext) async throws {
        try addAssign(&lhs, rhs)
    }

    @inlinable
    public static func addAssignCoeffAsync(_ lhs: inout CoeffCiphertext, _ rhs: CoeffCiphertext) async throws {
        try addAssignCoeff(&lhs, rhs)
    }

    @inlinable
    public static func addAssignEvalAsync(_ lhs: inout EvalCiphertext, _ rhs: EvalCiphertext) async throws {
        try addAssignEval(&lhs, rhs)
    }

    @inlinable
    public static func subAssignCoeffAsync(_ lhs: inout CoeffCiphertext, _ rhs: CoeffCiphertext) async throws {
        try subAssignCoeff(&lhs, rhs)
    }

    @inlinable
    public static func subAssignEvalAsync(_ lhs: inout EvalCiphertext, _ rhs: EvalCiphertext) async throws {
        try subAssignEval(&lhs, rhs)
    }

    @inlinable
    public static func addAssignCoeffAsync(
        _ ciphertext: inout CoeffCiphertext,
        _ plaintext: CoeffPlaintext) async throws
    {
        try addAssignCoeff(&ciphertext, plaintext)
    }

    @inlinable
    public static func addAssignEvalAsync(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) async throws {
        try addAssignEval(&ciphertext, plaintext)
    }

    @inlinable
    public static func subAssignCoeffAsync(
        _ ciphertext: inout CoeffCiphertext,
        _ plaintext: CoeffPlaintext) async throws
    {
        try subAssignCoeff(&ciphertext, plaintext)
    }

    @inlinable
    public static func subAssignEvalAsync(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) async throws {
        try subAssignEval(&ciphertext, plaintext)
    }

    @inlinable
    public static func subCoeffAsync(_ plaintext: CoeffPlaintext,
                                     _ ciphertext: CoeffCiphertext) async throws -> CoeffCiphertext
    {
        try subCoeff(plaintext, ciphertext)
    }

    @inlinable
    public static func subEvalAsync(_ plaintext: EvalPlaintext,
                                    _ ciphertext: EvalCiphertext) async throws -> EvalCiphertext
    {
        try subEval(plaintext, ciphertext)
    }

    @inlinable
    public static func mulAssignAsync(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) async throws {
        try mulAssign(&ciphertext, plaintext)
    }

    @inlinable
    public static func negAssignCoeffAsync(_ ciphertext: inout CoeffCiphertext) async {
        negAssign(&ciphertext)
    }

    @inlinable
    public static func negAssignEvalAsync(_ ciphertext: inout EvalCiphertext) async {
        negAssign(&ciphertext)
    }

    @inlinable
    public static func innerProductAsync(
        _ lhs: some Collection<CanonicalCiphertext>,
        _ rhs: some Collection<CanonicalCiphertext>) async throws
        -> CanonicalCiphertext
    {
        try innerProduct(lhs, rhs)
    }

    @inlinable
    public static func innerProductAsync(ciphertexts: some Collection<EvalCiphertext>,
                                         plaintexts: some Collection<EvalPlaintext>) async throws -> EvalCiphertext
    {
        try innerProduct(ciphertexts: ciphertexts, plaintexts: plaintexts)
    }

    @inlinable
    public static func innerProductAsync(ciphertexts: some Collection<EvalCiphertext>,
                                         plaintexts: some Collection<EvalPlaintext?>) async throws -> EvalCiphertext
    {
        try innerProduct(ciphertexts: ciphertexts, plaintexts: plaintexts)
    }

    @inlinable
    public static func mulAssignAsync(_ lhs: inout CanonicalCiphertext, _ rhs: CanonicalCiphertext) async throws {
        try mulAssign(&lhs, rhs)
    }

    @inlinable
    public static func addAssignAsync(_ lhs: inout CanonicalCiphertext, _ rhs: CanonicalCiphertext) async throws {
        try addAssign(&lhs, rhs)
    }

    @inlinable
    public static func subAssignAsync(_ lhs: inout CanonicalCiphertext, _ rhs: CanonicalCiphertext) async throws {
        try subAssign(&lhs, rhs)
    }

    @inlinable
    public static func subAssignAsync(
        _ ciphertext: inout CanonicalCiphertext,
        _ plaintext: CoeffPlaintext) async throws
    {
        try subAssign(&ciphertext, plaintext)
    }

    @inlinable
    public static func subAssignAsync(_ ciphertext: inout CanonicalCiphertext,
                                      _ plaintext: EvalPlaintext) async throws
    {
        try subAssign(&ciphertext, plaintext)
    }

    @inlinable
    public static func subAsync(_ plaintext: CoeffPlaintext,
                                _ ciphertext: CanonicalCiphertext) async throws -> CanonicalCiphertext
    {
        try sub(plaintext, ciphertext)
    }

    @inlinable
    public static func subAsync(_ plaintext: EvalPlaintext,
                                _ ciphertext: CanonicalCiphertext) async throws -> CanonicalCiphertext
    {
        try sub(plaintext, ciphertext)
    }

    @inlinable
    public static func modSwitchDownAsync(_ ciphertext: inout CanonicalCiphertext) async throws {
        try modSwitchDown(&ciphertext)
    }

    @inlinable
    public static func applyGaloisAsync(
        ciphertext: inout CanonicalCiphertext,
        element: Int,
        using key: EvaluationKey) async throws
    {
        try applyGalois(ciphertext: &ciphertext, element: element, using: key)
    }

    @inlinable
    public static func relinearizeAsync(_ ciphertext: inout CanonicalCiphertext,
                                        using key: EvaluationKey) async throws
    {
        try relinearize(&ciphertext, using: key)
    }

    @inlinable
    public static func forwardNttAsync(_ ciphertext: inout CoeffCiphertext) async throws -> EvalCiphertext {
        try forwardNtt(&ciphertext)
    }

    @inlinable
    public static func inverseNttAsync(_ ciphertext: inout EvalCiphertext) async throws -> CoeffCiphertext {
        try inverseNtt(&ciphertext)
    }

    @inlinable
    public static func modSwitchDownToSingleAsync(_ ciphertext: inout CanonicalCiphertext) async throws {
        try modSwitchDownToSingle(&ciphertext)
    }

    @inlinable
    public static func multiplyPowerOfXAsync(_ ciphertext: inout CoeffCiphertext, power: Int) async throws {
        try multiplyPowerOfX(&ciphertext, power: power)
    }
    // swiftlint:enable missing_docs
}

// MARK: - Implementations generalized over PolyFormat

extension HeScheme {
    /// In-place ciphertext-plaintext addition: `ciphertext += plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to add; will store the sum.
    ///   - plaintext: Plaintext to add.
    /// - Throws: Error upon failure to add.
    /// - seealso: ``HeScheme/addAssign(_:_:)-407pg`` for a sync version.
    @inlinable
    public static func addAssignAsync<CiphertextFormat: PolyFormat, PlaintextFormat: PolyFormat>(
        _ ciphertext: inout Ciphertext<Self, CiphertextFormat>,
        _ plaintext: Plaintext<Self, PlaintextFormat>) async throws
    {
        // swiftlint:disable force_cast
        if CiphertextFormat.self == Coeff.self, PlaintextFormat.self == Coeff.self {
            var coeffCiphertext = ciphertext as! CoeffCiphertext
            try await addAssignCoeffAsync(&coeffCiphertext, plaintext as! CoeffPlaintext)
            ciphertext = coeffCiphertext as! Ciphertext<Self, CiphertextFormat>
        } else if CiphertextFormat.self == Eval.self, PlaintextFormat.self == Eval.self {
            var evalCiphertext = ciphertext as! EvalCiphertext
            try await addAssignEvalAsync(&evalCiphertext, plaintext as! EvalPlaintext)
            ciphertext = evalCiphertext as! Ciphertext<Self, CiphertextFormat>
        } else {
            throw HeError.unsupportedHeOperation(
                """
                Addition between ciphertext in \(CiphertextFormat.description) \
                and plaintext in \(PlaintextFormat.description).
                """)
        }
        // swiftlint:enable force_cast
    }

    /// In-place ciphertext addition: `lhs += rhs`.
    ///
    /// - Parameters:
    ///   - lhs: Ciphertext to add; will store the sum.
    ///   - rhs: Ciphertext to add.
    /// - Throws: Error upon failure to add.
    /// - seealso: ``HeScheme/addAssign(_:_:)-1sd4b`` for a sync version.
    @inlinable
    public static func addAssignAsync<LhsFormat: PolyFormat, RhsFormat: PolyFormat>(
        _ lhs: inout Ciphertext<Self, LhsFormat>,
        _ rhs: Ciphertext<Self, RhsFormat>) async throws
    {
        // swiftlint:disable force_cast
        if LhsFormat.self == Coeff.self {
            var lhsCoeffCiphertext = lhs as! CoeffCiphertext
            if RhsFormat.self == Coeff.self {
                try await addAssignCoeffAsync(&lhsCoeffCiphertext, rhs as! CoeffCiphertext)
            } else {
                fatalError("Unsupported Format \(RhsFormat.description)")
            }
            lhs = lhsCoeffCiphertext as! Ciphertext<Self, LhsFormat>
        } else if LhsFormat.self == Eval.self {
            var lhsEvalCiphertext = lhs as! EvalCiphertext
            if RhsFormat.self == Eval.self {
                try await addAssignEvalAsync(&lhsEvalCiphertext, rhs as! EvalCiphertext)
            } else {
                fatalError("Unsupported Format \(RhsFormat.description)")
            }
            lhs = lhsEvalCiphertext as! Ciphertext<Self, LhsFormat>
        } else {
            fatalError("Unsupported Format \(LhsFormat.description)")
        }
        // swiftlint:enable force_cast
    }
}
