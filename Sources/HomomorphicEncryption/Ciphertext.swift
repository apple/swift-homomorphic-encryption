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

/// Ciphertext type.
public struct Ciphertext<Scheme: HeScheme, Format: PolyFormat>: Equatable, Sendable {
    /// Context for HE computation.
    public let context: Context<Scheme>
    @usableFromInline var polys: [PolyRq<Scheme.Scalar, Format>]
    @usableFromInline var correctionFactor: Scheme.Scalar
    @usableFromInline var seed: [UInt8] = []

    /// The number of polynomials in the ciphertext.
    ///
    /// After a fresh encryption, the ciphertext has ``HeScheme/freshCiphertextPolyCount`` polynomials.
    /// The count may change during the course of HE operations, e.g. increase during ciphertext multiplication,
    /// or decrease during relinearization ``Ciphertext/relinearize(using:)``.
    public var polyCount: Int {
        polys.count
    }

    @inlinable
    init(
        context: Context<Scheme>,
        polys: [PolyRq<Scheme.Scalar, Format>],
        correctionFactor: Scheme.Scalar,
        seed: [UInt8] = [])
    {
        self.context = context
        self.polys = polys
        self.correctionFactor = correctionFactor
        self.seed = seed
    }

    /// Generates a ciphertext of zeros.
    ///
    /// A zero ciphertext may arise from HE computations, e.g., by subtracting a ciphertext from itself, or multiplying
    /// a ciphertext with a zero plaintext.
    ///
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - moduliCount: Number of moduli in the zero ciphertext. If `nil`, the ciphertext will have the ciphertext
    /// context with all the coefficient moduli in `context`.
    /// - Returns: A zero ciphertext.
    /// - Throws: Error upon failure to encode.
    /// - Warning: a zero ciphertext is *transparent*, i.e., everyone can see the the underlying plaintext, zero in
    /// this case. Transparency can propagate to ciphertexts operating with transparent ciphertexts, e.g.
    /// ```
    ///  transparentCiphertext * ciphertext = transparentCiphertext
    ///  transparentCiphertext * plaintext = transparentCiphertext
    ///  transparentCiphertext + plaintext = transparentCiphertext
    /// ```
    /// - seelaso: ``Ciphertext/isTransparent()``
    @inlinable
    public static func zero(context: Context<Scheme>, moduliCount: Int? = nil) throws -> Ciphertext<Scheme, Format> {
        try Scheme.zero(context: context, moduliCount: moduliCount)
    }

    // MARK: ciphertext += plaintext

    @inlinable
    public static func += (
        ciphertext: inout Ciphertext<Scheme, Format>,
        plaintext: Plaintext<Scheme, some PolyFormat>) throws
    {
        try Scheme.validateEquality(of: ciphertext.context, and: plaintext.context)
        try Scheme.addAssign(&ciphertext, plaintext)
    }

    // MARK: ciphertext += ciphertext

    @inlinable
    public static func += (lhs: inout Ciphertext<Scheme, Format>, rhs: Ciphertext<Scheme, some PolyFormat>) throws {
        try Scheme.validateEquality(of: lhs.context, and: rhs.context)
        try Scheme.addAssign(&lhs, rhs)
    }

    // MARK: ciphertext -= ciphertext

    @inlinable
    public static func -= (lhs: inout Ciphertext<Scheme, Format>, rhs: Ciphertext<Scheme, some PolyFormat>) throws {
        try Scheme.validateEquality(of: lhs.context, and: rhs.context)
        try Scheme.subAssign(&lhs, rhs)
    }

    // MARK: ciphertext -= plaintext

    @inlinable
    public static func -= (
        ciphertext: inout Ciphertext<Scheme, Format>,
        plaintext: Plaintext<Scheme, some PolyFormat>) throws
    {
        try Scheme.validateEquality(of: ciphertext.context, and: plaintext.context)
        try Scheme.subAssign(&ciphertext, plaintext)
    }

    // MARK: ciphertext *= plaintext

    @inlinable
    public static func *= (ciphertext: inout Ciphertext<Scheme, Format>, plaintext: Plaintext<Scheme, Eval>) throws
        where Format == Eval
    {
        try Scheme.validateEquality(of: ciphertext.context, and: plaintext.context)
        try Scheme.mulAssign(&ciphertext, plaintext)
    }

    // MARK: ciphertext *= ciphertext

    @inlinable
    public static func *= (lhs: inout Ciphertext<Scheme, Format>, rhs: Ciphertext<Scheme, Format>) throws
        where Format == Scheme.CanonicalCiphertextFormat
    {
        try Scheme.validateEquality(of: lhs.context, and: rhs.context)
        try Scheme.mulAssign(&lhs, rhs)
    }

    // MARK: ciphertext = -ciphertext

    @inlinable
    public static prefix func - (_ ciphertext: Ciphertext<Scheme, Format>) -> Self {
        var result = ciphertext
        Scheme.negAssign(&result)
        return result
    }

    /// Computes whether a ciphertext is transparent.
    ///
    /// A *transparent* ciphertext reveals the underlying plaintext to any observer. For instance,
    /// ``Ciphertext/zero(context:moduliCount:)`` yields a transparent transparent.
    /// - Returns: Whether the ciphertext is transparent.
    /// - seealso: ``HeScheme/isTransparent(ciphertext:)`` for an alternative API.
    @inlinable
    public func isTransparent() -> Bool {
        Scheme.isTransparent(ciphertext: self)
    }

    @inlinable
    package mutating func clearSeed() {
        seed = []
    }

    @inlinable
    func forwardNtt() throws -> Ciphertext<Scheme, Eval> where Format == Coeff {
        let polys = try polys.map { try $0.forwardNtt() }
        return Ciphertext<Scheme, Eval>(context: context, polys: polys, correctionFactor: correctionFactor, seed: seed)
    }

    @inlinable
    func inverseNtt() throws -> Ciphertext<Scheme, Coeff> where Format == Eval {
        let polys = try polys.map { try $0.inverseNtt() }
        return Ciphertext<Scheme, Coeff>(context: context, polys: polys, correctionFactor: correctionFactor, seed: seed)
    }

    /// Converts the ciphertext to a ``HeScheme/CoeffCiphertext``.
    /// - Returns: The converted ciphertext.
    /// - Throws: Error upon failure to convert the ciphertext.
    @inlinable
    public func convertToCoeffFormat() throws -> Ciphertext<Scheme, Coeff> {
        if Format.self == Eval.self {
            if let ciphertext = self as? Ciphertext<Scheme, Eval> {
                return try ciphertext.inverseNtt()
            }
            throw HeError.errorCastingPolyFormat(from: Format.self, to: Eval.self)
        }
        if let ciphertext = self as? Ciphertext<Scheme, Coeff> {
            return ciphertext
        }
        throw HeError.errorCastingPolyFormat(from: Format.self, to: Coeff.self)
    }

    /// Converts the ciphertext to a ``HeScheme/EvalCiphertext``.
    /// - Returns: The converted ciphertext.
    /// - Throws: Error upon failure to convert the ciphertext.
    @inlinable
    public func convertToEvalFormat() throws -> Ciphertext<Scheme, Eval> {
        if Format.self == Coeff.self {
            if let ciphertext = self as? Ciphertext<Scheme, Coeff> {
                return try ciphertext.forwardNtt()
            }
            throw HeError.errorCastingPolyFormat(from: Format.self, to: Coeff.self)
        }
        if let ciphertext = self as? Ciphertext<Scheme, Eval> {
            return ciphertext
        }
        throw HeError.errorCastingPolyFormat(from: Format.self, to: Eval.self)
    }

    /// Converts the ciphertext to a ``HeScheme/CanonicalCiphertext``.
    /// - Returns: The converted ciphertext.
    /// - Throws: Error upon failure to convert the ciphertext.
    @inlinable
    public func convertToCanonicalFormat() throws -> Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat> {
        if Scheme.CanonicalCiphertextFormat.self == Coeff.self {
            // swiftlint:disable:next force_cast
            return try convertToCoeffFormat() as! Scheme.CanonicalCiphertext
        }
        if Scheme.CanonicalCiphertextFormat.self == Eval.self {
            // swiftlint:disable:next force_cast
            return try convertToEvalFormat() as! Scheme.CanonicalCiphertext
        }
        throw HeError.errorCastingPolyFormat(from: Format.self, to: Scheme.CanonicalCiphertextFormat.self)
    }

    /// Rotates the columns of a ciphertext.
    ///
    /// - Parameters:
    ///   - step: Number of slots to rotate. Negative values indicate a left rotation, and positive values indicate a
    /// right rotation. Must have absolute value in `[1, N / 2 - 1]` where `N` is the RLWE ring dimension, given by
    /// ``EncryptionParameters/polyDegree``.
    ///   - evaluationKey: Evaluation key to use in the HE computation. Must contain the Galois element associated with
    /// `step`, see ``GaloisElement/rotatingColumns(by:degree:)``.
    /// - Throws: failure to rotate ciphertext's columns.
    /// - seealso: ``HeScheme/rotateColumns(of:by:using:)-7h3fz`` for an alternate API and more information.
    @inlinable
    public mutating func rotateColumns(by step: Int,
                                       using evaluationKey: EvaluationKey<Scheme>) throws
        where Format == Scheme.CanonicalCiphertextFormat
    {
        try Scheme.rotateColumns(of: &self, by: step, using: evaluationKey)
    }

    /// Swaps the rows of a ciphertext.
    ///
    /// A plaintext in ``EncodeFormat/simd`` format can be viewed a `2 x (N / 2)` matrix of coefficients.
    /// For instance, for `N = 8`, given a ciphertext encrypting a plaintext with values
    /// ```
    /// [1, 2, 3, 4, 5, 6, 7, 8]
    /// ```
    /// calling ``HeScheme/swapRows(of:using:)`` with `step: 1` will yield a ciphertext decrypting to
    /// ```
    /// [5, 6, 7, 8, 1, 2, 3, 4]
    /// ```
    /// - Parameter evaluationKey: Evaluation key to use in the HE computation. Must contain the Galois element
    /// associated with `step`, see ``GaloisElement/rotatingColumns(by:degree:)``.
    /// - Throws: error upon failure to swap the ciphertext's rows.
    /// - seealso: ``HeScheme/swapRows(of:using:)-50tac`` for an alternate API.
    @inlinable
    public mutating func swapRows(using evaluationKey: EvaluationKey<Scheme>) throws
        where Format == Scheme.CanonicalCiphertextFormat
    {
        try Scheme.swapRows(of: &self, using: evaluationKey)
    }

    /// Performs modulus switching on the ciphertext.
    ///
    /// - Throws: Error upon failure to mod-switch.
    /// - seealso: ``HeScheme/modSwitchDown(_:)`` for an alternative API and more information.
    @inlinable
    public mutating func modSwitchDown() throws where Format == Scheme.CanonicalCiphertextFormat {
        try Scheme.modSwitchDown(&self)
    }

    /// Performs modulus switching to a single modulus.
    ///
    /// If the ciphertext already has a single modulus, this is a no-op.
    /// - Throws: Error upon failure to modulus switch.
    /// - seealso: ``Ciphertext/modSwitchDown()`` for more information and an alternative API.
    @inlinable
    public mutating func modSwitchDownToSingle() throws where Format == Scheme.CanonicalCiphertextFormat {
        while moduli.count > 1 {
            try Scheme.modSwitchDown(&self)
        }
    }

    /// Decryption of a ciphertext.
    /// - Parameter secretKey: Secret key to decrypt with.
    /// - Returns: The plaintext decryption of the ciphertext.
    /// - Throws: Error upon failure to decrypt.
    /// - Warning: The ciphertext must have at least ``HeScheme/minNoiseBudget`` noise to ensure accurate decryption.
    ///  - seealso: The noise budget can be computed using
    ///  ``Ciphertext/noiseBudget(using:variableTime:)``.
    ///  - seealso: ``HeScheme/decrypt(_:using:)`` for an alternative API.
    @inlinable
    public func decrypt(using secretKey: SecretKey<Scheme>) throws -> Scheme.CoeffPlaintext {
        try Scheme.decrypt(self, using: secretKey)
    }

    /// Computes the noise budget of the ciphertext.
    ///
    /// The *noise budget* of the ciphertext decreases throughout HE operations. Once a ciphertext's noise budget is
    /// below
    /// ``HeScheme/minNoiseBudget``, decryption may yield inaccurate plaintexts.
    /// - Parameters:
    ///   - secretKey: Secret key.
    ///   - variableTime: Must be `true`, indicating the secret key coefficients are leaked through timing.
    /// - Returns: The noise budget.
    /// - Throws: Error upon failure to compute the noise budget.
    /// - Warning: Leaks `secretKey` through timing. Should be used for testing only.
    /// - seealso: ``HeScheme/noiseBudget(of:using:variableTime:)`` for an alternative API.
    @inlinable
    public func noiseBudget(using secretKey: SecretKey<Scheme>, variableTime: Bool) throws -> Double {
        try Scheme.noiseBudget(of: self, using: secretKey, variableTime: variableTime)
    }
}

extension Ciphertext: PolyCollection {
    public typealias Scalar = Scheme.Scalar

    @inlinable
    public func polyContext() -> PolyContext<Scheme.Scalar> {
        polys[0].context
    }
}

extension Ciphertext: CustomStringConvertible {
    public var description: String {
        "Ciphertext<\(Scheme.self), \(Format.self)>(\(context), \(polys), correctionFactor=\(correctionFactor)"
    }
}

extension Ciphertext {
    // MARK: ciphertext + plaintext

    /// Ciphertext-plaintext addition.
    /// - Parameters:
    ///   - ciphertext: Ciphertext to add.
    ///   - plaintext: Plaintext to add.
    /// - Returns: A ciphertext encrypting the sum.
    /// - Throws: Error upon failure to add.
    @inlinable
    public static func + (ciphertext: Ciphertext<Scheme, Format>,
                          plaintext: Plaintext<Scheme, some PolyFormat>) throws -> Self
    {
        var result = ciphertext
        try result += plaintext
        return result
    }

    /// Ciphertext-plaintext addition.
    /// - Parameters:
    ///   - plaintext: Plaintext to add.
    ///   - ciphertext: Ciphertext to add.
    /// - Returns: A ciphertext encrypting the sum.
    /// - Throws: Error upon failure to add.
    @inlinable
    public static func + (plaintext: Plaintext<Scheme, some PolyFormat>,
                          ciphertext: Ciphertext<Scheme, Format>) throws -> Self
    {
        try ciphertext + plaintext
    }

    // MARK: ciphertext - plaintext

    /// Ciphertext-plaintext subtraction.
    /// - Parameters:
    ///   - ciphertext: Ciphertext to subtract from.
    ///   - plaintext: Plaintext to subtract.
    /// - Returns: A ciphertext encrypting the difference `ciphertext - plaintext`.
    /// - Throws: Error upon failure to subtract.
    @inlinable
    public static func - (ciphertext: Ciphertext<Scheme, Format>,
                          plaintext: Plaintext<Scheme, some PolyFormat>) throws -> Self
    {
        var result = ciphertext
        try result -= plaintext
        return result
    }

    // MARK: ciphertext + ciphertext

    /// Ciphertext addition.
    /// - Parameters:
    ///   - lhs: Ciphertext to add.
    ///   - rhs: Plaintext to add.
    /// - Returns: A ciphertext encrypting the sum `lhs + rhs'.
    /// - Throws: Error upon failure to add.
    @inlinable
    public static func + (lhs: Ciphertext<Scheme, Format>, rhs: Ciphertext<Scheme, some PolyFormat>) throws -> Self {
        var result = lhs
        try result += rhs
        return result
    }

    // MARK: ciphertext - ciphertext

    /// Ciphertext subtraction.
    /// - Parameters:
    ///   - lhs: Ciphertext to subtract from.
    ///   - rhs: Plaintext to subtract.
    /// - Returns: A ciphertext encrypting the difference `lhs - rhs'.
    /// - Throws: Error upon failure to subtract.
    @inlinable
    public static func - (lhs: Ciphertext<Scheme, Format>, rhs: Ciphertext<Scheme, some PolyFormat>) throws -> Self {
        var result = lhs
        try result -= rhs
        return result
    }

    // MARK: ciphertext * plaintext

    /// Ciphertext-plaintext multiplication.
    /// - Parameters:
    ///   - ciphertext: Ciphertext to multiply.
    ///   - plaintext: Plaintext to multiply.
    /// - Returns: A ciphertext encrypting the product `ciphertext * plaintext`.
    /// - Throws: Error upon failure to multiply.
    @inlinable
    public static func * (ciphertext: Ciphertext<Scheme, Format>, plaintext: Plaintext<Scheme, Eval>) throws -> Self
        where Format == Eval
    {
        var result = ciphertext
        try result *= plaintext
        return result
    }

    /// Ciphertext-plaintext multiplication.
    /// - Parameters:
    ///   - plaintext: Plaintext to multiply.
    ///   - ciphertext: Ciphertext to multiply.
    /// - Returns: A ciphertext encrypting the product `ciphertext * plaintext`.
    /// - Throws: Error upon failure to multiply.
    @inlinable
    public static func * (plaintext: Plaintext<Scheme, Eval>, ciphertext: Ciphertext<Scheme, Format>) throws -> Self
        where Format == Eval
    {
        try ciphertext * plaintext
    }

    // MARK: ciphertext * ciphertext

    /// Ciphertext multiplication.
    /// - Parameters:
    ///   - lhs: Ciphertext to multiply.
    ///   - rhs: Ciphertext to multiply.
    /// - Returns: A ciphertext encrypting the product `lhs * rhs`.
    /// - Throws: Error upon failure to multiply.
    /// > Note: the values of the decrypted product depend on the ``EncodeFormat`` of the plaintexts encrypted by `lhs`
    /// and `rhs.`
    ///
    /// > Important: The resulting ciphertext has 3 polynomials and can be relinearized. See
    /// ``HeScheme/relinearize(_:using:)``
    @inlinable
    public static func * (lhs: Ciphertext<Scheme, Format>, rhs: Ciphertext<Scheme, Format>) throws -> Self
        where Format == Scheme.CanonicalCiphertextFormat
    {
        var result = lhs
        try result *= rhs
        return result
    }
}

extension Ciphertext where Format == Coeff {
    /// Computes `ciphertext * x^{-power}`.
    ///
    /// - Parameter power: Power in the monomial; must be positive.
    /// - Throws: Error upon failure to compute the inverse.
    @inlinable
    public mutating func multiplyInversePowerOfX(power: Int) throws {
        precondition(power >= 0)
        for index in polys.indices {
            try polys[index].multiplyInversePowerOfX(power)
        }
    }
}

extension Ciphertext where Format == Scheme.CanonicalCiphertextFormat {
    /// Applies a Galois transformation.
    ///
    /// - Parameters:
    ///   - element: Galois element of the transformation. Must be odd in `[1, 2 * N - 1]` where `N` is the RLWE ring
    /// dimension, given by ``EncryptionParameters/polyDegree``.
    ///   - key: Evaluation key. Must contain Galois element `element`.
    /// - Throws: Error upon failure to apply the Galois transformation.
    /// - seealso: ``HeScheme/applyGalois(ciphertext:element:using:)`` for an alternative API and more information.
    @inlinable
    public mutating func applyGalois(element: Int, using key: EvaluationKey<Scheme>) throws {
        try Scheme.applyGalois(ciphertext: &self, element: element, using: key)
    }

    /// Relinearizes the ciphertext.
    ///
    /// - Parameter key: Evaluation key to relinearize with. Must contain a `RelinearizationKey`.
    /// - Throws: Error upon failure to relinearize.
    /// - seealso: ``HeScheme/relinearize(_:using:)`` for an alternative API and more information.
    @inlinable
    public mutating func relinearize(using key: EvaluationKey<Scheme>) throws {
        try Scheme.relinearize(&self, using: key)
    }
}

extension Collection {
    @inlinable
    func sum<Scheme>() throws -> Element where Element == Ciphertext<Scheme, Eval> {
        precondition(!isEmpty)
        // swiftlint:disable:next force_unwrapping
        return try dropFirst().reduce(first!) { try $0 + $1 }
    }

    @inlinable
    func sum<Scheme>() throws -> Element where Element == Ciphertext<Scheme, Coeff> {
        precondition(!isEmpty)
        // swiftlint:disable:next force_unwrapping
        return try dropFirst().reduce(first!) { try $0 + $1 }
    }

    @inlinable
    func sum<Scheme>() throws -> Element where Element == Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat> {
        precondition(!isEmpty)
        // swiftlint:disable:next force_unwrapping
        return try dropFirst().reduce(first!) { try $0 + $1 }
    }

    /// Computes an inner product between self and a collection of (optional) plaintexts in ``Eval`` format.
    ///
    /// The inner product encrypts `sum_{i, plaintexts[i] != nil} self[i] * plaintexts[i]`. `plaintexts[i]`
    /// may be `nil`, which denotes a zero plaintext.
    /// - Parameter plaintexts: Plaintexts. Must not be empty and have `count` matching `self.count`.
    /// - Returns: A ciphertext encrypting the inner product.
    /// - Throws: Error upon failure to compute inner product.
    @inlinable
    public func innerProduct<Scheme>(plaintexts: some Collection<Plaintext<Scheme, Eval>?>) throws -> Element
        where Element == Ciphertext<Scheme, Eval>
    {
        try Scheme.innerProduct(ciphertexts: self, plaintexts: plaintexts)
    }

    /// Computes an inner product between self and a collection of plaintexts in ``Eval`` format.
    ///
    /// The inner product encrypts `sum_{i} self[i] * plaintexts[i]`.
    /// - Parameter plaintexts: Plaintexts. Must not be empty and have `count` matching `self.count`.
    /// - Returns: A ciphertext encrypting the inner product.
    /// - Throws: Error upon failure to compute inner product.
    @inlinable
    public func innerProduct<Scheme>(plaintexts: some Collection<Plaintext<Scheme, Eval>>) throws -> Element
        where Element == Ciphertext<Scheme, Eval>
    {
        try Scheme.innerProduct(ciphertexts: self, plaintexts: plaintexts)
    }

    /// Computes an inner product between self and another collection of ciphertexts.
    ///
    /// The inner product encrypts `sum_{i} self[i] * ciphertexts[i]`.
    /// - Parameter ciphertexts: Ciphertexts. Must not be empty and have `count` matching `self.count`.
    /// - Returns: A ciphertext encrypting the inner product.
    /// - Throws: Error upon failure to compute inner product.
    @inlinable
    public func innerProduct<Scheme>(ciphertexts: some Collection<Element>) throws -> Element
        where Element == Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>
    {
        try Scheme.innerProduct(self, ciphertexts)
    }
}
