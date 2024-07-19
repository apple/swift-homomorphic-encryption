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

/// Polynomial format.
///
/// - Warning: There should be no other conformances to ``PolyFormat`` beyond ``Coeff`` and ``Eval``.
public protocol PolyFormat {
    /// A textual representation of the format.
    static var description: String { get }
}

/// Coefficient format.
///
/// The `coefficient` format of a polynomial `p(x) = a_0 + a_1 x + ... + a_{N-1} x^{N-1}` is the list of its
/// coefficients: `[a_0, a_1, ..., a_{N-1}]`.
public final class Coeff: PolyFormat {
    public static var description: String {
        "Coeff format"
    }
}

/// Evaluation format.
///
/// A polynomial in Evaluation format is a list of its coefficients, after transforming the polynomial with the
/// *number-theoretic transform (NTT)*.
public final class Eval: PolyFormat {
    public static var description: String {
        "Eval format"
    }
}

/// Plaintext encoding formats.
///
/// This differs from the ``PolyFormat``: while the ``PolyFormat`` specifies the representation of the polynomials, the
/// encoding format specifies the computations performed on the underlying plaintext, during HE computation.
public enum EncodeFormat: CaseIterable {
    /// Element-wise encoding of coefficients.
    ///
    /// Plaintexts in ``coefficient`` format are encoded using ``Coeff`` format. Addition, subtraction, and negation to
    /// plaintexts in ``coefficient`` format are performed element-wise on the coefficients, while multiplication yields
    /// a convolution of the coefficients.
    case coefficient

    /// Single-instruction multiple-data (SIMD) encoding.
    ///
    /// Plaintexts in ``simd`` format yield element-wise addition, subtraction, negation, *and multiplication*.
    ///
    /// SIMD encoding also supports ``HeScheme/rotateColumns(of:by:using:)-5mcg`` and
    /// ``HeScheme/swapRows(of:using:)-7lya8``.
    /// > Note: Requires an NTT-friendly plaintext modulus. ``EncryptionParameters/supportsSimdEncoding``
    case simd
}

/// Protocol for HE schemes.
public protocol HeScheme {
    /// Coefficient type for each polynomial.
    associatedtype Scalar: ScalarType

    /// Polynomial format for the <doc:/documentation/HomomorphicEncryption/HeScheme/CanonicalCiphertext>.
    associatedtype CanonicalCiphertextFormat: PolyFormat

    /// Plaintext in ``Coeff`` format.
    typealias CoeffPlaintext = Plaintext<Self, Coeff>

    /// Plaintext in ``Eval`` format.
    typealias EvalPlaintext = Plaintext<Self, Eval>

    /// Ciphertext in ``Coeff`` format.
    ///
    /// ``Ciphertext/convertToCoeffFormat()`` can be used to convert a ciphertext to a ``CoeffCiphertext``.
    typealias CoeffCiphertext = Ciphertext<Self, Coeff>

    /// Ciphertext in ``Eval`` format.
    ///
    /// ``Ciphertext/convertToEvalFormat()`` can be used to convert a ciphertext to a ``CoeffCiphertext``.
    typealias EvalCiphertext = Ciphertext<Self, Eval>

    /// The canonical representation of a ciphertext.
    ///
    /// The canonical representation is the default ciphertext representation.
    /// ``Ciphertext/convertToCanonicalFormat()-1ouc4``
    /// can be used to convert a ciphertext to a ``CoeffCiphertext``. However, some operations may require a specific
    /// format, such as ``CoeffCiphertext`` or ``EvalCiphertext``.
    typealias CanonicalCiphertext = Ciphertext<Self, CanonicalCiphertextFormat>

    /// Secret key type.
    typealias SecretKey = HomomorphicEncryption.SecretKey<Self>

    /// Evaluation key type.
    typealias EvaluationKey = HomomorphicEncryption.EvaluationKey<Self>

    /// The number of polynomials in a freshly encrypted ciphertext.
    ///
    /// Some operations such as ciphertext-ciphertext multiplication, or relinearization may change the number of
    /// polynomials in a ciphertext.
    /// - seealso: ``HeScheme/relinearize(_:using:)``.
    static var freshCiphertextPolyCount: Int { get }

    /// The minimum `noise budget` to guarantee a successful decryption.
    ///
    /// - seealso: ``HeScheme/noiseBudget(of:using:variableTime:)-5p5m0``.
    static var minNoiseBudget: Double { get }

    /// Generates a ``SecretKey``.
    /// - Parameter context: Context for HE computation.
    /// - Returns: A freshly generated secret key.
    /// - Throws: Error upon failure to generate a secret key.
    /// - seealso: ``Context/generateSecretKey()`` for an alternative API.
    static func generateSecretKey(context: Context<Self>) throws -> SecretKey

    /// Generates an ``EvaluationKey``.
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - configuration: Evaluation key configuration.
    ///   - secretKey: Secret key used to generate the evaluation key.
    /// - Returns: A freshly generated evaluation key.
    /// - Throws: Error upon failure to generate an evaluation key.
    /// - seealso: ``Context/generateEvaluationKey(configuration:using:)`` for an alternative API.
    static func generateEvaluationKey(
        context: Context<Self>,
        configuration: EvaluationKeyConfiguration,
        using secretKey: SecretKey) throws
        -> EvaluationKey

    /// Encodes values into a plaintext with coefficient format.
    ///
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - values: Values to encode.
    ///   - format: Encoding format.
    /// - Returns: A plaintext encoding `values`.
    /// - Throws: Error upon failure to encode.
    static func encode(context: Context<Self>, values: [some ScalarType], format: EncodeFormat) throws -> CoeffPlaintext

    /// Encodes values into a plaintext with evaluation format.
    ///
    /// The encoded plaintext will have a ``Plaintext/polyContext()`` with the `moduliCount` first ciphertext moduli.
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - values: Values to encode.
    ///   - format: Encoding format.
    ///   - moduliCount: Number of coefficient moduli in the encoded plaintext.
    /// - Returns: A plaintext encoding `values`.
    /// - Throws: Error upon failure to encode.
    static func encode(context: Context<Self>, values: [some ScalarType], format: EncodeFormat,
                       moduliCount: Int) throws -> EvalPlaintext

    /// Encodes `values` into a plaintext with evaluation format and with top-level ciphertext context with all moduli.
    /// - seealso: ``HeScheme/encode(context:values:format:moduliCount:)``
    /// for an alternative which allows specifying the `moduliCount`.
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - values: Values to encode.
    ///   - format: Encoding format.
    /// - Returns: A plaintext encoding `values`.
    /// - Throws: Error upon failure to encode.
    static func encode(context: Context<Self>, values: [some ScalarType], format: EncodeFormat) throws -> EvalPlaintext

    /// Decodes a plaintext in ``Coeff`` format.
    /// - Parameters:
    ///   - plaintext: Plaintext to decode.
    ///   - format: Encoding format of the plaintext.
    /// - Returns: The decoded values.
    /// - Throws: Error upon failure to decode the plaintext.
    /// - seealso: ``Plaintext/decode(format:)-9l5kz`` for an alternative API.
    static func decode<T: ScalarType>(plaintext: CoeffPlaintext, format: EncodeFormat) throws -> [T]

    /// Decodes a plaintext in ``Eval`` format.
    /// - Parameters:
    ///   - plaintext: Plaintext to decode.
    ///   - format: Encoding format of the plaintext.
    /// - Returns: The decoded values.
    /// - Throws: Error upon failure to decode the plaintext.
    /// - seealso: ``Plaintext/decode(format:)-i9hh`` for an alternative API.
    static func decode<T: ScalarType>(plaintext: EvalPlaintext, format: EncodeFormat) throws -> [T]

    /// Symmetric secret key encryption of a plaintext.
    /// - Parameters:
    ///   - plaintext: Plaintext to encrypt.
    ///   - secretKey: Secret key to encrypt with.
    /// - Returns: A ciphertext encrypting `plaintext`.
    /// - Throws: Error upon failure to encrypt the plaintext.
    /// - seealso: ``Plaintext/encrypt(using:)`` for an alternative API.
    static func encrypt(_ plaintext: CoeffPlaintext, using secretKey: SecretKey) throws -> CanonicalCiphertext

    /// Generates a ciphertext of zeros in ``Coeff`` format.
    ///
    /// A zero ciphertext may arise from HE computations, e.g., by subtracting a ciphertext from itself, or multiplying
    /// a ciphertext with a zero plaintext.
    ///
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - moduliCount: Number of moduli in the zero ciphertext.
    /// - Returns: A zero ciphertext.
    /// - Throws: Error upon failure to generate a zero ciphertext..
    /// - Warning: a zero ciphertext is *transparent*, i.e., everyone can see the the underlying plaintext, zero in this
    /// case.
    /// Transparency can propagate to ciphertexts operating with transparent ciphertexts, e.g.
    /// ```
    ///  transparentCiphertext * ciphertext = transparentCiphertext
    ///  transparentCiphertext * plaintext = transparentCiphertext
    ///  transparentCiphertext + plaintext = transparentCiphertext
    /// ```
    /// - seealso: ``HeScheme/isTransparent(ciphertext:)-31w9f``
    static func zeroCiphertext(context: Context<Self>, moduliCount: Int) throws -> CoeffCiphertext

    /// Generates a ciphertext of zeros in ``Eval`` format.
    ///
    /// A zero ciphertext may arise from HE computations, e.g., by subtracting a ciphertext from itself, or multiplying
    /// a ciphertext with a zero plaintext.
    ///
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - moduliCount: Number of moduli in the zero ciphertext.
    /// - Returns: A zero ciphertext.
    /// - Throws: Error upon failure to encode.
    ///  - Warning: a zero ciphertext is *transparent*, i.e., everyone can see the the underlying plaintext, zero in
    /// this
    /// case.
    /// Transparency can propagate to ciphertexts operating with transparent ciphertexts, e.g.
    /// ```
    ///  transparentCiphertext * ciphertext = transparentCiphertext
    ///  transparentCiphertext * plaintext = transparentCiphertext
    ///  transparentCiphertext + plaintext = transparentCiphertext
    /// ```
    /// - seealso: ``HeScheme/isTransparent(ciphertext:)-31w9f``
    static func zeroCiphertext(context: Context<Self>, moduliCount: Int) throws -> EvalCiphertext

    /// Computes whether a ciphertext is transparent.
    ///
    /// A *transparent* ciphertext reveals the underlying plaintext to any observer. For instance,
    /// ``HeScheme/zeroCiphertext(context:moduliCount:)-52gz2`` yields a transparent transparent.
    /// - Parameter ciphertext: Ciphertext whose transparency to compute.
    /// - Returns: Whether the ciphertext is transparent.
    /// - seealso: ``Ciphertext/isTransparent()-zkhb`` for an alternative API.
    static func isTransparent(ciphertext: CanonicalCiphertext) -> Bool

    /// Computes whether a ciphertext is transparent.
    ///
    /// A *transparent* ciphertext reveals the underlying plaintext to any observer. For instance,
    /// ``HeScheme/zeroCiphertext(context:moduliCount:)-1xec3`` yields a transparent transparent.
    /// - Parameter ciphertext: Ciphertext whose transparency to compute.
    /// - Returns: Whether the ciphertext is transparent.
    /// - seealso: ``Ciphertext/isTransparent()-2e258`` for an alternative API.
    static func isTransparent(ciphertext: CoeffCiphertext) -> Bool

    /// Computes whether a ciphertext is transparent.
    ///
    /// A *transparent* ciphertext reveals the underlying plaintext to any observer. For instance,
    /// ``HeScheme/zeroCiphertext(context:moduliCount:)-52gz2`` yields a transparent transparent.
    /// - Parameter ciphertext: Ciphertext whose transparency to compute.
    /// - Returns: Whether the ciphertext is transparent.
    /// - seealso: ``Ciphertext/isTransparent()-8x30o`` for an alternative API.
    static func isTransparent(ciphertext: EvalCiphertext) -> Bool

    /// Decryption of a ciphertext in coefficient format.
    /// - Parameters:
    ///   - ciphertext: Ciphertext to decrypt.
    ///   - secretKey: Secret key to decrypt with.
    /// - Returns: The plaintext decryption of the ciphertext.
    /// - Throws: Error upon failure to decrypt.
    /// - Warning: The ciphertext must have at least ``HeScheme/minNoiseBudget`` noise to ensure accurate decryption.
    ///  - seealso: The noise budget can be computed using
    ///  ``HeScheme/noiseBudget(of:using:variableTime:)-143f3``.
    ///  - seealso: ``Ciphertext/decrypt(using:)-4n5b2`` for an alternative API.
    static func decrypt(_ ciphertext: CoeffCiphertext, using secretKey: SecretKey) throws -> CoeffPlaintext

    /// Decryption of a ciphertext in evaluation format.
    /// - Parameters:
    ///   - ciphertext: Ciphertext to decrypt.
    ///   - secretKey: Secret key to decrypt with.
    /// - Returns: The plaintext decryption of the ciphertext.
    /// - Throws: Error upon failure to decrypt.
    /// - Warning: The ciphertext must have at least ``HeScheme/minNoiseBudget`` noise to ensure accurate decryption.
    ///  - seealso: The noise budget can be computed using
    ///  ``HeScheme/noiseBudget(of:using:variableTime:)-7vpza``.
    ///  - seealso: ``Ciphertext/decrypt(using:)-62y2c`` for an alternative API.
    static func decrypt(_ ciphertext: EvalCiphertext, using secretKey: SecretKey) throws -> CoeffPlaintext

    /// Decryption of a ciphertext in canonical format.
    /// - Parameters:
    ///   - ciphertext: Ciphertext to decrypt.
    ///   - secretKey: Secret key to decrypt with.
    /// - Returns: The plaintext decryption of the ciphertext.
    /// - Throws: Error upon failure to decrypt.
    /// - Warning: The ciphertext must have at least ``HeScheme/minNoiseBudget`` noise to ensure accurate decryption.
    ///  - seealso: The noise budget can be computed using
    ///  ``HeScheme/noiseBudget(of:using:variableTime:)-5p5m0``.
    ///  - seealso: ``Ciphertext/decrypt(using:)-9qn9g`` for an alternative API.
    static func decrypt(_ ciphertext: CanonicalCiphertext, using secretKey: SecretKey) throws -> CoeffPlaintext

    /// Rotates the columns of a ciphertext.
    ///
    /// A plaintext in ``EncodeFormat/simd`` format can be viewed a `2 x (N / 2)` matrix of coefficients, where `N` is
    /// the ``EncryptionParameters/polyDegree``.
    /// Each column is rotated by `step`.
    /// For instance, for `N = 8`, given a ciphertext encrypting a plaintext with values
    /// ```
    /// [1, 2, 3, 4, 5, 6, 7, 8]
    /// ```
    /// calling ``HeScheme/rotateColumns(of:by:using:)-5mcg`` with `step: 1` will yield a ciphertext decrypting to
    /// ```
    /// [4, 1, 2, 3, 8, 5, 6, 7]
    ///  ```
    /// - Parameters:
    ///   - ciphertext: Ciphertext whose columns to rotate.
    ///   - step: Number of slots to rotate. Negative values indicate a left rotation, and positive values indicate a
    /// right rotation. Must have absolute value in `[1, N / 2 - 1]` where `N` is the RLWE ring dimension, given by
    /// ``EncryptionParameters/polyDegree``.
    ///   - evaluationKey: Evaluation key to use in the HE computation. Must contain the Galois element associated with
    /// `step`, see ``GaloisElement/rotatingColumns(by:degree:)``.
    /// - Throws: failure to rotate ciphertext's columns.
    /// - seealso: ``Ciphertext/rotateColumns(by:using:)`` for an alternate API.
    static func rotateColumns(
        of ciphertext: inout CanonicalCiphertext,
        by step: Int,
        using evaluationKey: EvaluationKey) throws

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
    /// - Parameters:
    ///   - ciphertext: Ciphertext whose rows to swap.
    ///   - evaluationKey: Evaluation key to use in the HE computation. Must contain the Galois element returned from
    /// ``GaloisElement/swappingRows(degree:)``.
    /// - Throws: error upon failure to swap the ciphertext's rows.
    /// - seealso: ``Ciphertext/swapRows(using:)`` for an alternate API.
    static func swapRows(of ciphertext: inout CanonicalCiphertext, using evaluationKey: EvaluationKey) throws

    /// In-place plaintext addition: `lhs += rhs`.
    /// - Parameters:
    ///   - lhs: Plaintext to add; will store the sum.
    ///   - rhs: Plaintext to add.
    /// - Throws: Error upon failure to add.
    static func addAssign(_ lhs: inout CoeffPlaintext, _ rhs: CoeffPlaintext) throws

    /// In-place plaintext addition: `lhs += rhs`.
    /// - Parameters:
    ///   - lhs: Plaintext to add; will store the sum.
    ///   - rhs: Plaintext to add.
    /// - Throws: Error upon failure to add.
    static func addAssign(_ lhs: inout EvalPlaintext, _ rhs: EvalPlaintext) throws

    /// In-place ciphertext addition: `lhs += rhs`.
    /// - Parameters:
    ///   - lhs: Ciphertext to add; will store the sum.
    ///   - rhs: Ciphertext to add.
    /// - Throws: Error upon failure to add.
    static func addAssign(_ lhs: inout CoeffCiphertext, _ rhs: CoeffCiphertext) throws

    /// In-place ciphertext addition: `lhs += rhs`.
    /// - Parameters:
    ///   - lhs: Ciphertext to add; will store the sum.
    ///   - rhs: Ciphertext to add.
    /// - Throws: Error upon failure to add.
    static func addAssign(_ lhs: inout EvalCiphertext, _ rhs: EvalCiphertext) throws

    /// In-place ciphertext subtraction: `lhs -= rhs`.
    /// - Parameters:
    ///   - lhs: Ciphertext to subtract from; will store the difference.
    ///   - rhs: Ciphertext to subtract.
    /// - Throws: Error upon failure to subtract.
    static func subAssign(_ lhs: inout CoeffCiphertext, _ rhs: CoeffCiphertext) throws

    /// In-place ciphertext subtraction: `lhs -= rhs`.
    ///
    /// - Parameters:
    ///   - lhs: Ciphertext to subtract from; will store the difference.
    ///   - rhs: Ciphertext to subtract.
    /// - Throws: Error upon failure to subtract.
    static func subAssign(_ lhs: inout EvalCiphertext, _ rhs: EvalCiphertext) throws

    /// In-place ciphertext-plaintext addition: `ciphertext += plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to add; will store the sum.
    ///   - plaintext: Plaintext to add.
    /// - Throws: Error upon failure to add.
    static func addAssign(_ ciphertext: inout CoeffCiphertext, _ plaintext: CoeffPlaintext) throws

    /// In-place ciphertext-plaintext addition: `ciphertext += plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to add; will store the sum.
    ///   - plaintext: Plaintext to add.
    /// - Throws: Error upon failure to add.
    static func addAssign(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) throws

    /// In-place ciphertext-plaintext subtraction: `ciphertext -= plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to subtract from; will store the difference.
    ///   - plaintext: Plaintext to subtract.
    /// - Throws: Error upon failure to subtract.
    static func subAssign(_ ciphertext: inout CoeffCiphertext, _ plaintext: CoeffPlaintext) throws

    /// In-place ciphertext-plaintext subtraction: `ciphertext -= plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to subtract from; will store the difference.
    ///   - plaintext: Plaintext to subtract.
    /// - Throws: Error upon failure to subtract.
    static func subAssign(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) throws

    /// In-place ciphertext-plaintext multiplication: `ciphertext *= plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to multiply; will store the product.
    ///   - plaintext: Plaintext to multiply.
    /// - Throws: Error upon failure to multiply.
    static func mulAssign(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) throws

    /// In-place ciphertext negation: `ciphertext = -ciphertext`.
    ///
    /// - Parameter ciphertext: Ciphertext to negate.
    static func negAssign(_ ciphertext: inout EvalCiphertext)

    /// In-place ciphertext negation: `ciphertext = -ciphertext`.
    ///
    /// - Parameter ciphertext: Ciphertext to negate.
    static func negAssign(_ ciphertext: inout CoeffCiphertext)

    /// Computes an inner product between two collections of ciphertexts.
    ///
    /// The inner product encrypts `sum_{i} lhs[i] * rhs[i]`.
    /// - Parameters:
    ///   - lhs: Ciphertexts. Must not be empty.
    ///   - rhs: Ciphertexts. Must not be empty and have `count` matching `lhs.count`.
    /// - Returns: A ciphertext encrypting the inner product.
    /// - Throws: Error upon failure to compute inner product.
    static func innerProduct(
        _ lhs: some Collection<CanonicalCiphertext>,
        _ rhs: some Collection<CanonicalCiphertext>) throws
        -> CanonicalCiphertext

    /// Computes an inner product between two collections.
    ///
    /// The inner product encrypts `sum_{i} ciphertexts[i] * plaintexts[i]`.
    /// - Parameters:
    ///   - ciphertexts: Ciphertexts. Must not be empty.
    ///   - plaintexts: Plaintexts. Must not be empty and have `count` matching
    /// `ciphertexts.count`.
    /// - Returns: A ciphertext encrypting the inner product.
    /// - Throws: Error upon failure to compute inner product.
    static func innerProduct(ciphertexts: some Collection<EvalCiphertext>,
                             plaintexts: some Collection<EvalPlaintext>) throws -> EvalCiphertext

    /// Computes an inner product between two collections.
    ///
    /// The inner product encrypts `sum_{i, plaintexts[i] != nil} self[i] * plaintexts[i]`. `plaintexts[i]`
    /// may be `nil`, which denotes a zero plaintext.
    /// - Parameters:
    ///   - ciphertexts: Ciphertexts. Must not be empty.
    ///   - plaintexts: Plaintexts. Must not be empty and have `count` matching
    /// `ciphertexts.count`. `nil` plaintexts indicate zero plaintexts which can be ignored in the computation.
    /// - Returns: A ciphertext encrypting the inner product.
    /// - Throws: Error upon failure to compute inner product.
    static func innerProduct(ciphertexts: some Collection<EvalCiphertext>,
                             plaintexts: some Collection<EvalPlaintext?>) throws -> EvalCiphertext

    /// In-place ciphertext multiplication: `ciphertext *= ciphertext`.
    ///
    /// - Parameters:
    ///   - lhs: Ciphertext to multiply to; will store the product.
    ///   - rhs: Ciphertext to multiply.
    /// - Throws: Error upon failure to multiply.
    /// > Note: the values of the decrypted product depend on the ``EncodeFormat`` of the plaintexts encrypted by `lhs`
    /// and `rhs.`
    ///
    /// > Important: The resulting ciphertext has 3 polynomials and can be relinearized. See
    /// ``HeScheme/relinearize(_:using:)``
    static func mulAssign(_ lhs: inout CanonicalCiphertext, _ rhs: CanonicalCiphertext) throws

    /// In-place ciphertext addition: `lhs += rhs`.
    ///
    /// - Parameters:
    ///   - lhs: Ciphertext to add; will store the sum.
    ///   - rhs: Ciphertext to add.
    /// - Throws: Error upon failure to add.
    static func addAssign(_ lhs: inout CanonicalCiphertext, _ rhs: CanonicalCiphertext) throws

    /// In-place ciphertext-plaintext addition: `ciphertext += plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to add; will store the sum.
    ///   - plaintext: Plaintext to add.
    /// - Throws: Error upon failure to add.
    static func addAssign(_ ciphertext: inout CanonicalCiphertext, _ plaintext: CoeffPlaintext) throws

    /// In-place ciphertext-plaintext addition: `ciphertext += plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to add; will store the sum.
    ///   - plaintext: Plaintext to add.
    /// - Throws: Error upon failure to add.
    static func addAssign(_ ciphertext: inout CanonicalCiphertext, _ plaintext: EvalPlaintext) throws

    /// In-place ciphertext subtraction: `lhs -= rhs`.
    ///
    /// - Parameters:
    ///   - lhs: Ciphertext to subtract from; will store the difference.
    ///   - rhs: Ciphertext to subtract..
    /// - Throws: Error upon failure to subtract.
    static func subAssign(_ lhs: inout CanonicalCiphertext, _ rhs: CanonicalCiphertext) throws

    /// In-place ciphertext-plaintext subtraction: `ciphertext -= plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to subtract from; will store the difference.
    ///   - plaintext: Plaintext to subtract.
    /// - Throws: Error upon failure to subtract.
    static func subAssign(_ ciphertext: inout CanonicalCiphertext, _ plaintext: CoeffPlaintext) throws

    /// In-place ciphertext-plaintext subtraction: `ciphertext -= plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to subtract from; will store the difference.
    ///   - plaintext: Plaintext to subtract.
    /// - Throws: Error upon failure to subtract.
    static func subAssign(_ ciphertext: inout CanonicalCiphertext, _ plaintext: EvalPlaintext) throws

    /// In-place ciphertext negation: `ciphertext = -ciphertext`.
    ///
    /// - Parameter ciphertext:  Ciphertext to negate.
    static func negAssign(_ ciphertext: inout CanonicalCiphertext)

    /// Performs modulus switching on the ciphertext.
    ///
    /// Modulus switching drops the last coefficient modulus in the ciphertext's current ciphertext modulus, without
    /// affecting the value of the plaintext after decryption. Modulus switching reduces the runtime, serialization
    /// size, and memory overhead of the resulting ciphertext. However, it may also reduce the noise budget (see
    /// ``HeScheme/noiseBudget(of:using:variableTime:)-5p5m0``) of the ciphertext. The ideal time to mod switch
    /// therefore
    /// depends on the encrypted circuit. A simple guideline is to `modSwitchDown` immediately prior to serialization
    /// and sending the ciphertext to the secret key owner.
    /// - Parameter ciphertext: Ciphertext; must have > 1 ciphertext modulus.
    /// - Throws: Error upon failure to mod-switch.
    /// - seealso: ``Ciphertext/modSwitchDown()`` for an alternative API.
    static func modSwitchDown(_ ciphertext: inout CanonicalCiphertext) throws

    /// Applies a Galois transformation, also known as a Frobenius transformation.
    ///
    /// The Galois transformation with Galois element `p` transforms the ciphertext encoding the polynomial `f(x)`
    /// depending on the ``EncodeFormat`` used:
    /// * ``EncodeFormat/coefficient``:
    ///   - `f(x)` is transformed to `f(x^p)`.
    /// * ``EncodeFormat/simd``:
    ///   - If there is a `step` for which `p` is the result of ``GaloisElement/rotatingColumns(by:degree:)``, then the
    /// Galois transformation rotates the columns of the
    /// plaintext. See ``HeScheme/rotateColumns(of:by:using:)-7h3fz``.
    ///   - If `p` is the result of ``GaloisElement/swappingRows(degree:)``, the Galois transformation swaps the rows of
    /// the plaintext. See ``HeScheme/swapRows(of:using:)-50tac``.
    /// - Parameters:
    ///   - ciphertext: Ciphertext to transform.
    ///   - element: Galois element of the transformation. Must be odd in `[1, 2 * N - 1]` where `N` is the RLWE ring
    /// dimension, given by ``EncryptionParameters/polyDegree``.
    ///   - key: Evaluation key. Must contain Galois element `element`.
    /// - Throws: Error upon failure to apply the Galois transformation.
    static func applyGalois(
        ciphertext: inout CanonicalCiphertext,
        element: Int,
        using key: EvaluationKey) throws

    /// Relinearizes a ciphertext.
    ///
    /// Relinearization reduces the number of polynomials in a ciphertext after ciphertext-ciphertext multiplication.
    /// Relinearization doesn't change the decryption of the ciphertext.
    /// > Tip: Relinearization decreases the number of polynomials in the ciphertext, so computations on a relinearized
    /// ciphertext will be faster than a non-relinearized ciphertext. So relinearization should generally be performed
    /// immediately following ciphertext-ciphertext multiplication. However, in some cases, such as computing an inner
    /// product
    /// between two ciphertext vectors, relinearization can be delayed until after the summation, resulting in just a
    /// single relinearization.
    /// - Parameters:
    ///   - ciphertext: Ciphertext; must be the result of a ciphertext-ciphertext multiplication
    ///   - key: Evaluation key; must contain a `RelinearizationKey`.
    /// - Throws: Error upon failure to relinearize the ciphertext.
    static func relinearize(_ ciphertext: inout CanonicalCiphertext, using key: EvaluationKey) throws

    /// Validates the equality of two contexts.
    /// - Parameters:
    ///   - lhs: A Context to compare.
    ///   - rhs: Another context to compare.
    /// - Throws: Error upon unequal contexts.
    static func validateEquality(of lhs: Context<Self>, and rhs: Context<Self>) throws

    /// Computes the noise budget of a ciphertext.
    ///
    /// The *noise budget* of a ciphertext decreases throughout HE operations. Once a ciphertext's noise budget is below
    /// ``HeScheme/minNoiseBudget``, decryption may yield inaccurate plaintexts.
    /// - Parameters:
    ///   - ciphertext: Ciphertext whose noise budget to compute.
    ///   - secretKey: Secret key.
    ///   - variableTime: Must be `true`, indicating the secret key coefficients are leaked through timing.
    /// - Returns: The noise budget.
    /// - Throws: Error upon failure to compute the noise budget.
    /// - Warning: Leaks `secretKey` through timing. Should be used for testing only.
    /// - seealso: ``Ciphertext/noiseBudget(using:variableTime:)-7dicj`` for an alternative API.
    static func noiseBudget(of ciphertext: CanonicalCiphertext, using secretKey: SecretKey, variableTime: Bool) throws
        -> Double

    /// Computes the noise budget of a ciphertext.
    ///
    /// The *noise budget* of a ciphertext decreases throughout HE operations. Once a ciphertext's noise budget is below
    /// ``HeScheme/minNoiseBudget``, decryption may yield inaccurate plaintexts.
    /// - Parameters:
    ///   - ciphertext: Ciphertext whose noise budget to compute.
    ///   - secretKey: Secret key.
    ///   - variableTime: Must be `true`, indicating the secret key coefficients are leaked through timing.
    /// - Returns: The noise budget.
    /// - Throws: Error upon failure to compute the noise budget.
    /// - Warning: Leaks `secretKey` through timing. Should be used for testing only.
    /// - seealso: ``Ciphertext/noiseBudget(using:variableTime:)-6ha4l`` for an alternative API.
    static func noiseBudget(of ciphertext: CoeffCiphertext, using secretKey: SecretKey, variableTime: Bool) throws
        -> Double

    /// Computes the noise budget of a ciphertext.
    ///
    /// The *noise budget* of a ciphertext decreases throughout HE operations. Once a ciphertext's noise budget is below
    /// ``HeScheme/minNoiseBudget``, decryption may yield inaccurate plaintexts.
    /// - Parameters:
    ///   - ciphertext: Ciphertext whose noise budget to compute.
    ///   - secretKey: Secret key.
    ///   - variableTime: Must be `true`, indicating the secret key coefficients are leaked through timing.
    /// - Returns: The noise budget.
    /// - Throws: Error upon failure to compute the noise budget.
    /// - Warning: Leaks `secretKey` through timing. Should be used for testing only.
    /// - seealso: ``Ciphertext/noiseBudget(using:variableTime:)-39n1i`` for an alternative API.
    static func noiseBudget(of ciphertext: EvalCiphertext, using secretKey: SecretKey, variableTime: Bool) throws
        -> Double
}

extension HeScheme {
    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func validateEquality(of lhs: Context<Self>, and rhs: Context<Self>) throws {
        guard lhs == rhs else {
            throw HeError.unequalContexts(got: lhs, expected: rhs)
        }
    }
}

extension HeScheme {
    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func rotateColumns(
        of ciphertext: inout CanonicalCiphertext,
        by step: Int,
        using evaluationKey: EvaluationKey) throws
    {
        let element = try GaloisElement.rotatingColumns(by: step, degree: ciphertext.context.degree)
        try applyGalois(ciphertext: &ciphertext, element: element, using: evaluationKey)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func swapRows(of ciphertext: inout CanonicalCiphertext, using evaluationKey: EvaluationKey) throws {
        let element = GaloisElement.swappingRows(degree: ciphertext.context.degree)
        try applyGalois(ciphertext: &ciphertext, element: element, using: evaluationKey)
    }
}

extension HeScheme {
    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func innerProduct(_ lhs: some Collection<CanonicalCiphertext>,
                                    _ rhs: some Collection<CanonicalCiphertext>) throws -> CanonicalCiphertext
    {
        guard lhs.count == rhs.count else {
            throw HeError.incompatibleCiphertextCount(lhs.count, expected: rhs.count)
        }
        return try (zip(lhs, rhs).map { try $0.0 * $0.1 }).sum<Scheme.CanonicalCiphertextFormat>()
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func innerProduct(ciphertexts: some Collection<EvalCiphertext>,
                                    plaintexts: some Collection<EvalPlaintext?>) throws -> EvalCiphertext
    {
        guard let firstCiphertext = ciphertexts.first else {
            fatalError("Empty ciphertexts in inner product")
        }
        return try (zip(ciphertexts, plaintexts).map { ciphertext, plaintext in
            guard let plaintext else {
                return try Self.zeroCiphertext(
                    context: firstCiphertext.context,
                    moduliCount: firstCiphertext.moduli.count)
            }
            return try ciphertext * plaintext
        }).sum()
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func innerProduct(ciphertexts: some Collection<EvalCiphertext>,
                                    plaintexts: some Collection<EvalPlaintext>) throws -> EvalCiphertext
    {
        guard ciphertexts.count == plaintexts.count else {
            throw HeError.incompatibleCiphertextCount(ciphertexts.count, expected: plaintexts.count)
        }
        // the precondition in sum will fail if self or plaintexts is empty
        return try (zip(ciphertexts, plaintexts).map { try $0.0 * $0.1 }).sum()
    }
}

// MARK: forwarding to Context

extension Context {
    /// Generates a ``SecretKey``.
    /// - Returns: A freshly generated secret key.
    /// - Throws: Error upon failure to generate a secret key.
    /// - seealso: ``HeScheme/generateSecretKey(context:)`` for an alternative API.
    @inlinable
    public func generateSecretKey() throws -> SecretKey<Scheme> {
        try Scheme.generateSecretKey(context: self)
    }

    /// Generates an ``EvaluationKey``.
    /// - Parameters:
    ///   - configuration: Evaluation key configuration.
    ///   - secretKey: Secret key used to generate the evaluation key.
    /// - Returns: A freshly generated evaluation key.
    /// - Throws: Error upon failure to generate an evaluation key.
    /// - seealso: ``HeScheme/generateEvaluationKey(context:configuration:using:)`` for an alternative API.
    @inlinable
    public func generateEvaluationKey(
        configuration: EvaluationKeyConfiguration,
        using secretKey: SecretKey<Scheme>) throws
        -> EvaluationKey<Scheme>
    {
        try Scheme.generateEvaluationKey(context: self, configuration: configuration, using: secretKey)
    }
}
