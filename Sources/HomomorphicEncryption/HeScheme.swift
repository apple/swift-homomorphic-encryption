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

import ModularArithmetic

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

/// The (row, column) dimensions for ``EncodeFormat/simd`` encoding.
///
/// With ``EncodeFormat/simd`` encoding, the encoded values can be viewed as a matrix of scalars. Some HE operations
/// such as ``HeScheme/rotateColumns(of:by:using:)-5mcg`` and ``HeScheme/swapRows(of:using:)-7lya8`` operate on the rows
/// and columns of the matrix.
public struct SimdEncodingDimensions: Codable, Equatable, Hashable, Sendable {
    /// Number of rows of scalars encoded in each plaintext.
    public let rowCount: Int
    /// Number of columns of scalars encoded in each plaintext.
    public let columnCount: Int

    /// Initializes a new ``SimdEncodingDimensions``.
    /// - Parameters:
    ///   - rowCount: Number of rows of scalars in each plaintext.
    ///   - columnCount: Number of columns of scalars in each plaintext.
    public init(rowCount: Int, columnCount: Int) {
        self.rowCount = rowCount
        self.columnCount = columnCount
    }
}

/// Protocol for HE schemes.
///
/// The protocol should be implemented when adding a new HE scheme.
/// However, several functions have an alternative API which is more ergonomic and should be preferred.
public protocol HeScheme {
    /// Coefficient type for each polynomial.
    associatedtype Scalar: ScalarType
    /// Coefficient type for signed encoding/decoding.
    typealias SignedScalar = Scalar.SignedScalar

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
    /// ``Ciphertext/convertToEvalFormat()`` can be used to convert a ciphertext to an ``EvalCiphertext``.
    typealias EvalCiphertext = Ciphertext<Self, Eval>

    /// The canonical representation of a ciphertext.
    ///
    /// The canonical representation is the default ciphertext representation.
    /// ``Ciphertext/convertToCanonicalFormat()`` can be used to convert a ciphertext to a ``CanonicalCiphertext``.
    /// However, some operations may require a specific format, such as ``CoeffCiphertext`` or ``EvalCiphertext``.
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
    /// - seealso: ``Ciphertext/noiseBudget(using:variableTime:)``.
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
    ///   - config: Evaluation key configuration.
    ///   - secretKey: Secret key used to generate the evaluation key.
    /// - Returns: A freshly generated evaluation key.
    /// - Throws: Error upon failure to generate an evaluation key.
    /// - seealso: ``Context/generateEvaluationKey(config:using:)`` for an alternative API.
    static func generateEvaluationKey(
        context: Context<Self>,
        config: EvaluationKeyConfig,
        using secretKey: SecretKey) throws
        -> EvaluationKey

    /// Returns the dimension counts for ``EncodeFormat/simd`` encoding, or `nil` if the HE scheme does
    /// not support SIMD encoding for the given parameters.
    static func encodeSimdDimensions(for parameters: EncryptionParameters<Self>) -> SimdEncodingDimensions?

    /// Encodes values into a plaintext with coefficient format.
    ///
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - values: Values to encode.
    ///   - format: Encoding format.
    /// - Returns: A plaintext encoding `values`.
    /// - Throws: Error upon failure to encode.
    /// - seealso: ``Context/encode(values:format:)`` for an alternative API.
    /// - seealso: ``HeScheme/encode(context:signedValues:format:)`` to encode signed values.
    static func encode(context: Context<Self>, values: some Collection<Scalar>, format: EncodeFormat) throws
        -> CoeffPlaintext

    /// Encodes signed values into a plaintext with coefficient format.
    ///
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - signedValues: Signed values to encode.
    ///   - format: Encoding format.
    /// - Returns: A plaintext encoding `signedValues`.
    /// - Throws: Error upon failure to encode.
    /// - seealso: ``Context/encode(signedValues:format:)`` for an alternative API.
    /// - seealso: ``HeScheme/encode(context:values:format:)`` to encode unsigned values.
    static func encode(context: Context<Self>, signedValues: some Collection<SignedScalar>, format: EncodeFormat) throws
        -> CoeffPlaintext

    /// Encodes values into a plaintext with evaluation format.
    ///
    /// The encoded plaintext will have a ``Plaintext/polyContext()`` with the `moduliCount` first ciphertext moduli.
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - values: Values to encode.
    ///   - format: Encoding format.
    ///   - moduliCount: Optional number of moduli. If not set, encoding will use the top-level ciphertext context with
    /// all the moduli.
    /// - Returns: A plaintext encoding `values`.
    /// - Throws: Error upon failure to encode.
    /// - seealso: ``Context/encode(values:format:moduliCount:)`` for an alternative API.
    /// - seealso: ``HeScheme/encode(context:signedValues:format:moduliCount:)`` to encode signed values.
    static func encode(context: Context<Self>, values: some Collection<Scalar>, format: EncodeFormat,
                       moduliCount: Int?) throws -> EvalPlaintext

    /// Encodes signed values into a plaintext with evaluation format.
    ///
    /// The encoded plaintext will have a ``Plaintext/polyContext()`` with the `moduliCount` first ciphertext moduli.
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - signedValues: Signed values to encode.
    ///   - format: Encoding format.
    ///   - moduliCount: Optional number of moduli. If not set, encoding will use the top-level ciphertext context with
    /// all the moduli.
    /// - Returns: A plaintext encoding `signedValues`.
    /// - Throws: Error upon failure to encode.
    /// - seealso: ``Context/encode(signedValues:format:moduliCount:)`` for an alternative API.
    /// - seealso: ``HeScheme/encode(context:values:format:moduliCount:)`` to encode unsigned values.
    static func encode(context: Context<Self>, signedValues: some Collection<Scalar.SignedScalar>, format: EncodeFormat,
                       moduliCount: Int?) throws -> EvalPlaintext

    /// Decodes a plaintext in ``Coeff`` format.
    /// - Parameters:
    ///   - plaintext: Plaintext to decode.
    ///   - format: Encoding format of the plaintext.
    /// - Returns: The decoded values.
    /// - Throws: Error upon failure to decode the plaintext.
    /// - seealso: ``Plaintext/decode(format:)-28hb7`` for an alternative API.
    static func decodeCoeff(plaintext: CoeffPlaintext, format: EncodeFormat) throws -> [Scalar]

    /// Decodes a plaintext in ``Coeff`` format into signed values.
    /// - Parameters:
    ///   - plaintext: Plaintext to decode.
    ///   - format: Encoding format of the plaintext.
    /// - Returns: The decoded signed values.
    /// - Throws: Error upon failure to decode the plaintext.
    /// - seealso: ``Plaintext/decode(format:)-2agje`` for an alternative API.
    static func decodeCoeff(plaintext: CoeffPlaintext, format: EncodeFormat) throws -> [SignedScalar]

    /// Decodes a plaintext in ``Eval`` format.
    /// - Parameters:
    ///   - plaintext: Plaintext to decode.
    ///   - format: Encoding format of the plaintext.
    /// - Returns: The decoded values.
    /// - Throws: Error upon failure to decode the plaintext.
    /// - seealso: ``Plaintext/decode(format:)-28hb7`` for an alternative API.
    static func decodeEval(plaintext: EvalPlaintext, format: EncodeFormat) throws -> [Scalar]

    /// Decodes a plaintext in ``Eval`` format to signed values.
    /// - Parameters:
    ///   - plaintext: Plaintext to decode.
    ///   - format: Encoding format of the plaintext.
    /// - Returns: The decoded signed values.
    /// - Throws: Error upon failure to decode the plaintext.
    /// - seealso: ``Plaintext/decode(format:)-2agje`` for an alternative API.
    static func decodeEval(plaintext: EvalPlaintext, format: EncodeFormat) throws -> [SignedScalar]

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
    ///   - moduliCount: Number of moduli in the zero ciphertext. If `nil`, the ciphertext will have the ciphertext
    /// context with all the coefficient moduli in `context`.
    /// - Returns: A zero ciphertext.
    /// - Throws: Error upon failure to generate a zero ciphertext.
    /// - Warning: a zero ciphertext is *transparent*, i.e., everyone can see the the underlying plaintext, zero in
    /// this case. Transparency can propagate to ciphertexts operating with transparent ciphertexts, e.g.
    /// ```
    ///  transparentCiphertext * ciphertext = transparentCiphertext
    ///  transparentCiphertext * plaintext = transparentCiphertext
    ///  transparentCiphertext + plaintext = transparentCiphertext
    /// ```
    /// - seealso: ``HeScheme/isTransparent(ciphertext:)``
    /// - seealso: ``Ciphertext/zero(context:moduliCount:)`` for an alternative API.
    static func zeroCiphertextCoeff(context: Context<Self>, moduliCount: Int?) throws -> CoeffCiphertext

    /// Generates a ciphertext of zeros in ``Eval`` format.
    ///
    /// A zero ciphertext may arise from HE computations, e.g., by subtracting a ciphertext from itself, or multiplying
    /// a ciphertext with a zero plaintext.
    ///
    /// - Parameters:
    ///   - context: Context for HE computation.
    ///   - moduliCount: Number of moduli in the zero ciphertext. If `nil`, the ciphertext will have the ciphertext
    /// context with all the coefficient moduli in `context`.
    /// - Returns: A zero ciphertext.
    /// - Throws: Error upon failure to generate a zero ciphertext.
    /// - Warning: a zero ciphertext is *transparent*, i.e., everyone can see the the underlying plaintext, zero in
    /// this case. Transparency can propagate to ciphertexts operating with transparent ciphertexts, e.g.
    /// ```
    ///  transparentCiphertext * ciphertext = transparentCiphertext
    ///  transparentCiphertext * plaintext = transparentCiphertext
    ///  transparentCiphertext + plaintext = transparentCiphertext
    /// ```
    /// - seealso: ``HeScheme/isTransparent(ciphertext:)``
    /// - seealso: ``Ciphertext/zero(context:moduliCount:)`` for an alternative API.
    static func zeroCiphertextEval(context: Context<Self>, moduliCount: Int?) throws -> EvalCiphertext

    /// Computes whether a ciphertext is transparent.
    ///
    /// A *transparent* ciphertext reveals the underlying plaintext to any observer. For instance,
    /// ``HeScheme/zeroCiphertextCoeff(context:moduliCount:)`` yields a transparent transparent.
    /// - Parameter ciphertext: Ciphertext whose transparency to compute.
    /// - Returns: Whether the ciphertext is transparent.
    /// - seealso: ``Ciphertext/isTransparent()`` for an alternative API.
    static func isTransparentCoeff(ciphertext: CoeffCiphertext) -> Bool

    /// Computes whether a ciphertext is transparent.
    ///
    /// A *transparent* ciphertext reveals the underlying plaintext to any observer. For instance,
    /// ``HeScheme/zeroCiphertextEval(context:moduliCount:)`` yields a transparent transparent.
    /// - Parameter ciphertext: Ciphertext whose transparency to compute.
    /// - Returns: Whether the ciphertext is transparent.
    /// - seealso: ``Ciphertext/isTransparent()`` for an alternative API.
    static func isTransparentEval(ciphertext: EvalCiphertext) -> Bool

    /// Decryption of a ciphertext in coefficient format.
    /// - Parameters:
    ///   - ciphertext: Ciphertext to decrypt.
    ///   - secretKey: Secret key to decrypt with.
    /// - Returns: The plaintext decryption of the ciphertext.
    /// - Throws: Error upon failure to decrypt.
    /// - Warning: The ciphertext must have at least ``HeScheme/minNoiseBudget`` noise to ensure accurate decryption.
    ///  - seealso: The noise budget can be computed using ``Ciphertext/noiseBudget(using:variableTime:)``.
    ///  - seealso: ``Ciphertext/decrypt(using:)`` for an alternative API.
    static func decryptCoeff(_ ciphertext: CoeffCiphertext, using secretKey: SecretKey) throws -> CoeffPlaintext

    /// Decryption of a ciphertext in evaluation format.
    /// - Parameters:
    ///   - ciphertext: Ciphertext to decrypt.
    ///   - secretKey: Secret key to decrypt with.
    /// - Returns: The plaintext decryption of the ciphertext.
    /// - Throws: Error upon failure to decrypt.
    /// - Warning: The ciphertext must have at least ``HeScheme/minNoiseBudget`` noise to ensure accurate decryption.
    ///  - seealso: The noise budget can be computed using ``Ciphertext/noiseBudget(using:variableTime:)``.
    ///  - seealso: ``Ciphertext/decrypt(using:)`` for an alternative API.
    static func decryptEval(_ ciphertext: EvalCiphertext, using secretKey: SecretKey) throws -> CoeffPlaintext

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
    static func addAssignCoeff(_ lhs: inout CoeffCiphertext, _ rhs: CoeffCiphertext) throws

    /// In-place ciphertext addition: `lhs += rhs`.
    /// - Parameters:
    ///   - lhs: Ciphertext to add; will store the sum.
    ///   - rhs: Ciphertext to add.
    /// - Throws: Error upon failure to add.
    static func addAssignEval(_ lhs: inout EvalCiphertext, _ rhs: EvalCiphertext) throws

    /// In-place ciphertext subtraction: `lhs -= rhs`.
    /// - Parameters:
    ///   - lhs: Ciphertext to subtract from; will store the difference.
    ///   - rhs: Ciphertext to subtract.
    /// - Throws: Error upon failure to subtract.
    static func subAssignCoeff(_ lhs: inout CoeffCiphertext, _ rhs: CoeffCiphertext) throws

    /// In-place ciphertext subtraction: `lhs -= rhs`.
    ///
    /// - Parameters:
    ///   - lhs: Ciphertext to subtract from; will store the difference.
    ///   - rhs: Ciphertext to subtract.
    /// - Throws: Error upon failure to subtract.
    static func subAssignEval(_ lhs: inout EvalCiphertext, _ rhs: EvalCiphertext) throws

    /// In-place ciphertext-plaintext addition: `ciphertext += plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to add; will store the sum.
    ///   - plaintext: Plaintext to add.
    /// - Throws: Error upon failure to add.
    static func addAssignCoeff(_ ciphertext: inout CoeffCiphertext, _ plaintext: CoeffPlaintext) throws

    /// In-place ciphertext-plaintext addition: `ciphertext += plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to add; will store the sum.
    ///   - plaintext: Plaintext to add.
    /// - Throws: Error upon failure to add.
    static func addAssignEval(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) throws

    /// In-place ciphertext-plaintext subtraction: `ciphertext -= plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to subtract from; will store the difference.
    ///   - plaintext: Plaintext to subtract.
    /// - Throws: Error upon failure to subtract.
    static func subAssignCoeff(_ ciphertext: inout CoeffCiphertext, _ plaintext: CoeffPlaintext) throws

    /// In-place ciphertext-plaintext subtraction: `ciphertext -= plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to subtract from; will store the difference.
    ///   - plaintext: Plaintext to subtract.
    /// - Throws: Error upon failure to subtract.
    static func subAssignEval(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) throws

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
    static func negAssignCoeff(_ ciphertext: inout CoeffCiphertext)

    /// In-place ciphertext negation: `ciphertext = -ciphertext`.
    ///
    /// - Parameter ciphertext: Ciphertext to negate.
    static func negAssignEval(_ ciphertext: inout EvalCiphertext)

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

    /// Performs modulus switching on the ciphertext.
    ///
    /// Modulus switching drops the last coefficient modulus in the ciphertext's current ciphertext modulus, without
    /// affecting the value of the plaintext after decryption. Modulus switching reduces the runtime, serialization
    /// size, and memory overhead of the resulting ciphertext. However, it may also reduce the noise budget (see
    /// ``Ciphertext/noiseBudget(using:variableTime:)``) of the ciphertext. The ideal time to mod switch
    /// therefore depends on the encrypted circuit. A simple guideline is to `modSwitchDown` immediately prior to
    /// serialization and sending the ciphertext to the secret key owner.
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
    ///   - variableTime: If `true`, indicates the secret key coefficients may be leaked through timing.
    /// - Returns: The noise budget.
    /// - Throws: Error upon failure to compute the noise budget.
    /// - Warning: Leaks `secretKey` through timing. Should be used for testing only.
    /// - Warning: The noise budget depends on the encrypted message, which is impractical to know apriori. So this
    /// function should be treated only as a rough proxy for correct decryption, rather than a source of truth.
    ///   See Section 2 of <https://eprint.iacr.org/2016/510.pdf> for more details.
    /// - seealso: ``Ciphertext/noiseBudget(using:variableTime:)`` for an alternative API.
    static func noiseBudgetCoeff(of ciphertext: CoeffCiphertext, using secretKey: SecretKey, variableTime: Bool) throws
        -> Double

    /// Computes the noise budget of a ciphertext.
    ///
    /// The *noise budget* of a ciphertext decreases throughout HE operations. Once a ciphertext's noise budget is below
    /// ``HeScheme/minNoiseBudget``, decryption may yield inaccurate plaintexts.
    /// - Parameters:
    ///   - ciphertext: Ciphertext whose noise budget to compute.
    ///   - secretKey: Secret key.
    ///   - variableTime: If `true`, indicates the secret key coefficients may be leaked through timing.
    /// - Returns: The noise budget.
    /// - Throws: Error upon failure to compute the noise budget.
    /// - Warning: Leaks `secretKey` through timing. Should be used for testing only.
    /// - Warning: The noise budget depends on the encrypted message, which is impractical to know apriori. So this
    /// function should be treated only as a rough proxy for correct decryption, rather than a source of truth.
    ///   See Section 2 of <https://eprint.iacr.org/2016/510.pdf> for more details.
    /// - seealso: ``Ciphertext/noiseBudget(using:variableTime:)`` for an alternative API.
    static func noiseBudgetEval(of ciphertext: EvalCiphertext, using secretKey: SecretKey, variableTime: Bool) throws
        -> Double
}

extension HeScheme {
    /// Decryption of a ciphertext.
    /// - Parameters:
    ///   - ciphertext: Ciphertext to decrypt.
    ///   - secretKey: Secret key to decrypt with.
    /// - Returns: The plaintext decryption of the ciphertext.
    /// - Throws: Error upon failure to decrypt.
    /// - Warning: The ciphertext must have at least ``HeScheme/minNoiseBudget`` noise to ensure accurate decryption.
    ///  - seealso: The noise budget can be computed using ``Ciphertext/noiseBudget(using:variableTime:)``.
    ///  - seealso: ``Ciphertext/decrypt(using:)`` for an alternative API.
    @inlinable
    public static func decrypt<Format: PolyFormat>(_ ciphertext: Ciphertext<Self, Format>,
                                                   using secretKey: SecretKey) throws -> CoeffPlaintext
    {
        if Format.self == Coeff.self {
            // swiftlint:disable:next force_cast
            return try decryptCoeff(ciphertext as! CoeffCiphertext, using: secretKey)
        }
        if Format.self == Eval.self {
            // swiftlint:disable:next force_cast
            return try decryptEval(ciphertext as! EvalCiphertext, using: secretKey)
        }
        fatalError("Unsupported Format \(Format.description)")
    }

    /// In-place ciphertext-plaintext addition: `ciphertext += plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to add; will store the sum.
    ///   - plaintext: Plaintext to add.
    /// - Throws: Error upon failure to add.
    @inlinable
    public static func addAssign<CiphertextFormat: PolyFormat, PlaintextFormat: PolyFormat>(
        _ ciphertext: inout Ciphertext<Self, CiphertextFormat>,
        _ plaintext: Plaintext<Self, PlaintextFormat>) throws
    {
        // swiftlint:disable force_cast
        if CiphertextFormat.self == Coeff.self, PlaintextFormat.self == Coeff.self {
            var coeffCiphertext = ciphertext as! CoeffCiphertext
            try addAssignCoeff(&coeffCiphertext, plaintext as! CoeffPlaintext)
            ciphertext = coeffCiphertext as! Ciphertext<Self, CiphertextFormat>
        } else if CiphertextFormat.self == Eval.self, PlaintextFormat.self == Eval.self {
            var evalCiphertext = ciphertext as! EvalCiphertext
            try addAssignEval(&evalCiphertext, plaintext as! EvalPlaintext)
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
    @inlinable
    public static func addAssign<LhsFormat: PolyFormat, RhsFormat: PolyFormat>(
        _ lhs: inout Ciphertext<Self, LhsFormat>,
        _ rhs: Ciphertext<Self, RhsFormat>) throws
    {
        // swiftlint:disable force_cast
        if LhsFormat.self == Coeff.self {
            var lhsCoeffCiphertext = lhs as! CoeffCiphertext
            if RhsFormat.self == Coeff.self {
                try addAssignCoeff(&lhsCoeffCiphertext, rhs as! CoeffCiphertext)
            } else {
                fatalError("Unsupported Format \(RhsFormat.description)")
            }
            lhs = lhsCoeffCiphertext as! Ciphertext<Self, LhsFormat>
        } else if LhsFormat.self == Eval.self {
            var lhsEvalCiphertext = lhs as! EvalCiphertext
            if RhsFormat.self == Eval.self {
                try addAssignEval(&lhsEvalCiphertext, rhs as! EvalCiphertext)
            } else {
                fatalError("Unsupported Format \(RhsFormat.description)")
            }
            lhs = lhsEvalCiphertext as! Ciphertext<Self, LhsFormat>
        } else {
            fatalError("Unsupported Format \(LhsFormat.description)")
        }
        // swiftlint:enable force_cast
    }

    /// In-place ciphertext-plaintext subtraction: `ciphertext -= plaintext`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext to subtract from; will store the difference.
    ///   - plaintext: Plaintext to subtract.
    /// - Throws: Error upon failure to subtract.
    @inlinable
    public static func subAssign<CiphertextFormat: PolyFormat, PlaintextFormat: PolyFormat>(
        _ ciphertext: inout Ciphertext<Self, CiphertextFormat>,
        _ plaintext: Plaintext<Self, PlaintextFormat>) throws
    {
        // swiftlint:disable force_cast
        if CiphertextFormat.self == Coeff.self, PlaintextFormat.self == Coeff.self {
            var coeffCiphertext = ciphertext as! CoeffCiphertext
            try subAssignCoeff(&coeffCiphertext, plaintext as! CoeffPlaintext)
            ciphertext = coeffCiphertext as! Ciphertext<Self, CiphertextFormat>
        } else if CiphertextFormat.self == Eval.self, PlaintextFormat.self == Eval.self {
            var evalCiphertext = ciphertext as! EvalCiphertext
            try subAssignEval(&evalCiphertext, plaintext as! EvalPlaintext)
            ciphertext = evalCiphertext as! Ciphertext<Self, CiphertextFormat>
        } else {
            throw HeError.unsupportedHeOperation(
                """
                Subtraction between ciphertext in \(CiphertextFormat.description) \
                and plaintext in \(PlaintextFormat.description).
                """)
        }
        // swiftlint:enable force_cast
    }

    /// In-place ciphertext subtraction: `lhs -= rhs`.
    ///
    /// - Parameters:
    ///   - lhs: Ciphertext to subtract from; will store the difference.
    ///   - rhs: Ciphertext to subtract.
    /// - Throws: Error upon failure to subtract.
    @inlinable
    public static func subAssign<LhsFormat: PolyFormat, RhsFormat: PolyFormat>(
        _ lhs: inout Ciphertext<Self, LhsFormat>,
        _ rhs: Ciphertext<Self, RhsFormat>) throws
    {
        // swiftlint:disable force_cast
        if LhsFormat.self == Coeff.self {
            var lhsCoeffCiphertext = lhs as! CoeffCiphertext
            if RhsFormat.self == Coeff.self {
                try subAssignCoeff(&lhsCoeffCiphertext, rhs as! CoeffCiphertext)
            } else {
                fatalError("Unsupported Format \(RhsFormat.description)")
            }
            lhs = lhsCoeffCiphertext as! Ciphertext<Self, LhsFormat>
        } else if LhsFormat.self == Eval.self {
            var lhsEvalCiphertext = lhs as! EvalCiphertext
            if RhsFormat.self == Eval.self {
                try subAssignEval(&lhsEvalCiphertext, rhs as! EvalCiphertext)
            } else {
                fatalError("Unsupported Format \(RhsFormat.description)")
            }
            lhs = lhsEvalCiphertext as! Ciphertext<Self, LhsFormat>
        } else {
            fatalError("Unsupported Format \(LhsFormat.description)")
        }
        // swiftlint:enable force_cast
    }

    /// In-place ciphertext negation: `ciphertext = -ciphertext`.
    ///
    /// - Parameter ciphertext: Ciphertext to negate.
    @inlinable
    public static func negAssign<Format: PolyFormat>(_ ciphertext: inout Ciphertext<Self, Format>) {
        // swiftlint:disable force_cast
        if Format.self == Coeff.self {
            var coeffCiphertext = ciphertext as! CoeffCiphertext
            negAssignCoeff(&coeffCiphertext)
            ciphertext = coeffCiphertext as! Ciphertext<Self, Format>
        } else if Format.self == Eval.self {
            var evalCiphertext = ciphertext as! EvalCiphertext
            negAssignEval(&evalCiphertext)
            ciphertext = evalCiphertext as! Ciphertext<Self, Format>
        } else {
            fatalError("Unsupported Format \(Format.description)")
        }
        // swiftlint:enable force_cast
    }

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
    /// - seealso: ``Ciphertext/noiseBudget(using:variableTime:)`` for an alternative API.
    @inlinable
    public static func noiseBudget<Format: PolyFormat>(
        of ciphertext: Ciphertext<Self, Format>,
        using secretKey: SecretKey,
        variableTime: Bool) throws
        -> Double
    {
        // swiftlint:disable force_cast
        if Format.self == Coeff.self {
            return try noiseBudgetCoeff(
                of: ciphertext as! CoeffCiphertext,
                using: secretKey,
                variableTime: variableTime)
        }
        if Format.self == Eval.self {
            return try noiseBudgetEval(of: ciphertext as! EvalCiphertext, using: secretKey, variableTime: variableTime)
        }
        fatalError("Unsupported Format \(Format.description)")
        // swiftlint:enable force_cast
    }

    /// Computes whether a ciphertext is transparent.
    ///
    /// A *transparent* ciphertext reveals the underlying plaintext to any observer. For instance,
    /// ``Ciphertext/zero(context:moduliCount:)`` yields a transparent transparent.
    /// - Parameter ciphertext: Ciphertext whose transparency to compute.
    /// - Returns: Whether the ciphertext is transparent.
    /// - seealso: ``Ciphertext/isTransparent()`` for an alternative API.
    @inlinable
    public static func isTransparent<Format: PolyFormat>(ciphertext: Ciphertext<Self, Format>) -> Bool {
        // swiftlint:disable force_cast
        if Format.self == Coeff.self {
            return isTransparentCoeff(ciphertext: ciphertext as! CoeffCiphertext)
        }
        if Format.self == Eval.self {
            return isTransparentEval(ciphertext: ciphertext as! EvalCiphertext)
        }
        fatalError("Unsupported Format \(Format.description)")
        // swiftlint:enable force_cast
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
    public static func zero<Format: PolyFormat>(context: Context<Self>,
                                                moduliCount: Int? = nil) throws -> Ciphertext<Self, Format>
    {
        if Format.self == Coeff.self {
            let coeffCiphertext = try zeroCiphertextCoeff(context: context, moduliCount: moduliCount)
            // swiftlint:disable:next force_cast
            return coeffCiphertext as! Ciphertext<Self, Format>
        }
        if Format.self == Eval.self {
            let evalCiphertext = try zeroCiphertextEval(context: context, moduliCount: moduliCount)
            // swiftlint:disable:next force_cast
            return evalCiphertext as! Ciphertext<Self, Format>
        }
        fatalError("Unsupported Format \(Format.description)")
    }

    /// Decodes a plaintext.
    /// - Parameters:
    ///   - plaintext: Plaintext to decode.
    ///   - format: Encoding format of the plaintext.
    /// - Returns: The decoded values.
    /// - Throws: Error upon failure to decode the plaintext.
    /// - seealso: ``Plaintext/decode(format:)-28hb7`` for an alternative API.
    @inlinable
    public static func decode<Format: PolyFormat>(
        plaintext: Plaintext<Self, Format>,
        format: EncodeFormat) throws -> [Scalar]
    {
        if Format.self == Coeff.self {
            // swiftlint:disable:next force_cast
            let coeffPlaintext = plaintext as! CoeffPlaintext
            return try decodeCoeff(plaintext: coeffPlaintext, format: format)
        }
        if Format.self == Eval.self {
            // swiftlint:disable:next force_cast
            let evalPlaintext = plaintext as! EvalPlaintext
            return try decodeEval(plaintext: evalPlaintext, format: format)
        }
        fatalError("Unsupported Format \(Format.description)")
    }

    /// Decodes a plaintext to signed values.
    /// - Parameters:
    ///   - plaintext: Plaintext to decode.
    ///   - format: Encoding format of the plaintext.
    /// - Returns: The decoded signed values.
    /// - Throws: Error upon failure to decode the plaintext.
    /// - seealso: ``Plaintext/decode(format:)-2agje`` for an alternative API.
    @inlinable
    public static func decode<Format: PolyFormat>(
        plaintext: Plaintext<Self, Format>,
        format: EncodeFormat) throws -> [SignedScalar]
    {
        if Format.self == Coeff.self {
            // swiftlint:disable:next force_cast
            let coeffPlaintext = plaintext as! CoeffPlaintext
            return try decodeCoeff(plaintext: coeffPlaintext, format: format)
        }
        if Format.self == Eval.self {
            // swiftlint:disable:next force_cast
            let evalPlaintext = plaintext as! EvalPlaintext
            return try decodeEval(plaintext: evalPlaintext, format: format)
        }
        fatalError("Unsupported Format \(Format.description)")
    }
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

    @inlinable
    package static func rotateColumnsMultiStep(
        of ciphertext: inout CanonicalCiphertext,
        by step: Int,
        using evaluationKey: EvaluationKey) throws
    {
        if step == 0 {
            return
        }

        guard let galoisKey = evaluationKey.galoisKey else {
            throw HeError.missingGaloisKey
        }

        // Short-circuit to single rotation if possible.
        let degree = ciphertext.degree
        let galoisElement = try GaloisElement.rotatingColumns(by: step, degree: degree)
        if galoisKey.keys.keys.contains(galoisElement) {
            try ciphertext.rotateColumns(by: step, using: evaluationKey)
            return
        }

        let galoisElements = Array(galoisKey.keys.keys)
        let steps = GaloisElement.stepsFor(elements: galoisElements, degree: degree).values.compactMap { $0 }

        let positiveStep = if step < 0 {
            step + degree / 2
        } else {
            step
        }

        let plan = try GaloisElement.planMultiStep(supportedSteps: steps, step: positiveStep, degree: degree)
        guard let plan else {
            throw HeError.invalidRotationStep(step: step, degree: degree)
        }
        for (step, count) in plan {
            try (0..<count).forEach { _ in try ciphertext.rotateColumns(by: step, using: evaluationKey) }
        }
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
        return try (zip(lhs, rhs).map { try $0.0 * $0.1 }).sum()
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
                return try EvalCiphertext.zero(
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
    ///   - config: Evaluation key configuration.
    ///   - secretKey: Secret key used to generate the evaluation key.
    /// - Returns: A freshly generated evaluation key.
    /// - Throws: Error upon failure to generate an evaluation key.
    /// - seealso: ``HeScheme/generateEvaluationKey(context:config:using:)`` for an alternative API.
    @inlinable
    public func generateEvaluationKey(
        config: EvaluationKeyConfig,
        using secretKey: SecretKey<Scheme>) throws
        -> EvaluationKey<Scheme>
    {
        try Scheme.generateEvaluationKey(context: self, config: config, using: secretKey)
    }
}
