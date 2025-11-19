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

public import ModularArithmetic

extension Bfv {
    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encodeSimdDimensions(for parameters: EncryptionParameters<T>) -> SimdEncodingDimensions? {
        guard parameters.supportsSimdEncoding else {
            return nil
        }
        return SimdEncodingDimensions(rowCount: 2, columnCount: parameters.polyDegree / 2)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(context: Context, values: some Collection<Scalar>,
                              format: EncodeFormat) throws -> CoeffPlaintext
    {
        try context.encode(values: values, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(context: Context, signedValues: some Collection<SignedScalar>,
                              format: EncodeFormat) throws -> CoeffPlaintext
    {
        try context.encode(signedValues: signedValues, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(context: Context, values: some Collection<Scalar>, format: EncodeFormat,
                              moduliCount: Int?) throws -> EvalPlaintext
    {
        let coeffPlaintext = try Self.encode(context: context, values: values, format: format)
        return try coeffPlaintext.convertToEvalFormat(moduliCount: moduliCount)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(
        context: Context,
        signedValues: some Collection<SignedScalar>,
        format: EncodeFormat,
        moduliCount: Int?) throws -> EvalPlaintext
    {
        let coeffPlaintext = try Self.encode(context: context, signedValues: signedValues, format: format)
        return try coeffPlaintext.convertToEvalFormat(moduliCount: moduliCount)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decodeCoeff(plaintext: CoeffPlaintext, format: EncodeFormat) throws -> [Scalar] {
        try plaintext.context.decode(plaintext: plaintext, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decodeCoeff(plaintext: CoeffPlaintext, format: EncodeFormat) throws -> [SignedScalar] {
        try plaintext.context.decode(plaintext: plaintext, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decodeEval(plaintext: EvalPlaintext, format: EncodeFormat) throws -> [Scalar] {
        try plaintext.convertToCoeffFormat().decode(format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decodeEval(plaintext: EvalPlaintext, format: EncodeFormat) throws -> [SignedScalar] {
        try plaintext.convertToCoeffFormat().decode(format: format)
    }

    /// Calculates the number of least significant bits (LSBs) per polynomial that can be excluded
    /// from serialization of a single-modulus ciphertext, when decryption is performed immediately after
    /// deserialization.
    ///
    /// In BFV, the LSB bits of each polynomial may be excluded from the serialization,
    /// since they are rarely used in decryption. This yields a smaller
    /// serialization size, at the cost of a small chance of decryption
    /// error.
    /// - seealso: Section 5.2 of <https://eprint.iacr.org/2022/207.pdf>.
    @inlinable
    public static func skipLSBsForDecryption(for parameters: EncryptionParameters<Scalar>) -> [Int] {
        let q0 = parameters.coefficientModuli[0]
        let t = parameters.plaintextModulus
        // Note, Appendix F of the paper claims the low `l' = floor(log2(q/t))` bits of
        // a message are unused during decryption. This is off by one, due to
        // also needing the MSB decimal bit for correct rounding.
        // Concretely, let x=7, t=5, q=64. Then, floor(log2(q/t)) = 3.
        // Decrypting `x` yields `round(x * t / q) = round(0.546875) = 1`,
        // whereas decrypting `(x >> 3) >> 3) = 0` yields `round(0 * t / q) = 0`.
        // Hence, we subtract one from the definition of `l'` compared to the paper.
        //
        // Also, Appendix F fails to address ciphertext error. If the error
        // is less than q/4t, then we have the error introduced by the dropped
        // bits be less than q/4t so we can correctly decrypt.
        let lPrime = if q0 >= 2 * t {
            (q0 / t).log2 - 3
        } else {
            0
        }

        // Then, we want the error introduced by dropping
        // bits to be `<= q/4p` since it is additive with the
        // ciphertext error. Set number of bits dropped
        // in `b` to `floor(log(q/8p))`. Next, estimate
        // how many bits to drop from a so that
        // w.h.p., the introduced error is less
        // than q/8p.
        //
        // The paper uses `z_score * sqrt(2N/9) * 2^{l_a} + 2^{l_b} < 2^{l'}`
        // Setting `l_b = l' - 1`, this yields
        // `z_score * sqrt(2N/9) * 2^{l_a} < 2^{l'-1}`, iff
        // `log2(z_score * sqrt(2N/9)) + l_a < l' - 1`, iff
        // `l_a < l' - 1 - log2(z_score * sqrt(2N/9))`, which is true for
        // `l_a = floor(l' - 1 - log2(z_score * sqrt(2N/9)))`
        // The paper uses z_score = 7; we use a larger z_score since we are decrypting N
        // coefficients, rather than a single LWE coefficient. This yields a
        // a per-coefficient decryption error `Pr(|x| > z_score)`, where `x ~ N(0, 1)`.
        // This yields a < 2^-49.5 per-coefficient decryption error.
        // By union bound, the message decryption error is
        // `< 2^(log2(N) - 49.5) = 2^-36.5` for `N=8192`
        //
        // We also add a check: if we're only dropping at most one bit in `a`, then
        // it is safer to drop that bit in `b` instead since the error's
        // dependence on `b` is deterministic.
        var poly0SkipLSBs = max(lPrime, 0)
        let zScore = 8.0
        let tmp = Int(zScore * (2.0 * Double(parameters.polyDegree) / 9.0).squareRoot())
        var poly1SkipLSBs = lPrime - (tmp == 0 ? 0 : tmp.ceilLog2)
        if poly1SkipLSBs <= 1 {
            poly0SkipLSBs = max(lPrime + 1, 0)
            poly1SkipLSBs = 0
        }
        return [poly0SkipLSBs, poly1SkipLSBs]
    }
}
