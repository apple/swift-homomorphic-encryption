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

/// Standard deviation for error polynomial in RLWE samples.
public enum ErrorStdDev: Hashable, Codable, Sendable {
    /// Target Standard deviation `8 / sqrt(2 pi) ~= 3.2`.
    ///
    /// In practice, since we sample using a centered binomial distribution,
    /// the sampled standard deviation may exceed the target standard deviation.
    case stdDev32
}

extension ErrorStdDev {
    /// Floating-point representation of the error standard deviation.
    public var toDouble: Double {
        switch self {
        case .stdDev32: 3.2
        }
    }
}

/// Security level for encryption parameters based on ternary secrets.
public enum SecurityLevel: Hashable, Codable, Sendable {
    /// Post-quantum 128-bit security.
    case quantum128
    /// No security enforced.
    ///
    /// - Warning: should be used for testing only. No guarantees are made about cryptographic security in this case.
    case unchecked
}

/// Encryption parameters for an RLWE-based HE scheme.
///
/// These parameters are considered public.
public struct EncryptionParameters<Scheme: HeScheme>: Hashable, Codable, Sendable {
    /// The maximum modulus value for a single coefficient or plaintext modulus.
    public static var maxSingleModulus: Scheme.Scalar {
        Modulus<Scheme.Scalar>.max
    }

    /// Polynomial degree `N` of the RLWE polynomial ring.
    ///
    /// Must be a power of two.
    public let polyDegree: Int
    /// Plaintext modulus, `t`.
    ///
    /// This is the modulus on which encrypted computation occurs.
    public let plaintextModulus: Scheme.Scalar

    /// Co-prime coefficient moduli.
    ///
    /// The last coefficient modulus (`coefficientModuli.last`) is reserved for use in key-switching operations, such
    /// as:
    /// * ``HeScheme/applyGalois(ciphertext:element:using:)``
    /// * ``HeScheme/rotateColumns(of:by:using:)-5mcg``
    /// * ``HeScheme/swapRows(of:using:)-7lya8``
    /// * ``HeScheme/relinearize(_:using:)``
    ///
    /// and should generally be chosen as the largest of the coefficient moduli to minimize noise growth on those
    /// operations.
    /// - seealso: ``Ciphertext/noiseBudget(using:variableTime:)``
    public let coefficientModuli: [Scheme.Scalar]

    /// RLWE error polynomial standard deviation.
    public let errorStdDev: ErrorStdDev

    /// Security level of the encryption parameters.
    ///
    /// - Warning: If set to ``SecurityLevel/unchecked``, no guarantees are made about cryptographic security.
    public let securityLevel: SecurityLevel

    /// Whether or not encryption parameters support ``EncodeFormat/simd`` encoding.
    public var supportsSimdEncoding: Bool { plaintextModulus.isNttModulus(for: polyDegree) }

    /// Whether or not encryption parameters use of an ``EvaluationKey``.
    public var supportsEvaluationKey: Bool { coefficientModuli.count > 1 }

    /// The number of bits that can be encoded in a single ``Plaintext``.
    public var bitsPerPlaintext: Int { polyDegree * plaintextModulus.log2 }

    /// The number of bytes that can be encoded in a single ``Plaintext``.
    public var bytesPerPlaintext: Int { bitsPerPlaintext / UInt8.bitWidth }

    /// Initializes encryption parameters.
    /// - Parameters:
    ///   - polyDegree: Polynomial modulus degree `N`.
    ///   - plaintextModulus: Plaintext modulus `t`. Must be prime and less than all `coefficientModuli`.
    ///   - coefficientModuli: List of coefficient moduli `q = q_0 * ... * q_{L-1}`. Must be co-prime and less than `1
    /// << (T.bitWidth - 2)`. Order matters.
    ///   - errorStdDev: RLWE error standard deviation.
    ///   - securityLevel: Security level to enforce.
    /// - Throws: ``HeError`` upon invalid or insecure encryption parameters.
    /// - Warning: If `securityLevel` is set to ``SecurityLevel/unchecked``, no guarantees are made about cryptographic
    /// security.
    public init(
        polyDegree: Int,
        plaintextModulus: Scheme.Scalar,
        coefficientModuli: [Scheme.Scalar],
        errorStdDev: ErrorStdDev,
        securityLevel: SecurityLevel) throws
    {
        self.polyDegree = polyDegree
        self.plaintextModulus = plaintextModulus
        self.coefficientModuli = coefficientModuli
        self.errorStdDev = errorStdDev
        self.securityLevel = securityLevel

        guard polyDegree.isPowerOfTwo else {
            throw HeError.invalidEncryptionParameters(self)
        }
        let log2CoefficientModulus = coefficientModuli.map { log2(Float($0)) }.reduce(0, +)
        guard try log2CoefficientModulus <= Float(Self.maxLog2CoefficientModulus(
            degree: polyDegree,
            securityLevel: securityLevel)),
            errorStdDev == ErrorStdDev.stdDev32
        else {
            throw HeError.insecureEncryptionParameters(self)
        }
        // Due to some usage of OctoWidth
        guard coefficientModuli.count <= 8 else {
            throw HeError.invalidEncryptionParameters(self)
        }
        for coefficientModulus in coefficientModuli {
            guard coefficientModulus > plaintextModulus,
                  coefficientModulus.isNttModulus(for: polyDegree)
            else {
                throw HeError.invalidEncryptionParameters(self)
            }
        }
        for modulus in coefficientModuli + [plaintextModulus] {
            guard modulus.isPrime(variableTime: true),
                  (1...Self.maxSingleModulus).contains(modulus),
                  modulus != Scheme.Scalar.rnsCorrectionFactor,
                  modulus != Scheme.Scalar.mTilde
            else {
                throw HeError.invalidEncryptionParameters(self)
            }
        }
    }

    /// Initializes ``EncryptionParameters`` from predefined RLWE parameters.
    /// - Parameter rlweParameters: Predefined RLWE parameters.
    /// - Throws: ``HeError`` upon failure to initialize encryption parameters.
    public init(from rlweParameters: PredefinedRlweParameters) throws {
        switch rlweParameters {
        case .insecure_n_8_logq_5x18_logt_5:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 17) + 177, // 131249
                (1 << 17) + 225, // 131297
                (1 << 17) + 369, // 131441
                (1 << 17) + 417, // 131489
                (1 << 17) + 545, // 131617
            ]
            try self.init(
                polyDegree: 8,
                plaintextModulus: (1 << 4) + 1 /* 17 */,
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .unchecked)

        case .insecure_n_512_logq_4x60_logt_20:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 59) + 13313, // 576460752303436801
                (1 << 59) + 16385, // 576460752303439873
                (1 << 59) + 23553, // 576460752303447041
                (1 << 59) + 48129, // 576460752303471617
            ]
            try self.init(
                polyDegree: 512,
                plaintextModulus: (1 << 19) + 1025, /* 525313 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .unchecked)

        case .n_4096_logq_16_33_33_logt_4:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 16) - 24575, // 40961
                (1 << 33) - 81919, // 8589852673
                (1 << 33) - 90111, // 8589844481
            ]
            try self.init(
                polyDegree: 4096,
                plaintextModulus: (1 << 3) + 3, /* 11 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_4096_logq_27_28_28_logt_13:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 27) - 40959, // 134176769
                (1 << 28) - 65535, // 268369921
                (1 << 28) - 73727, // 268361729
            ]
            try self.init(
                polyDegree: 4096,
                plaintextModulus: (1 << 12) + 3, /* 4099 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_4096_logq_27_28_28_logt_5:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 27) - 40959, // 134176769
                (1 << 28) - 65535, // 268369921
                (1 << 28) - 73727, // 268361729
            ]
            try self.init(
                polyDegree: 4096,
                plaintextModulus: (1 << 4) + 1, /* 17 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_8192_logq_3x55_logt_42:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 55) - 311_295, // 36028797018652673
                (1 << 55) - 1_392_639, // 36028797017571329
                (1 << 55) - 1_507_327, // 36028797017456641
            ]
            try self.init(
                polyDegree: 8192,
                plaintextModulus: (1 << 41) + 32769, /* 2199023288321 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_8192_logq_3x55_logt_30:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 55) - 311_295, // 36028797018652673
                (1 << 55) - 1_392_639, // 36028797017571329
                (1 << 55) - 1_507_327, // 36028797017456641
            ]
            try self.init(
                polyDegree: 8192,
                plaintextModulus: (1 << 29) + 32769, /* 536903681 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_8192_logq_3x55_logt_29:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 55) - 311_295, // 36028797018652673
                (1 << 55) - 1_392_639, // 36028797017571329
                (1 << 55) - 1_507_327, // 36028797017456641
            ]
            try self.init(
                polyDegree: 8192,
                plaintextModulus: (1 << 28) + 147_457, /* 268582913 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_8192_logq_3x55_logt_24:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 55) - 311_295, // 36028797018652673
                (1 << 55) - 1_392_639, // 36028797017571329
                (1 << 55) - 1_507_327, // 36028797017456641
            ]
            try self.init(
                polyDegree: 8192,
                plaintextModulus: (1 << 23) + 16385, /* 8404993 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_8192_logq_29_60_60_logt_15:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 29) - 180_223, // 536690689
                (1 << 60) - 16383, // 1152921504606830593
                (1 << 60) - 98303, // 1152921504606748673
            ]
            try self.init(
                polyDegree: 8192,
                plaintextModulus: (1 << 14) + 27, /* 16411 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_8192_logq_40_60_60_logt_26:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 40) - 147_455, // 1099511480321
                (1 << 60) - 16383, // 1152921504606830593
                (1 << 60) - 98303, // 1152921504606748673
            ]
            try self.init(
                polyDegree: 8192,
                plaintextModulus: (1 << 25) + 278_529, /* 33832961 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_8192_logq_28_60_60_logt_20:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 28) - 65535, // 268369921
                (1 << 60) - 16383, // 1152921504606830593
                (1 << 60) - 98303, // 1152921504606748673
            ]
            try self.init(
                polyDegree: 8192,
                plaintextModulus: (1 << 19) + 32769, /* 557057 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .insecure_n_16_logq_60_logt_15:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 60) - 16383, // 1152921504606830593
            ]
            try self.init(
                polyDegree: 16,
                plaintextModulus: (1 << 14) + 33, /* 16417 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .unchecked)

        case .n_4096_logq_27_28_28_logt_6:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 27) - 40959, // 134176769
                (1 << 28) - 65535, // 268369921
                (1 << 28) - 73727, // 268361729
            ]
            try self.init(
                polyDegree: 4096,
                plaintextModulus: (1 << 5) + 5, /* 37 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_4096_logq_27_28_28_logt_16:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 27) - 40959, // 134176769
                (1 << 28) - 65535, // 268369921
                (1 << 28) - 73727, // 268361729
            ]
            try self.init(
                polyDegree: 4096,
                plaintextModulus: (1 << 15) + 8193, /* 40961 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_4096_logq_27_28_28_logt_17:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 27) - 40959, // 134176769
                (1 << 28) - 65535, // 268369921
                (1 << 28) - 73727, // 268361729
            ]
            try self.init(
                polyDegree: 4096,
                plaintextModulus: (1 << 16) + 1, /* 65537 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)

        case .n_4096_logq_27_28_28_logt_4:
            let coefficientModuli: [Scheme.Scalar] = [
                (1 << 27) - 40959, // 134176769
                (1 << 28) - 65535, // 268369921
                (1 << 28) - 73727, // 268361729
            ]
            try self.init(
                polyDegree: 4096,
                plaintextModulus: (1 << 3) + 3, /* 11 */
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .quantum128)
        }
    }

    /// Returns the maximum log2 of the coefficient modulus to ensure security.
    ///
    /// Derived from ADPS16 cost model using the lattice estimator <https://github.com/malb/lattice-estimator/> (commit
    /// 8b25d433d87b8f3028ea228cc3e65d5ade6780f6, from Oct 25, 2022).
    /// - Parameters:
    ///   - degree: Degree of the RLWE polynomial.
    ///   - securityLevel: desired security level.
    /// - Returns: The maximum coefficient modulus.
    /// - Throws: Error upon invalid `degree`.
    /// - Warning: ``SecurityLevel/unchecked`` does not enforce any security.
    public static func maxLog2CoefficientModulus(degree: Int, securityLevel: SecurityLevel) throws -> Int {
        switch securityLevel {
        case .unchecked: Int.max
        case .quantum128:
            switch degree {
            case 1024: 21
            case 2048: 41
            case 4096: 83
            case 8192: 165
            case 16384: 330
            case 32768: 660
            default:
                throw HeError.invalidDegree(degree)
            }
        }
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
    func skipLSBsForDecryption() -> [Int] {
        guard Scheme.self == Bfv<Scheme.Scalar>.self else {
            return Array(repeating: 0, count: Scheme.freshCiphertextPolyCount)
        }
        let q0 = coefficientModuli[0]
        let t = plaintextModulus
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
        let tmp = Int(zScore * (2.0 * Double(polyDegree) / 9.0).squareRoot())
        var poly1SkipLSBs = lPrime - (tmp == 0 ? 0 : tmp.ceilLog2)
        if poly1SkipLSBs <= 1 {
            poly0SkipLSBs = max(lPrime + 1, 0)
            poly1SkipLSBs = 0
        }
        return [poly0SkipLSBs, poly1SkipLSBs]
    }
}

extension EncryptionParameters: CustomStringConvertible {
    public var description: String {
        "EncryptionParameters<\(Scheme.self)>(" +
            "degree=\(polyDegree), " +
            "plaintextModulus=\(plaintextModulus), " +
            "coefficientModuli=\(coefficientModuli), " +
            "errorStdDev=\(errorStdDev), " +
            "securityLevel=\(securityLevel)"
    }
}

/// Pre-defined encryption parameters available for use on client.
public enum PredefinedRlweParameters: String, Hashable, CaseIterable, CustomStringConvertible, Codable,
    CodingKeyRepresentable,
    Sendable
{
    // swiftlint:disable sorted_enum_cases
    case insecure_n_8_logq_5x18_logt_5 // Warning - Insecure parameters, used for testing only
    case insecure_n_512_logq_4x60_logt_20 // Warning - Insecure parameters, used for testing only
    case n_4096_logq_16_33_33_logt_4 // NTT-unfriendly plaintext modulus
    case n_4096_logq_27_28_28_logt_13 // NTT-unfriendly plaintext modulus
    case n_4096_logq_27_28_28_logt_5 // NTT-unfriendly plaintext modulus
    case n_8192_logq_3x55_logt_42
    case n_8192_logq_3x55_logt_30
    case n_8192_logq_3x55_logt_29
    case n_8192_logq_3x55_logt_24
    case n_8192_logq_29_60_60_logt_15 // NTT-unfriendly plaintext modulus
    case n_8192_logq_40_60_60_logt_26
    case n_8192_logq_28_60_60_logt_20
    case insecure_n_16_logq_60_logt_15 // Warning - Insecure parameters, used for testing only
    case n_4096_logq_27_28_28_logt_6 // NTT-unfriendly plaintext modulus
    case n_4096_logq_27_28_28_logt_16 // Plaintext CRT params
    case n_4096_logq_27_28_28_logt_17 // Plaintext CRT params
    case n_4096_logq_27_28_28_logt_4 // NTT-unfriendly plaintext modulus
    // swiftlint:enable sorted_enum_cases

    public var description: String {
        let rlweDescription = switch self {
        case .insecure_n_8_logq_5x18_logt_5:
            "insecure_n_8_logq_5x18_logt_5"
        case .insecure_n_512_logq_4x60_logt_20:
            "insecure_n_512_logq_4x60_logt_20"
        case .n_4096_logq_16_33_33_logt_4:
            "n_4096_logq_16_33_33_logt_4"
        case .n_4096_logq_27_28_28_logt_13:
            "n_4096_logq_27_28_28_logt_13"
        case .n_4096_logq_27_28_28_logt_5:
            "n_4096_logq_27_28_28_logt_5"
        case .n_8192_logq_3x55_logt_42:
            "n_8192_logq_3x55_logt_42"
        case .n_8192_logq_3x55_logt_30:
            "n_8192_logq_3x55_logt_30"
        case .n_8192_logq_3x55_logt_29:
            "n_8192_logq_3x55_logt_29"
        case .n_8192_logq_3x55_logt_24:
            "n_8192_logq_3x55_logt_24"
        case .n_8192_logq_29_60_60_logt_15:
            "n_8192_logq_29_60_60_logt_15"
        case .n_8192_logq_40_60_60_logt_26:
            "n_8192_logq_40_60_60_logt_26"
        case .n_8192_logq_28_60_60_logt_20:
            "n_8192_logq_28_60_60_logt_20"
        case .insecure_n_16_logq_60_logt_15:
            "insecure_n_16_logq_60_logt_15"
        case .n_4096_logq_27_28_28_logt_6:
            "n_4096_logq_27_28_28_logt_6"
        case .n_4096_logq_27_28_28_logt_16:
            "n_4096_logq_27_28_28_logt_16"
        case .n_4096_logq_27_28_28_logt_17:
            "n_4096_logq_27_28_28_logt_17"
        case .n_4096_logq_27_28_28_logt_4:
            "n_4096_logq_27_28_28_logt_4"
        }
        return "PredefinedRlweParameters: \(rlweDescription)"
    }

    /// Computes whether or not the predefined RLWE parameters supports representing polynomial coefficients using a
    /// scalar type.
    /// - Parameter scalarType: Scalar type to represent polynomial coefficients.
    /// - Returns: Whether or not the RLWE parameters supoport `scalarType`.
    public func supportsScalar(_ scalarType: (some ScalarType).Type) -> Bool {
        switch scalarType.bitWidth {
        case 32:
            switch self {
            case .insecure_n_8_logq_5x18_logt_5, .n_4096_logq_27_28_28_logt_13, .n_4096_logq_27_28_28_logt_5,
                 .n_4096_logq_27_28_28_logt_6, .n_4096_logq_27_28_28_logt_16, .n_4096_logq_27_28_28_logt_17,
                 .n_4096_logq_27_28_28_logt_4:
                return true
            // avoid `default: false` to ensure new encryption parameter sets explicitly opt in/out of 32-bit support
            case .insecure_n_512_logq_4x60_logt_20, .n_4096_logq_16_33_33_logt_4, .n_8192_logq_3x55_logt_42,
                 .n_8192_logq_3x55_logt_30, .n_8192_logq_3x55_logt_29, .n_8192_logq_3x55_logt_24,
                 .n_8192_logq_29_60_60_logt_15, .n_8192_logq_40_60_60_logt_26,
                 .n_8192_logq_28_60_60_logt_20, .insecure_n_16_logq_60_logt_15:
                return false
            }
        case 64: return true
        default: return false
        }
    }
}
