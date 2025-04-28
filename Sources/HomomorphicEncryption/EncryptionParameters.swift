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

import Foundation
import ModularArithmetic

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
public struct EncryptionParameters<Scalar: ScalarType>: Hashable, Codable, Sendable {
    /// The maximum modulus value for a single coefficient or plaintext modulus.
    public static var maxSingleModulus: Scalar {
        Modulus<Scalar>.max
    }

    /// Polynomial degree `N` of the RLWE polynomial ring.
    ///
    /// Must be a power of two.
    public let polyDegree: Int
    /// Plaintext modulus, `t`.
    ///
    /// This is the modulus on which encrypted computation occurs.
    public let plaintextModulus: Scalar

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
    public let coefficientModuli: [Scalar]

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
        plaintextModulus: Scalar,
        coefficientModuli: [Scalar],
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
        // Due to some usage of `Width32`
        guard coefficientModuli.count <= 32 else {
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
                  modulus != Scalar.rnsCorrectionFactor,
                  modulus != Scalar.mTilde
            else {
                throw HeError.invalidEncryptionParameters(self)
            }
        }
    }

    /// Initializes ``EncryptionParameters`` from predefined RLWE parameters.
    /// - Parameter rlweParameters: Predefined RLWE parameters.
    /// - Throws: ``HeError`` upon failure to initialize encryption parameters.
    public init(from rlweParameters: PredefinedRlweParameters) throws {
        try self.init(
            polyDegree: rlweParameters.polyDegree,
            plaintextModulus: Scalar(rlweParameters.plaintextModulus),
            coefficientModuli: rlweParameters.coefficientModuli.map { Scalar($0) },
            errorStdDev: rlweParameters.errorStdDev,
            securityLevel: rlweParameters.securityLevel)
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

    /// The (row, column) dimension counts for ``EncodeFormat/simd`` encoding.
    ///
    /// If the HE scheme does not support ``EncodeFormat/simd`` encoding, returns `nil`.
    public func simdDimensions<Scheme: HeScheme>(for _: Scheme.Type) -> SimdEncodingDimensions?
        where Scheme.Scalar == Scalar
    {
        Scheme.encodeSimdDimensions(for: self)
    }
}

extension EncryptionParameters: CustomStringConvertible {
    public var description: String {
        "EncryptionParameters<\(Scalar.self)>(" +
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

    /// The RLWE polynomial degree.
    public var polyDegree: Int {
        switch self {
        case .insecure_n_8_logq_5x18_logt_5: 8
        case .insecure_n_16_logq_60_logt_15: 16
        case .insecure_n_512_logq_4x60_logt_20: 512
        case .n_4096_logq_27_28_28_logt_6,
             .n_4096_logq_27_28_28_logt_16,
             .n_4096_logq_27_28_28_logt_17,
             .n_4096_logq_27_28_28_logt_4,
             .n_4096_logq_16_33_33_logt_4,
             .n_4096_logq_27_28_28_logt_13,
             .n_4096_logq_27_28_28_logt_5: 4096
        case .n_8192_logq_3x55_logt_42,
             .n_8192_logq_3x55_logt_30,
             .n_8192_logq_3x55_logt_29,
             .n_8192_logq_3x55_logt_24,
             .n_8192_logq_29_60_60_logt_15,
             .n_8192_logq_40_60_60_logt_26,
             .n_8192_logq_28_60_60_logt_20: 8192
        }
    }

    /// The security level.
    public var securityLevel: SecurityLevel {
        switch self {
        case .insecure_n_8_logq_5x18_logt_5, .insecure_n_512_logq_4x60_logt_20, .insecure_n_16_logq_60_logt_15:
            .unchecked
        case .n_4096_logq_16_33_33_logt_4, .n_4096_logq_27_28_28_logt_13, .n_4096_logq_27_28_28_logt_4,
             .n_4096_logq_27_28_28_logt_5, .n_4096_logq_27_28_28_logt_6, .n_4096_logq_27_28_28_logt_16,
             .n_4096_logq_27_28_28_logt_17, .n_8192_logq_29_60_60_logt_15, .n_8192_logq_28_60_60_logt_20,
             .n_8192_logq_3x55_logt_24, .n_8192_logq_3x55_logt_29, .n_8192_logq_3x55_logt_30,
             .n_8192_logq_40_60_60_logt_26, .n_8192_logq_3x55_logt_42:
            .quantum128
        }
    }

    /// The standard deviation of the error polynomial.
    public var errorStdDev: ErrorStdDev {
        switch self {
        case .insecure_n_8_logq_5x18_logt_5, .insecure_n_512_logq_4x60_logt_20, .insecure_n_16_logq_60_logt_15,
             .n_4096_logq_16_33_33_logt_4, .n_4096_logq_27_28_28_logt_13, .n_4096_logq_27_28_28_logt_4,
             .n_4096_logq_27_28_28_logt_5, .n_4096_logq_27_28_28_logt_6, .n_4096_logq_27_28_28_logt_16,
             .n_4096_logq_27_28_28_logt_17, .n_8192_logq_29_60_60_logt_15, .n_8192_logq_28_60_60_logt_20,
             .n_8192_logq_3x55_logt_24, .n_8192_logq_3x55_logt_29, .n_8192_logq_3x55_logt_30,
             .n_8192_logq_40_60_60_logt_26, .n_8192_logq_3x55_logt_42:
            .stdDev32
        }
    }

    /// The plaintext modulus.
    public var plaintextModulus: UInt64 {
        switch self {
        case .insecure_n_8_logq_5x18_logt_5: (1 << 4) + 1 // 17
        case .insecure_n_16_logq_60_logt_15: (1 << 14) + 33 // 16417
        case .insecure_n_512_logq_4x60_logt_20: (1 << 19) + 1025 // 525_313
        case .n_4096_logq_16_33_33_logt_4: (1 << 3) + 3 // 11
        case .n_4096_logq_27_28_28_logt_4: (1 << 3) + 3 // 11
        case .n_4096_logq_27_28_28_logt_5: (1 << 4) + 1 // 17
        case .n_4096_logq_27_28_28_logt_6: (1 << 5) + 5 // 37
        case .n_4096_logq_27_28_28_logt_13: (1 << 12) + 3 // 4099
        case .n_4096_logq_27_28_28_logt_16: (1 << 15) + 8193 // 40961,
        case .n_4096_logq_27_28_28_logt_17: (1 << 16) + 1 // 65537
        case .n_8192_logq_3x55_logt_24: (1 << 23) + 16385 // 8404993
        case .n_8192_logq_3x55_logt_29: (1 << 28) + 147_457 // 268582913
        case .n_8192_logq_3x55_logt_30: (1 << 29) + 32769 // 536903681
        case .n_8192_logq_3x55_logt_42: (1 << 41) + 32769 // 2199023288321
        case .n_8192_logq_29_60_60_logt_15: (1 << 14) + 27 // 16411
        case .n_8192_logq_28_60_60_logt_20: (1 << 19) + 32769 // 557057
        case .n_8192_logq_40_60_60_logt_26: (1 << 25) + 278_529 // 33832961
        }
    }

    /// The ciphertext coefficient moduli.
    public var coefficientModuli: [UInt64] {
        switch self {
        case .insecure_n_8_logq_5x18_logt_5:
            [
                (1 << 17) + 177, // 131249
                (1 << 17) + 225, // 131297
                (1 << 17) + 369, // 131441
                (1 << 17) + 417, // 131489
                (1 << 17) + 545, // 131617
            ]
        case .insecure_n_16_logq_60_logt_15:
            [
                (1 << 60) - 16383, // 1152921504606830593
            ]
        case .insecure_n_512_logq_4x60_logt_20:
            [
                (1 << 59) + 13313, // 576460752303436801
                (1 << 59) + 16385, // 576460752303439873
                (1 << 59) + 23553, // 576460752303447041
                (1 << 59) + 48129, // 576460752303471617
            ]
        case .n_4096_logq_16_33_33_logt_4:
            [
                (1 << 16) - 24575, // 40961
                (1 << 33) - 81919, // 8589852673
                (1 << 33) - 90111, // 8589844481
            ]
        case .n_4096_logq_27_28_28_logt_4, .n_4096_logq_27_28_28_logt_5, .n_4096_logq_27_28_28_logt_6,
             .n_4096_logq_27_28_28_logt_13,
             .n_4096_logq_27_28_28_logt_16, .n_4096_logq_27_28_28_logt_17:
            [
                (1 << 27) - 40959, // 134176769
                (1 << 28) - 65535, // 268369921
                (1 << 28) - 73727, // 268361729
            ]
        case .n_8192_logq_3x55_logt_24, .n_8192_logq_3x55_logt_29, .n_8192_logq_3x55_logt_30, .n_8192_logq_3x55_logt_42:
            [
                (1 << 55) - 311_295, // 36028797018652673
                (1 << 55) - 1_392_639, // 36028797017571329
                (1 << 55) - 1_507_327, // 36028797017456641
            ]
        case .n_8192_logq_29_60_60_logt_15:
            [
                (1 << 29) - 180_223, // 536690689
                (1 << 60) - 16383, // 1152921504606830593
                (1 << 60) - 98303, // 1152921504606748673
            ]
        case .n_8192_logq_40_60_60_logt_26:
            [
                (1 << 40) - 147_455, // 1099511480321
                (1 << 60) - 16383, // 1152921504606830593
                (1 << 60) - 98303, // 1152921504606748673
            ]
        case .n_8192_logq_28_60_60_logt_20:
            [
                (1 << 28) - 65535, // 268369921
                (1 << 60) - 16383, // 1152921504606830593
                (1 << 60) - 98303, // 1152921504606748673
            ]
        }
    }

    /// Whether or not the encryption parameters support generation of an evaluation key.
    public var supportsEvaluationKey: Bool {
        coefficientModuli.count > 1
    }

    /// Whether or not the encryption parameters support ``EncodeFormat/simd`` encoding.
    public var supportsSimdEncoding: Bool {
        plaintextModulus.isNttModulus(for: polyDegree)
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
                true
            // avoid `default: false` to ensure new encryption parameter sets explicitly opt in/out of 32-bit support
            case .insecure_n_512_logq_4x60_logt_20, .n_4096_logq_16_33_33_logt_4, .n_8192_logq_3x55_logt_42,
                 .n_8192_logq_3x55_logt_30, .n_8192_logq_3x55_logt_29, .n_8192_logq_3x55_logt_24,
                 .n_8192_logq_29_60_60_logt_15, .n_8192_logq_40_60_60_logt_26,
                 .n_8192_logq_28_60_60_logt_20, .insecure_n_16_logq_60_logt_15:
                false
            }
        case 64: true
        default: false
        }
    }
}
