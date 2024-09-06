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

/// Error type for ``HomomorphicEncryption``.
public enum HeError: Error, Equatable {
    case coprimeModuli(moduli: [Int64])
    case emptyModulus
    case encodingDataCountExceedsLimit(count: Int, limit: Int)
    /// The actual encoding data might be sensitive, so we omit it.
    case encodingDataOutOfBounds(_ closedRange: ClosedRange<Int64>)
    case errorCastingPolyFormat(_ description: String)
    case incompatibleCiphertextAndPlaintext(_ description: String)
    case incompatibleCiphertextCount(_ description: String)
    case incompatibleCiphertexts(_ description: String)
    case insecureEncryptionParameters(_ description: String)
    case invalidCiphertext(_ description: String)
    case invalidCoefficientIndex(index: Int, degree: Int)
    case invalidContext(_ description: String)
    case invalidCorrectionFactor(_ description: String)
    case invalidDegree(_ degree: Int)
    case invalidEncryptionParameters(_ description: String)
    case invalidFormat(_ description: String)
    case invalidGaloisElement(_ element: Int)
    case invalidModulus(_ modulus: Int64)
    case invalidNttModulus(modulus: Int64, degree: Int)
    case invalidPolyContext(_ description: String)
    case invalidRotationParameter(range: Int, columnCount: Int)
    case invalidRotationStep(step: Int, degree: Int)
    case missingGaloisElement(element: Int)
    case missingGaloisKey
    case missingRelinearizationKey
    case notEnoughPrimes(significantBitCounts: [Int], preferringSmall: Bool, nttDegree: Int)
    case notInvertible(modulus: Int64)
    case polyContextMismatch(_ description: String)
    case serializationBufferNotContiguous
    case serializationBufferSizeMismatch(polyContext: String, actual: Int, expected: Int)
    case serializedBufferSizeMismatch(polyContext: String, actual: Int, expected: Int)
    case simdEncodingNotSupported(_ description: String)
    case unequalContexts(_ description: String)
    case unsupportedHeOperation(description: String)
}

extension HeError {
    @inlinable
    static func encodingDataOutOfBounds(for bounds: ClosedRange<some SignedScalarType>) -> Self {
        .encodingDataOutOfBounds(Int64(bounds.lowerBound)...Int64(bounds.upperBound))
    }

    @inlinable
    static func encodingDataOutOfBounds(for bounds: Range<some ScalarType>) -> Self {
        .encodingDataOutOfBounds(Int64(bounds.lowerBound)...(Int64(bounds.upperBound) - 1))
    }

    @inlinable
    static func errorCastingPolyFormat(from t1: (some PolyFormat).Type, to t2: (some PolyFormat).Type) -> Self {
        .errorCastingPolyFormat("Error casting poly format from: \(t1.description) to: \(t2.description)")
    }

    @inlinable
    static func incompatibleCiphertextAndPlaintext(
        ciphertext: Ciphertext<some HeScheme, some PolyFormat>,
        plaintext: Plaintext<some Any, some Any>) -> Self
    {
        .incompatibleCiphertextAndPlaintext(
            "Incompatible ciphertext \(ciphertext.description) and plaintext \(plaintext.description)")
    }

    @inlinable
    static func incompatibleCiphertextCount(
        _ got: Int,
        expected: Int) -> Self
    {
        .incompatibleCiphertextCount("Incompatible ciphertext count: \(got), expected \(expected)")
    }

    @inlinable
    static func incompatibleCiphertexts(
        _ lhs: Ciphertext<some HeScheme, some PolyFormat>,
        _ rhs: Ciphertext<some Any, some Any>) -> Self
    {
        .incompatibleCiphertexts("Incompatible ciphertexts: \(lhs.description), \(rhs.description)")
    }

    @inlinable
    static func insecureEncryptionParameters(_ encryptionParameters: EncryptionParameters<some HeScheme>) -> Self {
        .insecureEncryptionParameters("\(encryptionParameters.description)")
    }

    @inlinable
    static func invalidCiphertext(_ ciphertext: Ciphertext<some HeScheme, some PolyFormat>,
                                  message: String? = nil) -> Self
    {
        let message = message.map { " \($0)" } ?? ""
        return .invalidCiphertext("Invalid ciphertext: \(ciphertext.description) \(message)")
    }

    @inlinable
    static func invalidContext(_ context: Context<some Any>) -> Self {
        .invalidContext("\(context.description)")
    }

    @inlinable
    static func invalidCorrectionFactor(_ t: Int) -> Self {
        .invalidCorrectionFactor(t.description)
    }

    @inlinable
    static func invalidEncryptionParameters(_ encryptionParameters: EncryptionParameters<some HeScheme>) -> Self {
        .invalidEncryptionParameters(encryptionParameters.description)
    }

    @inlinable
    static func invalidFormat(_ t: (some PolyFormat).Type) -> Self {
        .invalidFormat(t.description)
    }

    @inlinable
    static func invalidPolyContext(_ context: PolyContext<some Any>) -> Self {
        .invalidPolyContext(context.description)
    }

    @inlinable
    static func polyContextMismatch(got: PolyContext<some Any>, expected: PolyContext<some Any>) -> Self {
        .polyContextMismatch("PolyContext mismatch: got \(got.description), expected \(expected.description)")
    }

    @inlinable
    static func serializationBufferSizeMismatch(
        polyContext: PolyContext<some ScalarType>,
        actual: Int,
        expected: Int) -> Self
    {
        .serializationBufferSizeMismatch(
            polyContext: polyContext.description,
            actual: actual,
            expected: expected)
    }

    @inlinable
    static func serializedBufferSizeMismatch(
        polyContext: PolyContext<some ScalarType>,
        actual: Int,
        expected: Int) -> Self
    {
        .serializedBufferSizeMismatch(
            polyContext: polyContext.description,
            actual: actual,
            expected: expected)
    }

    @inlinable
    static func simdEncodingNotSupported(for encryptionParameters: EncryptionParameters<some HeScheme>) -> Self {
        .simdEncodingNotSupported(encryptionParameters.description)
    }

    @inlinable
    static func unequalContexts(got: Context<some Any>, expected: Context<some Any>) -> Self {
        .unequalContexts("Unequal contexts: \(got.description) is not equal to \(expected.description)")
    }

    @inlinable
    static func unsupportedHeOperation(_ message: @autoclosure () -> String = "",
                                       file: StaticString = #file,
                                       line: UInt = #line) -> Self
    {
        .unsupportedHeOperation(description: "Unsupported HE operation: \(message()): \(file):\(line)")
    }
}

extension HeError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .coprimeModuli(moduli):
            "Coprime moduli \(moduli)"
        case .emptyModulus:
            "Empty modulus"
        case let .encodingDataCountExceedsLimit(count, limit):
            "Actual number of data \(count) exceeds limit \(limit)"
        case let .encodingDataOutOfBounds(closedRange):
            "Values not in encoding bounds \(closedRange)"
        case let .errorCastingPolyFormat(description):
            "\(description) "
        case let .incompatibleCiphertextCount(description):
            "\(description)"
        case let .incompatibleCiphertexts(description):
            description
        case let .incompatibleCiphertextAndPlaintext(description):
            "\(description)"
        case let .insecureEncryptionParameters(description):
            "Insecure encryption parameters \(description)"
        case let .invalidCoefficientIndex(index, degree):
            "Invalid coefficient index \(index) for degree \(degree)"
        case let .invalidCiphertext(description):
            "\(description)"
        case let .invalidContext(description):
            "Invalid context \(description)"
        case let .invalidCorrectionFactor(description):
            "Invalid correction factor \(description)"
        case let .invalidDegree(degree):
            "Invalid degree \(degree)"
        case let .invalidEncryptionParameters(description):
            "Invalid encryption parameters \(description)"
        case let .invalidFormat(description):
            "An unrecognized format \(description) is used"
        case let .invalidGaloisElement(element):
            "Invalid Galois element is used: \(element)"
        case let .invalidModulus(modulus):
            "Invalid modulus \(modulus)"
        case let .invalidNttModulus(modulus, degree):
            "Invalid NTT modulus \(modulus) for degree \(degree)"
        case let .invalidPolyContext(description):
            "Invalid PolyContext \(description)"
        case let .invalidRotationParameter(range, columnCount):
            "Invalid rotation parameter: rotation circle \(range) must be a factor of column size \(columnCount)"
        case let .invalidRotationStep(step, degree):
            "Invalid rotation step \(step) for degree \(degree)"
        case let .missingGaloisElement(element):
            "Missing Galois element \(element)"
        case .missingGaloisKey:
            "Missing Galois key"
        case .missingRelinearizationKey:
            "Missing relinearization key"
        case let .notEnoughPrimes(significantBitCounts, preferSmall, nttDegree):
            """
            Not enough primes with significantBitCounts \(significantBitCounts),
            preferring \(preferSmall ? "small" : "large"), for nttDegree \(nttDegree)
            """
        case let .notInvertible(modulus):
            "Value not invertible mod \(modulus)"
        case let .polyContextMismatch(description):
            description
        case .serializationBufferNotContiguous:
            "Serialization buffer not contiguous"
        case let .serializationBufferSizeMismatch(
            polyContext: polyContext,
            actual: actual,
            expected: expected):
            "Serialization buffer size mismatch: \(polyContext), actual size: \(actual), expected size: \(expected), "
        case let .serializedBufferSizeMismatch(
            polyContext: polyContext,
            actual: actual,
            expected: expected):
            "Serialized buffer size mismatch: \(polyContext), actual size: \(actual), expected size: \(expected), "
        case let .simdEncodingNotSupported(encryptionParameters):
            "SIMD encoding is not supported for encryption parameters \(encryptionParameters)"
        case let .unequalContexts(description):
            "\(description)"
        case let .unsupportedHeOperation(description):
            "\(description)"
        }
    }
}
