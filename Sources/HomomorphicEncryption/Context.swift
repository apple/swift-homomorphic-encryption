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

/// Pre-computation for HE operations.
///
/// HE operations are typically only supported between objects, such as ``Ciphertext``, ``Plaintext``,
/// ``EvaluationKey``, ``SecretKey``,  with the same context.
public final class Context<Scheme: HeScheme>: HeContext, Equatable, Sendable {
    public typealias Scalar = Scheme.Scalar

    /// Encryption parameters.
    public let encryptionParameters: EncryptionParameters<Scalar>

    /// Plaintext context, with modulus `t`, the plaintext modulus.
    public let plaintextContext: PolyContext<Scalar>

    /// Encoding matrix for ``Encoding.simd`` encoding.
    public let simdEncodingMatrix: [Int]

    /// Context for the secret key.
    public let secretKeyContext: PolyContext<Scalar>

    /// Top-level ciphertext context.
    public let ciphertextContext: PolyContext<Scalar>

    /// Contexts for key-switching keys.
    ///
    /// The i'th context contains `q_0, ..., q_i, q_{L-1}`, and has next context dropping `q_{L-1}`
    /// E.g., `keySwitchingContexts[0].context.moduli = [q_0, q_1, q_L]`, and
    /// `keySwitchingContexts[0].next.moduli = [q_0, q_1]`
    public let keySwitchingContexts: [PolyContext<Scalar>]

    /// The rns tools for each level of ciphertexts, with number of moduli in descending order.
    public let _rnsTools: [_RnsTool<Scalar>]

    /// The plaintext modulus,`t`.
    public var plaintextModulus: Scalar { encryptionParameters.plaintextModulus }
    /// The coefficient moduli, `q_0, ..., q_L`.
    public var coefficientModuli: [Scalar] { encryptionParameters.coefficientModuli }
    /// The RLWE polynomial degree `N`.
    public var degree: Int { encryptionParameters.polyDegree }
    /// Whether or not the context supports ``EncodeFormat/simd`` encoding.
    public var supportsSimdEncoding: Bool { encryptionParameters.supportsSimdEncoding }
    /// The (row, column) dimension counts for ``EncodeFormat/simd`` encoding.
    ///
    /// If the HE scheme does not support ``EncodeFormat/simd`` encoding, returns `nil`.
    public var simdDimensions: SimdEncodingDimensions? {
        Scheme.encodeSimdDimensions(for: encryptionParameters)
    }

    /// Whether or not the context supports use of an ``EvaluationKey``.
    public var supportsEvaluationKey: Bool { encryptionParameters.supportsEvaluationKey }
    /// The number of bits that can be encoded in a single ``Plaintext``.
    public var bitsPerPlaintext: Int { encryptionParameters.bitsPerPlaintext }
    /// The number of bytes that can be encoded in a single ``Plaintext``.
    public var bytesPerPlaintext: Int { encryptionParameters.bytesPerPlaintext }

    /// Initializes a context.
    ///
    /// - Parameter encryptionParameters: Encryption parameters.
    /// - Throws: Error upon failure to initialize the context.
    @inlinable
    public init(encryptionParameters: EncryptionParameters<Scalar>) throws {
        self.encryptionParameters = encryptionParameters
        self.simdEncodingMatrix = Self.generateEncodingMatrix(encryptionParameters: encryptionParameters)

        self.secretKeyContext = try PolyContext(
            degree: encryptionParameters.polyDegree,
            moduli: encryptionParameters.coefficientModuli)

        var ciphertextModuli = encryptionParameters.coefficientModuli
        let keySwitchModulus: Scalar? = if ciphertextModuli.count > 1 {
            ciphertextModuli.popLast()
        } else {
            nil
        }
        var rnsTools = [_RnsTool<Scalar>]()
        rnsTools.reserveCapacity(ciphertextModuli.count)
        let ciphertextContext = try PolyContext<Scalar>(
            degree: encryptionParameters.polyDegree,
            moduli: ciphertextModuli)

        self.keySwitchingContexts = try keySwitchModulus.map { keySwitchModulus in
            try (1...ciphertextModuli.count).map { prefixCount in
                let moduli = Array(ciphertextModuli.prefix(prefixCount) + [keySwitchModulus])
                let nextContext = try ciphertextContext.getContext(moduliCount: prefixCount)
                let context = try PolyContext(
                    degree: encryptionParameters.polyDegree,
                    moduli: moduli,
                    next: nextContext)
                guard moduli.count < context.maxLazyProductAccumulationCount() else {
                    throw HeError.invalidEncryptionParameters(encryptionParameters)
                }
                return context
            }
        } ?? []
        self.ciphertextContext = ciphertextContext
        self.plaintextContext = try PolyContext(
            degree: encryptionParameters.polyDegree,
            moduli: [encryptionParameters.plaintextModulus])

        let rnsToolContext = try _RnsTool.RnsToolContext(
            inputContext: ciphertextContext,
            outputContext: plaintextContext)
        var rnsToolsCiphertextContext = ciphertextContext
        try rnsTools.append(_RnsTool(from: ciphertextContext, to: plaintextContext, rnsToolContext: rnsToolContext))
        while let nextContext = rnsToolsCiphertextContext.next {
            try rnsTools.append(_RnsTool(from: nextContext, to: plaintextContext, rnsToolContext: rnsToolContext))
            rnsToolsCiphertextContext = nextContext
        }
        self._rnsTools = rnsTools
    }

    /// Returns a boolean value indicating whether two contexts are equal.
    /// - Parameters:
    ///   - lhs: A context to compare.
    ///   - rhs: Another context to compare.
    /// - Returns: Whether or not the two contexts are equal.
    @inlinable
    public static func == (lhs: Context<Scheme>, rhs: Context<Scheme>) -> Bool {
        lhs === rhs || lhs.encryptionParameters == rhs.encryptionParameters
    }

    @inlinable
    public func getRnsTool(moduliCount: Int) -> _RnsTool<Scalar> {
        precondition(moduliCount <= _rnsTools.count && moduliCount > 0, "Invalid number of moduli")
        return _rnsTools[_rnsTools.count - moduliCount]
    }
}

extension Context: CustomStringConvertible {
    public var description: String {
        "Context<\(Scheme.self)>(encryptionParameters=\(encryptionParameters.description))"
    }
}
