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

public import Foundation
public import ModularArithmetic

extension Bfv {
    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decryptCoeff(_ ciphertext: CoeffCiphertext,
                                    using secretKey: SecretKey<Bfv<T>>) throws -> CoeffPlaintext
    {
        try decryptEval(ciphertext.forwardNtt(), using: secretKey)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decryptEval(_ ciphertext: EvalCiphertext,
                                   using secretKey: SecretKey<Bfv<T>>) throws -> CoeffPlaintext
    {
        let t = ciphertext.context.plaintextModulus
        let dotProduct = try Self.dotProduct(ciphertext: ciphertext, with: secretKey)
        let scalingFactor = try ciphertext.correctionFactor.inverseMod(modulus: t, variableTime: true)
        let rnsTool = ciphertext.context.getRnsTool(moduliCount: dotProduct.moduli.count)
        let plaintext = try rnsTool.scaleAndRound(poly: dotProduct, scalingFactor: scalingFactor)

        return try CoeffPlaintext(context: ciphertext.context, poly: plaintext)
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
    public static func skipLSBsForDecryption(for ciphertext: CoeffCiphertext) -> [Int] {
        guard ciphertext.polyContext().moduli.count == 1 else {
            return Array(repeating: 0, count: ciphertext.polyCount)
        }

        let encryptionParams = ciphertext.context.encryptionParameters
        let q0 = encryptionParams.coefficientModuli[0]
        let t = encryptionParams.plaintextModulus
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
        let tmp = Int(zScore * (2.0 * Double(encryptionParams.polyDegree) / 9.0).squareRoot())
        var poly1SkipLSBs = lPrime - (tmp == 0 ? 0 : tmp.ceilLog2)
        if poly1SkipLSBs <= 1 {
            poly0SkipLSBs = max(lPrime + 1, 0)
            poly1SkipLSBs = 0
        }
        return [poly0SkipLSBs, poly1SkipLSBs]
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func noiseBudgetEval(
        of ciphertext: EvalCiphertext,
        using secretKey: SecretKey<Bfv<T>>,
        variableTime: Bool) throws -> Double
    {
        // See Definition 1 of
        // https://www.microsoft.com/en-us/research/wp-content/uploads/2017/06/sealmanual_v2.2.pdf.
        // More precisely, we should use Theorem 1 from https://eprint.iacr.org/2016/510.pdf, but it's more complicated
        // and unlikely to make a difference in practice, especially as the noise budget in itself is just a rough
        // proxy for correct decryption. For example, with `q=131249, t=17`, a ciphertext has noise budget 0.67181 with
        // Definition 1, but noise budget 0.66854 with Theorem 1.
        var vTimesT = try Self.dotProduct(ciphertext: ciphertext, with: secretKey)
        vTimesT *= Array(repeating: ciphertext.context.plaintextModulus, count: vTimesT.moduli.count)
        let rnsTool = ciphertext.context.getRnsTool(moduliCount: vTimesT.moduli.count)

        func computeNoiseBudget<U: FixedWidthInteger & UnsignedInteger>(of _: PolyRq<T, Coeff>,
                                                                        _: U.Type) throws -> Double
        {
            let vTimesTComposed: [U] = try rnsTool.crtCompose(poly: vTimesT)
            let q: U = vTimesT.moduli.product()
            let qDiv2 = (q &+ 1) &>> 1
            let noiseInfinityNorm = Double(vTimesTComposed.map { coeff in
                if coeff > qDiv2 {
                    q &- coeff
                } else {
                    coeff
                }
            }.max() ?? U(0))
            guard noiseInfinityNorm != 0 else {
                return Double.infinity
            }
            let qDouble = vTimesT.moduli.map { Double($0) }.reduce(1.0) { $0 * $1 }
            return log2(qDouble / (2 * noiseInfinityNorm))
        }

        let tMax = Double(T.max)
        let crtMaxIntermediateValue = rnsTool.crtComposeMaxIntermediateValue()
        switch crtMaxIntermediateValue {
        case 0..<tMax:
            return try computeNoiseBudget(of: vTimesT, T.self)
        case tMax..<pow(tMax, 2):
            precondition(variableTime)
            return try computeNoiseBudget(of: vTimesT, T.DoubleWidth.self)
        case pow(tMax, 2)..<pow(tMax, 4):
            precondition(variableTime)
            return try computeNoiseBudget(of: vTimesT, QuadWidth<T>.self)
        case pow(tMax, 4)..<pow(tMax, 8):
            precondition(variableTime)
            return try computeNoiseBudget(of: vTimesT, OctoWidth<T>.self)
        case pow(tMax, 8)..<pow(tMax, 16):
            precondition(variableTime)
            return try computeNoiseBudget(of: vTimesT, Width16<T>.self)
        case pow(tMax, 16)..<pow(tMax, 32):
            precondition(variableTime)
            return try computeNoiseBudget(of: vTimesT, Width32<T>.self)
        default:
            preconditionFailure("crtMaxIntermediateValue \(crtMaxIntermediateValue) too large")
        }
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func noiseBudgetCoeff(of ciphertext: CoeffCiphertext,
                                        using secretKey: SecretKey<Bfv<T>>, variableTime: Bool) throws -> Double
    {
        try noiseBudgetEval(of: ciphertext.convertToEvalFormat(), using: secretKey, variableTime: variableTime)
    }

    @inlinable
    static func dotProduct(ciphertext: EvalCiphertext,
                           with secretKey: SecretKey<Bfv<T>>) throws -> PolyRq<T, Coeff>
    {
        let s0 = secretKey.poly
        var dotProduct = ciphertext.polys[0]
        var secretKeyPower = s0
        for (polyIndex, ci) in ciphertext.polys[1...].enumerated() {
            var ci = ci
            PolyRq<T, Eval>.mulAssign(&ci, secretPoly: secretKeyPower)
            dotProduct += ci
            if polyIndex != ciphertext.polys.indices.last {
                secretKeyPower *= s0
            }
        }
        secretKeyPower.zeroize()
        return try dotProduct.inverseNtt()
    }
}
