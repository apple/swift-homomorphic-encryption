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

        return CoeffPlaintext(context: ciphertext.context, poly: plaintext)
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
        case tMax..<pow(tMax, 4):
            precondition(variableTime)
            return try computeNoiseBudget(of: vTimesT, QuadWidth<T>.self)
        case tMax..<pow(tMax, 8):
            precondition(variableTime)
            return try computeNoiseBudget(of: vTimesT, OctoWidth<T>.self)
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
