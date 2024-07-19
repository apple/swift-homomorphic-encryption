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

extension Bfv {
    @usableFromInline
    enum PlaintextTranslateOp {
        case Add
        case Subtract
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func zeroCiphertext(context: Context<Self>, moduliCount: Int) throws -> CoeffCiphertext {
        let zeroPoly = try PolyRq<Scalar, Coeff>.zero(
            context: context.ciphertextContext
                .getContext(moduliCount: moduliCount))
        let polys = [PolyRq<Scalar, Coeff>](repeating: zeroPoly, count: Bfv.freshCiphertextPolyCount)
        return Bfv.CoeffCiphertext(context: context, polys: polys, correctionFactor: 1)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func zeroCiphertext(context: Context<Self>, moduliCount: Int) throws -> EvalCiphertext {
        let zeroPoly = try PolyRq<Scalar, Eval>.zero(
            context: context.ciphertextContext
                .getContext(moduliCount: moduliCount))
        let polys = [PolyRq<Scalar, Eval>](repeating: zeroPoly, count: Bfv.freshCiphertextPolyCount)
        return Bfv.EvalCiphertext(context: context, polys: polys, correctionFactor: 1)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func isTransparent(ciphertext: CoeffCiphertext) -> Bool {
        // Decryption multiplies all the polynomials except the first with powers of the secret key.
        // So the ciphertext is transparent if all polynomials except the first are zeros.
        ciphertext.polys[1...].allSatisfy { poly in
            poly.isZero(variableTime: true)
        }
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func isTransparent(ciphertext: EvalCiphertext) -> Bool {
        // Decryption multiplies all the polynomials except the first with powers of the secret key.
        // So the ciphertext is transparent if all polynomials except the first are zeros.
        ciphertext.polys[1...].allSatisfy { poly in poly.isZero(variableTime: true) }
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encrypt(_ plaintext: Plaintext<Self, Coeff>,
                               using secretKey: SecretKey<Bfv<T>>) throws -> CanonicalCiphertext
    {
        var ciphertext = try encryptZero(for: plaintext.context, using: secretKey)
        try Self.addAssign(&ciphertext, plaintext)
        return ciphertext
    }

    @inlinable
    static func plaintextTranslate(
        ciphertext: inout CoeffCiphertext,
        plaintext: CoeffPlaintext,
        op: PlaintextTranslateOp) throws
    {
        guard ciphertext.correctionFactor == 1 else {
            throw HeError.invalidCorrectionFactor(Int(ciphertext.correctionFactor))
        }
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        let rnsTool = ciphertext.context.getRnsTool(moduliCount: ciphertext.moduli.count)
        let tThreshold = Scalar.DoubleWidth(rnsTool.tThreshold)

        // Will store floor(([Q]_t * plain[i] + floor((t+1)/2)) / t)
        var adjust = plaintext
        for idx in plaintext.poly.polyIndices(rnsIndex: 0) {
            var adjustCoeff = Scalar.DoubleWidth(rnsTool.qModT.multipliedFullWidth(by: plaintext[idx]))
            adjustCoeff &+= tThreshold
            adjust[idx] = rnsTool.t.dividingFloor(by: adjustCoeff).low
        }
        var c0 = ciphertext.polys[0]
        for (rnsIndex, rnsDelta) in rnsTool.qDivT.enumerated() {
            for (plainIndex, cipherIndex) in c0.polyIndices(rnsIndex: rnsIndex).enumerated() {
                let plainTimesDelta = rnsDelta.multiplyMod(plaintext[plainIndex])
                let roundQTimesMt = plainTimesDelta.addMod(adjust[plainIndex], modulus: rnsDelta.modulus)
                switch op {
                case PlaintextTranslateOp.Add:
                    c0[cipherIndex] = c0[cipherIndex].addMod(roundQTimesMt, modulus: rnsDelta.modulus)
                case PlaintextTranslateOp.Subtract:
                    c0[cipherIndex] = c0[cipherIndex].subtractMod(roundQTimesMt, modulus: rnsDelta.modulus)
                }
            }
        }
        ciphertext.polys[0] = c0
    }

    @inlinable
    static func encryptZero(for context: Context<Bfv<T>>,
                            using secretKey: SecretKey<Bfv<T>>) throws -> CanonicalCiphertext
    {
        let ciphertextContext = context.ciphertextContext
        return try encryptZero(for: context, using: secretKey, with: ciphertextContext)
    }

    @inlinable
    static func encryptZero(for context: Context<Bfv<T>>,
                            using secretKey: SecretKey<Bfv<T>>,
                            with ciphertextContext: PolyContext<T>) throws -> CanonicalCiphertext
    {
        let seed = [UInt8](randomByteCount: NistAes128Ctr.SeedCount)
        var aRng = try NistAes128Ctr(seed: seed)
        // NTT is a linear transformation, so we can sample in Eval form directly
        let a = PolyRq<Scalar, Eval>.random(context: ciphertextContext, using: &aRng)

        // use a new rng, because we might send the seed for `a` and we do not
        // want to also send the seed for the error polynomial
        var errRng = SystemRandomNumberGenerator()
        var errorPoly = PolyRq<Scalar, Coeff>.zero(context: ciphertextContext)

        errorPoly.randomizeCenteredBinomialDistribution(
            standardDeviation: context.encryptionParameters.errorStdDev.toDouble,
            using: &errRng)

        var c0Coeff = a
        PolyRq<T, Eval>.mulAssign(&c0Coeff, secretPoly: secretKey.poly)
        var c0 = try c0Coeff.inverseNtt()
        c0 += errorPoly

        errorPoly.zeroize()

        let aCoeff = try a.inverseNtt()
        return CanonicalCiphertext(
            context: context,
            polys: [-c0, aCoeff],
            correctionFactor: 1,
            seed: seed)
    }
}
