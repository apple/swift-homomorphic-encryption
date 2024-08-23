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

@usableFromInline
package struct RnsTool<T: ScalarType>: Sendable {
    /// `Q = q_0, ..., q_{L-1}`.
    @usableFromInline let inputContext: PolyContext<T>
    /// `t_0, ..., t_{M-1}`.
    @usableFromInline let outputContext: PolyContext<T>
    /// `[q, B_sk]`.
    @usableFromInline let qBskContext: PolyContext<T>
    /// `Q mod t_0`.
    @usableFromInline let qModT: T
    /// reduction by `t_0`.
    @usableFromInline let t: Modulus<T>
    /// Multiplication by `gamma^{-1}` mod `t`, mod `t`.
    @usableFromInline let inverseGammaModT: MultiplyConstantModulus<T>
    /// Multiplication by  `-(Q^{-1})` mod `m_tilde`, mod `t`.
    @usableFromInline let negInverseQModMTilde: MultiplyConstantModulus<T>
    /// Multiplication by `B^{-1} mod m_sk`, mod `m_sk`.
    @usableFromInline let inverseBModMSk: MultiplyConstantModulus<T>
    /// i'th entry stores `q_i - t_0`.
    @usableFromInline let tIncrement: [T]
    /// i'th entry stores `\tilde{m} mod qi`.
    @usableFromInline let mTildeModQ: [T]
    /// `-(Q^{-1}) mod {t, gamma}`.
    @usableFromInline let negInverseQModTGamma: [T]
    /// `|gamma * t|_qi``.
    @usableFromInline let prodGammaTModQ: [T]
    /// Multiplication by `m_tilde^{-1} mod B_sk`, mod `B_sk`.
    @usableFromInline let inverseMTildeModBSk: [MultiplyConstantModulus<T>]
    /// Multiplication by `Q^{-1} mod B_sk`, mod `B_sk`.
    @usableFromInline let inverseQModBSk: [MultiplyConstantModulus<T>]
    /// i'th entry stores modulus for multiplcaiton by `floor(Q / t_0) % q_i`, mod `q_i`
    /// Also called `delta` in the literature.
    @usableFromInline let qDivT: [MultiplyConstantModulus<T>]
    /// Multiplication by `Q mod B_sk`, mod `B_sk`.
    @usableFromInline let qModBSk: [MultiplyConstantModulus<T>]
    /// Multiplication by `-B mod q_i`, mod `q_i`.
    @usableFromInline let negBModQ: [MultiplyConstantModulus<T>]
    /// Multiplication by `B mod q_i`, mod `q_i`.
    @usableFromInline let bModQ: [MultiplyConstantModulus<T>]
    /// Base conversion from `Q` to `B_sk`.
    @usableFromInline let rnsConvertQToBSk: RnsBaseConverter<T>
    /// Base conversion from `B` to `M_sk`.
    @usableFromInline let rnsConvertBtoMSk: RnsBaseConverter<T>
    /// Base conversion from `B` to `Q`.
    @usableFromInline let rnsConvertBtoQ: RnsBaseConverter<T>
    /// Base conversion matrix from `Q` to `[B_sk, m_tilde]`, where
    /// `B` is an auxiliary base, `m_sk` is an extra modulus, and the
    /// `B_sk = [B, m_sk]` is an extended base.
    @usableFromInline let rnsConvertQToBSkMTilde: RnsBaseConverter<T>
    /// Base conversion from `Q` to `[t, gamma]`.
    @usableFromInline let rnsConvertQToTGamma: RnsBaseConverter<T>

    @inlinable var tThreshold: T {
        (outputContext.moduli[0] + 1) / 2
    }

    @inlinable var bSkContext: PolyContext<T> {
        rnsConvertQToBSk.outputContext
    }

    @inlinable
    init(from inputContext: PolyContext<T>, to outputContext: PolyContext<T>) throws {
        guard inputContext.degree == outputContext.degree, outputContext.moduli.count == 1 else {
            throw HeError.invalidPolyContext(inputContext)
        }
        let degree = inputContext.degree
        self.inputContext = inputContext
        self.outputContext = outputContext

        let correctionFactor = T.rnsCorrectionFactor
        let t = outputContext.reduceModuli[0]
        let gammaT = T.DoubleWidth(correctionFactor.multipliedFullWidth(by: t.modulus))
        self.prodGammaTModQ = inputContext.reduceModuli.map { qI in qI.reduce(gammaT) }
        self.inverseGammaModT = try MultiplyConstantModulus(
            multiplicand: correctionFactor.inverseMod(modulus: t.modulus, variableTime: true),
            modulus: t.modulus,
            variableTime: true)

        let tGammaContext = try PolyContext(degree: degree, moduli: [t.modulus, correctionFactor])
        self.rnsConvertQToTGamma = try RnsBaseConverter(from: inputContext, to: tGammaContext)
        self.negInverseQModTGamma = try tGammaContext.reduceModuli.map { modulus in
            let qMod = inputContext.qRemainder(dividingBy: modulus)
            return try qMod.inverseMod(modulus: modulus.modulus, variableTime: true).negateMod(modulus: modulus.modulus)
        }

        let qModMTilde = inputContext.qRemainder(dividingBy: Modulus(modulus: T.mTilde, variableTime: true))
        let negInverseQModMTilde = try qModMTilde.inverseMod(modulus: T.mTilde, variableTime: true)
            .negateMod(modulus: T.mTilde)
        self.negInverseQModMTilde = MultiplyConstantModulus(
            multiplicand: negInverseQModMTilde,
            modulus: T.mTilde,
            variableTime: true)

        self.qModT = inputContext.qRemainder(dividingBy: t)
        self.tIncrement = inputContext.moduli.map { qi in qi - t.modulus }
        self.t = t

        // At least 8 moduli supported, more when their product is far from `T.max`.
        let octoModuli = inputContext.moduli.map { modulus in OctoWidth<T>(integerLiteral: Int(modulus)) }
        let q: OctoWidth<T> = inputContext.moduli.product()
        let qDivT = q / OctoWidth<T>(integerLiteral: Int(t.modulus))

        self.qDivT = octoModuli.map { qi in MultiplyConstantModulus(
            multiplicand: T(qDivT % qi),
            modulus: T(qi),
            variableTime: true)
        }

        // auxiliary base B_sk = [B, m_sk]
        let bSkModuli = try T.generatePrimes(
            significantBitCounts: Array(repeating: T.bitWidth - 3, count: inputContext.moduli.count + 1),
            preferringSmall: true,
            nttDegree: degree)
        let bSkMTildeModuli = bSkModuli + [T.mTilde]
        guard let mSk = bSkModuli.last else {
            throw HeError.emptyModulus
        }

        let bSkMTildeContext = try PolyContext(degree: degree, moduli: bSkMTildeModuli)
        guard let bSkContext = bSkMTildeContext.next else {
            throw HeError.invalidPolyContext(bSkMTildeContext)
        }
        guard let bContext = bSkContext.next else {
            throw HeError.invalidPolyContext(bSkContext)
        }

        let bModQi = inputContext.reduceModuli.map { qi in
            bContext.qRemainder(dividingBy: qi)
        }
        self.bModQ = zip(bModQi, inputContext.moduli).map { bModQi, qi in
            MultiplyConstantModulus(
                multiplicand: bModQi,
                modulus: qi,
                variableTime: true)
        }
        self.negBModQ = zip(bModQi, inputContext.moduli).map { bModQi, qi in
            let negBModQi = bModQi.negateMod(modulus: qi)
            return MultiplyConstantModulus(
                multiplicand: negBModQi,
                modulus: qi,
                variableTime: true)
        }

        self.qModBSk = bSkModuli.map { modulus in
            let qModBSk = inputContext.qRemainder(dividingBy: Modulus(modulus: modulus, variableTime: true))
            return MultiplyConstantModulus(multiplicand: qModBSk, modulus: modulus, variableTime: true)
        }
        self.inverseMTildeModBSk = try bSkModuli.map { modulus in
            let inverseMTildeModBSk = try T.mTilde.inverseMod(modulus: modulus, variableTime: true)
            return MultiplyConstantModulus(multiplicand: inverseMTildeModBSk, modulus: modulus, variableTime: true)
        }

        self.mTildeModQ = inputContext.reduceModuli.map { qi in qi.reduce(T.mTilde) }

        let qBSkModuli = inputContext.moduli + bSkModuli
        self.qBskContext = try PolyContext(degree: degree, moduli: qBSkModuli)

        self.inverseQModBSk = try bSkContext.reduceModuli.map { modulus in
            let qMod = inputContext.qRemainder(dividingBy: modulus)
            let multiplicand = try qMod.inverseMod(modulus: modulus.modulus, variableTime: true)
            return MultiplyConstantModulus(multiplicand: multiplicand, divisionModulus: modulus.divisionModulus)
        }

        let mSkContext = try PolyContext(degree: degree, moduli: [mSk])
        self.inverseBModMSk = try {
            let bModMSk = bContext.qRemainder(dividingBy: mSkContext.reduceModuli[0])
            let multiplicand = try bModMSk.inverseMod(modulus: mSk, variableTime: true)
            return MultiplyConstantModulus(multiplicand: multiplicand, modulus: mSk, variableTime: true)
        }()
        self.rnsConvertQToBSk = try RnsBaseConverter(from: inputContext, to: bSkContext)
        self.rnsConvertQToBSkMTilde = try RnsBaseConverter(from: inputContext, to: bSkMTildeContext)
        self.rnsConvertBtoMSk = try RnsBaseConverter(from: bContext, to: mSkContext)
        self.rnsConvertBtoQ = try RnsBaseConverter(from: bContext, to: inputContext)
    }

    /// Performs scaling and rounding.
    ///
    /// Given input polynomial with `Delta * m + v` for `|v|_{infty} <= q/t (1/2 - k / gamma) - |q|_t / 2`, returns
    /// `[m]_t`, for plaintext modulus `t`, coefficient modulus `q`, and ``ScalarType/rnsCorrectionFactor`` gamma.
    /// - Parameters:
    ///   - poly: Polynomial whose coefficients to scale and round.
    ///   - scalingFactor: Factor to multiply the polynomial by.
    /// - Returns: The scaled and rounded polynomial.
    /// - seealso: Algorithm 2 from <https://eprint.iacr.org/2016/510.pdf>.
    /// - Throws: Error upon failure to compute the scaling and rounding.
    @inlinable
    func scaleAndRound(poly: PolyRq<T, Coeff>, scalingFactor: T) throws -> PolyRq<T, Coeff> {
        var poly = poly
        poly *= prodGammaTModQ

        var polyModGammaT = try rnsConvertQToTGamma.convertApproximate(poly: poly)
        polyModGammaT *= negInverseQModTGamma

        let correctionFactor = T.rnsCorrectionFactor
        let correctedGamma = correctionFactor / 2
        let t = outputContext.reduceModuli[0]

        var result = PolyRq<T, Coeff>.zero(context: outputContext)
        for (resultIdx, (polyModT, polyModGamma)) in zip(
            result.polyIndices(rnsIndex: 0),
            zip(polyModGammaT.poly(rnsIndex: 0), polyModGammaT.poly(rnsIndex: 1)))
        {
            let sGammaGreaterThan = t.reduce(correctionFactor &- polyModGamma).negateMod(modulus: t.modulus)
            let sGammaLessThan = t.reduce(polyModGamma)
            let inputModGammaGreaterThanCorrectedGamma = polyModGamma.constantTimeGreaterThan(correctedGamma)
            let sGamma = T.constantTimeSelect(
                if: inputModGammaGreaterThanCorrectedGamma,
                then: sGammaGreaterThan,
                else: sGammaLessThan)
            result[resultIdx] = polyModT.subtractMod(sGamma, modulus: t.modulus)
        }

        let scaledInverseGammaModT = inverseGammaModT.multiplyMod(scalingFactor)
        result *= [scaledInverseGammaModT]

        return result
    }

    /// Performs approximate base conversion from base `q` to base `[Bsk, m_tilde]`.
    ///
    /// Given input polynomial with cofficeint `x_i` in base `q`, the output polynomial will have coefficients
    /// `x_i * m_tilde mod q + a_i * q` in base `[Bsk, m_tilde]`, for some `a_x \in [0, num_in_moduli-1]`.
    /// - Parameter poly: Input polynomial with base `q`.
    /// - Returns: The converted polynomial with base `[Bsk, m_tilde]`.
    /// - Throws: Error upon failure to perform the base conversion.
    /// - seealso: Algorithm 1 from <https://eprint.iacr.org/2016/510.pdf>.
    @inlinable
    func convertApproximateBskMTilde(poly: PolyRq<T, Coeff>) throws -> PolyRq<T, Coeff> {
        let scaledInput = poly * mTildeModQ
        return try rnsConvertQToBSkMTilde.convertApproximate(poly: scaledInput)
    }

    /// Lifts a polynomial with base `q` to base `[b, B_sk]`.
    /// - Parameter poly: has base `q`
    /// - Returns: `out` with base `[q, B_sk]`
    /// - Throws: Error upon failure to perform the base convresion.
    /// - seealso: Algorithm 2 from <https://eprint.iacr.org/2016/510.pdf>.
    @inlinable
    func liftQToQBsk(poly: PolyRq<T, Coeff>) throws -> PolyRq<T, Coeff> {
        var poly = poly
        var outputBsk = try convertApproximateBskMTilde(poly: poly)
        // correct multiples of q
        try smallMontgomeryReduce(poly: &outputBsk)
        poly.data.append(rows: outputBsk.data.data)
        return PolyRq(context: qBskContext, data: poly.data)
    }

    /// Performs Montgomery reduction of a polynomial.
    ///
    /// - Parameter poly: Input must have base `[B_sk, m_tilde]`. The output will be `poly * m_tilde^{-1} mod q`, with
    /// base `[B_sk]`.
    /// - Throws: Error upon invalid polynomial.
    @inlinable
    func smallMontgomeryReduce(poly: inout PolyRq<T, Coeff>) throws {
        let mTildeDivThreshold = T.mTilde >> 1
        let mTildeRow = poly.moduli.count - 1

        let rMTildeLessThanThreshold = poly.polyIndices(rnsIndex: mTildeRow).map { polyIndex in
            var rMTilde = poly.data[polyIndex]
            rMTilde = negInverseQModMTilde.multiplyMod(rMTilde)
            poly.data[polyIndex] = rMTilde
            return rMTilde.constantTimeLessThan(mTildeDivThreshold)
        }
        for (rnsIndex, bsk) in poly.moduli.dropLast().enumerated() {
            let qModBsk = qModBSk[rnsIndex]
            let inverseMTildeModBSk = inverseMTildeModBSk[rnsIndex]
            for (coeffIndex, (polyIndex, mTildeIndex)) in zip(
                poly.polyIndices(rnsIndex: rnsIndex),
                poly.polyIndices(rnsIndex: mTildeRow)).enumerated()
            {
                var rMTilde = poly.data[mTildeIndex]
                rMTilde = T.constantTimeSelect(
                    if: rMTildeLessThanThreshold[coeffIndex],
                    then: rMTilde,
                    else: rMTilde &+ bsk &- T.mTilde)
                var polyData = poly.data[polyIndex]
                polyData &+= qModBsk.multiplyModLazy(rMTilde)
                polyData = inverseMTildeModBSk.multiplyMod(polyData)
                poly.data[polyIndex] = polyData
            }
        }
        try poly.dropContext(to: bSkContext)
    }

    /// Uncorrected RNS flooring.
    ///
    /// The output will be `(floor(x/q) + a_x) % B_sk`, where `a_x \in [-(L-1), L-1]`
    /// - Parameter poly: Polynomial with base `[q, Bsk]`.
    /// - Returns: Polynomial in base `[Bsk]``.
    /// - Throws: Error upon failure to compute the approximate floor.
    /// - seealso: Section 4.3 of <https://eprint.iacr.org/2016/510.pdf>.
    @inlinable
    func approximateFloor(poly: PolyRq<T, Coeff>) throws -> PolyRq<T, Coeff> {
        let qModuliCount = inputContext.moduli.count
        let polyModBSk = (qModuliCount..<poly.moduli.count).flatMap { rnsIndex in
            poly.poly(rnsIndex: rnsIndex)
        }
        var polyModQ = poly
        try polyModQ.dropContext(to: inputContext)
        var output = try rnsConvertQToBSk.convertApproximate(poly: polyModQ)
        polyModBSk.withUnsafeBufferPointer { polyModBSkPtr in
            for (rnsIndex, inverseQModBSk) in inverseQModBSk.enumerated() {
                let bSk = rnsConvertQToBSk.outputContext.moduli[rnsIndex]
                let outputIndices = output.polyIndices(rnsIndex: rnsIndex)
                output.data.data.withUnsafeMutableBufferPointer { outputPtr in
                    for polyIndex in outputIndices {
                        let inputCoeff = polyModBSkPtr[polyIndex]
                        let outputCoeff = outputPtr[polyIndex]
                        outputPtr[polyIndex] = inverseQModBSk.multiplyMod(inputCoeff &+ bSk &- outputCoeff)
                    }
                }
            }
        }
        return output
    }

    /// Base conversion from input in base `Bsk = [B, m_sk]` to output in base `q`.
    @inlinable
    func convertApproximateBskToQ(poly: PolyRq<T, Coeff>) throws -> PolyRq<T, Coeff> {
        let qModuliCount = inputContext.moduli.count
        let polyModMSk = (qModuliCount..<poly.moduli.count).flatMap { rnsIndex in
            poly.poly(rnsIndex: rnsIndex)
        }

        var polyModB = poly
        guard let bContext = bSkContext.next else {
            throw HeError.invalidPolyContext(bSkContext)
        }
        try polyModB.dropContext(to: bContext)

        rnsConvertBtoMSk.convertApproximateProducts(of: &polyModB)
        var alphaSk = rnsConvertBtoMSk.convertApproximate(using: polyModB)
        guard let mSk = bSkContext.moduli.last else {
            throw HeError.invalidPolyContext(bSkContext)
        }
        let mSkThreshold = mSk &>> 1
        let coeffIndices = alphaSk.coeffIndices
        var alphaExceedsThreshold = [T]()
        alphaExceedsThreshold.reserveCapacity(coeffIndices.count)
        alphaSk.data.data.withUnsafeMutableBufferPointer { alphaSkPtr in
            for coeffIndex in coeffIndices {
                let polyModMSkCoeff = polyModMSk[coeffIndex]
                var alphaSk = alphaSkPtr[coeffIndex]
                alphaSk = inverseBModMSk
                    .multiplyMod(alphaSk &+ inverseBModMSk.modulus &- polyModMSkCoeff)
                alphaSkPtr[coeffIndex] = alphaSk
                alphaExceedsThreshold.append(alphaSk.constantTimeGreaterThan(mSkThreshold))
            }
        }

        var output = rnsConvertBtoQ.convertApproximate(using: polyModB)
        output.data.data.withUnsafeMutableBufferPointer { outputPtr in
            alphaSk.data.data.withUnsafeBufferPointer { alphaSkPtr in
                alphaExceedsThreshold.withUnsafeBufferPointer { alphaExceedsThresholdPtr in
                    for (rnsIndex, (qi, (bModQi, negBModQi))) in zip(inputContext.moduli, zip(bModQ, negBModQ))
                        .enumerated()
                    {
                        for (coeffIndex, outputIndex) in polyModB.polyIndices(rnsIndex: rnsIndex).enumerated() {
                            // Center alphaSk before Shenoy-Kumeresan conversion
                            let adjust = T.constantTimeSelect(
                                if: alphaExceedsThresholdPtr[coeffIndex],
                                then: bModQi.multiplyMod(mSk &- alphaSkPtr[coeffIndex]),
                                else: negBModQi.multiplyMod(alphaSkPtr[coeffIndex]))
                            outputPtr[outputIndex] = outputPtr[outputIndex].addMod(adjust, modulus: qi)
                        }
                    }
                }
            }
        }

        return output
    }

    @inlinable
    func floorQBskToQ(poly: PolyRq<T, Coeff>) throws -> PolyRq<T, Coeff> {
        let floored = try approximateFloor(poly: poly)
        return try convertApproximateBskToQ(poly: floored)
    }

    ///  Performs Chinese remainder theorem (CRT) composition.
    /// - Parameters:
    ///   - poly: Polynomial whose coefficients to compose.
    ///   - variableTime: Must be `true`, indicating the coefficients of the polynomial are leaked through timing.
    /// - Returns: The coefficients of `poly`, each in `[0, Q - 1]`.
    /// - Warning: `V`'s operations must be constant time to prevent leaking `poly` through timing.
    @inlinable
    package func crtCompose<V: FixedWidthInteger & UnsignedInteger>(poly: PolyRq<T, Coeff>) throws -> [V] {
        // Use arbitrary base converter that has same inputContext
        try rnsConvertQToBSk.crtCompose(poly: poly)
    }

    /// Returns an upper bound on the maximum value during a `crtCompose` call.
    @inlinable
    package func crtComposeMaxIntermediateValue() -> Double {
        CrtComposer.composeMaxIntermediateValue(moduli: inputContext.moduli)
    }
}
