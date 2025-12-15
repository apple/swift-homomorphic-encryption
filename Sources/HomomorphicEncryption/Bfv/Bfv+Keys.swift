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
    public static func generateSecretKey(context: Context) throws -> SecretKey<Bfv<T>> {
        var s = PolyRq<Scalar, Coeff>.zero(context: context.secretKeyContext)
        var rng = SystemRandomNumberGenerator()
        s.randomizeTernary(using: &rng)

        return try SecretKey(poly: s.forwardNtt())
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func generateEvaluationKey(
        context: Context,
        config: EvaluationKeyConfig,
        using secretKey: borrowing SecretKey<Bfv<T>>) throws -> EvaluationKey<Bfv<T>>
    {
        guard context.supportsEvaluationKey else {
            throw HeError.unsupportedHeOperation()
        }
        var galoisKeys: [Int: Self.KeySwitchKey] = [:]
        for element in config.galoisElements where !galoisKeys.keys.contains(element) {
            let switchedKey = try secretKey.poly.applyGalois(element: element)
            galoisKeys[element] = try _generateKeySwitchKey(
                context: context,
                currentKey: switchedKey,
                targetKey: secretKey)
        }
        var galoisKey: GaloisKey?
        if !galoisKeys.isEmpty {
            galoisKey = GaloisKey(keys: galoisKeys)
        }
        var relinearizationKey: _RelinearizationKey<Self>?
        if config.hasRelinearizationKey {
            relinearizationKey = try Self.generateRelinearizationKey(context: context, secretKey: secretKey)
        }
        return EvaluationKey(galoisKey: galoisKey, relinearizationKey: relinearizationKey)
    }

    @inlinable
    static func generateRelinearizationKey(context: Context,
                                           secretKey: borrowing SecretKey<Self>) throws
        -> _RelinearizationKey<Self>
    {
        let s2 = secretKey.poly * secretKey.poly
        let keySwitchingKey = try _generateKeySwitchKey(context: context, currentKey: s2, targetKey: secretKey)
        return _RelinearizationKey(keySwitchKey: keySwitchingKey)
    }

    ///  Generate the key switching key from current key to target key.
    @inlinable
    public static func _generateKeySwitchKey(context: Context,
                                             currentKey: consuming PolyRq<T, Eval>,
                                             targetKey: borrowing SecretKey<Bfv<T>>) throws -> _KeySwitchKey<Bfv<T>>
    {
        guard let keyModulus = context.coefficientModuli.last else {
            throw HeError.invalidEncryptionParameters(context.encryptionParameters)
        }
        let ciphertextContext = context.ciphertextContext
        let degree = context.degree
        var ciphers: [Ciphertext<Bfv<T>, Eval>] = []
        ciphers.reserveCapacity(ciphertextContext.moduli.count)
        for (rowIndex, modulus) in ciphertextContext.reduceModuli.enumerated() {
            let keySwitchKeyCoeff = try Bfv<T>.encryptZero(
                for: context,
                using: targetKey,
                with: context.keySwitchingContexts[targetKey.moduli.count - 2])
            var keySwitchKey = try keySwitchKeyCoeff.forwardNtt()

            let modulusProduct = MultiplyConstantModulus(
                multiplicand: modulus.reduce(keyModulus),
                modulus: modulus.modulus,
                variableTime: true)
            for columnIndex in 0..<degree {
                let prod = modulusProduct.multiplyMod(currentKey.data[rowIndex, columnIndex])
                keySwitchKey.polys[0].data[rowIndex, columnIndex] = keySwitchKey.polys[0].data[rowIndex, columnIndex]
                    .addMod(prod, modulus: modulus.modulus)
            }
            ciphers.append(keySwitchKey)
        }
        // zeroize currentKey and drop it
        currentKey.zeroize()
        _ = consume currentKey

        return KeySwitchKey(context: context, ciphertexts: ciphers)
    }

    /// Computes the key-switching update of a target polynomial.
    ///
    /// We use hybrid key-switching from Appendix B.2.3 of <https://eprint.iacr.org/2021/204.pdf>, with:
    /// * `alpha = 1`, i.e., a single key-switching modulus
    /// * The HPS trick from Appendix B.2.1.
    ///
    /// To switch the key of 2-polynomial ciphertext `[c0, c1]` from secret key `sA` to another secret key `sB`, we need
    /// to set `c0 := c0 + c1 * ksk.p0`, and `c1 := c1 * ksk.p1`, where `ksk.p0` is the 0'th polynomial in the
    /// key-switching key.
    /// This function computes `c1 * ksk.p0` and `c1 * ksk.p1`.
    /// - Parameters:
    ///   - context: Context for HE computation
    ///   - target: The polynomial to perform key-switching on. The paper calls this `D_{Q_i}(a)`.
    ///   - keySwitchingKey: keySwitchingKey. The paper calls this `P_{Q_i}(a)`
    /// - Returns: The key-switching update for a 2-polynomial ciphertext.
    /// - Throws: Error upon failure to compute key-switching update.
    /// - seealso: ``Bfv/generateEvaluationKey(context:config:using:)``.
    @inlinable
    public static func _computeKeySwitchingUpdate(
        context: Context,
        target: PolyRq<Scalar, CanonicalCiphertextFormat>,
        keySwitchingKey: Self.KeySwitchKey) throws -> [PolyRq<Scalar, CanonicalCiphertextFormat>]
    {
        //  The implementation loosely follows the outline on page 36 of <https://eprint.iacr.org/2021/204.pdf>.
        // The inner product is computed in an extended base `q_0, q_1, ..., q_l, q_{ks}`, where `q_{ks}` is the special
        // key-switching modulus.

        let degree = target.degree
        let decomposeModuliCount = target.moduli.count
        let rnsModuliCount = decomposeModuliCount &+ 1

        let keySwitchingContext = context.keySwitchingContexts[target.moduli.count - 1]
        guard let topKeySwitchingContext = context.keySwitchingContexts.last else {
            throw HeError.invalidContext(context)
        }
        let keySwitchingModuli = keySwitchingContext.reduceModuli

        let keyComponentCount = keySwitchingKey.ciphertexts[0].polys.count
        let polys = [PolyRq<Scalar, Eval>](
            repeating: PolyRq.zero(context: keySwitchingContext),
            count: keyComponentCount)
        var ciphertextProd: EvalCiphertext = try Ciphertext(context: context,
                                                            polys: polys,
                                                            correctionFactor: 1)
        let targetCoeff = try target.convertToCoeffFormat()

        let keyCiphers = keySwitchingKey.ciphertexts
        for rnsIndex in 0..<rnsModuliCount {
            let keyIndex = rnsIndex == rnsModuliCount &- 1 ? topKeySwitchingContext.moduli.count &- 1 : rnsIndex
            let keyModulus = keySwitchingModuli[rnsIndex]

            // Use lazy accumulator to minimize modular reductions
            var accumulator = Array2d(
                data: [T.DoubleWidth](
                    repeating: 0,
                    count: keyComponentCount &* degree),
                rowCount: keyComponentCount,
                columnCount: degree)

            for decomposeIndex in 0..<decomposeModuliCount {
                let qKeyJ = keySwitchingModuli[decomposeIndex]
                var bufferSlice = targetCoeff.poly(rnsIndex: decomposeIndex)
                if qKeyJ.modulus > keyModulus.modulus {
                    for index in bufferSlice.indices {
                        bufferSlice[index] = keyModulus.reduce(bufferSlice[index])
                    }
                }

                try bufferSlice.withUnsafeMutableBufferPointer { bufferPtr in
                    try topKeySwitchingContext.forwardNtt(
                        // swiftlint:disable:next force_unwrapping
                        dataPtr: bufferPtr.baseAddress!,
                        modulus: keyModulus.modulus)
                }
                for (index, poly) in keyCiphers[decomposeIndex].polys.enumerated() {
                    let accIndex = poly.data.index(row: index, column: 0)
                    let polyIndex = poly.data.index(row: keyIndex, column: 0)
                    // let polySpan = poly.data.data.span
                    for columnIndex in 0..<degree {
                        let prod = bufferSlice[columnIndex]
                            .multipliedFullWidth(by: poly.data.data[polyIndex &+ columnIndex])
                        // Overflow avoided by `maxLazyProductAccumulationCount()` check during context
                        // initialization
                        accumulator[accIndex &+ columnIndex] &+= T.DoubleWidth(prod)
                    }
                }
            }
            let prodIndex = ciphertextProd.polys[0].data.index(row: rnsIndex, column: 0)
            for rowIndex in ciphertextProd.polys.indices {
                let accIndex = accumulator.index(row: rowIndex, column: 0)
                // var ciphertextProdSpan = ciphertextProd.polys[rowIndex].data.data.mutableSpan
                for columnIndex in 0..<degree {
                    ciphertextProd.polys[rowIndex].data.data[prodIndex &+ columnIndex] = keyModulus
                        .reduce(accumulator[accIndex &+ columnIndex])
                }
            }
        }
        var canonicalProd = try ciphertextProd.convertToCanonicalFormat()
        // Drop the special modulus
        try canonicalProd.modSwitchDown()
        return canonicalProd.polys
    }
}
