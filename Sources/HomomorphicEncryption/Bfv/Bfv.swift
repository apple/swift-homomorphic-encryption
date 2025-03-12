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

import ModularArithmetic

/// Brakerski-Fan-Vercauteren cryptosystem.
public enum Bfv<T: ScalarType>: HeScheme {
    public typealias Scalar = T

    public typealias CanonicalCiphertextFormat = Coeff

    public static var freshCiphertextPolyCount: Int {
        2
    }

    public static var minNoiseBudget: Double {
        0
    }

    // MARK: HE operations

    @inlinable
    public static func addAssign<F: PolyFormat>(_ lhs: inout Plaintext<Bfv<T>, F>, _ rhs: Plaintext<Bfv<T>, F>) throws {
        try validateEquality(of: lhs.context, and: rhs.context)
        lhs.poly += rhs.poly
    }

    @inlinable
    public static func addAssignCoeff<F: PolyFormat>(
        _ lhs: inout Ciphertext<Bfv<T>, F>,
        _ rhs: Ciphertext<Bfv<T>, F>) throws
    {
        try addAssignSameType(&lhs, rhs)
    }

    @inlinable
    public static func addAssignEval<F: PolyFormat>(
        _ lhs: inout Ciphertext<Bfv<T>, F>,
        _ rhs: Ciphertext<Bfv<T>, F>) throws
    {
        try addAssignSameType(&lhs, rhs)
    }

    @inlinable
    static func addAssignSameType<F: PolyFormat>(
        _ lhs: inout Ciphertext<Bfv<T>, F>,
        _ rhs: Ciphertext<Bfv<T>, F>) throws
    {
        try validateEquality(of: lhs.context, and: rhs.context)
        for (polyIndex, rhsPoly) in zip(lhs.polys.indices, rhs.polys) {
            lhs.polys[polyIndex] += rhsPoly
        }
        lhs.clearSeed()
    }

    @inlinable
    public static func subAssignCoeff<F: PolyFormat>(
        _ lhs: inout Ciphertext<Bfv<T>, F>,
        _ rhs: Ciphertext<Bfv<T>, F>) throws
    {
        try subAssignSameType(&lhs, rhs)
    }

    @inlinable
    public static func subAssignEval<F: PolyFormat>(
        _ lhs: inout Ciphertext<Bfv<T>, F>,
        _ rhs: Ciphertext<Bfv<T>, F>) throws
    {
        try subAssignSameType(&lhs, rhs)
    }

    @inlinable
    static func subAssignSameType<F: PolyFormat>(
        _ lhs: inout Ciphertext<Bfv<T>, F>,
        _ rhs: Ciphertext<Bfv<T>, F>) throws
    {
        try validateEquality(of: lhs.context, and: rhs.context)
        for (polyIndex, rhsPoly) in zip(lhs.polys.indices, rhs.polys) {
            lhs.polys[polyIndex] -= rhsPoly
        }
        lhs.clearSeed()
    }

    @inlinable
    public static func addAssignCoeff(_ ciphertext: inout CoeffCiphertext, _ plaintext: CoeffPlaintext) throws {
        try plaintextTranslate(ciphertext: &ciphertext, plaintext: plaintext, op: PlaintextTranslateOp.Add)
    }

    @inlinable
    public static func subAssignCoeff(_ ciphertext: inout CoeffCiphertext, _ plaintext: CoeffPlaintext) throws {
        try plaintextTranslate(ciphertext: &ciphertext, plaintext: plaintext, op: PlaintextTranslateOp.Subtract)
    }

    @inlinable
    public static func mulAssign(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        guard ciphertext.moduli.count == plaintext.moduli.count else {
            throw HeError.incompatibleCiphertextAndPlaintext(ciphertext: ciphertext, plaintext: plaintext)
        }
        for polyIndex in ciphertext.polys.indices {
            ciphertext.polys[polyIndex] *= plaintext.poly
        }
        ciphertext.clearSeed()
    }

    @inlinable
    public static func negAssignCoeff(_ ciphertext: inout CoeffCiphertext) {
        for polyIndex in ciphertext.polys.indices {
            ciphertext.polys[polyIndex] = -ciphertext.polys[polyIndex]
        }
        ciphertext.clearSeed()
    }

    @inlinable
    public static func negAssignEval(_ ciphertext: inout EvalCiphertext) {
        for polyIndex in ciphertext.polys.indices {
            ciphertext.polys[polyIndex] = -ciphertext.polys[polyIndex]
        }
        ciphertext.clearSeed()
    }

    // MARK: Unsupported operations

    // These operations could be supported with extra NTT conversions, but NTTs are expensive, so we prefer to
    // keep NTT conversions explicit

    @inlinable
    public static func addAssignEval(_: inout EvalCiphertext, _: EvalPlaintext) throws {
        throw HeError.unsupportedHeOperation()
    }

    @inlinable
    public static func subAssignEval(_: inout EvalCiphertext, _: EvalPlaintext) throws {
        throw HeError.unsupportedHeOperation()
    }

    @inlinable
    public static func modSwitchDown(_ ciphertext: inout CanonicalCiphertext) throws {
        precondition(
            ciphertext.correctionFactor == 1,
            "BFV modulus switching not implemented for correction factor not equal to 1")
        for polyIndex in ciphertext.polys.indices {
            try ciphertext.polys[polyIndex].divideAndRoundQLast()
        }
        ciphertext.clearSeed()
    }

    @inlinable
    public static func applyGalois(
        ciphertext: inout CanonicalCiphertext,
        element: Int,
        using evaluationKey: EvaluationKey<Bfv<T>>) throws
    {
        precondition(ciphertext.polys.count == 2, "ciphertext must have two polys when applying galois")
        precondition(
            ciphertext.correctionFactor == 1,
            "BFV Galois automorphisms not implemented for correction factor not equal to 1")
        guard let galoisKey = evaluationKey.galoisKey else {
            throw HeError.missingGaloisKey
        }
        guard let keySwitchingKey = galoisKey.keys[element] else {
            throw HeError.missingGaloisElement(element: element)
        }
        ciphertext.polys[0] = ciphertext.polys[0].applyGalois(element: element)
        let tempC1 = ciphertext.polys[1].applyGalois(element: element)
        let update = try Self.computeKeySwitchingUpdate(
            context: ciphertext.context,
            target: tempC1,
            keySwitchingKey: keySwitchingKey)
        ciphertext.polys[0] += update[0]
        ciphertext.polys[1] = update[1]
        ciphertext.clearSeed()
    }

    @inlinable
    public static func relinearize(_ ciphertext: inout CanonicalCiphertext, using key: EvaluationKey<Self>) throws {
        precondition(
            ciphertext.correctionFactor == 1,
            "BFV Galois automorphisms not implemented for correction factor not equal to 1")
        guard ciphertext.polys.count == 3, let poly2 = ciphertext.polys.popLast() else {
            preconditionFailure("ciphertext must have three polys when relinearizing")
        }
        guard let relinearizationKey = key.relinearizationKey else {
            throw HeError.missingRelinearizationKey
        }
        let update = try Self.computeKeySwitchingUpdate(
            context: ciphertext.context,
            target: poly2,
            keySwitchingKey: relinearizationKey.keySwitchKey)

        ciphertext.polys[0] += update[0]
        ciphertext.polys[1] += update[1]
        ciphertext.clearSeed()
    }

    // MARK: Inner product

    @inlinable
    public static func innerProduct(_ lhs: some Collection<CanonicalCiphertext>,
                                    _ rhs: some Collection<CanonicalCiphertext>) throws -> CanonicalCiphertext
    {
        // Computes accumulator += ciphertext * plaintext
        func lazyMultiply(
            _ lhs: CanonicalCiphertext,
            _ rhs: CanonicalCiphertext,
            to accumulator: inout [Array2d<T.DoubleWidth>]) throws
        {
            try validateEquality(of: lhs.context, and: rhs.context)
            guard lhs.polys.count == freshCiphertextPolyCount, lhs.correctionFactor == 1 else {
                throw HeError.invalidCiphertext(lhs)
            }
            guard rhs.polys.count == freshCiphertextPolyCount, rhs.correctionFactor == 1 else {
                throw HeError.invalidCiphertext(rhs)
            }

            let lhsPolys = try computeBehzPolys(ciphertext: lhs)
            let rhsPolys = try computeBehzPolys(ciphertext: rhs)
            PolyRq.addingLazyProduct(lhsPolys[0], rhsPolys[0], to: &accumulator[0])
            PolyRq.addingLazyProduct(lhsPolys[0], rhsPolys[1], to: &accumulator[1])
            PolyRq.addingLazyProduct(lhsPolys[1], rhsPolys[0], to: &accumulator[1])
            PolyRq.addingLazyProduct(lhsPolys[1], rhsPolys[1], to: &accumulator[2])
        }

        let firstCiphertext = lhs[lhs.startIndex]
        let rnsTool = firstCiphertext.context.getRnsTool(moduliCount: firstCiphertext.moduli.count)
        let moduliCount = rnsTool.qBskContext.moduli.count
        let poly = firstCiphertext.polys[0]

        let maxProductCount = rnsTool.qBskContext.maxLazyProductAccumulationCount() / 2
        var accumulator = Array(
            repeating: Array2d(data: Array(repeating: T.DoubleWidth(0), count: moduliCount * poly.degree),
                               rowCount: moduliCount, columnCount: poly.degree),
            count: 3)
        var reduceCount = 0
        for (lhsCipher, rhsCipher) in zip(lhs, rhs) {
            try lazyMultiply(lhsCipher, rhsCipher, to: &accumulator)
            reduceCount += 1
            if reduceCount >= maxProductCount {
                reduceCount = 0
                reduceInPlace(accumulator: &accumulator, polyContext: rnsTool.qBskContext)
            }
        }
        var sum = EvalCiphertext(
            context: firstCiphertext.context,
            polys: Array(repeating: .zero(context: rnsTool.qBskContext), count: 3),
            correctionFactor: 1)
        reduceToCiphertext(accumulator: accumulator, result: &sum)

        return try dropExtendedBase(from: sum)
    }

    // Reduce lazy sum in place
    @inlinable
    static func reduceInPlace(accumulator: inout [Array2d<T.DoubleWidth>],
                              polyContext: PolyContext<Self.Scalar>)
    {
        for polyIndex in accumulator.indices {
            for (rnsIndex, modulus) in polyContext.reduceModuli.enumerated() {
                for index in accumulator[polyIndex].rowIndices(row: rnsIndex) {
                    accumulator[polyIndex]
                        .data[index] = T.DoubleWidth(modulus.reduce(accumulator[polyIndex].data[index]))
                }
            }
        }
    }

    // Reduce lazy sum and save it to a ciphertext
    @inlinable
    static func reduceToCiphertext(
        accumulator: [Array2d<T.DoubleWidth>],
        result: inout Ciphertext<Self, some PolyFormat>)
    {
        let poly = result.polys[0]
        for (polyIndex, accumulatorPoly) in accumulator.enumerated() {
            accumulatorPoly.data.withUnsafeBufferPointer { accumulatorPolyPtr in
                result.polys[polyIndex].data.data.withUnsafeMutableBufferPointer { resultPtr in
                    for (rnsIndex, modulus) in poly.polyContext().reduceModuli.enumerated() {
                        for index in poly.polyIndices(rnsIndex: rnsIndex) {
                            resultPtr[index] = modulus.reduce(accumulatorPolyPtr[index])
                        }
                    }
                }
            }
        }
    }

    @inlinable
    public static func innerProduct(ciphertexts: some Collection<EvalCiphertext>,
                                    plaintexts: some Collection<EvalPlaintext?>) throws -> EvalCiphertext
    {
        // Computes accumulator += ciphertext * plaintext
        func lazyMultiply(
            ciphertext: EvalCiphertext,
            plaintext: EvalPlaintext,
            to accumulator: inout [Array2d<T.DoubleWidth>]) throws
        {
            try validateEquality(of: ciphertext.context, and: plaintext.context)
            guard ciphertext.moduli.count == plaintext.moduli.count else {
                throw HeError.incompatibleCiphertextAndPlaintext(ciphertext: ciphertext, plaintext: plaintext)
            }
            for (polyIndex, ciphertextPoly) in ciphertext.polys.enumerated() {
                PolyRq.addingLazyProduct(ciphertextPoly, plaintext.poly, to: &accumulator[polyIndex])
            }
        }

        precondition(plaintexts.count == ciphertexts.count)
        guard var result = ciphertexts.first else {
            preconditionFailure("Empty ciphertexts")
        }
        let poly = result.polys[0]
        let maxProductCount = poly.context.maxLazyProductAccumulationCount()
        var accumulator = Array(
            repeating: Array2d(data: Array(repeating: T.DoubleWidth(0), count: poly.data.count),
                               rowCount: poly.moduli.count, columnCount: poly.degree),
            count: Bfv.freshCiphertextPolyCount)

        var reduceCount = 0
        for (ciphertext, plaintext) in zip(ciphertexts, plaintexts) {
            guard let plaintext else { continue }
            try lazyMultiply(ciphertext: ciphertext, plaintext: plaintext, to: &accumulator)
            reduceCount += 1
            if reduceCount >= maxProductCount {
                reduceCount = 0
                reduceInPlace(accumulator: &accumulator, polyContext: result.polyContext())
            }
        }

        reduceToCiphertext(accumulator: accumulator, result: &result)
        return result
    }

    @inlinable
    public static func forwardNtt(_ ciphertext: CoeffCiphertext) throws -> EvalCiphertext {
        let polys = try ciphertext.polys.map { try $0.forwardNtt() }
        return Ciphertext<Bfv<T>, Eval>(context: ciphertext.context,
                                        polys: polys,
                                        correctionFactor: ciphertext.correctionFactor,
                                        seed: ciphertext.seed)
    }

    @inlinable
    public static func inverseNtt(_ ciphertext: EvalCiphertext) throws -> CoeffCiphertext {
        let polys = try ciphertext.polys.map { try $0.inverseNtt() }
        return Ciphertext<Bfv<T>, Coeff>(context: ciphertext.context,
                                         polys: polys,
                                         correctionFactor: ciphertext.correctionFactor,
                                         seed: ciphertext.seed)
    }
}
