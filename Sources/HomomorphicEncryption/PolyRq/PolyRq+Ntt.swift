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

extension ScalarType {
    /// Returns whether or not a prime value is a valid NTT modulus.
    ///
    /// - Parameter degree: Degree of the RLWE polynomial.
    /// - Returns: whether or not the value is a value NTT modulus
    /// - Note: `self` must be prime.
    @inlinable
    func isNttModulus(for degree: Int) -> Bool {
        assert(isPrime(variableTime: true))
        return degree.isPowerOfTwo && self % Self(2 * degree) == 1 && self != 1
    }

    @inlinable
    func isPrimitiveRootOfUnity(degree: Int, modulus: Self) -> Bool {
        // For degree a power of two, it suffices to check root^(degree/2) == -1 mod p
        // This implies root^degree == 1 mod p. Also, note 2 is the only prime factor of
        // degree. See
        // https://en.wikipedia.org/wiki/Root_of_unity_modulo_n#Testing_whether_x_is_a_primitive_k-th_root_of_unity_modulo_n.
        precondition(degree.isPowerOfTwo)
        return powMod(exponent: Self(degree / 2), modulus: modulus, variableTime: true) == modulus - 1
    }

    /// Generate a primitive `degree'th` root of unity for integers mod this value.
    ///
    /// This value must be prime.
    /// - Parameter degree: Must be a power of two.
    /// - Returns: The primitive root of unity.
    @inlinable
    func generatePrimitiveRootOfUnity(degree: Int) -> Self? {
        precondition(degree.isPowerOfTwo)
        precondition(isPrime(variableTime: true))

        // See https://en.wikipedia.org/wiki/Root_of_unity_modulo_n#Finding_a_primitive_k-th_root_of_unity_modulo_n
        // Carmichael function lambda(p) = p - 1 for p prime
        let lambdaP = self - 1

        // "If k does not divide lambda(n), then there will be no k-th roots of unity, at all."
        if !lambdaP.isMultiple(of: Self(degree)) {
            return nil
        }

        // The number of primitive roots mod p for p prime is phi(p-1), where phi is
        // Euler's totient function. We know phi(p-1) > p / (e^gamma log(log(p)) + 3 /
        // log(log(p)) (https://en.wikipedia.org/wiki/Euler%27s_totient_function#Growth_rate).
        // So the probability that a random value in [0, p-1] is a primitive root is at
        // least phi(p-1)/p > 1 / (e^gamma log(log(p)) + 3 / log(log(p)) > 1/8 for p
        // < 2^64 and where gamma is the Euler–Mascheroni constant ~= 0.577. That
        // is, we have at least 1/8 chance of finding a root on each attempt. So, (1 -
        // 1/8)^T < 2^{-128} yields T = 665 trials suffices for less than 2^{-128}
        // chance of failure.
        let trialCount = 665
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<trialCount {
            var root = Self.random(in: 0..<self, using: &rng)
            // root^(lambda(p)/degree) will be a primitive degree'th root of unity if root
            // is a lambda(p)'th root
            root = root.powMod(exponent: lambdaP / Self(degree), modulus: self, variableTime: true)
            if root.isPrimitiveRootOfUnity(degree: degree, modulus: self) {
                return root
            }
        }
        return nil
    }

    /// Generates the smallest primitive `degree`'th primitive root for integers mod this value, `p`.
    ///
    /// This value, `p`, must be prime.
    /// - Parameter degree: Must be a power of two that divides `p - 1`.
    /// - Returns: The primitive root of unity.
    @inlinable
    func minPrimitiveRootOfUnity(degree: Int) -> Self? {
        guard var smallestGenerator = generatePrimitiveRootOfUnity(degree: degree) else {
            return nil
        }
        var currentGenerator = smallestGenerator

        // Given a generator g, g^l is a degree'th root of unity iff l and degree are
        // co-prime. Since degree is a power of two, we can check g, g^3, g^5, ...
        // See https://en.wikipedia.org/wiki/Root_of_unity_modulo_n#Finding_multiple_primitive_k-th_roots_modulo_n
        let generatorSquared = currentGenerator.powMod(exponent: 2, modulus: self, variableTime: true)
        let modulus = ReduceModulus(modulus: self, bound: ReduceModulus.InputBound.ModulusSquared, variableTime: true)
        for _ in 0..<degree / 2 {
            if currentGenerator < smallestGenerator {
                smallestGenerator = currentGenerator
            }
            currentGenerator = modulus.multiplyMod(currentGenerator, generatorSquared)
        }
        return smallestGenerator
    }
}

@usableFromInline
struct NttContext<T: ScalarType>: Sendable {
    @usableFromInline let rootOfUnityPowers: MultiplyConstantArrayModulus<T>
    @usableFromInline let inverseRootOfUnityPowers: MultiplyConstantArrayModulus<T>
    @usableFromInline let inverseDegree: MultiplyConstantModulus<T> // degree^{-1} mod modulus
    // (degree)^{-1} * w^{-N} mod modulus for `w` a root of unity mod modulus
    @usableFromInline let inverseDegreeRootOfUnity: MultiplyConstantModulus<T>

    @inlinable
    init(degree: Int, modulus: T) throws {
        precondition(modulus.isNttModulus(for: degree))
        guard let rootOfUnity = modulus.minPrimitiveRootOfUnity(degree: 2 * degree) else {
            throw HeError.invalidNttModulus(modulus: Int64(modulus), degree: 2 * degree)
        }
        let inverseRootOfUnity = try rootOfUnity.inverseMod(modulus: modulus, variableTime: true)
        let reduceModulus = Modulus(modulus: modulus, variableTime: true)
        var rootOfUnityPowers = Array(repeating: T(1), count: degree)
        var inverseRootOfUnityPowers = Array(repeating: T(1), count: degree)
        var previousIdx = 0
        for idx in 1..<UInt32(degree) {
            let reverseIdx = Int(idx.reverseBits(bitCount: degree.log2))
            rootOfUnityPowers[reverseIdx] = reduceModulus.multiplyMod(
                rootOfUnity,
                rootOfUnityPowers[previousIdx])
            inverseRootOfUnityPowers[reverseIdx] = reduceModulus.multiplyMod(
                inverseRootOfUnity,
                inverseRootOfUnityPowers[previousIdx])
            previousIdx = reverseIdx
        }
        self.rootOfUnityPowers = MultiplyConstantArrayModulus(
            multiplicands: rootOfUnityPowers,
            modulus: modulus,
            variableTime: true)

        // Reorder inverse root of unity powers for sequential access in inverse NTT
        var inverseIdx = 1
        var reorderedInverseRootOfUnityPowers = Array(repeating: T(1), count: degree)
        for m in (0..<degree.log2).reversed().map({ 1 << $0 }) {
            for i in 0..<m {
                reorderedInverseRootOfUnityPowers[inverseIdx] = inverseRootOfUnityPowers[m + i]
                inverseIdx += 1
            }
        }
        self.inverseRootOfUnityPowers = MultiplyConstantArrayModulus(
            multiplicands: reorderedInverseRootOfUnityPowers,
            modulus: modulus,
            variableTime: true)

        let inverseDegree = try T(degree).inverseMod(modulus: modulus, variableTime: true)
        self.inverseDegree = MultiplyConstantModulus(multiplicand: inverseDegree, modulus: modulus, variableTime: true)

        let inverseDegreeRootOfUnity = inverseDegree.multiplyMod(
            reorderedInverseRootOfUnityPowers[degree - 1],
            modulus: modulus, variableTime: true)
        self.inverseDegreeRootOfUnity = MultiplyConstantModulus(
            multiplicand: inverseDegreeRootOfUnity,
            modulus: modulus,
            variableTime: true)
    }
}

/// Computes a lazy forward NTT butterfly.
/// - Parameters:
///   - x: In `[0, lazyReductionCounter * modulus - 1]`.
///   - y:  Unbounded range.
///   - rootOfUnity: Multiplication by a root of unity `w`, mod `modulus`.
///   - twiceModulus:  `2 * modulus`.
///   - lazyReductionCounter: Bound on the inputs/outputs.
/// - Returns: `(x + w * y mod modulus, x - w * y mod modulus)` in `[0, (lazyReductionCounter + 2) * modulus - 1]`.
/// - seealso: Algorithm 4 from <https://arxiv.org/pdf/1205.2926>.
@inlinable
func forwardButterfly<T: ScalarType>(
    x: T,
    y: T,
    rootOfUnity: MultiplyConstantModulus<T>,
    twiceModulus: T,
    lazyReductionCounter: Int) -> (T, T)
{
    assert((T(lazyReductionCounter) + 2).multipliedReportingOverflow(by: rootOfUnity.modulus).overflow == false)
    assert(x < T(lazyReductionCounter) * rootOfUnity.modulus)

    let t = rootOfUnity.multiplyModLazy(y) // in [0, 2 * modulus]
    let yOut = x &+ twiceModulus &- t
    let xOut = x &+ t

    assert(t < 2 * rootOfUnity.modulus)
    assert(xOut < (T(lazyReductionCounter) + 2) * rootOfUnity.modulus)
    assert(yOut < (T(lazyReductionCounter) + 2) * rootOfUnity.modulus)

    return (xOut, yOut)
}

extension PolyRq where F == Coeff {
    /// Performs the forward number-theoretic transform (NTT).
    /// - Returns: The ``Eval`` representation of the polynomial.
    /// - Throws: Error upon failure to compute the forward NTT.
    @inlinable
    public consuming func forwardNtt() throws -> PolyRq<T, Eval> {
        try context.validateNttModuli()
        var currentContext: PolyContext<T>? = context
        while let context = currentContext, let modulus = context.moduli.last {
            let rowOffset = data.index(row: context.moduli.count - 1, column: 0)
            try data.data.withUnsafeMutableBufferPointer { dataPtr in
                // swiftlint:disable:next force_unwrapping
                try context.forwardNtt(dataPtr: dataPtr.baseAddress! + rowOffset, modulus: modulus)
            }
            currentContext = context.next
        }
        return PolyRq<T, Eval>(context: context, data: data)
    }
}

extension PolyContext {
    /// Performs the forward number-theoretic transform (NTT) on a single modulus.
    /// - Parameters:
    ///   - dataPtr: Pointer to the coefficients mod `modulus`.
    ///   - modulus: Modulus.
    /// - Throws: Error upon failure to compute the forward NTT.
    @inlinable
    func forwardNtt(dataPtr: UnsafeMutablePointer<T>, modulus: T) throws {
        // We modify Harvey's approach <https://arxiv.org/pdf/1205.2926> with delayed modular reduction.
        var context = self
        while modulus != context.moduli.last, let nextContext = context.next {
            context = nextContext
        }
        guard modulus == context.moduli.last else {
            throw HeError.invalidPolyContext(context)
        }
        guard let nttContext = context.nttContext, let modulusReduceFactor = context.reduceModuli.last
        else {
            throw HeError.invalidPolyContext(context)
        }

        let n = degree
        let twiceModulus = modulus << 1
        let rootOfUnityPowers = nttContext.rootOfUnityPowers
        // The forward butterfly transforms `x,y` in
        // `[0, k * modulus)` -> `[0, (k + 2) * modulus)`.
        // We delay modular reduction until overflowing T, i.e.
        // `(kMax + 2) * modulus > T.max`, so `kMax = floor(T.max / modulus) - 2
        var lazyReductionCounter = -1 // k
        // kMax
        let maxLazyReductionCounter = modulusReduceFactor.singleWordModulus.factor.low &- 2

        func applyFinalStageOp(m: Int, op: (_ x: inout T, _ y: inout T) -> Void) {
            for i in 0..<m {
                let xIdx = 2 &* i
                let yIdx = xIdx &+ 1
                let rootOfUnity = rootOfUnityPowers[m &+ i]
                var x = dataPtr[xIdx]
                var y = dataPtr[yIdx]
                op(&x, &y)
                (x, y) = forwardButterfly(
                    x: x,
                    y: y,
                    rootOfUnity: rootOfUnity,
                    twiceModulus: twiceModulus,
                    lazyReductionCounter: lazyReductionCounter)
                // reduce all the way back to [0, modulus)
                dataPtr[xIdx] = modulusReduceFactor.reduce(x)
                dataPtr[yIdx] = modulusReduceFactor.reduce(y)
            }
        }

        func applyNonFinalStageOp(m: Int, t: Int, op: (_ x: inout T, _ y: inout T) -> Void) {
            for i in 0..<m {
                let rootOfUnity = rootOfUnityPowers[m &+ i]
                let j1 = 2 &* i &* t
                for j in j1..<j1 &+ t {
                    var x = dataPtr[j]
                    var y = dataPtr[j &+ t]
                    op(&x, &y)
                    (dataPtr[j], dataPtr[j &+ t]) = forwardButterfly(
                        x: x,
                        y: y,
                        rootOfUnity: rootOfUnity,
                        twiceModulus: twiceModulus,
                        lazyReductionCounter: lazyReductionCounter)
                }
            }
        }

        for log2m in 0..<n.log2 {
            let m = 1 &<< log2m
            let t = n &>> (log2m &+ 1)
            lazyReductionCounter &+= 2
            let timeToReduce = lazyReductionCounter > maxLazyReductionCounter
            if timeToReduce {
                if t == 1 {
                    lazyReductionCounter &-= 2
                } else {
                    lazyReductionCounter = 1
                }
            }
            switch (t, timeToReduce) {
            case (1, true):
                applyFinalStageOp(m: m) { x, _ in
                    x = x.subtractIfExceeds(twiceModulus)
                }
            case (1, false):
                applyFinalStageOp(m: m) { _, _ in }
            case (_, true):
                applyNonFinalStageOp(m: m, t: t) { x, _ in
                    x = modulusReduceFactor.reduce(x)
                }
            case (_, false):
                applyNonFinalStageOp(m: m, t: t) { _, _ in }
            }
        }
    }
}

/// Computes a lazy inverse NTT butterfly.
/// - Parameters:
///   - x: In `[0, kModulus)`.
///   - y: In `[0, kModulus)`.
///   - inverseRootOfUnity: Multiplication by an inverse root of unity `w^{-1}`, mod `modulus`.
///   - kModulus:  `k * modulus`.
/// - Returns: `(x + y mod modulus, w^{-1} (x - y) mod modulus)` in `[0, 2 * kModulus - 1]` and `[0, 2 * w^{-1} - 1]`.
/// - seealso: Algorithm 3 from <https://arxiv.org/pdf/1205.2926>.
@inlinable
func inverseButterfly<T: ScalarType>(
    x: T,
    y: T,
    inverseRootOfUnity: MultiplyConstantModulus<T>,
    kModulus: T) -> (T, T)
{
    assert(x < kModulus)
    assert(y < kModulus)

    let t = x &+ kModulus &- y
    let x = x &+ y
    let y = inverseRootOfUnity.multiplyModLazy(t)

    assert(x < 2 * kModulus)
    assert(y < 2 * inverseRootOfUnity.modulus)
    return (x, y)
}

extension PolyRq where F == Eval {
    /// Performs the inverse number-theoretic transform (NTT).
    /// - Returns: The ``Coeff`` representation of the polynomial.
    /// - Throws: Error upon failure to compute the inverse NTT.
    @inlinable
    public consuming func inverseNtt() throws -> PolyRq<T, Coeff> {
        try context.validateNttModuli()
        var currentContext: PolyContext<T>? = context
        while let context = currentContext {
            try inverseNtt(using: context)
            currentContext = context.next
        }
        return PolyRq<T, Coeff>(context: context, data: data)
    }

    /// Computes the inverse number-theoretic transform (NTT) on the last modulus in the context.
    /// - Parameter context: Context whose last modulus to use for the NTT.
    /// - Throws: Error upon failure to compute the inverse NTT.
    @inlinable
    mutating func inverseNtt(using context: PolyContext<T>) throws {
        // We modify Harvey's approach <https://arxiv.org/pdf/1205.2926> with delayed modular reduction.
        let moduli = context.moduli
        guard let modulus = moduli.last else {
            throw HeError.emptyModulus
        }
        let rnsIndex = moduli.count &- 1
        let n = degree

        let rowOffset = data.rowIndices(row: rnsIndex).first
        guard let rowOffset, let nttContext = context.nttContext
        else {
            throw HeError.invalidPolyContext(context)
        }
        let inverseRootOfUnityPowers = nttContext.inverseRootOfUnityPowers
        let inverseDegree = nttContext.inverseDegree
        let inverseDegreeRootOfUnity = nttContext.inverseDegreeRootOfUnity

        let modulusMultiplesCount = min(degree.log2 &+ 1, modulus.leadingZeroBitCount)
        let reduceModulus = context.reduceModuli[rnsIndex]

        var rootIdx = 1
        var lazyReductionCounter = -1
        let nDiv2 = n &>> 1
        // swiftlint:disable:next closure_body_length
        data.data.withUnsafeMutableBufferPointer { dataPtr in
            // swiftlint:disable:next force_unwrapping
            let dataPtr = dataPtr.baseAddress! + rowOffset

            for log2m in (0..<n.log2).reversed() {
                let m = 1 &<< log2m
                let t = n &>> (log2m &+ 1)
                lazyReductionCounter &+= 1
                let timeToReduce = lazyReductionCounter == modulusMultiplesCount
                if timeToReduce {
                    if m == 1 {
                        lazyReductionCounter &-= 1
                    } else {
                        lazyReductionCounter = 0
                    }
                }
                let kTimesModulus = modulus &<< lazyReductionCounter

                if m == 1 {
                    // Final stage, folding in multiplication by n^{-1} and modular reduction
                    func applyOp(_ op: (_ x: inout T, _ y: inout T) -> Void) {
                        for xIdx in 0..<nDiv2 {
                            let yIdx = xIdx &+ nDiv2
                            var x = dataPtr[xIdx]
                            var y = dataPtr[yIdx]
                            op(&x, &y)
                            let tx = x &+ y
                            let ty = x &+ kTimesModulus &- y
                            dataPtr[xIdx] = inverseDegree.multiplyMod(tx)
                            dataPtr[yIdx] = inverseDegreeRootOfUnity.multiplyMod(ty)
                        }
                    }

                    if timeToReduce {
                        applyOp { x, y in
                            x = x.subtractIfExceeds(kTimesModulus)
                            y = y.subtractIfExceeds(kTimesModulus)
                        }
                    } else {
                        applyOp { _, _ in }
                    }
                } else if t == 1 {
                    func applyOp(_ op: (_ x: inout T, _ y: inout T) -> Void) {
                        for i in 0..<m {
                            let inverseRootOfUnity = inverseRootOfUnityPowers[rootIdx &+ i]
                            let j1 = 2 &* i &* t
                            var x = dataPtr[j1]
                            var y = dataPtr[j1 &+ t]
                            op(&x, &y)
                            (dataPtr[j1], dataPtr[j1 &+ t]) = inverseButterfly(
                                x: x,
                                y: y,
                                inverseRootOfUnity: inverseRootOfUnity,
                                kModulus: kTimesModulus)
                        }
                    }
                    if timeToReduce {
                        applyOp { x, y in
                            x = reduceModulus.reduce(x)
                            y = reduceModulus.reduce(y)
                        }
                    } else {
                        applyOp { _, _ in }
                    }
                } else {
                    func applyOp(_ op: (_ x: inout T, _ y: inout T) -> Void) {
                        for i in 0..<m {
                            let inverseRootOfUnity = inverseRootOfUnityPowers[rootIdx &+ i]
                            let j1 = 2 &* i &* t
                            for j in j1..<(j1 &+ t) {
                                var x = dataPtr[j]
                                var y = dataPtr[j &+ t]
                                op(&x, &y)
                                (dataPtr[j], dataPtr[j &+ t]) = inverseButterfly(
                                    x: x,
                                    y: y,
                                    inverseRootOfUnity: inverseRootOfUnity,
                                    kModulus: kTimesModulus)
                            }
                        }
                    }
                    if timeToReduce {
                        applyOp { x, y in
                            x = reduceModulus.reduce(x)
                            y = reduceModulus.reduce(y)
                        }
                    } else {
                        applyOp { _, _ in }
                    }
                }
                rootIdx &+= m
            }
        }
    }
}
