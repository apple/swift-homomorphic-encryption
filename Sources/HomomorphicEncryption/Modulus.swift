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

/// Stores pre-computed data for efficient modular operations.
/// - Warning: The operations may leak the modulus through timing or other side channels. So this struct should only be
/// used for public moduli.
public struct Modulus<T: ScalarType>: Equatable, Sendable {
    /// The maximum valid modulus value.
    public static var max: T {
        ReduceModulus.max
    }

    /// Single-word modular reduction.
    @usableFromInline let singleWordModulus: ReduceModulus<T>
    /// Double-word modular reduction.
    @usableFromInline let doubleWordModulus: ReduceModulus<T>
    /// Modular multiplication reduction.
    @usableFromInline let reduceProductModulus: ReduceModulus<T>
    /// `ceil(2^k / modulus) - 2^(2 * T.bitWidth)` for
    /// `k = 2 * T.bitWidth + ceil(log2(modulus)`.
    @usableFromInline let divisionModulus: DivisionModulus<T>
    /// The modulus, `p`.
    public let modulus: T

    /// Initializes a ``Modulus``.
    /// - Parameters:
    ///   - modulus: Modulus. Must be less than ``Modulus/max``.
    ///   - variableTime: Must be `true`, indicating `modulus` is leaked through timing.
    /// - Warning: Leaks `modulus` through timing.
    @inlinable
    public init(modulus: T, variableTime: Bool) {
        precondition(variableTime)
        self.singleWordModulus = ReduceModulus(
            modulus: modulus,
            bound: ReduceModulus.InputBound.SingleWord,
            variableTime: true)
        self.doubleWordModulus = ReduceModulus(
            modulus: modulus,
            bound: ReduceModulus.InputBound.DoubleWord,
            variableTime: true)
        self.reduceProductModulus = ReduceModulus(
            modulus: modulus,
            bound: ReduceModulus.InputBound.ModulusSquared,
            variableTime: true)
        self.divisionModulus = DivisionModulus(modulus: modulus)
        self.modulus = modulus
    }

    /// Performs modular reduction with modulus `p`.
    /// - Parameter x: Value to reduce.
    /// - Returns: `x mod p` in `[0, p).`
    @inlinable
    public func reduce(_ x: T) -> T {
        singleWordModulus.reduce(x)
    }

    /// Performs modular reduction with modulus `p`.
    /// - Parameter x: Value to reduce.
    /// - Returns: `x mod p` in `[0, p).`
    @inlinable
    public func reduce(_ x: T.SignedScalar) -> T {
        singleWordModulus.reduce(x)
    }

    /// Performs modular reduction with modulus `p`.
    /// - Parameter x: Value to reduce.
    /// - Returns: `x mod p` in `[0, p).`
    @inlinable
    public func reduce(_ x: T.DoubleWidth) -> T {
        doubleWordModulus.reduce(x)
    }

    /// Performs modular reduction of a product with modulus `p`.
    /// - Parameter x: Must be in `[0, p^2)`.
    /// - Returns: `x mod p` in `[0, p).`
    @inlinable
    public func reduceProduct(_ x: T.DoubleWidth) -> T {
        reduceProductModulus.reduceProduct(x)
    }

    /// Performs modular multiplication with modulus `p`.
    /// - Parameters:
    ///   - x: Must be `< p`.
    ///   - y: Must be `< p`.
    /// - Returns: `x * y mod p`.
    @inlinable
    public func multiplyMod(_ x: T, _ y: T) -> T {
        precondition(x < modulus)
        precondition(y < modulus)
        let product = x.multipliedFullWidth(by: y)
        return reduceProduct(T.DoubleWidth(product))
    }

    /// Computes a division by the modulus and flooring.
    /// - Parameter dividend: Number to divide.
    /// - Returns: `dividend / modulus`, rounded down to the next integer.
    @inlinable
    public func dividingFloor(by dividend: T.DoubleWidth) -> T.DoubleWidth {
        divisionModulus.dividingFloor(by: dividend)
    }
}

/// Precomputation for constant-time division by a modulus.
@usableFromInline
struct DivisionModulus<T: ScalarType>: Equatable, Sendable {
    // See <https://en.wikipedia.org/wiki/Division_algorithm#Division_by_a_constant>

    @usableFromInline let modulus: T
    /// `ceil(2^k / modulus) - 2^(2 * T.bitWidth)` for
    /// `k = 2 * T.bitWidth + ceil(log2(modulus)`.
    @usableFromInline let factor: T.DoubleWidth

    /// Initializes a ``DivisionModulus``.
    /// - Parameter modulus: Modulus.
    /// - Warning: Leaks `modulus` through timing.
    @inlinable
    init(modulus: T) {
        self.modulus = modulus
        let k = T.bitWidth * 2 + modulus.ceilLog2
        // ceil(2^k / p) = floor(2^k / p) + (2^k % p) != 0
        let twoPowK = QuadWidth<T>(1) << k
        let twoPowKDivP = twoPowK.quotientAndRemainder(dividingBy: QuadWidth<T>(modulus))
        let increment = twoPowKDivP.remainder == 0 ? 0 : 1
        let ceil2PowKDivP = twoPowKDivP.quotient &+ QuadWidth<T>(increment)
        let twoPow2T = QuadWidth<T>(1) &<< (2 &* T.bitWidth)
        let diff = ceil2PowKDivP &- twoPow2T
        self.factor = T.DoubleWidth(diff.low)
    }

    /// Computes a division by the modulus and flooring.
    /// - Parameter dividend: Number to divide.
    /// - Returns: `dividend / modulus`, rounded down to the next integer.
    @inlinable
    func dividingFloor(by dividend: T.DoubleWidth) -> T.DoubleWidth {
        // For `T.BitWidth = 64`, we have pre-computed
        // `factor = ceil(2^k / p) - 2^128`, for `k = 128 + ceil(log2(p))`.
        // Now, we compute
        // `floor(x / p) = (((x - b) >> 1) + b) >> (ceil(log2(p)) - 1)`
        // where `b = (x * factor) >> 128`
        let b = factor.multipliedFullWidth(by: dividend).high
        let numerator = ((dividend &- b) &>> 1) &+ b
        let shift = modulus.ceilLog2 &- 1
        return numerator &>> shift
    }
}

/// Pre-computed factor for fast modular reduction.
@usableFromInline
struct ReduceModulus<T: ScalarType>: Equatable, Sendable {
    @usableFromInline
    enum InputBound {
        case SingleWord
        case DoubleWord
        case ModulusSquared
    }

    /// The maximum valid modulus value.
    @usableFromInline static var max: T {
        // Constrained by `reduceProduct` and `reduce(_ x: T.SignedScalar)`
        (T(1) << (T.bitWidth - 2)) - 1
    }

    /// Power used in computed Barrett factor.
    @usableFromInline let shift: Int
    /// Barrett factor.
    @usableFromInline let factor: T.DoubleWidth
    /// The modulus, `p`.
    @usableFromInline let modulus: T
    /// `modulus.previousPowerOfTwo`.
    @usableFromInline let modulusPreviousPowerOfTwo: T
    /// `round(2^{log2(p) - 1) * 2^{T.bitWidth} / p)`.
    @usableFromInline let signedFactor: T.SignedScalar

    /// Performs pre-computation for fast modular reduction.
    /// - Parameters:
    ///   - modulus: modulus for modular operations; leaked through timing.
    ///   - bound: Upper bound on modular reduction inputs.
    ///   - variableTime: Must be `true`, indicating `modulus` is leaked through timing.
    /// - Warning: Leaks `modulus` through timing.`
    @inlinable
    init(modulus: T, bound: InputBound, variableTime: Bool) {
        precondition(variableTime)
        precondition(modulus <= Self.max)
        self.modulus = modulus
        self.modulusPreviousPowerOfTwo = modulus.previousPowerOfTwo
        switch bound {
        case .SingleWord:
            self.shift = T.bitWidth
            // floor(2^T.bitwidth / p)
            self.factor = T.DoubleWidth((high: 1, low: 0)) / T.DoubleWidth(modulus)
            if modulus.isPowerOfTwo {
                // This should actually be `T.SignedScalar.max + 1`, but this works too.
                // See `reduce(_ x: T.SignedScalar)` for more information.
                self.signedFactor = T.SignedScalar.max
            } else {
                // We compute `round(2^{log2(p) - 1} * 2^{T.bitWidth} / p)` by noting
                // `2^{log2(p)} = q.previousPowerOfTwo`, and `round(x/p) = floor(x + floor(p/2) / p)`.
                let numerator = T.DoubleWidth((high: modulus.previousPowerOfTwo >> 1, low: T.Magnitude(modulus) >> 1))
                // Guaranteed to fit into single word, since `2^{log2(p) - 1) / p < 1/2` for `p` not a power of 2,
                // which implies `signedFactor < 2^{T.bitWidth} / 2`
                self.signedFactor = T.SignedScalar((numerator / T.DoubleWidth(modulus)).low)
            }

        case .DoubleWord:
            self.shift = 2 * T.bitWidth
            self.factor = if modulus.isPowerOfTwo {
                T.DoubleWidth(1) << (shift - modulus.log2)
            } else {
                // floor(2^{2 * t} / p) == floor((2^{2 * t} - 1) / p) for p not a power of two
                T.DoubleWidth.max / T.DoubleWidth(modulus)
            }
            self.signedFactor = 0 // Unused

        case .ModulusSquared:
            let reduceModulusAlpha = T.bitWidth - 2
            self.shift = modulus.significantBitCount + reduceModulusAlpha
            let numerator = T.DoubleWidth(1) << shift
            self.factor = numerator / T.DoubleWidth(modulus)
            self.signedFactor = 0 // Unused
        }
    }

    /// Returns `x mod p` using T.bitWidth-bit Barrett reduction.
    /// Proof of correctness:
    ///   Let `t = T.bitWidth`
    ///   * Let `b = floor(2^t / p)`.
    ///   * Let `q = floor(x * b / 2^t)`.
    ///   * We want to show `0 <= x - q * p < 2p`
    ///   * First, by definition of `b`, `0 <= 2^t / p - b < 1`. (1)
    ///   * Second, by definition of `q`, `0 <= x * b / 2^t - q < 1`. (2)
    ///   * Multiplying (1) by `x * p / 2^t` yields
    ///    `0 <= x - x * b * p / 2^t < x * p / 2^t`. (3)
    ///   * Multiplying (2) by `p` yields `0 <= x * p * b / 2^t - q * p < p` (4).
    ///   * Adding (3) and (4) yields `0 <= x - q * p < x * p / 2^t + p < 2 * p`.
    /// Note, the bound on `p < 2^t / 2` comes from `2 * p < 2^t`.
    @inlinable
    func reduce(_ x: T) -> T {
        assert(shift == T.bitWidth)
        let qHat = x.multiplyHigh(factor.low)
        let z = x &- qHat &* modulus
        return z.subtractIfExceeds(modulus)
    }

    /// Returns `x mod p` in `[0, p)` for signed integer `x`.
    ///
    /// Requires the modulus `p` to satisfy `p < 2^{T.bitWidth - 2}`.
    /// See Algorithm 5 from <https://eprint.iacr.org/2018/039.pdf>.
    /// The proof of Lemma 4 still goes through for odd moduli `q < 2^{T.bitWidth - 2}`, by using the bound
    /// `floor(2^k \beta / q) >= 2^k \beta / q - 1`, rather than
    /// `floor(2^k \beta / q) >= 2^k \beta / q - 1/2`.
    /// For a `q` a power of two, the `signedFactor` is off by one (`2^{T.bitWidth} - 1` instead of `2^{T.bitWidth}`),
    /// so we provide a quick proof of correctness in this case.
    /// Using notation from the proof of Lemma 4 of <https://eprint.iacr.org/2018/039.pdf>, and assuming `a >= 0`,
    /// we have `2^k = q / 2`, so `v = floor(2^k β / q) = β / 2`. Since we are using `v - 1` instead of `v`, we have
    /// `r = a - q * floor(a * (v - 1) / (2^k β))`. Using `floor(x) >= x - 1`, we have
    ///  `<= a - q * (a * (v - 1) / (2^k β)) + q`. Using  `v = β / 2` and `2^k = q / 2`, we have
    ///   `= a - q * (a β / 2 - a) / (β q / 2) + q`
    ///   `= a - a + q a / (β q / 2) + q`
    ///   `= a / (β / 2) + q`
    ///   `< 1 + q` for `a < β / 2`.
    /// Since we use `v - 1` instead of `v`, the result can only be larger than as Algorithm 5 is written.
    /// Hence, the lower bound `r > -1` from the proof of Lemma 4 still holds.
    /// Since `r < q + 1`, `r > -1`, and `r` is integral, we have `r in [0, q]`.
    /// The final `subtractIfExceeds` ensures `r in [0, q - 1]`.
    ///
    /// The proof follows analagously for `a < 0`.
    ///
    /// - Parameter x: Value to reduce.
    /// - Returns: `x mod p` in `[0, p)`.
    @inlinable
    func reduce(_ x: T.SignedScalar) -> T {
        assert(shift == T.bitWidth)
        var t = x.multiplyHigh(signedFactor) >> (modulus.log2 - 1)
        t = t &* T.SignedScalar(modulus)
        return T(x &- t).subtractIfExceeds(modulus)
    }

    /// Returns `x mod p`.
    ///
    /// Requires modulus `p < 2^{T.bitWidth - 1}`.
    /// Useful when `x >= p^2`, otherwise use `` reduceProduct``.
    /// Proof of correctness:
    ///   Let `t = T.bitWidth`
    ///     Let `b = floor(2^{2 * t} / p)`
    ///     Let `q = floor(x * b / 2^{2 * t}})`
    ///     We want to show `0 <= x - q * p < 2p`.
    ///     First, by definition of `b`, `0 <= 2^{2 * t} / p - b < 1`      (1)
    ///     Second, by definition of `q`, `0 <= x * b / 2^{2 * t} - q < 1` (2)
    ///     Multiplying (1) by `x * p / 2^{2 * t}` yields
    ///     `0 <= x - x * b * p / 2^{2 * t}} < x * p / 2^{2 * t}`        (3)
    ///     Multiplying (2) by `p` yields
    ///     `0 <= x * p * b / 2^{2 * t}} - q * p < p`                    (4)
    ///     Adding (3) and (4) yields
    ///     `0 <= x - q * p < x * p / 2^{2 * t} + p < 2 * p`.
    ///
    /// Note, the bound on `p < 2^{t - 1}` comes from `2 * p < 2^t`
    @inlinable
    func reduce(_ x: T.DoubleWidth) -> T {
        assert(shift == x.bitWidth)
        let qHat = x.multipliedFullWidth(by: factor)
        let qP = qHat.high &* T.DoubleWidth(modulus)
        let z = x &- qP
        return z.low.subtractIfExceeds(modulus)
    }

    /// Performs modular reduction of a product with modulus `p`.
    /// - Parameter x: Must be in `[0, p^2)`.
    /// - Returns: `x mod p` for `p`.
    @inlinable
    func reduceProduct(_ x: T.DoubleWidth) -> T {
        // Algorithm 2 from https://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
        assert(x < T.DoubleWidth(modulus.multipliedFullWidth(by: modulus)))
        let n = modulus.significantBitCount
        let reduceModulusBeta = -2
        let nPlusBeta = n &+ reduceModulusBeta
        let xShift = x &>> nPlusBeta
        assert(xShift <= T.max)
        assert(xShift.high == 0)
        let qHat = xShift.low.multipliedFullWidth(by: factor.low).high
        let z = x.low &- qHat &* modulus
        return z.subtractIfExceeds(modulus)
    }

    /// Performs modular multiplication with modulus `p`.
    /// - Parameters:
    ///   - x: Must be `< p`.
    ///   - y: Must be `< p`.
    /// - Returns: `x * y mod p`.
    @inlinable
    func multiplyMod(_ x: T, _ y: T) -> T {
        precondition(x < modulus)
        precondition(y < modulus)
        let product = x.multipliedFullWidth(by: y)
        return reduceProduct(T.DoubleWidth(product))
    }
}

/// A modulus for multiplication with a constant.
@usableFromInline
struct MultiplyConstantModulus<T: ScalarType>: Sendable {
    @usableFromInline let multiplicand: T
    @usableFromInline let modulus: T
    @usableFromInline let factor: T /// Barrett factor.

    @inlinable
    init(multiplicand: T, modulus: T, factor: T) {
        self.multiplicand = multiplicand
        self.modulus = modulus
        self.factor = factor
    }

    /// Initializes a ``MultiplyConstantModulus``.
    /// - Parameters:
    ///   - multiplicand: Multiplicand. Must be `< modulus`
    ///   - modulus: Modulus. Leaked through timing.
    ///   - variableTime: If `true`, indicates the multiplicand may be leaked through timing.
    /// - Warning: Leaks `modulus` and, if `variableTime` is true, `multiplicand` through timing.
    @inlinable
    init(multiplicand: T, modulus: T, variableTime: Bool) {
        assert(multiplicand < modulus)
        if variableTime {
            self.init(
                multiplicand: multiplicand,
                modulus: modulus,
                factor: modulus.dividingFullWidth((high: multiplicand, low: 0)).quotient)
        } else {
            let divisionModulus = DivisionModulus(modulus: modulus)
            self.init(multiplicand: multiplicand, divisionModulus: divisionModulus)
        }
    }

    @inlinable
    init(multiplicand: T, divisionModulus: DivisionModulus<T>) {
        // multiplicand << T.bitWidth
        let dividend = T.DoubleWidth((high: multiplicand, low: 0))
        self.init(
            multiplicand: multiplicand,
            modulus: divisionModulus.modulus,
            factor: divisionModulus.dividingFloor(by: dividend).low)
    }

    @inlinable
    func multiplyModLazy(_ rhs: T) -> T {
        let q = rhs.multiplyHigh(factor)
        let prod = rhs &* multiplicand
        let qModulus = q &* modulus
        // We know prod - q * modulus < 2 * modulus.
        // Since modulus < 2^63, it suffices to compute only the low 64 bits of the result
        let result = prod &- qModulus
        assert(result < (modulus << 1))
        return result
    }

    @inlinable
    func multiplyMod(_ rhs: T) -> T {
        multiplyModLazy(rhs).subtractIfExceeds(modulus)
    }
}

/// A modulus for multiplication by an array of constants.
@usableFromInline
struct MultiplyConstantArrayModulus<T: ScalarType>: Sendable {
    @usableFromInline let multiplicands: [T]
    @usableFromInline let factors: [T]
    @usableFromInline let modulus: T

    /// Initializes a ``MultiplyConstantArrayModulus``.
    /// - Parameters:
    ///   - multiplicands: Multiplicands.
    ///   - modulus: Modulus.
    ///   - variableTime: Whether or not `multiplicands` or `modulus` may be leaked through timing.
    /// - Warning: May leak `multiplicands` and `modulus` through timing.
    @inlinable
    init(multiplicands: [T], modulus: T, variableTime: Bool) {
        assert(multiplicands.allSatisfy { $0 < modulus })
        self.multiplicands = multiplicands
        self.factors = multiplicands.map { multiplicand in MultiplyConstantModulus(
            multiplicand: multiplicand,
            modulus: modulus,
            variableTime: variableTime).factor
        }
        self.modulus = modulus
    }

    @inlinable
    subscript(index: Int) -> MultiplyConstantModulus<T> {
        factors.withUnsafeBufferPointer { factorPtr in
            multiplicands.withUnsafeBufferPointer { multiplicandsPtr in
                MultiplyConstantModulus(
                    multiplicand: multiplicandsPtr[index],
                    modulus: modulus,
                    factor: factorPtr[index])
            }
        }
    }
}
