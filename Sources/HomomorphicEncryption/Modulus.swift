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
@usableFromInline
struct Modulus<T: ScalarType>: Equatable, Sendable {
    /// The maximum valid modulus value.
    @usableFromInline static var max: T {
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
    @usableFromInline let modulus: T

    /// Initializes a ``Modulus``.
    /// - Parameters:
    ///   - modulus: Modulus.
    ///   - variableTime: Must be `true`, indicating `modulus` is leaked through timing.
    /// - Warning: Leaks `modulus` through timing.
    @inlinable
    init(modulus: T, variableTime: Bool) {
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

    @inlinable
    func reduce(_ x: T) -> T {
        singleWordModulus.reduce(x)
    }

    @inlinable
    func reduce(_ x: T.DoubleWidth) -> T {
        doubleWordModulus.reduce(x)
    }

    /// Performs modular reduction with modulus `p`.
    /// - Parameter x: Must be `< p^2`.
    /// - Returns: `x mod p` for `p`.
    @inlinable
    func reduceProduct(_ x: T.DoubleWidth) -> T {
        reduceProductModulus.reduceProduct(x)
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

    /// Computes a division by the modulus and flooring.
    /// - Parameter dividend: Number to divide.
    /// - Returns: `dividend / modulus`, rounded down to the next integer.
    @inlinable
    func dividingFloor(by dividend: T.DoubleWidth) -> T.DoubleWidth {
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
        // Constrained by `reduceProduct`
        (T(1) << (T.bitWidth - 2)) - 1
    }

    /// Power used in computed Barrett factor.
    @usableFromInline let shift: Int
    /// Barrett factor.
    @usableFromInline let factor: T.DoubleWidth
    @usableFromInline let modulus: T

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
        switch bound {
        case .SingleWord:
            self.shift = T.bitWidth
            let numerator = T.DoubleWidth(1) << shift
            // 2^T.bitwidth // p
            self.factor = numerator / T.DoubleWidth(modulus)
        case .DoubleWord:
            self.shift = 2 * T.bitWidth
            self.factor = if modulus.isPowerOfTwo {
                T.DoubleWidth(1) << (shift - modulus.log2)
            } else {
                // floor(2^{2 * t} / p) == floor((2^{2 * t} - 1) / p) for p not a power of two
                T.DoubleWidth.max / T.DoubleWidth(modulus)
            }
        case .ModulusSquared:
            let reduceModulusAlpha = T.bitWidth - 2
            self.shift = modulus.significantBitCount + reduceModulusAlpha
            let numerator = T.DoubleWidth(1) << shift
            self.factor = numerator / T.DoubleWidth(modulus)
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

    /// Returns `x mod p`.
    ///
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
    /// Note, the bound on `p < 2^63` comes from `2 * p < T.max`
    @inlinable
    func reduce(_ x: T.DoubleWidth) -> T {
        assert(shift == x.bitWidth)
        let qHat = x.multipliedFullWidth(by: factor)
        let qP = qHat.high &* T.DoubleWidth(modulus)
        let z = x &- qP
        return z.low.subtractIfExceeds(modulus)
    }

    /// Performs modular reduction with modulus `p`.
    /// - Parameter x: Must be `< p^2`.
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
        let qHat = T(xShift).multipliedFullWidth(by: factor.low).high
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
