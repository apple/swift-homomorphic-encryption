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

extension Modulus {
    /// Initializes a ``Modulus``.
    /// - Parameters:
    ///   - modulus: Modulus. Must be less than `Modulus/max`
    ///   - variableTime: Must be `true`, indicating `modulus` is leaked through timing.
    /// - Warning: Leaks `modulus` through timing.
    @inlinable
    public init(modulus: T, variableTime: Bool) {
        precondition(variableTime)
        let singleWordModulus = ReduceModulus(
            modulus: modulus,
            bound: ReduceModulus.InputBound.SingleWord,
            variableTime: true)
        let doubleWordModulus = ReduceModulus(
            modulus: modulus,
            bound: ReduceModulus.InputBound.DoubleWord,
            variableTime: true)
        let reduceProductModulus = ReduceModulus(
            modulus: modulus,
            bound: ReduceModulus.InputBound.ModulusSquared,
            variableTime: true)
        let divisionModulus = DivisionModulus(modulus: modulus)
        self.init(
            modulus: modulus,
            singleWordModulus: singleWordModulus,
            doubleWordModulus: doubleWordModulus,
            reduceProductModulus: reduceProductModulus,
            divisionModulus: divisionModulus)
    }
}

extension DivisionModulus {
    /// Initializes a ``DivisionModulus``.
    /// - Parameter modulus: Modulus.
    /// - Warning: Leaks `modulus` through timing.
    @inlinable
    public init(modulus: T) {
        let doubleFactor: T.DoubleWidth
        let singleFactor: T
        // compute doubleFactor
        do {
            let k = 2 * T.bitWidth + modulus.ceilLog2
            // ceil(2^k / p) = floor(2^k / p) + (2^k % p) != 0
            let twoPowK = QuadWidth<T>(1) << k
            let twoPowKDivP = twoPowK.quotientAndRemainder(dividingBy: QuadWidth<T>(modulus))
            let increment = twoPowKDivP.remainder == 0 ? 0 : 1
            let ceil2PowKDivP = twoPowKDivP.quotient &+ QuadWidth<T>(increment)
            let twoPow2T = QuadWidth<T>(1) &<< (2 &* T.bitWidth)
            let diff = ceil2PowKDivP &- twoPow2T
            doubleFactor = T.DoubleWidth(diff.low)
        }
        // compute singleFactor
        do {
            let k = T.bitWidth + modulus.ceilLog2
            // ceil(2^k / p) = floor(2^k / p) + (2^k % p) != 0
            let twoPowK = T.DoubleWidth(1) &<< k
            let twoPowKDivP = twoPowK.quotientAndRemainder(dividingBy: T.DoubleWidth(modulus))
            let increment = twoPowKDivP.remainder == 0 ? 0 : 1
            let ceil2PowKDivP = T.DoubleWidth(twoPowKDivP.quotient) + T.DoubleWidth(increment)
            let twoPowT = T.DoubleWidth(1) &<< T.bitWidth
            let diff = ceil2PowKDivP &- twoPowT
            singleFactor = diff.low
        }
        self.init(modulus: modulus, singleFactor: singleFactor, doubleFactor: doubleFactor)
    }
}

extension MultiplyConstantModulus {
    /// Initializes a ``MultiplyConstantModulus``.
    /// - Parameters:
    ///   - multiplicand: Multiplicand. Must be `< modulus`
    ///   - modulus: Modulus. Leaked through timing.
    ///   - variableTime: If `true`, indicates the multiplicand may be leaked through timing.
    /// - Warning: Leaks `modulus` and, if `variableTime` is true, `multiplicand` through timing.
    @inlinable
    public init(multiplicand: T, modulus: T, variableTime: Bool) {
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
}

extension MultiplyConstantArrayModulus {
    /// Initializes a ``MultiplyConstantArrayModulus``.
    /// - Parameters:
    ///   - multiplicands: Multiplicands.
    ///   - modulus: Modulus.
    ///   - variableTime: Whether or not `multiplicands` or `modulus` may be leaked through timing.
    /// - Warning: May leak `multiplicands` and `modulus` through timing.
    @inlinable
    public init(multiplicands: [T], modulus: T, variableTime: Bool) {
        assert(multiplicands.allSatisfy { $0 < modulus })
        let factors = multiplicands.map { multiplicand in
            MultiplyConstantModulus(
                multiplicand: multiplicand,
                modulus: modulus,
                variableTime: variableTime).factor
        }
        self.init(multiplicands: multiplicands, factors: factors, modulus: modulus)
    }
}
