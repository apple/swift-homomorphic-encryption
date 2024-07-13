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

/// Represents a polynomial in `R_q = Z_q(X)^N / (X^N + 1)` for `N` a power of
/// two and `q` a (possibly) multi-word integer.
///
/// The number-theoretic transform is used for efficient arithmetic.
public struct PolyRq<T: ScalarType, F: PolyFormat>: Equatable, Sendable {
    /// Context for the polynomial.
    @usableFromInline var context: PolyContext<T>
    /// Residue number system (RNS) decomposition of each coefficient.
    ///
    /// Coefficients are stored in coefficient-major order. That is, `data[rns_index, coeff_index]` stores the
    /// `coeff_index`'th coefficient mod `q_{rns_index}.`
    public var data: Array2d<T>

    @inlinable
    init(context: PolyContext<T>, data: Array2d<T>) {
        precondition(context.degree == data.columnCount)
        precondition(context.moduli.count == data.rowCount)
        self.context = context
        self.data = data
        assert(isValidData())
    }

    @inlinable subscript(_ index: Int) -> T {
        get {
            data[index]
        }
        set {
            data[index] = newValue
        }
    }
}

extension PolyRq: PolyCollection {
    @inlinable
    public func polyContext() -> PolyContext<T> {
        context
    }
}

// MARK: computed properties

extension PolyRq {
    @inlinable public var coeffIndices: Range<Int> {
        0..<data.columnCount
    }

    @inlinable public var rnsIndices: Range<Int> {
        0..<data.rowCount
    }
}

extension PolyRq {
    @inlinable
    func validateMetadataEquality(with other: Self) {
        precondition(context == other.context)
        precondition(data.rowCount == other.data.rowCount)
        precondition(data.columnCount == other.data.columnCount)
    }

    @inlinable
    public func isValidData() -> Bool {
        for (rnsIndex, modulus) in moduli.enumerated() {
            for index in data.rowIndices(row: rnsIndex) {
                guard data[index] < modulus else {
                    return false
                }
            }
        }

        return true
    }

    @inlinable
    func polyIndices(rnsIndex: Int) -> Range<Int> {
        data.rowIndices(row: rnsIndex)
    }

    @inlinable
    public func rnsIndices(coeffIndex: Int) -> StrideTo<Int> {
        data.columnIndices(column: coeffIndex)
    }

    @inlinable
    public func poly(rnsIndex: Int) -> [T] {
        data.row(row: rnsIndex)
    }

    @inlinable
    func coefficient(coeffIndex: Int) -> [T] {
        data.collectValues(indices: rnsIndices(coeffIndex: coeffIndex))
    }
}

extension PolyRq {
    /// Initialize a Polynomial with all coefficients set to zero.
    ///
    /// - Parameter context: Context which the polynomial will have.
    /// - Returns: The zero polynomial.
    @inlinable
    public static func zero(context: PolyContext<T>) -> Self {
        let degree = context.degree
        let moduliCount = context.moduli.count
        let zeroes = Array2d(
            data: Array(repeating: T.zero, count: degree * moduliCount),
            rowCount: moduliCount,
            columnCount: degree)
        return Self(context: context, data: zeroes)
    }

    // MARK: Arithmetic operators

    @inlinable
    public static func += (_ lhs: inout Self, _ rhs: Self) {
        lhs.validateMetadataEquality(with: rhs)

        lhs.data.data.withUnsafeMutableBufferPointer { lhsData in
            rhs.data.data.withUnsafeBufferPointer { rhsData in
                for (rnsIndex, modulus) in rhs.moduli.enumerated() {
                    for index in rhs.polyIndices(rnsIndex: rnsIndex) {
                        lhsData[index] = lhsData[index].addMod(rhsData[index], modulus: modulus)
                    }
                }
            }
        }
    }

    @inlinable
    public static func -= (_ lhs: inout Self, _ rhs: Self) {
        lhs.validateMetadataEquality(with: rhs)

        lhs.data.data.withUnsafeMutableBufferPointer { lhsData in
            rhs.data.data.withUnsafeBufferPointer { rhsData in
                for (rnsIndex, modulus) in rhs.moduli.enumerated() {
                    for index in rhs.polyIndices(rnsIndex: rnsIndex) {
                        lhsData[index] = lhsData[index].subtractMod(rhsData[index], modulus: modulus)
                    }
                }
            }
        }
    }

    /// Computes `lhs *= secretPoly`.
    /// - Parameters:
    ///   - lhs: Polynomial to multiply.
    ///   - secretPoly: Secret key polynomial. May have context which
    /// is a parent context of `lhs.context`.
    /// > Note: `secretPoly` will not be copied or change size, so this functions is suitable for use
    /// with sensitive polynomials.
    @inlinable
    public static func mulAssign(_ lhs: inout Self, secretPoly: borrowing Self) where F == Eval {
        let context = lhs.context
        precondition(secretPoly.context.isParentOfOrEqual(to: context))
        lhs.data.data.withUnsafeMutableBufferPointer { lhsData in
            secretPoly.data.data.withUnsafeBufferPointer { rhsData in
                for (rnsIndex, modulus) in context.reduceModuli.enumerated() {
                    for index in secretPoly.polyIndices(rnsIndex: rnsIndex) {
                        lhsData[index] = modulus.multiplyMod(lhsData[index], rhsData[index])
                    }
                }
            }
        }
    }

    @inlinable
    public static func *= (_ lhs: inout Self, _ rhs: Self) where F == Eval {
        lhs.validateMetadataEquality(with: rhs)
        mulAssign(&lhs, secretPoly: rhs)
    }

    /// Computes `accumulator += lhs * rhs` without modular reduction.
    ///
    /// - Warning: Doesn't check for overflow.
    @inlinable
    public static func addingLazyProduct(_ lhs: Self, _ rhs: Self, to accumulator: inout Array2d<T.DoubleWidth>)
        where F == Eval
    {
        precondition(accumulator.shape == rhs.data.shape)
        lhs.validateMetadataEquality(with: rhs)

        lhs.data.data.withUnsafeBufferPointer { lhsData in
            rhs.data.data.withUnsafeBufferPointer { rhsData in
                accumulator.data.withUnsafeMutableBufferPointer { accumulatorPtr in
                    for rnsIndex in rhs.moduli.indices {
                        for index in rhs.polyIndices(rnsIndex: rnsIndex) {
                            accumulatorPtr[index] &+=
                                T.DoubleWidth(lhsData[index].multipliedFullWidth(by: rhsData[index]))
                        }
                    }
                }
            }
        }
    }

    /// Computes `lhs *= rhs` for `rhs` a scalar in RNS form.
    /// - Parameters:
    ///   - lhs: Polynomial; will store the product.
    ///   - rhs: A scalar in RNS form, i.e., `rhs[i] = y mod q_i` for scalar `y`.
    @inlinable
    public static func *= (_ lhs: inout Self, _ rhs: [T]) {
        precondition(lhs.moduli.count == rhs.count)

        for ((rnsIndex, modulus), rhsResidue) in zip(lhs.reduceModuli.enumerated(), rhs) {
            let multiplicationModulus = MultiplyConstantModulus(
                multiplicand: rhsResidue,
                divisionModulus: modulus.divisionModulus)
            let polyIndices = lhs.polyIndices(rnsIndex: rnsIndex)
            lhs.data.data.withUnsafeMutableBufferPointer { lhsData in
                for index in polyIndices {
                    lhsData[index] = multiplicationModulus.multiplyMod(lhsData[index])
                }
            }
        }
    }

    @inlinable
    public static func + (_ lhs: Self, _ rhs: Self) -> Self {
        var result = lhs
        result += rhs
        return result
    }

    @inlinable
    public static func - (_ lhs: Self, _ rhs: Self) -> Self {
        var result = lhs
        result -= rhs
        return result
    }

    @inlinable
    public static func * (_ lhs: Self, _ rhs: Self) -> Self where F == Eval {
        var result = lhs
        result *= rhs
        return result
    }

    @inlinable
    public static func * (_ lhs: Self, _ rhs: [T]) -> Self {
        var result = lhs
        result *= rhs
        return result
    }

    @inlinable
    public static prefix func - (_ rhs: Self) -> Self {
        var result = Self.zero(context: rhs.context)
        result.data.data.withUnsafeMutableBufferPointer { resultData in
            rhs.data.data.withUnsafeBufferPointer { rhsData in
                for (rnsIndex, modulus) in rhs.moduli.enumerated() {
                    for index in rhs.polyIndices(rnsIndex: rnsIndex) {
                        resultData[index] = rhsData[index].negateMod(modulus: modulus)
                    }
                }
            }
        }

        return result
    }

    @inlinable
    public mutating func dropContext(to context: PolyContext<T>) throws {
        if self.context == context {
            return
        }
        guard self.context.isParent(of: context) else {
            throw HeError.invalidPolyContext(context)
        }
        self.context = context
        if data.rowCount > moduli.count {
            data.removeLastRows(data.rowCount - moduli.count)
        }
    }

    @inlinable
    func checkContext(_ context: PolyContext<T>) throws {
        guard self.context == context else {
            throw HeError.polyContextMismatch(got: self.context, expected: context)
        }
    }

    /// Computes whether the polynomial has all zero coefficients.
    /// - Parameter variableTime: Must be `true`, indicating the coefficients of the polynomial are leaked through
    /// runtime.
    /// - Returns: Whether the polynomial is zero.
    /// - Warning: Leaks `self` through timing.
    @inlinable
    public func isZero(variableTime: Bool) -> Bool {
        precondition(variableTime)
        return data.data.allSatisfy { coefficient in coefficient == 0 }
    }

    /// Clears the memory in the polynomial.
    @inlinable
    public mutating func zeroize() {
        data.zeroize()
    }
}

extension PolyRq where F == Coeff {
    /// Divides and rounds each coefficient by the last modulus in the chain,
    /// then drops the last modulus.
    ///
    /// This polynomial must have a next context.
    /// - throws: Error upon failure to perform division and rounding.
    /// - seealso: Algorithm 8 of <https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9395438>,
    /// Algorithm 2 of <https://eprint.iacr.org/2018/931.pdf> for more details.
    @inlinable
    mutating func divideAndRoundQLast() throws {
        guard let newContext = context.next else {
            throw HeError.invalidPolyContext(context)
        }
        guard let qLast = context.moduli.last else {
            throw HeError.emptyModulus
        }

        // Add `q_last  >> 1` to change from flooring to rounding
        var dataLast = data.row(row: context.moduli.count - 1)
        data.removeLastRows(1)
        let qLastDiv2 = qLast >> 1
        for coeff in dataLast.indices {
            dataLast[coeff] = dataLast[coeff].addMod(qLastDiv2, modulus: qLast)
        }

        for (rnsIndex, (qLastModQi, qi)) in zip(context.inverseQLast, newContext.reduceModuli)
            .enumerated()
        {
            let qLastDiv2ModQi = qi.reduce(qLastDiv2)
            for (coeffIndex, dataIndex) in polyIndices(rnsIndex: rnsIndex).enumerated() {
                let tmp = qi.reduce(dataLast[coeffIndex])
                let coeff = data[dataIndex].addMod(qLastDiv2ModQi, modulus: qi.modulus)
                    .subtractMod(tmp, modulus: qi.modulus)
                data[dataIndex] = qLastModQi.multiplyMod(coeff)
            }
        }
        context = newContext
    }
}

extension PolyRq where F == Coeff {
    @inlinable
    mutating func multiplyInversePowerOfX(_ power: Int) throws {
        precondition(power >= 0)
        let effectiveStep = power % (degree &<< 1)
        if effectiveStep == 0 {
            return
        }
        try data.rotate(range: degree, step: effectiveStep)
        for (rowIndex, modulus) in moduli.enumerated() {
            if effectiveStep < degree {
                for columnIndex in degree &- effectiveStep..<degree {
                    data[rowIndex, columnIndex] = data[rowIndex, columnIndex].negateMod(modulus: modulus)
                }
            } else {
                for columnIndex in 0..<(degree &<< 1) &- effectiveStep {
                    data[rowIndex, columnIndex] = data[rowIndex, columnIndex].negateMod(modulus: modulus)
                }
            }
        }
    }
}

extension PolyRq {
    @inlinable
    public func convertToCoeff() throws -> PolyRq<T, Coeff> {
        switch F.self {
        case is Coeff.Type:
            guard let poly = self as? PolyRq<T, Coeff> else {
                throw HeError.errorInSameFormatCasting(F.self, Coeff.self)
            }
            return poly
        default:
            guard let poly = self as? PolyRq<T, Eval> else {
                throw HeError.errorInSameFormatCasting(F.self, Eval.self)
            }
            return try poly.inverseNtt()
        }
    }

    @inlinable
    public func convertToEval() throws -> PolyRq<T, Eval> {
        switch F.self {
        case is Coeff.Type:
            guard let poly = self as? PolyRq<T, Coeff> else {
                throw HeError.errorInSameFormatCasting(F.self, Coeff.self)
            }
            return try poly.forwardNtt()
        default:
            guard let poly = self as? PolyRq<T, Eval> else {
                throw HeError.errorInSameFormatCasting(F.self, Eval.self)
            }
            return poly
        }
    }

    @inlinable
    public func convertFormat<Format: PolyFormat>() throws -> PolyRq<T, Format> {
        switch Format.self {
        case is Coeff.Type:
            guard let poly = try convertToCoeff() as? PolyRq<T, Format> else {
                throw HeError.errorInSameFormatCasting(Format.self, F.self)
            }
            return poly
        case is Eval.Type:
            guard let poly = try convertToEval() as? PolyRq<T, Format> else {
                throw HeError.errorInSameFormatCasting(Format.self, F.self)
            }
            return poly
        default:
            guard let poly = self as? PolyRq<T, Format> else {
                throw HeError.errorInSameFormatCasting(Format.self, F.self)
            }
            return poly
        }
    }
}
