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

/// Represents a polynomial in `R_q = Z_q[X] / (X^N + 1)` for `N` a power of
/// two and `q` a (possibly) multi-word integer.
///
/// The number-theoretic transform is used for efficient arithmetic.
public struct PolyRq<T: ScalarType, F: PolyFormat>: Equatable, Sendable {
    /// Context for the polynomial.
    public var context: PolyContext<T>
    /// Residue number system (RNS) decomposition of each coefficient.
    ///
    /// Coefficients are stored in coefficient-major order. That is, `data[rns_index, coeff_index]` stores the
    /// `coeff_index`'th coefficient mod `q_{rns_index}.`
    public var data: Array2d<T>

    @inlinable
    public init(context: PolyContext<T>, data: Array2d<T>) {
        precondition(context.degree == data.columnCount)
        precondition(context.moduli.count == data.rowCount)
        self.context = context
        self.data = data
        assert(hasValidData())
    }

    @inlinable
    func index(rnsIndex: Int, coeffIndex: Int) -> Int {
        data.index(row: rnsIndex, column: coeffIndex)
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
    /// Indices of the polynomial coefficients.
    @inlinable public var coeffIndices: Range<Int> {
        0..<data.columnCount
    }

    /// Indices of the RNS moduli.
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

    /// Returns true if the polynomial data is valid for its ``PolyContext``, false otherwise.
    @inlinable
    public func hasValidData() -> Bool {
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
    func rnsIndices(coeffIndex: Int) -> StrideTo<Int> {
        data.columnIndices(column: coeffIndex)
    }

    /// Returns a polynomial's coefficients mod a RNS modulus.
    /// - Parameter rnsIndex: The index of the RNS modulus.
    /// - Returns: The coefficients mod `rnsIndex`.
    @inlinable
    public func poly(rnsIndex: Int) -> [T] {
        data.row(rnsIndex)
    }

    /// Returns a polynomial's coefficient RNS residues.
    /// - Parameter coeffIndex: Coefficient index; must be in `0..<context.degree`
    /// - Returns: The polynomial's coefficient in RNS form, i.e. mod `q_0, ..., q_{L-1}`.
    @inlinable
    public func coefficient(coeffIndex: Int) -> [T] {
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

    /// In-place polynomial addition: `lhs += rhs`.
    /// - Parameters:
    ///   - lhs: Polynomial to add to. Will store the sum.
    ///   - rhs: Polynomial to add.
    @inlinable
    public static func += (_ lhs: inout Self, _ rhs: Self) {
        lhs.validateMetadataEquality(with: rhs)

        var lhsData = lhs.data.data.mutableSpan
        let rhsData = rhs.data.data.span
        for (rnsIndex, modulus) in rhs.moduli.enumerated() {
            for index in rhs.polyIndices(rnsIndex: rnsIndex) {
                lhsData[index] = lhsData[index].addMod(rhsData[index], modulus: modulus)
            }
        }
    }

    /// In-place polynomial subtraction: `lhs -= rhs`.
    /// - Parameters:
    ///   - lhs: Polynomial to subtract from. Will store the difference.
    ///   - rhs: Polynomial to subtract.
    @inlinable
    public static func -= (_ lhs: inout Self, _ rhs: Self) {
        lhs.validateMetadataEquality(with: rhs)

        var lhsData = lhs.data.data.mutableSpan
        let rhsData = rhs.data.data.span
        for (rnsIndex, modulus) in rhs.moduli.enumerated() {
            for index in rhs.polyIndices(rnsIndex: rnsIndex) {
                lhsData[index] = lhsData[index].subtractMod(rhsData[index], modulus: modulus)
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
    static func mulAssign(_ lhs: inout Self, secretPoly: borrowing Self) where F == Eval {
        let context = lhs.context
        assert(secretPoly.context.isParentOfOrEqual(to: context))
        var lhsData = lhs.data.data.mutableSpan
        let rhsData = secretPoly.data.data.span
        for (rnsIndex, modulus) in context.reduceModuli.enumerated() {
            for index in secretPoly.polyIndices(rnsIndex: rnsIndex) {
                lhsData[index] = modulus.multiplyMod(lhsData[index], rhsData[index])
            }
        }
    }

    /// In-place polynomial multiplication: `lhs *= rhs`.
    /// - Parameters:
    ///   - lhs: Polynomial to multiply. Will store the product.
    ///   - rhs: Polynomial to multiply.
    @inlinable
    public static func *= (_ lhs: inout Self, _ rhs: Self) where F == Eval {
        lhs.validateMetadataEquality(with: rhs)
        mulAssign(&lhs, secretPoly: rhs)
    }

    /// Computes `accumulator += lhs * rhs` without modular reduction.
    ///
    /// - Warning: Doesn't check for overflow.
    @inlinable
    static func addingLazyProduct(_ lhs: Self, _ rhs: Self, to accumulator: inout Array2d<T.DoubleWidth>)
        where F == Eval
    {
        precondition(accumulator.shape == rhs.data.shape)
        lhs.validateMetadataEquality(with: rhs)

        let lhsData = lhs.data.data.span
        let rhsData = rhs.data.data.span
        var accumulatorSpan = accumulator.data.mutableSpan
        for rnsIndex in rhs.moduli.indices {
            for index in rhs.polyIndices(rnsIndex: rnsIndex) {
                accumulatorSpan[index] &+=
                    T.DoubleWidth(lhsData[index].multipliedFullWidth(by: rhsData[index]))
            }
        }
    }

    /// Computes `poly *= scalarResidues` for `scalarResidues` a scalar in RNS form.
    /// - Parameters:
    ///   - poly: Polynomial; will store the product.
    ///   - scalarResidues: A scalar in RNS form, i.e., `scalarResidues[i] = y mod q_i` for scalar `y`.
    @inlinable
    public static func *= (_ poly: inout Self, _ scalarResidues: [T]) {
        precondition(poly.moduli.count == scalarResidues.count)

        for ((rnsIndex, modulus), rhsResidue) in zip(poly.reduceModuli.enumerated(), scalarResidues) {
            let multiplicationModulus = MultiplyConstantModulus(
                multiplicand: rhsResidue,
                divisionModulus: modulus.divisionModulus)
            let polyIndices = poly.polyIndices(rnsIndex: rnsIndex)
            var lhsData = poly.data.data.mutableSpan
            for index in polyIndices {
                lhsData[index] = multiplicationModulus.multiplyMod(lhsData[index])
            }
        }
    }

    /// Polynomial addition: `lhs + rhs`.
    /// - Parameters:
    ///   - lhs: Polynomial to add. Must have the same ``PolyContext`` as `rhs`.
    ///   - rhs: Polynomial to add. Must have the same ``PolyContext`` as `lhs`.
    /// - Returns: The sum `lhs + rhs`.
    @inlinable
    public static func + (_ lhs: Self, _ rhs: Self) -> Self {
        var result = lhs
        result += rhs
        return result
    }

    /// Polynomial subtraction: `lhs - rhs`.
    /// - Parameters:
    ///   - lhs: Polynomial to subtract from. Must have the same ``PolyContext`` as `rhs`.
    ///   - rhs: Polynomial to subtract. Must have the same ``PolyContext`` as `lhs`.
    /// - Returns: The difference `lhs - rhs`.
    @inlinable
    public static func - (_ lhs: Self, _ rhs: Self) -> Self {
        var result = lhs
        result -= rhs
        return result
    }

    /// Polynomial multiplication: `lhs * rhs`.
    /// - Parameters:
    ///   - lhs: Polynomial to multiply. Must have the same ``PolyContext`` as `rhs`.
    ///   - rhs: Polynomial to multiply. Must have the same ``PolyContext`` as `lhs`.
    /// - Returns: The product `lhs * rhs`.
    @inlinable
    public static func * (_ lhs: Self, _ rhs: Self) -> Self where F == Eval {
        var result = lhs
        result *= rhs
        return result
    }

    /// Polynomial multiplication with a scalar: `self * scalar`.
    /// - Parameters:
    ///   - poly: Polynomial to multiply.
    ///   - scalarResidues: Scalar multiplicand in RNS form, i.e., mod `q_0, ..., q{L-1}`.
    /// - Returns: The polynomial product: `self * scalar`.
    @inlinable
    public static func * (_ poly: Self, _ scalarResidues: [T]) -> Self {
        var result = poly
        result *= scalarResidues
        return result
    }

    /// Polynomial negation: `-poly`.
    /// - Parameter poly: Polynomial to negate.
    /// - Returns: The negated value, `-poly`.
    @inlinable
    public static prefix func - (_ poly: Self) -> Self {
        var result = Self.zero(context: poly.context)
        var resultData = result.data.data.mutableSpan
        let rhsData = poly.data.data.span
        for (rnsIndex, modulus) in poly.moduli.enumerated() {
            for index in poly.polyIndices(rnsIndex: rnsIndex) {
                resultData[index] = rhsData[index].negateMod(modulus: modulus)
            }
        }
        return result
    }

    /// Drops the polynomial context to a child context.
    ///
    /// A context is a parent of a child context if the child context is a *next* context of the parent or one of its
    /// children. The next context typically drops the last modulus in the modulus chain.
    /// - Parameter context: the `this` must be equal to or a child context of `this` context.
    /// - Throws: Error upon failure to drop context.
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
    func isZero(variableTime: Bool) -> Bool {
        precondition(variableTime)
        return data.data.allSatisfy { coefficient in coefficient == 0 }
    }

    /// Clears the memory in the polynomial.
    @inlinable
    mutating func zeroize() {
        data.zeroize()
    }
}

extension PolyRq where F == Coeff {
    /// Divides and rounds each coefficient by the last modulus in the chain,
    /// then drops the last modulus.
    ///
    /// This polynomial must have a next context.
    /// - Throws: Error upon failure to perform division and rounding.
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
        var dataLast = data.row(context.moduli.count - 1)
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
    mutating func multiplyPowerOfX(_ power: Int) throws {
        // Calculate effective step once, handling both positive and negative powers
        let twiceDegree = degree &<< 1
        let absEffectiveStep = abs(power) % twiceDegree

        if absEffectiveStep == 0 {
            return // No change needed for powers that are multiples of 2*degree
        }

        // Determine rotation direction and effective step based on power sign
        let rotationStep = power < 0 ? -absEffectiveStep : absEffectiveStep
        try data.rotateColumns(by: rotationStep % degree)

        let negateColumns = switch (power < 0, absEffectiveStep < degree) {
        case (true, true): (degree &- absEffectiveStep)..<degree
        case (true, false): 0..<(twiceDegree &- absEffectiveStep)
        case (false, true): 0..<absEffectiveStep
        case (false, false): (absEffectiveStep &- degree)..<degree
        }
        for (rowIndex, modulus) in moduli.enumerated() {
            for columnIndex in negateColumns {
                data[rowIndex, columnIndex] = data[rowIndex, columnIndex].negateMod(modulus: modulus)
            }
        }
    }
}

extension PolyRq {
    /// Converts the polynomial to ``Coeff`` format.
    ///
    /// If the polynomial is already in ``Coeff`` format, the input polynomial is returned with no conversion.
    /// - Returns: The polynomial in ``Coeff`` format.
    @inlinable
    public func convertToCoeffFormat() throws -> PolyRq<T, Coeff> {
        switch F.self {
        case is Coeff.Type:
            guard let poly = self as? PolyRq<T, Coeff> else {
                throw HeError.errorCastingPolyFormat(from: F.self, to: Coeff.self)
            }
            return poly
        default:
            guard let poly = self as? PolyRq<T, Eval> else {
                throw HeError.errorCastingPolyFormat(from: F.self, to: Eval.self)
            }
            return try poly.inverseNtt()
        }
    }

    /// Converts the polynomial to ``Eval`` format.
    ///
    /// If the polynomial is already in ``Eval`` format, the input polynomial is returned with no conversion.
    /// - Returns: The polynomial in ``Eval`` format.
    @inlinable
    public func convertToEvalFormat() throws -> PolyRq<T, Eval> {
        switch F.self {
        case is Coeff.Type:
            guard let poly = self as? PolyRq<T, Coeff> else {
                throw HeError.errorCastingPolyFormat(from: F.self, to: Coeff.self)
            }
            return try poly.forwardNtt()
        default:
            guard let poly = self as? PolyRq<T, Eval> else {
                throw HeError.errorCastingPolyFormat(from: F.self, to: Eval.self)
            }
            return poly
        }
    }

    /// Converts the polynomial to the specified ``PolyFormat``.
    ///
    /// If the polynomial is already in ``PolyFormat``, the input polynomial is returned with no conversion.
    /// - Returns: The polynomial in ``PolyFormat`` format.
    @inlinable
    public func convertFormat<Format: PolyFormat>() throws -> PolyRq<T, Format> {
        switch Format.self {
        case is Coeff.Type:
            guard let poly = try convertToCoeffFormat() as? PolyRq<T, Format> else {
                throw HeError.errorCastingPolyFormat(from: F.self, to: Format.self)
            }
            return poly
        case is Eval.Type:
            guard let poly = try convertToEvalFormat() as? PolyRq<T, Format> else {
                throw HeError.errorCastingPolyFormat(from: F.self, to: Format.self)
            }
            return poly
        default:
            guard let poly = self as? PolyRq<T, Format> else {
                throw HeError.errorCastingPolyFormat(from: F.self, to: Format.self)
            }
            return poly
        }
    }
}
