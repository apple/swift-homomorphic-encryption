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

// This source file is part of the Swift.org open source project
//
// Copyright (c) 2024 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors

// Taken from
// https://github.com/swiftlang/swift/blob/fc23eef2d2b2e42116ac94a6cc0d0d2cc96688f5/test/Prototypes/DoubleWidth.swift.gyb
// and modified with the following changes:
// * Restrict `Base` to unsigned integers only.
// * Rename `DoubleWidth` to `DoubleWidthUInt`.

/// A fixed-width integer that has twice the bit width of its base type.
///
/// You can use the `DoubleWidthUInt` type to continue calculations with the result
/// of a full width arithmetic operation. Normally, when you perform a full
/// width operation, the result is a tuple of the high and low parts of the
/// result.
///
///     let a = 2241543570477705381
///     let b = 186319822866995413
///     let c = a.multipliedFullWidth(by: b)
///     // c == (high: 22640526660490081, low: 7959093232766896457)
///
/// The tuple `c` can't be used in any further comparisons or calculations. To
/// use this value, create a `DoubleWidthUInt` instance from the result. You can
/// use the `DoubleWidthUInt` instance in the same way that you would use any other
/// integer type.
///
///     let d = DoubleWidthUInt(a.multipliedFullWidth(by: b))
///     // d == 417644001000058515200174966092417353
///
///     // Check the calculation:
///     print(d / DoubleWidthUInt(a) == b)
///     // Prints "true"
///
///     if d > Int.max {
///         print("Too big to be an 'Int'!")
///     } else {
///         print("Small enough to fit in an 'Int'")
///     }
///     // Prints "Too big to be an 'Int'!"
///
/// The `DoubleWidthUInt` type is not intended as a replacement for a variable-width
/// integer type. Nesting `DoubleWidthUInt` instances, in particular, may result in
/// undesirable performance.
public struct DoubleWidthUInt<Base>: Sendable
    where
    Base: FixedWidthInteger & UnsignedInteger & Sendable, Base.Magnitude: Sendable
{
    public typealias High = Base
    public typealias Low = Base.Magnitude

    #if _endian(big)
    @usableFromInline var _storage: (high: High, low: Low)
    #else
    @usableFromInline var _storage: (low: Low, high: High)
    #endif

    /// The high part of the value.
    public var high: High {
        _storage.high
    }

    /// The low part of the value.
    public var low: Low {
        _storage.low
    }

    /// Creates a new instance from the given tuple of high and low parts.
    ///
    /// - Parameter value: The tuple to use as the source of the new instance's
    ///   high and low parts.
    @inlinable
    public init(_ value: (high: High, low: Low)) {
        #if _endian(big)
        self._storage = (high: value.0, low: value.1)
        #else
        self._storage = (low: value.1, high: value.0)
        #endif
    }

    // We expect users to invoke the public initializer above as demonstrated in
    // the documentation (that is, by passing in the result of a full width
    // operation).
    //
    // Internally, we'll need to create new instances by supplying high and low
    // parts directly; ((double parentheses)) greatly impair readability,
    // especially when nested:
    //
    //   DoubleWidthUInt<DoubleWidthUInt>((DoubleWidthUInt((0, 0)), DoubleWidthUInt((0, 0))))
    //
    // For that reason, we'll include an internal initializer that takes two
    // separate arguments.
    @inlinable init(_ _high: High, _ low: Low) {
        self.init((_high, low))
    }

    @inlinable
    public init() {
        self.init(0, 0)
    }
}

extension DoubleWidthUInt: CustomStringConvertible {
    public var description: String {
        String(self, radix: 10)
    }
}

extension DoubleWidthUInt: CustomDebugStringConvertible {
    public var debugDescription: String {
        "(\(_storage.high), \(_storage.low))"
    }
}

extension DoubleWidthUInt: Equatable {
    @inlinable
    public static func == (lhs: DoubleWidthUInt, rhs: DoubleWidthUInt) -> Bool {
        lhs._storage.low == rhs._storage.low
            && lhs._storage.high == rhs._storage.high
    }
}

extension DoubleWidthUInt: Comparable {
    @inlinable
    public static func < (lhs: DoubleWidthUInt, rhs: DoubleWidthUInt) -> Bool {
        if lhs._storage.high < rhs._storage.high { true }
        else if lhs._storage.high > rhs._storage.high { false }
        else { lhs._storage.low < rhs._storage.low }
    }
}

extension DoubleWidthUInt: Hashable {
    public var hashValue: Int {
        _hashValue(for: self)
    }

    @inlinable
    public func hash(into hasher: inout Hasher) {
        hasher.combine(low)
        hasher.combine(high)
    }
}

extension DoubleWidthUInt: Numeric {
    public typealias Magnitude = DoubleWidthUInt<Low>

    public var magnitude: Magnitude {
        Magnitude(Low(truncatingIfNeeded: _storage.high), _storage.low)
    }

    @inlinable init(_ _magnitude: Magnitude) {
        self.init(High(_magnitude._storage.high), _magnitude._storage.low)
    }

    @inlinable
    public init(_ source: some BinaryInteger) {
        guard let result = DoubleWidthUInt<Base>(exactly: source) else {
            preconditionFailure("Value is outside the representable range")
        }
        self = result
    }

    @inlinable
    public init?<T: BinaryInteger>(exactly source: T) {
        // Can't represent a negative 'source'
        guard source >= 0 else { return nil }

        // Is 'source' entirely representable in Low?
        if let low = Low(exactly: source.magnitude) {
            self.init((0, low))
        } else {
            // At this point we know source.bitWidth > Base.bitWidth, or else we
            // would've taken the first branch.
            let lowInT = source & T(~0 as Low)
            let highInT = source >> Low.bitWidth

            let low = Low(lowInT)
            guard let high = High(exactly: highInT) else { return nil }
            self.init(high, low)
        }
    }
}

extension DoubleWidthUInt {
    public struct Words {
        public var _high: High.Words
        public var _low: Low.Words

        @inlinable
        public init(_ value: DoubleWidthUInt<Base>) {
            // Multiples of word size only.
            guard Base.bitWidth == Base.Magnitude.bitWidth,
                  UInt.bitWidth % Base.bitWidth == 0 ||
                  Base.bitWidth % UInt.bitWidth == 0
            else {
                fatalError("Access to words is not supported on this type")
            }
            self._high = value._storage.high.words
            self._low = value._storage.low.words
            assert(!_low.isEmpty)
        }
    }
}

extension DoubleWidthUInt.Words: RandomAccessCollection {
    public typealias Index = Int

    public var startIndex: Index {
        0
    }

    public var endIndex: Index {
        count
    }

    public var count: Int {
        if Base.bitWidth < UInt.bitWidth { return 1 }
        return _low.count + _high.count
    }

    @inlinable
    public subscript(_ i: Index) -> UInt {
        if Base.bitWidth < UInt.bitWidth {
            precondition(i == 0, "Invalid index")
            assert(2 * Base.bitWidth <= UInt.bitWidth)

            return _low.first! | (_high.first! &<< Base.bitWidth._lowWord)
        }
        if i < _low.count {
            return _low[i + _low.startIndex]
        }

        return _high[i - _low.count + _high.startIndex]
    }
}

extension DoubleWidthUInt: FixedWidthInteger {
    public var words: Words {
        Words(self)
    }

    public static var isSigned: Bool {
        Base.isSigned
    }

    public static var max: DoubleWidthUInt {
        self.init(High.max, Low.max)
    }

    public static var min: DoubleWidthUInt {
        self.init(High.min, Low.min)
    }

    public static var bitWidth: Int {
        High.bitWidth + Low.bitWidth
    }

    @inlinable
    public func addingReportingOverflow(_ rhs: DoubleWidthUInt) -> (partialValue: DoubleWidthUInt, overflow: Bool) {
        let (low, lowOverflow) =
            _storage.low.addingReportingOverflow(rhs._storage.low)
        let (high, highOverflow) =
            _storage.high.addingReportingOverflow(rhs._storage.high)
        let result = (high &+ (lowOverflow ? 1 : 0), low)
        let overflow = highOverflow || high == Base.max && lowOverflow
        return (partialValue: DoubleWidthUInt(result), overflow: overflow)
    }

    @inlinable
    public func subtractingReportingOverflow(_ rhs: DoubleWidthUInt<Base>)
        -> (partialValue: DoubleWidthUInt<Base>, overflow: Bool)
    {
        let (low, lowOverflow) =
            _storage.low.subtractingReportingOverflow(rhs._storage.low)
        let (high, highOverflow) =
            _storage.high.subtractingReportingOverflow(rhs._storage.high)
        let result = (high &- (lowOverflow ? 1 : 0), low)
        let overflow = highOverflow || high == Base.min && lowOverflow
        return (partialValue: DoubleWidthUInt(result), overflow: overflow)
    }

    @inlinable
    public func multipliedReportingOverflow(
        by rhs: DoubleWidthUInt) -> (partialValue: DoubleWidthUInt, overflow: Bool)
    {
        let (carry, product) = multipliedFullWidth(by: rhs)
        let result = DoubleWidthUInt(truncatingIfNeeded: product)
        let didCarry = carry != (0 as DoubleWidthUInt)
        return (result, didCarry)
    }

    @inlinable
    public func quotientAndRemainder(
        dividingBy other: DoubleWidthUInt) -> (quotient: DoubleWidthUInt, remainder: DoubleWidthUInt)
    {
        let (quotient, remainder) = Magnitude._divide(magnitude, by: other.magnitude)
        return (DoubleWidthUInt(quotient), DoubleWidthUInt(remainder))
    }

    @inlinable
    public func dividedReportingOverflow(
        by other: DoubleWidthUInt) -> (partialValue: DoubleWidthUInt, overflow: Bool)
    {
        if other == (0 as DoubleWidthUInt) { return (self, true) }
        return (quotientAndRemainder(dividingBy: other).quotient, false)
    }

    @inlinable
    public func remainderReportingOverflow(
        dividingBy other: DoubleWidthUInt) -> (partialValue: DoubleWidthUInt, overflow: Bool)
    {
        if other == (0 as DoubleWidthUInt) { return (self, true) }
        return (quotientAndRemainder(dividingBy: other).remainder, false)
    }

    @inlinable
    public func multipliedFullWidth(
        by other: DoubleWidthUInt) -> (high: DoubleWidthUInt, low: DoubleWidthUInt.Magnitude)
    {
        func mul(_ x: Low, _ y: Low) -> (partial: Low, carry: Low) {
            let (high, low) = x.multipliedFullWidth(by: y)
            return (low, high)
        }

        func sum(_ x: Low, _ y: Low, _ z: Low) -> (partial: Low, carry: Low) {
            let (sum1, overflow1) = x.addingReportingOverflow(y)
            let (sum2, overflow2) = sum1.addingReportingOverflow(z)
            let carry: Low = (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
            return (sum2, carry)
        }

        let lhs = magnitude
        let rhs = other.magnitude

        let a = mul(rhs._storage.low, lhs._storage.low)
        let b = mul(rhs._storage.low, lhs._storage.high)
        let c = mul(rhs._storage.high, lhs._storage.low)
        let d = mul(rhs._storage.high, lhs._storage.high)

        let mid1 = sum(a.carry, b.partial, c.partial)
        let mid2 = sum(b.carry, c.carry, d.partial)

        let low = DoubleWidthUInt<Low>(mid1.partial, a.partial)
        let (sum_, overflow_) = mid1.carry.addingReportingOverflow(mid2.partial)
        let high = DoubleWidthUInt(High(mid2.carry + d.carry + (overflow_ ? 1 : 0)), sum_)

        return (high, low)
    }

    @inlinable
    public func dividingFullWidth(
        _ dividend: (high: DoubleWidthUInt, low: DoubleWidthUInt.Magnitude))
        -> (quotient: DoubleWidthUInt, remainder: DoubleWidthUInt)
    {
        let other = DoubleWidthUInt<DoubleWidthUInt>(dividend)
        let (quotient, remainder) = Magnitude._divide(other.magnitude, by: magnitude)
        return (DoubleWidthUInt(quotient), DoubleWidthUInt(remainder))
    }

    @inlinable
    public static func &= (
        lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt)
    {
        lhs._storage.low &= rhs._storage.low
        lhs._storage.high &= rhs._storage.high
    }

    @inlinable
    public static func |= (
        lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt)
    {
        lhs._storage.low |= rhs._storage.low
        lhs._storage.high |= rhs._storage.high
    }

    @inlinable
    public static func ^= (
        lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt)
    {
        lhs._storage.low ^= rhs._storage.low
        lhs._storage.high ^= rhs._storage.high
    }

    @inlinable
    public static func <<= (lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt) {
        // Shift is larger than this type's bit width.
        if rhs._storage.high != (0 as High) ||
            rhs._storage.low >= DoubleWidthUInt.bitWidth
        {
            lhs = 0
            return
        }

        lhs &<<= rhs
    }

    @inlinable
    public static func >>= (lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt) {
        // Shift is larger than this type's bit width.
        if rhs._storage.high != (0 as High) ||
            rhs._storage.low >= DoubleWidthUInt.bitWidth
        {
            lhs = 0
            return
        }

        lhs &>>= rhs
    }

    /// Returns this value "masked" by its bit width.
    ///
    /// "Masking" notionally involves repeatedly incrementing or decrementing this
    /// value by `self.bitWidth` until the result is contained in the range
    /// `0..<self.bitWidth`.
    @inlinable
    func _masked() -> DoubleWidthUInt {
        precondition(
            DoubleWidthUInt.bitWidth.nonzeroBitCount == 1,
            "DoubleWidthUInt.bitWidth must be a power of two; got \(DoubleWidthUInt.bitWidth)")
        return self & DoubleWidthUInt(DoubleWidthUInt.bitWidth &- 1)
    }

    @inlinable
    public static func &<<= (lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt) {
        let rhs = rhs._masked()

        guard rhs._storage.low < Base.bitWidth else {
            lhs._storage.high = High(
                truncatingIfNeeded: lhs._storage.low &<<
                    (rhs._storage.low &- Low(Base.bitWidth)))
            lhs._storage.low = 0
            return
        }

        guard rhs._storage.low != (0 as Low) else { return }
        lhs._storage.high &<<= High(rhs._storage.low)
        lhs._storage.high |= High(
            truncatingIfNeeded: lhs._storage.low &>>
                (Low(Base.bitWidth) &- rhs._storage.low))
        lhs._storage.low &<<= rhs._storage.low
    }

    @inlinable
    public static func &>>= (lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt) {
        let rhs = rhs._masked()

        guard rhs._storage.low < Base.bitWidth else {
            lhs._storage.low = Low(
                truncatingIfNeeded: lhs._storage.high &>>
                    High(rhs._storage.low &- Low(Base.bitWidth)))
            lhs._storage.high = lhs._storage.high < (0 as High) ? ~0 : 0
            return
        }

        guard rhs._storage.low != (0 as Low) else { return }
        lhs._storage.low &>>= rhs._storage.low
        lhs._storage.low |= Low(
            truncatingIfNeeded: lhs._storage.high &<<
                High(Low(Base.bitWidth) &- rhs._storage.low))
        lhs._storage.high &>>= High(rhs._storage.low)
    }

    @inlinable
    public static func + (lhs: DoubleWidthUInt, rhs: DoubleWidthUInt) -> DoubleWidthUInt {
        var lhs = lhs
        lhs += rhs
        return lhs
    }

    @inlinable
    public static func += (lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt) {
        let (result, overflow) = lhs.addingReportingOverflow(rhs)
        precondition(!overflow, "Overflow in +=")
        lhs = result
    }

    @inlinable
    public static func * (lhs: DoubleWidthUInt, rhs: DoubleWidthUInt) -> DoubleWidthUInt {
        var lhs = lhs
        lhs *= rhs
        return lhs
    }

    @inlinable
    public static func *= (lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt) {
        let (result, overflow) = lhs.multipliedReportingOverflow(by: rhs)
        precondition(!overflow, "Overflow in *=")
        lhs = result
    }

    @inlinable
    public static func - (lhs: DoubleWidthUInt, rhs: DoubleWidthUInt) -> DoubleWidthUInt {
        var lhs = lhs
        lhs -= rhs
        return lhs
    }

    @inlinable
    public static func -= (
        lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt)
    {
        let (result, overflow) = lhs.subtractingReportingOverflow(rhs)
        precondition(!overflow, "Overflow in -=")
        lhs = result
    }

    @inlinable
    public static func / (lhs: DoubleWidthUInt<Base>, rhs: DoubleWidthUInt<Base>) -> DoubleWidthUInt<Base> {
        var lhs = lhs
        lhs /= rhs
        return lhs
    }

    @inlinable
    public static func /= (lhs: inout DoubleWidthUInt, rhs: DoubleWidthUInt) {
        let (result, overflow) = lhs.dividedReportingOverflow(by: rhs)
        precondition(!overflow, "Overflow in /=")
        lhs = result
    }

    @inlinable
    public static func % (lhs: DoubleWidthUInt<Base>, rhs: DoubleWidthUInt<Base>) -> DoubleWidthUInt<Base> {
        var lhs = lhs
        lhs %= rhs
        return lhs
    }

    @inlinable
    public static func %= (lhs: inout DoubleWidthUInt<Base>, rhs: DoubleWidthUInt<Base>) {
        let (result, overflow) = lhs.remainderReportingOverflow(dividingBy: rhs)
        precondition(!overflow, "Overflow in %=")
        lhs = result
    }

    @inlinable
    public init(_truncatingBits bits: UInt) {
        _storage.low = Low(_truncatingBits: bits)
        _storage.high = High(_truncatingBits: bits >> UInt(Low.bitWidth))
    }

    @inlinable
    public init(integerLiteral x: Int) {
        self.init(x)
    }

    public var leadingZeroBitCount: Int {
        high == (0 as High)
            ? High.bitWidth + low.leadingZeroBitCount
            : high.leadingZeroBitCount
    }

    public var trailingZeroBitCount: Int {
        low == (0 as Low)
            ? Low.bitWidth + high.trailingZeroBitCount
            : low.trailingZeroBitCount
    }

    public var nonzeroBitCount: Int {
        high.nonzeroBitCount + low.nonzeroBitCount
    }

    public var byteSwapped: DoubleWidthUInt {
        DoubleWidthUInt(
            High(truncatingIfNeeded: low.byteSwapped),
            Low(truncatingIfNeeded: high.byteSwapped))
    }
}

extension DoubleWidthUInt: UnsignedInteger where Base: FixedWidthInteger & UnsignedInteger {
    /// Returns the quotient and remainder after dividing a triple-width magnitude
    /// `lhs` by a double-width magnitude `rhs`.
    ///
    /// This operation is conceptually that described by Burnikel and Ziegler
    /// (1998).
    @inlinable
    static func _divide(
        _ lhs: (high: Low, mid: Low, low: Low), by rhs: Magnitude) -> (quotient: Low, remainder: Magnitude)
    {
        // The following invariants are guaranteed to hold by dividingFullWidth or
        // quotientAndRemainder before this method is invoked:
        assert(rhs.leadingZeroBitCount == 0)
        assert(Magnitude(lhs.high, lhs.mid) < rhs)

        guard lhs.high != (0 as Low) else {
            let lhs_ = Magnitude(lhs.mid, lhs.low)
            return lhs_ < rhs ? (0, lhs_) : (1, lhs_ &- rhs)
        }

        // Estimate the quotient.
        var quotient = lhs.high == rhs.high
            ? Low.max
            : rhs.high.dividingFullWidth((lhs.high, lhs.mid)).quotient
        // Compute quotient * rhs.
        // TODO: This could be performed more efficiently.
        var product =
            DoubleWidthUInt<Magnitude>(
                0, Magnitude(quotient.multipliedFullWidth(by: rhs.low)))
        let (x, y) = quotient.multipliedFullWidth(by: rhs.high)
        product += DoubleWidthUInt<Magnitude>(Magnitude(0, x), Magnitude(y, 0))
        // Compute the remainder after decrementing quotient as necessary.
        var remainder =
            DoubleWidthUInt<Magnitude>(
                Magnitude(0, lhs.high), Magnitude(lhs.mid, lhs.low))
        while remainder < product {
            quotient = quotient &- 1
            remainder += DoubleWidthUInt<Magnitude>(0, rhs)
        }
        remainder -= product

        return (quotient, remainder.low)
    }

    /// Returns the quotient and remainder after dividing a quadruple-width
    /// magnitude `lhs` by a double-width magnitude `rhs`.
    @inlinable
    static func _divide(
        _ lhs: DoubleWidthUInt<Magnitude>, by rhs: Magnitude) -> (quotient: Magnitude, remainder: Magnitude)
    {
        guard _fastPath(rhs > (0 as Magnitude)) else {
            fatalError("Division by zero")
        }
        guard _fastPath(rhs >= lhs.high) else {
            fatalError("Division results in an overflow")
        }

        if lhs.high == (0 as Magnitude) {
            return lhs.low.quotientAndRemainder(dividingBy: rhs)
        }

        if rhs.high == (0 as Low) {
            let a = lhs.high.high % rhs.low
            let b = a == (0 as Low)
                ? lhs.high.low % rhs.low
                : rhs.low.dividingFullWidth((a, lhs.high.low)).remainder
            let (x, c) = b == (0 as Low)
                ? lhs.low.high.quotientAndRemainder(dividingBy: rhs.low)
                : rhs.low.dividingFullWidth((b, lhs.low.high))
            let (y, d) = c == (0 as Low)
                ? lhs.low.low.quotientAndRemainder(dividingBy: rhs.low)
                : rhs.low.dividingFullWidth((c, lhs.low.low))
            return (Magnitude(x, y), Magnitude(0, d))
        }

        // Left shift both rhs and lhs, then divide and right shift the remainder.
        let shift = rhs.leadingZeroBitCount
        let rhs = rhs &<< shift
        let lhs = lhs &<< shift
        if lhs.high.high == (0 as Low),
           Magnitude(lhs.high.low, lhs.low.high) < rhs
        {
            let (quotient, remainder) =
                Magnitude._divide((lhs.high.low, lhs.low.high, lhs.low.low), by: rhs)
            return (Magnitude(0, quotient), remainder &>> shift)
        }
        let (x, a) =
            Magnitude._divide((lhs.high.high, lhs.high.low, lhs.low.high), by: rhs)
        let (y, b) =
            Magnitude._divide((a.high, a.low, lhs.low.low), by: rhs)
        return (Magnitude(x, y), b &>> shift)
    }

    /// Returns the quotient and remainder after dividing a double-width
    /// magnitude `lhs` by a double-width magnitude `rhs`.
    @inlinable
    static func _divide(
        _ lhs: Magnitude, by rhs: Magnitude) -> (quotient: Magnitude, remainder: Magnitude)
    {
        guard _fastPath(rhs > (0 as Magnitude)) else {
            fatalError("Division by zero")
        }
        guard rhs < lhs else {
            if _fastPath(rhs > lhs) { return (0, lhs) }
            return (1, 0)
        }

        if lhs.high == (0 as Low) {
            let (quotient, remainder) =
                lhs.low.quotientAndRemainder(dividingBy: rhs.low)
            return (Magnitude(quotient), Magnitude(remainder))
        }

        if rhs.high == (0 as Low) {
            let (x, a) = lhs.high.quotientAndRemainder(dividingBy: rhs.low)
            let (y, b) = a == (0 as Low)
                ? lhs.low.quotientAndRemainder(dividingBy: rhs.low)
                : rhs.low.dividingFullWidth((a, lhs.low))
            return (Magnitude(x, y), Magnitude(0, b))
        }

        // Left shift both rhs and lhs, then divide and right shift the remainder.
        let shift = rhs.leadingZeroBitCount
        // Note the use of `>>` instead of `&>>` below,
        // as `high` should be zero if `shift` is zero.
        let high = (lhs >> (Magnitude.bitWidth &- shift)).low
        let rhs = rhs &<< shift
        let lhs = lhs &<< shift
        let (quotient, remainder) =
            Magnitude._divide((high, lhs.high, lhs.low), by: rhs)
        return (Magnitude(0, quotient), remainder &>> shift)
    }
}

@usableFromInline typealias QuadWidth<T: ModularArithmetic.CoreScalarType> = DoubleWidthUInt<T.DoubleWidth>
@usableFromInline typealias OctoWidth<T: ModularArithmetic.CoreScalarType> = DoubleWidthUInt<QuadWidth<T>>
@usableFromInline typealias Width16<T: ModularArithmetic.CoreScalarType> = DoubleWidthUInt<OctoWidth<T>>
@usableFromInline typealias Width32<T: ModularArithmetic.CoreScalarType> = DoubleWidthUInt<Width16<T>>
