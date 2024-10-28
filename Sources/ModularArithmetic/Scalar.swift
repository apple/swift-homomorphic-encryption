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

/// Scalar type for ``PolyRq`` polynomial coefficients.
public protocol CoreScalarType: FixedWidthInteger, UnsignedInteger, Sendable
    where Self.Magnitude: Sendable
{
    /// Scalar which can hold a product of two `ScalarType` multiplicands.
    associatedtype DoubleWidth: DoubleWidthType, Sendable where DoubleWidth.Scalar == Self

    /// Holds signed values of the same bit-width.
    associatedtype SignedScalar: CoreSignedScalarType where SignedScalar.UnsignedScalar == Self

    /// Correction factor for RNS base conversions.
    ///
    /// Should be co-prime to plaintext modulus `t` and coefficient modulus `q` and chosen as large as possible to
    /// minimize error. Also called *Gamma*.
    /// - seealso: <https://eprint.iacr.org/2016/510.pdf>.
    static var rnsCorrectionFactor: Self { get }

    /// Auxiliary modulus used to remove extra multiples of the coefficient modulus `q`.
    ///
    /// -seealso: Section 5.2 of <https://eprint.iacr.org/2016/510.pdf>.
    static var mTilde: Self { get }

    /// Used for signed-unsigned conversion.
    init(bitPattern: SignedScalar)
}

/// Signed scalar type for representing signed values when converted to plaintext.
public protocol CoreSignedScalarType: FixedWidthInteger, SignedInteger, Sendable
    where Self.Magnitude: Sendable
{
    /// Holds unsigned value of the same bit-width.
    associatedtype UnsignedScalar: CoreScalarType where UnsignedScalar.SignedScalar == Self

    /// Used for unsigned-signed conversion.
    init(bitPattern: UnsignedScalar)
}

extension CoreSignedScalarType {
    /// Constant-time selection.
    /// - Parameters:
    ///   - condition: Selection bit. Must be 0 or `0xFFF...F`.
    ///   - value: Output if `condition` is `0xFFF...F`.
    ///   - other: Output if `condition` is zero.
    /// - Returns: `if condition & 1 { value } else { other }`.
    @inlinable
    public static func constantTimeSelect(
        if condition: Self.UnsignedScalar, then value: Self,
        else other: Self) -> Self
    {
        let result = Self.UnsignedScalar.constantTimeSelect(
            if: condition,
            then: Self.UnsignedScalar(bitPattern: value),
            else: Self.UnsignedScalar(bitPattern: other))
        return Self(bitPattern: result)
    }

    /// Computes the high `Self.bitWidth` bits of `self * rhs`.
    /// - Parameter rhs: Multiplicand.
    /// - Returns: the high `Self.bitWidth` bits  of `self * rhs`.
    @inlinable
    public func multiplyHigh(_ rhs: Self) -> Self {
        multipliedFullWidth(by: rhs).high
    }

    /// Constant-time centered-to-remainder conversion.
    /// - Parameter modulus: Modulus.
    /// - Returns: Given `self` in `[-floor(modulus/2), floor((modulus-1)/2)]`,
    /// returns `self % modulus` in `[0, modulus)`.
    @inlinable
    public func centeredToRemainder(modulus: some CoreScalarType) -> Self.UnsignedScalar {
        assert(self <= (Self(modulus) - 1) / 2)
        assert(self >= -Self(modulus) / 2)
        let condition = Self.UnsignedScalar(bitPattern: self >> (bitWidth - 1))
        let thenValue = Self.UnsignedScalar(
            bitPattern: self &+ Self(bitPattern: Self.UnsignedScalar(modulus)))
        let elseValue = Self.UnsignedScalar(bitPattern: self)
        return Self.UnsignedScalar.constantTimeSelect(
            if: condition, then: thenValue, else: elseValue)
    }
}

extension Int32: CoreSignedScalarType {
    public typealias UnsignedScalar = UInt32
}

extension UInt64: DoubleWidthType {
    /// Single-width scalar, with bit-width half that of the ``DoubleWidthType``.
    public typealias Scalar = UInt32
}

extension UInt32: CoreScalarType {
    public typealias DoubleWidth = UInt64
    public typealias SignedScalar = Int32

    public static var rnsCorrectionFactor: UInt32 {
        // ~1000'th largest prime less than 2**30,
        // but also NTT-unfriendly for N > 8
        (Self(1) << 30) - 20405
    }

    public static var mTilde: UInt32 {
        Self(1) << 16
    }
}

/// Double-width scalar type which can hold a product of two ``ScalarType`` multiplicands.
public protocol DoubleWidthType: FixedWidthInteger, UnsignedInteger {
    /// Single-width scalar, with bit-width half that of the ``DoubleWidthType``.
    associatedtype Scalar: CoreScalarType

    /// The high `Scalar.bitWidth` bits of the double-width value.
    var high: Scalar { get }
    /// The low `Scalar.bitWidth` bits of the double-width value.
    var low: Scalar { get }

    /// Initializes a ``DoubleWidthType``.
    /// - Parameter value: the high and low bits of the double-width value.
    init(_ value: (high: Scalar, low: Scalar.Magnitude))
}

extension DoubleWidthType {
    /// The high `Scalar.bitWidth` bits of the double-width value.
    public var high: Scalar {
        Scalar(truncatingIfNeeded: self &>> Scalar.bitWidth)
    }

    /// The low `Scalar.bitWidth` bits of the double-width type.
    public var low: Scalar {
        Scalar(truncatingIfNeeded: self)
    }

    /// Initializes a ``DoubleWidthType``.
    /// - Parameter value: the high and low bits of the double-width value.
    @inlinable
    public init(_ value: (high: Scalar, low: Scalar.Magnitude)) {
        self = (Self(value.high) &<< Scalar.bitWidth) | Self(value.low)
    }
}

extension UnsignedInteger where Self: FixedWidthInteger {
    /// Computes the high `Self.bitWidth` bits of `self * rhs`.
    /// - Parameter rhs: Multiplicand.
    /// - Returns: the high `Self.bitWidth` bits  of `self * rhs`.
    @inlinable
    public func multiplyHigh(_ rhs: Self) -> Self {
        multipliedFullWidth(by: rhs).high
    }

    /// Constant-time modular addition `(self + rhs) % modulus`.
    /// - Parameters:
    ///   - rhs: Summand. Must be in `[0, modulus - 1]`.
    ///   - modulus: Modulus. Must be in `[0, modulus - 1]`.
    /// - Returns: `(self + rhs) % modulus`.
    @inlinable
    public func addMod(_ rhs: Self, modulus: Self) -> Self {
        assert(self < modulus)
        assert(rhs < modulus)
        assert(modulus < Self.max / 2)
        let sum = self &+ rhs
        return sum.subtractIfExceeds(modulus)
    }

    /// Constant-time conditional subtraction.
    ///
    /// Computes a conditional subtraction, `if self >= modulus ? self - modulus : self`, which can be used for modular
    /// reduction of `self` from range `[0, 2 * modulus - 1]` to `[0, modulus - 1]`. The computation is constant-time.
    /// `self` must be less than or equal to `(Self.max >> 1) + modulus``
    /// - Parameter modulus: Modulus.
    /// - Returns: `self >= modulus ? self - modulus : self`.
    @inlinable
    public func subtractIfExceeds(_ modulus: Self) -> Self {
        assert(self <= (Self.max &>> 1) + modulus) // difference mask fails otherwise
        let difference = self &- modulus
        let mask = Self(0) &- (difference >> (bitWidth - 1))
        return difference &+ (modulus & mask)
    }

    /// Computes `-self mod modulus`.
    ///
    /// `self` must be in `[0, modulus - 1]`.
    /// - Parameter modulus: Modulus.
    /// - Returns: `-self mod modulus`.
    @inlinable
    public func negateMod(modulus: Self) -> Self {
        assert(self < modulus)
        return (modulus &- self).subtractIfExceeds(modulus)
    }

    /// Computes `self - rhs mod modulus`.
    ///
    /// `self` and `rhs` must be in `[0, modulus - 1]`.
    /// - Parameters:
    ///   - rhs: Must be in `[0, modulus - 1]`.
    ///   - modulus: Modulus.
    /// - Returns: `self - rhs mod modulus`.
    @inlinable
    public func subtractMod(_ rhs: Self, modulus: Self) -> Self {
        assert(rhs < modulus)
        assert(self < modulus)
        let sum = self &+ modulus &- rhs
        return sum.subtractIfExceeds(modulus)
    }
}

extension CoreScalarType {
    /// Computes modular exponentiation.
    ///
    /// Computes self raised to the power of `exponent` mod `modulus, i.e., `self^exponent mod modulus`.
    /// - Parameters:
    ///   - exponent: Exponent.
    ///   - modulus: Modulus.
    ///   - variableTime: Must be `true`, indicating this value, `modulus` and `exponent` are leaked through timing.
    /// - Returns: `self^exponent mod modulus`.
    /// - Warning: Leaks `self`, `exponent`, `modulus` through timing.
    @inlinable
    public func powMod(exponent: Self, modulus: Self, variableTime: Bool) -> Self {
        precondition(variableTime)
        if exponent == 0 {
            return 1
        }
        var base = self
        var exponent = exponent
        let modulus = ReduceModulus(
            modulus: modulus,
            bound: ReduceModulus.InputBound.ModulusSquared,
            variableTime: variableTime)
        var result = Self(1)
        for _ in 0...exponent.log2 {
            if (exponent & 1) != 0 {
                result = modulus.multiplyMod(result, base)
            }
            if exponent > 0 {
                base = modulus.multiplyMod(base, base)
            }
            exponent >>= 1
        }
        return result
    }
}

extension UInt32 {
    /// Reverses the bits of this value.
    ///
    /// - Parameter bitCount: Number of bits to reverse. Must be in `[1, 32]`.
    /// - Returns: The reversed bits of this value.
    @inlinable
    public func reverseBits(bitCount: Int) -> UInt32 {
        var x = self
        assert((1...32).contains(bitCount))
        // swap consecutive bits
        x = ((x & 0xAAAA_AAAA) &>> 1) | ((x & 0x5555_5555) << 1)
        // swap consecutive 2-bit pairs
        x = ((x & 0xCCCC_CCCC) &>> 2) | ((x & 0x3333_3333) << 2)
        // swap consecutive 4-bit pairs
        x = ((x & 0xF0F0_F0F0) &>> 4) | ((x & 0x0F0F_0F0F) << 4)
        // swap consecutive bytes
        x = ((x & 0xFF00_FF00) &>> 8) | ((x & 0x00FF_00FF) << 8)
        // swap consecutive 2-byte pairs
        x = (x &>> 16) | (x &<< 16)
        x &>>= 32 &- bitCount
        return x
    }
}

extension FixedWidthInteger {
    /// The base-2 logarithm of this value, rounded down.
    public var log2: Int {
        precondition(self > 0)
        return bitWidth - leadingZeroBitCount - 1
    }

    /// The base-2 logarithm of this value, rounded up.
    ///
    /// Warning: Leaks this value through timing.
    public var ceilLog2: Int {
        precondition(self > 0)
        return log2 + (isPowerOfTwo ? 0 : 1)
    }

    /// The number of significant bits in the binary representation of this value.
    ///
    /// Leading zero bits are not included in the count.
    public var significantBitCount: Int {
        bitWidth - leadingZeroBitCount
    }

    /// Whether or not this value is a positive power of two.
    ///
    /// Warning: Leaks this value through timing.
    public var isPowerOfTwo: Bool {
        self > 0 && nonzeroBitCount == 1
    }

    /// The next power of two greater than or equal to this value.
    ///
    /// This value must be non-negative.
    /// Warning: Leaks this value through timing.
    public var nextPowerOfTwo: Self {
        precondition(self >= 0)
        if self <= 1 {
            return 1
        }
        return 1 &<< ((self &- 1).log2 &+ 1)
    }

    /// The next power of two greater than or equal to this value.
    ///
    /// This value must be positive.
    public var previousPowerOfTwo: Self {
        precondition(self > 0)
        return 1 &<< (Self.bitWidth &- 1 - leadingZeroBitCount)
    }

    /// Computes a modular multiplication.
    ///
    /// Is not constant time. Use ``Modulus`` for a constant-time alternative, which is also faster when the modulus
    /// is re-used across multiple computations.
    /// - Parameters:
    ///   - rhs: Multiplicand.
    ///   - modulus: Modulus.
    ///   - variableTime: Must be `true`, indicating `modulus` is leaked through timing.
    /// - Warning: Leaks `modulus`, `self, `rhs` through timing.`
    /// - Returns: `self * rhs mod modulus`.
    @inlinable
    public func multiplyMod(_ rhs: Self, modulus: Self, variableTime: Bool) -> Self {
        precondition(variableTime)
        let multiplied = multipliedFullWidth(by: rhs)
        return modulus.dividingFullWidth(multiplied).remainder
    }

    /// Computes `ceil(self / divisor)`.
    /// Parameters:
    /// - divisor: the number to divide by.
    ///   - variableTime: Must be `true`, indicating this value and `divisor` are leaked through timing.
    /// - Returns: `ceil(self / divisor)`.
    /// Warning: Leaks this value and `divisor` through timing.
    @inlinable
    public func dividingCeil(_ divisor: Self, variableTime: Bool) -> Self {
        precondition(variableTime)
        precondition(divisor != 0)
        if self > 0, divisor > 0 {
            return (self - 1) / divisor + 1
        }
        if self < 0, divisor < 0 {
            return (self + 1) / divisor + 1
        }
        return self / divisor
    }

    /// Computes the smallest value greater than or equal to this value that is a multiple of `rhs`.
    ///
    /// This value must be non-negative.
    /// - Parameters:
    ///   - rhs: Value of which the output is a multiple of.
    ///   - variableTime: Must be `true`, indicating this value and `other` are leaked through timing.
    /// - Returns: the next multiple of this value.
    /// - Warning: Leaks this value and `other` through timing.
    @inlinable
    public func nextMultiple(of rhs: Self, variableTime: Bool) -> Self {
        precondition(variableTime)
        precondition(self >= 0)
        if rhs == 0 {
            return 0
        }
        return dividingCeil(rhs, variableTime: true) * rhs
    }

    /// Computes the largest value less than or equal to this value that is a multiple of `rhs`.
    ///
    /// This value must be non-negative.
    /// - Parameters:
    ///   - rhs: Value of which the output is a multiple of.
    ///   - variableTime: Must be `true`, indicating this value and `other` are leaked through timing.
    /// - Returns: the previous multiple of this value.
    /// - Warning: Leaks this value and `other` through timing.
    @inlinable
    public func previousMultiple(of rhs: Self, variableTime: Bool) -> Self {
        precondition(variableTime)
        precondition(self >= 0)
        if rhs == 0 {
            return 0
        }
        return (self / rhs) * rhs
    }
}

// MARK: constant-time operations

extension CoreScalarType {
    /// Constant-time selection.
    /// - Parameters:
    ///   - condition: Selection bit. Must be 0 or `0xFFF...F`.
    ///   - value: Output if `condition` is `0xFFF...F`.
    ///   - other: Output if `condition` is zero.
    /// - Returns: `if condition & 1 { value } else { other }`.
    @inlinable
    public static func constantTimeSelect(if condition: Self, then value: Self, else other: Self) -> Self {
        (~condition & other) | (condition & value)
    }

    /// Constant-time equality check.
    /// - Parameter other: Value to compare against.
    /// - Returns: `0xFFF...F` if `self == other`, and 0 otherwise.
    @inlinable
    public func constantTimeEqual(_ other: Self) -> Self {
        let x = self ^ other // == 0 iff self == other
        let msbToCheck = ~x & (x &- Self(1)) // MSB is 1 iff x == 0
        return msbToCheck.constantTimeMostSignificantBit()
    }

    /// Constant-time most-significant bit computation.
    /// - Returns: `0xFFF...F` if the most significant bit is 1, and 0 otherwise.
    @inlinable
    public func constantTimeMostSignificantBit() -> Self {
        ~((self &>> (bitWidth - 1)) &- 1)
    }

    /// Constant-time less than comparison.
    /// - Parameter other: Value to compare against.
    /// - Returns: `0xFFF...F` if `self < other`, and 0 otherwise.
    @inlinable
    public func constantTimeLessThan(_ other: Self) -> Self {
        let msbToCheck = (self ^ ((self ^ other) | ((self &- other) ^ self)))
        return msbToCheck.constantTimeMostSignificantBit()
    }

    /// Constant-time greater than comparison.
    /// - Parameter other: Value to compare against.
    /// - Returns: `0xFFF...F` if `self > other`, and 0 otherwise.
    @inlinable
    public func constantTimeGreaterThan(_ other: Self) -> Self {
        other.constantTimeLessThan(self)
    }

    /// Constant-time greater than or equal comparison.
    /// - Parameter other: Value to compare against.
    /// - Returns: `0xFFF...F` if `self >= other`, and 0 otherwise.
    @inlinable
    public func constantTimeGreaterThanOrEqual(_ other: Self) -> Self {
        ~constantTimeLessThan(other)
    }

    /// Constant-time remainder-to-centered conversion.
    /// - Parameter modulus: Modulus.
    /// - Returns: Given `self` in `[0,modulus)`, returns `self % modulus` 1
    ///    in `[-floor(modulus/2), floor(modulus-1)/2]`.
    @inlinable
    public func remainderToCentered(modulus: Self) -> Self.SignedScalar {
        let condition = constantTimeGreaterThan((modulus - 1) >> 1)
        let thenValue = Self.SignedScalar(self) - Self.SignedScalar(bitPattern: modulus)
        let elseValue = Self.SignedScalar(bitPattern: self)
        return Self.SignedScalar.constantTimeSelect(if: condition, then: thenValue, else: elseValue)
    }

    /// Returns `floor(self / modulus)`.
    /// - Parameter modulus: Divisor.
    /// - Returns: `floor(self / modulus)`.
    @inlinable
    public func dividingFloor(by modulus: Modulus<Self>) -> Self {
        modulus.dividingFloor(dividend: self)
    }
}

extension DoubleWidthType where Self.Scalar.DoubleWidth == Self {
    /// Returns `floor(self / modulus)`.
    /// - Parameter modulus: Divisor.
    /// - Returns: `floor(self / modulus)`.
    @inlinable
    public func dividingFloor(by modulus: Modulus<Self.Scalar>) -> Self {
        modulus.dividingFloor(dividend: self)
    }
}

extension FixedWidthInteger {
    /// Compute the reminder to a modular.
    /// - Note: not a constant time operation.
    @inlinable
    public func toRemainder(_ mod: Self, variableTime: Bool) -> Self {
        precondition(variableTime)
        precondition(mod > 0)
        var result = self % mod
        if result < 0 {
            result += mod
        }
        return result
    }
}
