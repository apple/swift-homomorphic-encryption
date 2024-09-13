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
public protocol ScalarType: FixedWidthInteger, UnsignedInteger, Codable, Sendable where Self.Magnitude: Sendable {
    /// Scalar which can hold a product of two `ScalarType` multiplicands.
    associatedtype DoubleWidth: DoubleWidthType, Sendable where DoubleWidth.Scalar == Self

    /// Holds signed values of the same bit-width.
    associatedtype SignedScalar: SignedScalarType where SignedScalar.UnsignedScalar == Self

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

public protocol SignedScalarType: FixedWidthInteger, SignedInteger, Codable, Sendable where Self.Magnitude: Sendable {
    /// Holds unsigned value of the same bit-width.
    associatedtype UnsignedScalar: ScalarType where UnsignedScalar.SignedScalar == Self

    /// Used for unsigned-signed conversion.
    init(bitPattern: UnsignedScalar)
}

extension SignedScalarType {
    /// Constant-time selection.
    /// - Parameters:
    ///   - condition: Selection bit. Must be 0 or `0xFFF...F`.
    ///   - value: Output if `condition` is `0xFFF...F`.
    ///   - other: Output if `condition` is zero.
    /// - Returns: `if condition & 1 { value } else { other }`.
    @inlinable
    public static func constantTimeSelect(if condition: Self.UnsignedScalar, then value: Self,
                                          else other: Self) -> Self
    {
        let result = Self.UnsignedScalar.constantTimeSelect(if: condition,
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
    public func centeredToRemainder(modulus: some ScalarType) -> Self.UnsignedScalar {
        assert(self <= (Self(modulus) - 1) / 2)
        assert(self >= -Self(modulus) / 2)
        let condition = Self.UnsignedScalar(bitPattern: self >> (bitWidth - 1))
        let thenValue = Self.UnsignedScalar(bitPattern: self &+ Self(bitPattern: Self.UnsignedScalar(modulus)))
        let elseValue = Self.UnsignedScalar(bitPattern: self)
        return Self.UnsignedScalar.constantTimeSelect(if: condition, then: thenValue, else: elseValue)
    }
}

extension Int32: SignedScalarType {
    public typealias UnsignedScalar = UInt32
}

extension Int64: SignedScalarType {
    public typealias UnsignedScalar = UInt64
}

extension UInt32: ScalarType {
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

extension UInt64: ScalarType {
    public typealias DoubleWidth = UInt128
    public typealias SignedScalar = Int64

    public static var rnsCorrectionFactor: UInt64 {
        // ~1000'th largest prime less than 2**62,
        // but also NTT-unfriendly for all N
        (Self(1) << 62) - 40797
    }

    public static var mTilde: UInt64 {
        Self(1) << 32
    }
}

/// Double-width scalar type which can hold a product of two ``ScalarType`` multiplicands.
public protocol DoubleWidthType: FixedWidthInteger, UnsignedInteger {
    /// Single-width scalar, with bit-width half that of the ``DoubleWidthType``.
    associatedtype Scalar: ScalarType

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
    @inlinable public var high: Scalar {
        Scalar(truncatingIfNeeded: self &>> Scalar.bitWidth)
    }

    /// The low `Scalar.bitWidth` bits of the double-width type.
    @inlinable public var low: Scalar {
        Scalar(truncatingIfNeeded: self)
    }

    /// Initializes a ``DoubleWidthType``.
    /// - Parameter value: the high and low bits of the double-width value.
    @inlinable
    public init(_ value: (high: Scalar, low: Scalar.Magnitude)) {
        self = (Self(value.high) &<< Scalar.bitWidth) | Self(value.low)
    }
}

extension UInt64: DoubleWidthType {
    /// Single-width scalar, with bit-width half that of the ``DoubleWidthType``.
    public typealias Scalar = UInt32
}

extension UInt128: DoubleWidthType {
    /// Single-width scalar, with bit-width half that of the ``DoubleWidthType``.
    public typealias Scalar = UInt64
}

extension FixedWidthInteger {
    /// Big endian byte representation of this value.
    public var bigEndianBytes: [UInt8] {
        var bigEndian = bigEndian
        return Swift.withUnsafeBytes(of: &bigEndian) { buffer in
            [UInt8](buffer)
        }
    }

    /// Little endian byte representation of this value.
    public var littleEndianBytes: [UInt8] {
        var littleEndian = littleEndian
        return Swift.withUnsafeBytes(of: &littleEndian) { buffer in
            [UInt8](buffer)
        }
    }

    /// Initializes a new instance from big endian bytes.
    /// - Parameter bigEndianBytes: Big endian byte representation of an integer.
    @inlinable
    public init(bigEndianBytes: some Collection<UInt8>) {
        var bigEndian = Self.zero
        withUnsafeMutableBytes(of: &bigEndian) { buffer in
            buffer.copyBytes(from: bigEndianBytes)
        }
        self.init(bigEndian: bigEndian)
    }

    /// Initializes a new instance from little endian bytes.
    /// - Parameter littleEndianBytes: Little endian byte representation of an integer.
    @inlinable
    public init(littleEndianBytes: some Collection<UInt8>) {
        var littleEndian = Self.zero
        withUnsafeMutableBytes(of: &littleEndian) { buffer in
            buffer.copyBytes(from: littleEndianBytes)
        }
        self.init(littleEndian: littleEndian)
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

extension ScalarType {
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

    /// Computes `self^{-1} mod modulus`.
    /// - Parameters:
    ///   - modulus: Modulus.
    ///   - variableTime: Must be `true`, indicating this value and `modulus` are leaked through timing.
    /// - Returns: `self^{-1} mod modulus`.
    /// - Throws: ``HeError/notInvertible(modulus:)`` if this value has no inverse mod `modulus`.
    @inlinable
    public func inverseMod(modulus: Self, variableTime: Bool) throws -> Self {
        precondition(variableTime)
        guard self != 0, modulus != 0 else {
            throw HeError.notInvertible(modulus: Int64(modulus))
        }
        var (a, m, x0, inverse) = (Int64(self), Int64(modulus), Int64(0), Int64(1))
        while a > 1 {
            guard m != 0 else {
                throw HeError.notInvertible(modulus: Int64(modulus))
            }
            inverse -= (a / m) * x0
            a %= m
            swap(&a, &m)
            swap(&x0, &inverse)
        }
        if inverse < 0 {
            inverse += Int64(modulus)
        }
        assert(multiplyMod(Self(inverse), modulus: modulus, variableTime: true) == 1)
        return Self(inverse)
    }
}

extension UInt32 {
    /// Reverses the bits of this value.
    ///
    /// - Parameter bitCount: Number of bits to reverse. Must be in `[1, 32]`.
    /// - Returns: The reversed bits of this value.
    @inlinable
    func reverseBits(bitCount: Int) -> UInt32 {
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
    @inlinable public var log2: Int {
        precondition(self > 0)
        return bitWidth - leadingZeroBitCount - 1
    }

    /// The base-2 logarithm of this value, rounded up.
    ///
    /// Warning: Leaks this value through timing.
    @inlinable public var ceilLog2: Int {
        precondition(self > 0)
        return log2 + (isPowerOfTwo ? 0 : 1)
    }

    /// The number of significant bits in the binary representation of this value.
    ///
    /// Leading zero bits are not included in the count.
    @inlinable public var significantBitCount: Int {
        bitWidth - leadingZeroBitCount
    }

    /// Whether or not this value is a positive power of two.
    ///
    /// Warning: Leaks this value through timing.
    @inlinable public var isPowerOfTwo: Bool {
        self > 0 && nonzeroBitCount == 1
    }

    /// The next power of two greater than or equal to this value.
    ///
    /// This value must be non-negative.
    /// Warning: Leaks this value through timing.
    @inlinable public var nextPowerOfTwo: Self {
        precondition(self >= 0)
        if self <= 1 {
            return 1
        }
        return 1 &<< ((self &- 1).log2 &+ 1)
    }

    /// The next power of two greater than or equal to this value.
    ///
    /// This value must be positive.
    @inlinable public var previousPowerOfTwo: Self {
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

extension ScalarType {
    /// Generates a list of prime numbers.
    ///
    /// Generated primes are increasing and in the range `[2^(b - 1), 2^b]` for each significantBitCount `b`.
    /// - Parameters:
    ///   - significantBitCounts: Bit count of each prime.
    ///   - preferringSmall: Whether or not to prefer small primes.
    ///   - nttDegree: Optionally, a power of two polynomial degree. If set, the generated primes will be usable in the
    /// number-theoretic transform (NTT).
    /// - Returns: Generated primes.
    /// - Throws: ``HeError/notEnoughPrimes(significantBitCounts:preferringSmall:nttDegree:)`` if not enough primes were
    /// found.
    /// - seealso: ``PolyRq/forwardNtt()`` and ``PolyRq/inverseNtt()``.
    @inlinable
    public static func generatePrimes(significantBitCounts: [Int], preferringSmall: Bool,
                                      nttDegree: Int = 1) throws -> [Self]
    {
        precondition(nttDegree.isPowerOfTwo)
        var primes: [Self] = []
        for significantBitCount in significantBitCounts {
            precondition(significantBitCount <= Self.bitWidth)
            let upperBound = if significantBitCount == Self.bitWidth {
                Self.max
            } else {
                Self(1) << significantBitCount
            }
            let range = (Self(1) << (significantBitCount - 1))..<upperBound
            let step = Self(2 * nttDegree)
            var candidatePrime = if preferringSmall {
                range.lowerBound + 1
            } else {
                (range.upperBound - step) + 1
            }
            while range.contains(candidatePrime) {
                if !primes.contains(Self(candidatePrime)), Self(candidatePrime).isPrime(variableTime: true),
                   Self(candidatePrime).isNttModulus(
                       for: nttDegree)
                {
                    primes.append(Self(candidatePrime))
                    break
                }
                if preferringSmall {
                    candidatePrime += step
                } else {
                    candidatePrime -= step
                }
            }
        }
        guard primes.count == significantBitCounts.count else {
            throw HeError.notEnoughPrimes(
                significantBitCounts: significantBitCounts,
                preferringSmall: preferringSmall,
                nttDegree: nttDegree)
        }
        return primes
    }

    /// Computes whether or not this value is prime.
    /// - Parameter variableTime: Must be `true`, indicating this value is leaked through timing.
    /// - Returns: Whether or not this value is prime.
    @inlinable
    func isPrime(variableTime: Bool) -> Bool {
        precondition(variableTime)
        if self <= 1 {
            return false
        }
        // Rabin-prime primality test
        let bases: [UInt] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        for base in bases {
            if self == base {
                return true
            }
            if isMultiple(of: Self(base)) {
                return false
            }
        }

        // write self = 2**r * d + 1 with d odd
        var r = Self.bitWidth - 1
        while r > 0, !(self - 1).isMultiple(of: Self(1) << r) {
            r -= 1
        }
        let twoPowR = Self(1) << r
        let d = (self - 1) / twoPowR
        assert(r != 0)
        assert(self == twoPowR * d + 1)
        assert(d & 1 == 1)

        let nPos = Self.Magnitude(self)
        witnessLoop: for base in bases {
            var x = UInt64(base).powMod(exponent: UInt64(d), modulus: UInt64(nPos), variableTime: true)
            if x == 1 || x == self - 1 {
                continue
            }
            for _ in 0..<r {
                x = x.powMod(exponent: 2, modulus: UInt64(nPos), variableTime: true)
                if x == self - 1 {
                    continue witnessLoop
                }
            }
            return false
        }
        return true
    }
}

// MARK: constant-time operations

extension ScalarType {
    /// Constant-time selection.
    /// - Parameters:
    ///   - condition: Selection bit. Must be 0 or `0xFFF...F`.
    ///   - value: Output if `condition` is `0xFFF...F`.
    ///   - other: Output if `condition` is zero.
    /// - Returns: `if condition & 1 { value } else { other }`.
    @inlinable
    static func constantTimeSelect(if condition: Self, then value: Self, else other: Self) -> Self {
        (~condition & other) | (condition & value)
    }

    /// Constant-time equality check.
    /// - Parameter other: Value to compare against.
    /// - Returns: `0xFFF...F` if `self == other`, and 0 otherwise.
    @inlinable
    func constantTimeEqual(_ other: Self) -> Self {
        let x = self ^ other // == 0 iff self == other
        let msbToCheck = ~x & (x &- Self(1)) // MSB is 1 iff x == 0
        return msbToCheck.constantTimeMostSignificantBit()
    }

    /// Constant-time most-significant bit computation.
    /// - Returns: `0xFFF...F` if the most significant bit is 1, and 0 otherwise.
    @inlinable
    func constantTimeMostSignificantBit() -> Self {
        ~((self &>> (bitWidth - 1)) &- 1)
    }

    /// Constant-time less than comparison.
    /// - Parameter other: Value to compare against.
    /// - Returns: `0xFFF...F` if `self < other`, and 0 otherwise.
    @inlinable
    func constantTimeLessThan(_ other: Self) -> Self {
        let msbToCheck = (self ^ ((self ^ other) | ((self &- other) ^ self)))
        return msbToCheck.constantTimeMostSignificantBit()
    }

    /// Constant-time greater than comparison.
    /// - Parameter other: Value to compare against.
    /// - Returns: `0xFFF...F` if `self > other`, and 0 otherwise.
    @inlinable
    func constantTimeGreaterThan(_ other: Self) -> Self {
        other.constantTimeLessThan(self)
    }

    /// Constant-time greater than or equal comparison.
    /// - Parameter other: Value to compare against.
    /// - Returns: `0xFFF...F` if `self >= other`, and 0 otherwise.
    @inlinable
    func constantTimeGreaterThanOrEqual(_ other: Self) -> Self {
        ~constantTimeLessThan(other)
    }

    /// Constant-time remainder-to-centered conversion.
    /// - Parameter modulus: Modulus.
    /// - Returns: Given `self` in `[0,modulus)`, returns `self % modulus` in `[-floor(modulus/2), floor(modulus-1)/2]`.
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
    func dividingFloor(by modulus: Modulus<Self>) -> Self {
        modulus.dividingFloor(dividend: self)
    }
}

extension DoubleWidthType where Self.Scalar.DoubleWidth == Self {
    /// Returns `floor(self / modulus)`.
    /// - Parameter modulus: Divisor.
    /// - Returns: `floor(self / modulus)`.
    @inlinable
    func dividingFloor(by modulus: Modulus<Self.Scalar>) -> Self {
        modulus.dividingFloor(dividend: self)
    }
}
