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

// These two protocols are merely defined to add the Codable protocol
public protocol ScalarType: ModularArithmetic.CoreScalarType, Codable where SignedScalar: SignedScalarType {}

public protocol SignedScalarType: ModularArithmetic.CoreSignedScalarType, Codable where UnsignedScalar: ScalarType {}

extension UInt32: ScalarType {}
extension Int32: SignedScalarType {}

extension Int64: SignedScalarType {}
extension UInt64: ScalarType {}

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

extension ScalarType {
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
