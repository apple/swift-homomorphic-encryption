// Copyright 2024-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

package import Foundation
public import HomomorphicEncryption
import RealModule
import Testing

/// Computes whether `self` is close to another floating-point value.
///
/// Asserts `abs(self - b) <= abs_tol + rel_tol * abs(b))` where `b` is another floating-point value.
/// - Parameters:
///   - expression: An expression returning finite floating-point value `b.
///   - relativeTolerance: An optional relative tolerance to enforce.
///   - absoluteTolerance: An optional absolute tolerance to enforce.
/// - Returns: true if the expressions are close to each other
extension BinaryFloatingPoint {
    @inlinable
    package func isClose(to value: Self,
                         relativeTolerance: Self = Self(1e-5),
                         absoluteTolerance: Self = Self(1e-8)) -> Bool
    {
        guard isFinite, value.isFinite else {
            return false
        }
        return abs(self - value) <= absoluteTolerance + relativeTolerance * abs(value)
    }
}

/// A simple random number generator used for testing.
///
/// This generates an arithmetic sequence by incrementing a UInt64 counter using wrapping arithmetic.
@usableFromInline
package struct TestRng: RandomNumberGenerator, PseudoRandomNumberGenerator {
    @usableFromInline var counter: UInt64 = 0

    /// Initializes the random number generator.
    /// - Parameter counter: The initial value to return.
    @inlinable
    package init(counter: UInt64 = 0) {
        self.counter = counter
    }

    /// Returns the next random number.
    /// - Returns: The next random number.
    @inlinable
    package mutating func next() -> UInt64 {
        defer { counter &+= 1 }
        return counter
    }
}

extension [UInt8] {
    /// Initializes a byte array from a base64-encoded string.
    ///
    /// Initializes to nil upon invalid base64 string.
    /// - Parameters:
    ///   - base64String: A base64-encoded string.
    ///   - options: An optional base64 decoding options.
    package init?(base64Encoded base64String: String, options: Data.Base64DecodingOptions = []) {
        if let data = Data(base64Encoded: base64String, options: options) {
            self = Array(data)
        } else {
            return nil
        }
    }

    /// Converts self to a base64-encoded string.
    /// - Parameter options: Optional Base64 encoding options.
    /// - Returns: base64-encoded string.
    package func base64EncodedString(options: Data.Base64EncodingOptions = []) -> String {
        Data(self).base64EncodedString(options: options)
    }

    /// Encodes a byte array into a hexadecimal string.
    ///
    /// String does not include a prefix, such as `0x`.
    /// - Returns: The hexadecimal string.
    package func hexEncodedString() -> String {
        reduce(into: "") { $0 += String(format: "%02x", $1) }
    }
}

extension TestUtils {
    /// Calculates the binomial coefficient.
    package static func binomialCoefficient(n: Int, k: Int) -> Double {
        func mult(_ range: ClosedRange<Int>) -> Double {
            range.reduce(1.0) { $0 * Double($1) }
        }

        func perm(n: Int, k: Int) -> Double {
            mult((n - k + 1)...n)
        }

        precondition(n >= 0 && k >= 0)
        if n == k {
            return 1.0
        }
        if k > n {
            return 0.0
        }
        if k == 0 {
            return 1.0
        }

        return perm(n: n, k: k) / mult(1...k)
    }

    /// Count the expected number of bins with a target count, assuming balls each assigned to a uniform random bin.
    /// - Parameters:
    ///   - binCount: Number of bins.
    ///   - ballCount: Number of balls.
    ///   - count: Target number of balls in a bin.
    /// - Returns: the expected number of bins with `count` balls.
    package static func expectedBallsInBinsCount(binCount: Int, ballCount: Int, count: Int) -> Double {
        // Pr(ballCount in first bin == count)
        let n = ballCount
        let k = count
        let p = 1 / Double(binCount)
        let binomialCoefficient = binomialCoefficient(n: n, k: k)

        func binomialPow(_ base: Double, _ exponent: Double) -> Double {
            // 0^0 set to be 1
            if base.isZero, exponent.isZero {
                1.0
            } else {
                Double.pow(base, exponent)
            }
        }

        // Probability mass function of binomial distribution
        let scalingFactor = binomialPow(p, Double(k)) * binomialPow(1.0 - p, Double(n - k))
        let probabilityOfExactlyCountBallsInFirstBin = binomialCoefficient * scalingFactor
        // Linearity of expectation
        return Double(binCount) * probabilityOfExactlyCountBallsInFirstBin
    }

    /// Generates random array for plaintext encoding.
    public static func getRandomPlaintextData<T: ScalarType>(count: Int,
                                                             in range: Range<T>) -> [T]
    {
        (0..<count).map { _ in T.random(in: range) }
    }

    package static func uniformnessTest<T>(poly: PolyRq<T, some Any>) {
        #expect(poly.hasValidData())
        for (rnsIndex, modulus) in poly.moduli.enumerated() {
            var valueCounts = [T: Int]()
            for coeff in poly.poly(rnsIndex: rnsIndex) {
                valueCounts[coeff] = (valueCounts[coeff] ?? 0) + 1
            }

            for binCount in 0..<5 {
                let expectedCount = expectedBallsInBinsCount(
                    binCount: Int(modulus),
                    ballCount: poly.degree,
                    count: binCount)
                let observedCount = if binCount == 0 {
                    Int(modulus) - valueCounts.count
                } else {
                    valueCounts.count { _, value in value == binCount }
                }

                #expect(expectedCount.isClose(
                    to: Double(observedCount),
                    relativeTolerance: 0.2,
                    absoluteTolerance: 11.0))
            }
        }
    }

    package static func computeVariance(poly: PolyRq<some Any, some Any>) -> Double {
        var sum = 0.0
        for (rnsIndex, modulus) in poly.moduli.enumerated() {
            let halfModulus = modulus / 2
            for coeff in poly.poly(rnsIndex: rnsIndex) {
                if coeff > halfModulus {
                    sum -= Double(modulus - coeff)
                } else {
                    sum += Double(coeff)
                }
            }
        }

        let average = sum / Double(poly.degree * poly.moduli.count)
        var variance = 0.0

        for (rnsIndex, modulus) in poly.moduli.enumerated() {
            let halfModulus = modulus / 2
            for coeff in poly.poly(rnsIndex: rnsIndex) {
                let deviation = if coeff > halfModulus {
                    average - Double(modulus - coeff)
                } else {
                    average - Double(coeff)
                }
                variance += deviation * deviation
            }
        }

        variance /= Double(poly.degree * poly.moduli.count)
        return variance
    }

    package static func crtDecompose<V: FixedWidthInteger, T: ScalarType>(value: V, moduli: [T]) -> [T] {
        moduli.map { q in
            var remainder = value.quotientAndRemainder(dividingBy: V(q)).remainder
            if remainder < 0 {
                remainder += V(q)
            }
            return T(remainder)
        }
    }

    package static func centeredBinomialDistributionTest<T>(poly: PolyRq<T, some Any>) {
        #expect(poly.hasValidData())
        let variance = computeVariance(poly: poly)
        let bounds = 9.0..<12.0
        #expect(bounds.contains(variance), "variance \(variance) not in bounds \(bounds)")

        // absolute value should be small
        let absoluteValueBound = Int64(18)
        // Maps signed "bigint" numbers to coefficient count
        var valueCounts = [Int64: Int]()
        // Maps CRT form to "bigint" form
        var crtToInt = [[T]: Int64]()

        for value in -absoluteValueBound...absoluteValueBound {
            let crtFrom = crtDecompose(value: value, moduli: poly.moduli)
            crtToInt[crtFrom] = value
        }

        var sum = Int64(0)
        for coeffIndex in poly.coeffIndices {
            let crtForm = poly.coefficient(coeffIndex: coeffIndex)
            if let bigint = crtToInt[crtForm] {
                valueCounts[bigint, default: 0] += 1
                sum += bigint
            } else {
                Issue.record("RNS coefficient too large: \(crtForm)")
            }
        }

        // Check distribution is zero-mean
        let mean = Double(sum) / Double(poly.degree)
        #expect(abs(mean) < 0.2)
    }

    package static func ternaryDistributionTest(poly: PolyRq<some Any, some Any>, pValue: Double) {
        #expect(poly.hasValidData())
        // Maps {-1, 0, 1} to coefficient count
        var valueCounts = [Int: Int]()

        let crtMinusOne = crtDecompose(value: -1, moduli: poly.moduli)
        let crtZero = crtDecompose(value: 0, moduli: poly.moduli)
        let crtOne = crtDecompose(value: 1, moduli: poly.moduli)

        for coeffIndex in poly.coeffIndices {
            let crt = poly.coefficient(coeffIndex: coeffIndex)
            switch crt {
            case crtMinusOne: valueCounts[-1, default: 0] += 1
            case crtZero: valueCounts[0, default: 0] += 1
            case crtOne: valueCounts[1, default: 0] += 1
            default: Issue.record("Invalid value in polynomial, residues: \(crt)")
            }
        }

        // Run right-tailed chi-squared test
        let expected = Double(poly.degree) / 3.0
        var chiSquareStat = 0.0
        for count in valueCounts.values {
            let diff = Double(count) - expected
            chiSquareStat += (diff * diff) / expected
        }

        // with degrees of freedom equal to 2 the cumulative distribution function of Chi Square distribution becomes
        // F(x; 2) = 1 - e^(-x / 2)
        // observeved P-value = 1 - F(x; 2) => observed P-value = e^(-x / 2)
        let observedPValue = Double.exp(-chiSquareStat / 2)
        #expect(observedPValue > pValue)
    }
}

/// A collection of constants used in tests.
public enum TestUtils {
    /// A polynomial degree suitable for testing.
    public static let testPolyDegree = 16
    /// A plaintext modulus suitable for testing.
    public static let testPlaintextModulus = 1153

    /// Generate the coefficient moduli for test
    @inlinable
    public static func testCoefficientModuli<T: ScalarType>() throws -> [T] {
        // Avoid assumptions on ordering of moduli
        // Also test `T.bitWidth  - 2
        if T.self == UInt32.self {
            return try T.generatePrimes(
                significantBitCounts: [28, 27, 29, 30],
                preferringSmall: false,
                nttDegree: TestUtils.testPolyDegree)
        }
        if T.self == UInt64.self {
            return try T.generatePrimes(
                significantBitCounts: [55, 52, 62, 58],
                preferringSmall: false,
                nttDegree: TestUtils.testPolyDegree)
        }
        preconditionFailure("Unsupported scalar type \(T.self)")
    }

    @inlinable
    package static func getTestEncryptionParameters<Scalar: ScalarType>() throws -> EncryptionParameters<Scalar> {
        try EncryptionParameters<Scalar>(
            polyDegree: testPolyDegree,
            plaintextModulus: Scalar(testPlaintextModulus),
            coefficientModuli: testCoefficientModuli(),
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.unchecked)
    }

    /// Returns a `HeContext` initialized with the parameters used for testing.
    @inlinable
    public static func getTestContext<Context: HeContext>() throws -> Context {
        try Context(encryptionParameters: getTestEncryptionParameters())
    }
}
