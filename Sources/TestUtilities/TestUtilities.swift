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

import HomomorphicEncryption
import RealModule
import XCTest

/// Validates two expressions are close to each other.
///
/// Asserts `abs(a-b) <= abs_tol + rel_tol * abs(b))` where `a, b` are the results of evaluating two expressions.
/// - Parameters:
///   - expression1: An expression returning floating-point type `T`.
///   - expression2: An expression returning floating-point type `T`.
///   - relativeTolerance: An optional relative tolerance to enforce.
///   - absoluteTolerance: An optional absolute tolerance to enforce.
///   - message: An optional description of a failure.
///   - file: The file where the failure occurs. The default is the filename of the test case where you call this
/// function.
///   - line: The line number where the failure occurs. The default is the line number where you call this function.
package func XCTAssertIsClose<T: BinaryFloatingPoint>(
    _ expression1: @autoclosure () throws -> T,
    _ expression2: @autoclosure () throws -> T,
    relativeTolerance: T = T(1e-5),
    absoluteTolerance: T = T(1e-8),
    _ message: @autoclosure () -> String = "",
    _ file: StaticString = #filePath,
    _ line: UInt = #line) rethrows
{
    let a = try expression1()
    XCTAssert(a.isFinite)
    let b = try expression2()
    XCTAssert(b.isFinite)

    let isClose = abs(a - b) <= absoluteTolerance + relativeTolerance * abs(b)
    XCTAssert(isClose, "\(a) is not close to \(b). \(message())", file: file, line: line)
}

/// Asserts that an expression throws a specified error.
/// - Parameters:
///   - expression: The expression to evaluate.
///   - error: The expected thrown error.
///   - message: An optional description of a failure.
///   - file: The file where the failure occurs. The default is the filename of the test case where you call this
/// function.
///   - line: The line number where the failure occurs. The default is the line number where you call this function.
package func XCTAssertThrowsError<E: Error & Equatable>(
    _ expression: @autoclosure () throws -> some Any,
    error: E,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line)
{
    XCTAssertThrowsError(try expression(), message(), file: file, line: line) { foundError in
        XCTAssertEqual(foundError as? E, error, message(), file: file, line: line)
    }
}

/// A simple random number generator used for testing.
///
/// This generates an arithmetic sequence by incrementing a UInt64 counter using wrapping arithmetic.
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
    /// Initializes a byte array from a hexadecimal string.
    ///
    /// Initializes to nil upon invalid hexadecimal string.
    /// - Parameter hexString: A hexadecimal string, without leading "0x".
    package init?(hexEncoded hexString: String) {
        // Ensure the string has an even number of characters
        guard hexString.count.isMultiple(of: 2) else {
            return nil
        }

        var data = Array()
        data.reserveCapacity(hexString.count / 2)
        var index = hexString.startIndex

        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            if let byte = UInt8(hexString[index..<nextIndex], radix: 16) {
                data.append(byte)
            } else {
                return nil // Invalid hex string
            }
            index = nextIndex
        }

        self = data
    }

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

package enum TestUtils {
    /// A polynomial degree suitable for testing.
    package static let testPolyDegree = 16
    /// A plaintext modulus suitable for testing.
    package static let testPlaintextModulus = 1153
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

    /// Returns the expected number of bins with "count" balls, assuming
    /// a total of "num_balls" balls each assigned to a uniform random bin
    /// among "num_bins" bins.
    package static func expectedBallsInBinsCount(binCount: Int, ballCount: Int, count: Int) -> Double {
        // Pr(ballCount in first bin == count)
        let n = ballCount
        let k = count
        let p = 1 / Double(binCount)
        let q = 1.0 - p
        let binomialCoefficient = binomialCoefficient(n: n, k: k)
        // Probability mass function of binomial distribution
        let probabilityOfExactlyCountBallsInFirstBin = binomialCoefficient * Double.pow(p, Double(k)) * Double.pow(
            q,
            Double(n - k))
        // Linearity of expectation
        return Double(binCount) * probabilityOfExactlyCountBallsInFirstBin
    }

    package static func getRandomPlaintextData<T: ScalarType>(count: Int,
                                                              in range: Range<T>) -> [T]
    {
        (0..<count).map { _ in T.random(in: range) }
    }

    package static func uniformnessTest<T>(poly: PolyRq<T, some Any>) {
        XCTAssert(poly.isValidData())
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

                XCTAssertIsClose(expectedCount, Double(observedCount), relativeTolerance: 0.2, absoluteTolerance: 11.0)
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
        XCTAssert(poly.isValidData())
        let variance = computeVariance(poly: poly)
        let bounds = 9.0..<12.0
        XCTAssert(bounds.contains(variance), "variance \(variance) not in bounds \(bounds)")

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
                XCTFail("RNS coefficient too large: \(crtForm)")
            }
        }

        // Check distribution is zero-mean
        let mean = Double(sum) / Double(poly.degree)
        XCTAssertLessThan(abs(mean), 0.2)
    }

    package static func ternaryDistributionTest(poly: PolyRq<some Any, some Any>, pValue: Double) {
        XCTAssert(poly.isValidData())
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
            default: XCTFail("Invalid value in polynomial, residues: \(crt)")
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
        XCTAssertGreaterThan(observedPValue, pValue)
    }
}

extension TestUtils {
    package static func testCoefficientModuli<T: ScalarType>(_: T.Type) throws -> [T] {
        if T.self == UInt32.self {
            return try T.generatePrimes(
                significantBitCounts: [28, 28, 28, 28],
                preferringSmall: false,
                nttDegree: TestUtils.testPolyDegree)
        }
        if T.self == UInt64.self {
            return try T.generatePrimes(
                significantBitCounts: [55, 55, 55, 55],
                preferringSmall: false,
                nttDegree: TestUtils.testPolyDegree)
        }
        preconditionFailure("Unsupported scalar type \(T.self)")
    }

    package static func getTestEncryptionParameters<Scheme: HeScheme>() throws -> EncryptionParameters<Scheme> {
        try EncryptionParameters<Scheme>(
            polyDegree: testPolyDegree,
            plaintextModulus: Scheme.Scalar(testPlaintextModulus),
            coefficientModuli: testCoefficientModuli(Scheme.Scalar.self),
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.unchecked)
    }

    package static func getTestContext<Scheme: HeScheme>() throws -> Context<Scheme> {
        try Context<Scheme>(encryptionParameters: getTestEncryptionParameters())
    }
}
