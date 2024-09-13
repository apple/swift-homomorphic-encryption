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

extension PolyRq {
    /// Generate a polynomial with uniform random coefficients.
    /// - Parameter context: Context for the generated polynomial.
    /// - Returns: The generated random polynomial.
    @inlinable
    public static func random(context: PolyContext<T>) -> Self {
        var rng = SystemRandomNumberGenerator()
        return Self.random(context: context, using: &rng)
    }

    ///  Generate a polynomial with uniform random coefficients.
    /// - Parameters:
    ///   - context: Context for the generated polynomial.
    ///   - rng: Random number generator to use.
    /// - Returns: The generated random polynomial.
    @inlinable
    public static func random(context: PolyContext<T>, using rng: inout some PseudoRandomNumberGenerator) -> Self {
        var poly = Self.zero(context: context)
        poly.randomizeUniform(using: &rng)
        return poly
    }

    /// Fills the polynomial with uniform random values.
    @inlinable
    public mutating func randomizeUniform() {
        // We can sample directly in Coeff or Eval domain
        var rng = SystemRandomNumberGenerator()
        randomizeUniform(using: &rng)
    }

    /// Fills the polynomial with uniformly random values.
    ///
    /// Requests a uniformly random u128 and uses modular reduction to reduce it
    /// to the right range.
    /// > Note: this isn't strictly uniform at random, but the bias is negligible
    /// for `moduli < 2^64`. See A.5.3 of
    /// <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf>.
    /// - Parameter rng: Random number generator to use.
    @inlinable
    public mutating func randomizeUniform(using rng: inout some PseudoRandomNumberGenerator) {
        let chunkCount = min(degree, 1024)
        let uint128ByteCount = MemoryLayout<UInt128>.size
        var randomBytes: [UInt8] = .init(repeating: 0, count: chunkCount * uint128ByteCount)
        // We can sample directly in Coeff or Eval domain
        for (rnsIndex, reduceModulus) in context.reduceModuliUInt64.enumerated() {
            for coeffIndex in stride(from: 0, to: degree, by: chunkCount) {
                rng.fill(&randomBytes)
                let offset = polyIndices(rnsIndex: rnsIndex).startIndex + coeffIndex
                for index in 0..<chunkCount {
                    // NOTE: for interoperability always ask rng for a UInt128 and reduces it
                    let u128 =
                        UInt128(littleEndianBytes: randomBytes[index * uint128ByteCount..<(index + 1) *
                                uint128ByteCount])
                    let u64 = reduceModulus.reduce(u128)
                    self[offset + index] = T(u64)
                }
            }
        }
    }

    /// Fills the polynomial with ternary values `[-1, 0, 1]`.
    @inlinable
    public mutating func randomizeTernary() where F == Coeff {
        var rng = SystemRandomNumberGenerator()
        randomizeTernary(using: &rng)
    }

    /// Fills the polynomial with ternary values `[-1, 0, 1]`.
    /// - Parameter rng: Random number generator to use.
    @inlinable
    public mutating func randomizeTernary(using rng: inout some PseudoRandomNumberGenerator) where F == Coeff {
        let reductionModulus = ReduceModulus(modulus: UInt64(3), bound: .DoubleWord, variableTime: true)
        for coeffIndex in coeffIndices {
            // sample 64 + 32 bits, that is at least 64 bits more than we need as prescribed
            // by NIST in Section A.5.3 of
            // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf.
            // Note: this is a bit faster than just using u128, because less randomness gets
            // consumed for each coefficient.
            let u64: UInt64 = rng.next()
            let u32: UInt32 = rng.next()
            let u128 = UInt128(u64) &<< 32 | UInt128(u32)

            let val = T(reductionModulus.reduce(u128))
            for (index, modulus) in zip(rnsIndices(coeffIndex: coeffIndex), moduli) {
                self[index] = val.subtractMod(1, modulus: modulus)
            }
        }
    }

    /// Fills the polynomial with coefficients drawn from a centered binomial distribution.
    ///
    /// - Parameter standardDeviation: Standard deviation of the distribution.
    @inlinable
    public mutating func randomizeCenteredBinomialDistribution(standardDeviation: Double) where F == Coeff {
        var rng = SystemRandomNumberGenerator()
        randomizeCenteredBinomialDistribution(standardDeviation: standardDeviation, using: &rng)
    }

    /// Fills the polynomial with coefficients drawn from a centered binomial distribution.
    /// - Parameters:
    ///   - standardDeviation: Standard deviation of the distribution.
    ///   - rng: Random number generator to use.
    @inlinable
    public mutating func randomizeCenteredBinomialDistribution(
        standardDeviation: Double,
        using rng: inout some PseudoRandomNumberGenerator) where F == Coeff
    {
        // figure out n based on the noise std dev.
        // variance = npq, p = q = 0.5
        // n = variance / pq
        // n = 4 * variance
        // let k = n / 2
        // k = 2 * variance
        let variance = standardDeviation * standardDeviation
        let k = Int((2 * variance).rounded(.up))
        let numberOfUint64sPerTrial = 2 * k.dividingCeil(UInt64.bitWidth, variableTime: true)
        var trialBits = [UInt64](repeating: 0, count: numberOfUint64sPerTrial)

        let half = numberOfUint64sPerTrial >> 1
        let mask = if !k.isMultiple(of: UInt64.bitWidth) {
            (UInt64(1) << (k % UInt64.bitWidth)) - 1
        } else {
            // do not mask any bits, if 64 divides k
            UInt64.max
        }

        for coeffIndex in coeffIndices {
            // fill trial bits
            trialBits.indices.forEach { trialBits[$0] = rng.next() }
            // mask off unneeded bits
            trialBits[half - 1] &= mask
            trialBits[numberOfUint64sPerTrial - 1] &= mask

            // count positive bits
            let positiveCount = trialBits[..<half].reduce(0) { partialResult, trial in
                partialResult + trial.nonzeroBitCount
            }

            // count negative bits
            let negativeCount = trialBits[half...].reduce(0) { partialResult, trial in
                partialResult + trial.nonzeroBitCount
            }

            let pos = T(positiveCount)
            let neg = T(negativeCount)

            for (index, modulus) in zip(rnsIndices(coeffIndex: coeffIndex), moduli) {
                self[index] = pos.subtractMod(neg, modulus: modulus)
            }
        }
    }
}
