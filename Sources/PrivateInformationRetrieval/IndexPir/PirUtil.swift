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

public import AsyncAlgorithms
public import HomomorphicEncryption
public import ModularArithmetic

/// A protocol  outlining the auxiliary functionalities used in PIR.
public protocol PirUtilProtocol: Sendable {
    /// The underlying HE scheme.
    associatedtype Scheme: HeScheme
    /// The Scalar type used by the HE scheme.
    associatedtype Scalar where Scalar == Scheme.Scalar
    /// HE ciphertext in canonical format.
    typealias CanonicalCiphertext = Scheme.CanonicalCiphertext

    /// Expand a small number of ciphertexts to a large number of ciphertexts.
    ///
    /// Each output will be the encryption of a constant poly, where the constant of i-th output is the i-th coefficient
    /// in the inputs.
    /// - Parameters:
    ///   - ciphertexts: ciphertexts to expand
    ///   - outputCount: how many outputs are expected
    ///   - evaluationKey: evaluation key used for rotation and apply galois
    /// - Returns: the expanded ciphertext
    static func expand(
        ciphertexts: consuming [CanonicalCiphertext],
        outputCount: Int,
        using evaluationKey: EvaluationKey<Scheme>) async throws -> [CanonicalCiphertext]

    /// Compress an binary array into ciphertexts such that the expanded ciphertexts is the original array.
    ///
    /// - Parameters:
    ///        - totalInputCount: the length of the binary array
    ///        - oneIndices: the position of 1s
    ///        - context: the context for HE
    ///        - secretKey: the secret key for encryption.
    static func compressBinaryInputs(
        totalInputCount: Int,
        oneIndices: [Int],
        context: Scheme.Context,
        using secretKey: SecretKey<Scheme>) throws -> [CanonicalCiphertext]
}

extension PirUtilProtocol {
    /// Convert one encrypted polynomial `c` to two encrypted polynomials, `p` and `q`.
    ///
    /// It is guaranteed that:
    /// (1) `p[k*t] = c[k*t]*2` for all `k` where `t = 2^logStep`.
    /// (2) `q[k*t] = c[k*t+offset]*2` for all `k` where `t = 2^logStep` and `offset = 2^{logStep-1}`.
    /// Other coefficients of `p` and `q` are all some linear combination of `c`'s coefficients whose indices are not
    /// multiples of `2^{logStep-1}`.
    /// Therefore, it is recommended to make sure `c` only has non-zero coefficients on positions that are multiples of
    /// `2^{logStep-1}` to avoid unintelligent results.
    /// The algorithm is to first apply a transformation to convert `f(x)` to `f(x^{degree/2^{logStep-1}})`, which flips
    /// the sign of the coefficients at `(2^{logStep}*i + 2^{logStep-1})`-th positions and keeps the coefficients at
    /// `2^{logStep}*i`-th positions. Other coefficients become permutation of original coefficients that are not at
    /// multiples-of-`2^{logStep-1}` positions. After that, sum/subtraction helps cancel coefficients at
    /// `2^{logStep}*i`-th  or `(2^{logStep}*i + 2^{logStep-1})`-th positions. As the last step, shifting by multiplying
    /// the polynomial with `x^-{2^{logStep-1}}` helps compensate for the offset of `2^{logStep-1})`.
    @inlinable
    package static func expandCiphertextForOneStep(
        _ ciphertext: CanonicalCiphertext,
        logStep: Int,
        using evaluationKey: EvaluationKey<Scheme>) async throws -> (CanonicalCiphertext, CanonicalCiphertext)
    {
        let degree = ciphertext.degree
        precondition(logStep <= degree.log2)
        let shiftingPower = 1 << (logStep - 1)

        let targetElement = 1 << (degree.log2 - logStep + 1) + 1
        var c1 = ciphertext

        guard let galoisElement = evaluationKey.config.galoisElements.filter({ element in
            element <= targetElement }).max()
        else {
            throw HeError.missingGaloisKey
        }
        let applyGaloisCount = 1 << ((targetElement - 1).log2 - (galoisElement - 1).log2)
        var currElement = 1
        for await _ in (0..<applyGaloisCount).async {
            try await Scheme.applyGaloisAsync(ciphertext: &c1, element: galoisElement, using: evaluationKey)
            currElement *= galoisElement
            currElement %= (2 * degree)
        }
        precondition(currElement == targetElement)

        var difference = ciphertext
        try await Scheme.subAssignAsync(&difference, c1)
        var differenceCoeff = try await difference.convertToCoeffFormat()
        try await Scheme.multiplyPowerOfXAsync(&differenceCoeff, power: -shiftingPower)
        let differenceCanonical = try await differenceCoeff.convertToCanonicalFormat()
        try await Scheme.addAssignAsync(&c1, ciphertext)
        return (c1, differenceCanonical)
    }

    /// Expand one ciphertext into given number of encrypted constant polynomials.
    ///
    /// The input ciphertext is expected to have zero-coefficient except at multiple-of-2^{logStep-1} positions
    /// Each time, the input ciphertext is expanded to two ciphertexts, containing the even/odd non-zero coefficients,
    /// respectively. These two ciphertexts are used to generate ceil(outputCount/2) and floor(outputCount/2)
    /// ciphertexts, respectively. When only 1 ciphertext is needed to be generated, no further expansion is needed.
    /// If outputCount is a power of two, then every resulting ciphertext will come from same number of expansion where
    /// each expansion will multiply the coefficients by 2.
    /// However when outputCount is not power of two, some of them may experience one less expansion. To make them have
    /// the same blow-up factor, we add the ciphertext to itself when returning.
    @inlinable
    package static func expandCiphertext(
        _ ciphertext: CanonicalCiphertext,
        outputCount: Int,
        logStep: Int,
        expectedHeight: Int,
        using evaluationKey: EvaluationKey<Scheme>) async throws -> [CanonicalCiphertext]
    {
        precondition(outputCount >= 0 && outputCount <= ciphertext.degree)
        var output = ciphertext
        if outputCount == 1 {
            if logStep > expectedHeight {
                return [ciphertext]
            }
            try await Scheme.addAssignAsync(&output, ciphertext)
            return [output]
        }
        let secondHalfCount = outputCount >> 1
        let firstHalfCount = outputCount - secondHalfCount

        let (p0, p1) = try await expandCiphertextForOneStep(
            ciphertext,
            logStep: logStep,
            using: evaluationKey)
        let firstHalf = try await expandCiphertext(
            p0,
            outputCount: firstHalfCount,
            logStep: logStep + 1,
            expectedHeight: expectedHeight,
            using: evaluationKey)
        let secondHalf = try await expandCiphertext(
            p1,
            outputCount: secondHalfCount,
            logStep: logStep + 1,
            expectedHeight: expectedHeight,
            using: evaluationKey)
        return zip(firstHalf.prefix(secondHalfCount), secondHalf).flatMap { [$0, $1] } + firstHalf
            .suffix(firstHalfCount - secondHalfCount)
    }

    /// Expand a ciphertext array into given number of encrypted constant polynomials.
    @inlinable
    public static func expand(ciphertexts: consuming [CanonicalCiphertext],
                              outputCount: Int,
                              using evaluationKey: EvaluationKey<Scheme>) async throws -> [CanonicalCiphertext]
    {
        precondition((ciphertexts.count - 1) * ciphertexts[0].degree < outputCount)
        precondition(ciphertexts.count * ciphertexts[0].degree >= outputCount)
        var remainingOutputs = outputCount
        let lengths: [Int] = ciphertexts.compactMap { ciphertext in
            let outputToGenerate = min(remainingOutputs, ciphertext.degree)
            remainingOutputs -= outputToGenerate
            return outputToGenerate
        }
        let expanded: [[CanonicalCiphertext]] = try await .init((0..<ciphertexts.count).async
            .map { [ciphertexts] ciphertextIndex in
                let outputToGenerate = lengths[ciphertextIndex]
                return try await expandCiphertext(
                    ciphertexts[ciphertextIndex],
                    outputCount: outputToGenerate,
                    logStep: 1,
                    expectedHeight: outputToGenerate.ceilLog2,
                    using: evaluationKey)
            })
        return expanded.flatMap(\.self)
    }

    /// Convert the MulPir indices into a plaintext.
    ///
    /// The MulPir indices are the indices of non-zero results after expansion
    @inlinable
    package static func compressInputsForOneCiphertext(totalInputCount: Int, oneIndices: [Int],
                                                       context: Scheme.Context) throws -> Plaintext<Scheme, Coeff>
    {
        precondition(totalInputCount <= context.degree)
        var rawData: [Scalar] = Array(repeating: 0, count: context.degree)

        let inputCountCeilLog = totalInputCount.ceilLog2
        let inverseInputCountCeilLog = try Scalar(2).powMod(
            exponent: Scalar(inputCountCeilLog),
            modulus: context.plaintextModulus,
            variableTime: true).inverseMod(modulus: context.plaintextModulus, variableTime: true)

        for index in oneIndices {
            rawData[index] = inverseInputCountCeilLog
        }
        return try context.encode(values: rawData, format: .coefficient)
    }

    /// Generate the ciphertext based on the given non-zero positions.
    @inlinable
    public static func compressBinaryInputs(
        totalInputCount: Int,
        oneIndices: [Int],
        context: Scheme.Context,
        using secretKey: SecretKey<Scheme>) throws -> [CanonicalCiphertext]
    {
        var remainingInputs = totalInputCount
        var processedInputCount = 0
        var plaintexts: [Plaintext<Scheme, Coeff>] = []

        while remainingInputs > 0 {
            let numberOfInputsToProcess = min(remainingInputs, context.degree)
            let inputs = oneIndices.filter { x in
                (processedInputCount..<(processedInputCount + numberOfInputsToProcess)).contains(x)
            }.map { $0 - processedInputCount }
            try plaintexts.append(compressInputsForOneCiphertext(
                totalInputCount: numberOfInputsToProcess,
                oneIndices: inputs,
                context: context))
            processedInputCount += numberOfInputsToProcess
            remainingInputs -= numberOfInputsToProcess
        }
        return try plaintexts.map { plaintext in try plaintext.encrypt(using: secretKey) }
    }
}

public enum PirUtil<Scheme: HeScheme>: PirUtilProtocol {}
