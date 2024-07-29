// Choosing encryption parameters.

// snippet.hide
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
// snippet.show

import HomomorphicEncryption

// Choosing encryption parameters is a tricky process, and must typically be
// done separately for each encrypted HE functionality.
// The encryption parameters consist of:
// N - the polynomial modulus degree. Up to N values can be stored in each
//     plaintext and ciphertext. Larger N yields higher security, but slower
//     runtimes.
// q - the coefficient modulus, a product of coefficient moduli. Larger q yields
//     more noise budget, but lower security (which can be mitigated by
//     increasing N). The last modulus in q is reserved for key-switching.
// t - the plaintext modulus. HE operations yield plaintext operations mod t.
//     A larger t reduces the noise budget, but increases the plaintext space.
//     Depending on the circuit, it may be desirable to ensure the plaintext
//     underlying the ciphertexts values do not exceed t throughout the
//     encrypted computation.

// A simple process for choosing parameters is to use one of the pre-defined
// encryption parameters. Generally, the coefficient moduli should all be as
// large as possible, while remaining under the maxLog2CoefficientModulus, and
// as close to the same size as possible.
let params4096 =
    try EncryptionParameters<Bfv<UInt64>>(from: .n_4096_logq_27_28_28_logt_5)
let params8192 =
    try EncryptionParameters<Bfv<UInt64>>(from: .n_8192_logq_3x55_logt_24)

// We can also create custom parameters.
// For instance, for a very small HE circuit, N=2048 might suffice.
// To maintain security, we ensure the coefficient modulus does not exceed the
// maximum log2 coefficient modulus for post-quantum 128-bit security.
let degree = 2048
let maxLog2Q = try EncryptionParameters<Bfv<UInt64>>.maxLog2CoefficientModulus(
    degree: degree,
    securityLevel: .quantum128)
precondition(maxLog2Q == 41)
// We can also stay in the range for 32-bit moduli, for faster runtimes.
let max2BitModulus = EncryptionParameters<Bfv<UInt32>>.maxSingleModulus
precondition(max2BitModulus.ceilLog2 == 30)

// The coefficient moduli must be NTT-friendly, so we set nttDegree: degree.
// We prefer moduli as close to the limit as possible, so we set
// preferringSmall: false.
let coefficientModuli = try UInt32
    .generatePrimes(
        significantBitCounts: [30],
        preferringSmall: false,
        nttDegree: degree)
// The plaintext modulus only needs to be NTT-friendly for SIMD encoding, so we
// omit the nttDegree argument. We typically choose the plaintext modulus near
// the low end of the bitwidth, as we typically encode up to floor(log2(t)) bits
// per coefficient. So choosing a larger t with the same bitwidth just reduces
// the noise budget, with no extra encoding capacity.
let plaintextModulus = try UInt32.generatePrimes(
    significantBitCounts: [14],
    preferringSmall: false)[0]
// This custom parameter set has only a single coefficient modulus, so it is not
// compatible with evaluation key operations.
let customParams = try EncryptionParameters<Bfv<UInt32>>(
    polyDegree: degree,
    plaintextModulus: plaintextModulus,
    coefficientModuli: coefficientModuli,
    errorStdDev: .stdDev32,
    securityLevel: .quantum128)
precondition(!customParams.supportsSimdEncoding)
precondition(!customParams.supportsEvaluationKey)

// snippet.hide
func summarize<Scheme: HeScheme>(
    parameters: EncryptionParameters<Scheme>) throws
{
    let values = (0..<8).map { Scheme.Scalar($0) }
    let context = try Context(encryptionParameters: parameters)
    let plaintext: Scheme.CoeffPlaintext = try context.encode(
        values: values,
        format: .coefficient)
    let secretKey = try context.generateSecretKey()
    let ciphertext = try plaintext.encrypt(using: secretKey)
    let noiseBudget = try ciphertext.noiseBudget(
        using: secretKey,
        variableTime: true)
    print(
        """
        \(parameters.description)
        noise budget: \(noiseBudget)
        supportsSimdEncoding: \(parameters.supportsSimdEncoding),
        supportsEvaluationKey: \(parameters.supportsEvaluationKey),
        bytesPerPlaintext: \(parameters.bytesPerPlaintext)\n
        """)
}

try summarize(parameters: customParams)
try summarize(parameters: params4096)
try summarize(parameters: params8192)
