// Example for noise budget: ``Ciphertext/noiseBudget(using:variableTime:)``.

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

// snippet.hide
// For this example, we add a helper function which checks decryption
// followed by decoding matches the expected value.
func checkDecryptsDecodes<Scheme: HeScheme>(
    _ ciphertext: Ciphertext<Scheme, some PolyFormat>,
    using secretKey: SecretKey<Scheme>,
    format: EncodeFormat,
    to expected: [Scheme.Scalar],
    _ message: @autoclosure () -> String = "",
    _ file: StaticString = #filePath,
    _ line: UInt = #line) throws
{
    let plaintext = try ciphertext.decrypt(using: secretKey)
    let decryptedData: [Scheme.Scalar] = try plaintext.decode(format: format)
    precondition(
        decryptedData == expected,
        """
        checkDecryptsDecodes failure:\(message()) at \(file):\(line). \
        Expected \(expected), got \(decryptedData)
        """)
}

// snippet.show
// We start by choosing some encryption parameters for the Bfv<UInt32> scheme.
let encryptionParameters =
    try EncryptionParameters<Bfv<UInt32>>(from: .insecure_n_8_logq_5x18_logt_5)
// Perform pre-computation for HE computation with these parameters.
let context = try Context(encryptionParameters: encryptionParameters)

// We encode N values in coefficient format and SIMD encoding.
let values = (0..<8).map { UInt32($0) }
let plaintext: Bfv<UInt32>.CoeffPlaintext = try context.encode(
    values: values,
    format: .simd)

// We generate a secret key and encrypt the plaintext.
let secretKey = try context.generateSecretKey()
var ciphertext = try plaintext.encrypt(using: secretKey)

// The noiseBudget of a ciphertext is a measure of how many encrypted operations
// can be performed on it, before decryption is no longer accurate. Noise is
// first added during encryption, and increases during each HE operation,
// thereby decreasing the noise budget. Different operations increase the noise
// by different amounts. The initial noise budget is determined by the ratio
// log2(q) / log2(t) in the encryption parameters. Larger q or smaller t yields
// a larger noise budget. We use `variableTime` to indicate this operation's
// runtime may depend on the secret key, presenting a possible side-channel
// attack. To avoid this side channel, simply avoid calling the noiseBudget
// function.
var noiseBudget = try ciphertext.noiseBudget(
    using: secretKey,
    variableTime: true)
// snippet.hide
print("noiseBudget after encryption:      \(noiseBudget)")
// snippet.show

// Adding a ciphertext with itself decreases the noise budget by 1.
try ciphertext += ciphertext
let noiseBudgetAfterAddition = try ciphertext.noiseBudget(
    using: secretKey,
    variableTime: true)
// snippet.hide
print("noiseBudget after addition:        \(noiseBudgetAfterAddition)")
// snippet.show
precondition(noiseBudgetAfterAddition == noiseBudget - 1)

// Multiplication increases the noise budget more than addition
try ciphertext *= ciphertext
let noiseBudgetAfterMultiplication = try ciphertext.noiseBudget(
    using: secretKey,
    variableTime: true)
// snippet.hide
print("noiseBudget after multiplication:  \(noiseBudgetAfterMultiplication)")
// snippet.show
precondition(noiseBudgetAfterMultiplication < noiseBudgetAfterAddition - 3)

// Relinearization and other EvaluationKey operations typically don't
// meaningfully affect the noise budget, when encryption parameters are chosen
// with the last ciphertext modulus at least as large as all the other
// ciphertext moduli.
let evaluationKeyConfig = EvaluationKeyConfiguration(hasRelinearizationKey: true)
let evaluationKey = try context.generateEvaluationKey(
    configuration: evaluationKeyConfig,
    using: secretKey)
try ciphertext.relinearize(using: evaluationKey)
let noiseBudgetAfterRelinearization = try ciphertext.noiseBudget(
    using: secretKey,
    variableTime: true)
// snippet.hide
print("noiseBudget after relinearization: \(noiseBudgetAfterRelinearization)")
// snippet.show
precondition(noiseBudgetAfterRelinearization > noiseBudgetAfterMultiplication -
    1)

// Once the noise budget budget is below the minimum, decryption yields
// inaccurate results.
let minNoiseBudget = Bfv<UInt32>.minNoiseBudget
// snippet.hide
print("Minimum noise budget", Bfv<UInt32>.minNoiseBudget)
// snippet.show
noiseBudget = noiseBudgetAfterRelinearization
ciphertext = try plaintext.encrypt(using: secretKey)
var expected = plaintext
while noiseBudget > minNoiseBudget {
    let decrypted = try ciphertext.decrypt(using: secretKey)
    precondition(decrypted == expected)
    try ciphertext += ciphertext
    try expected += expected
    noiseBudget = try ciphertext.noiseBudget(
        using: secretKey,
        variableTime: true)
    // snippet.hide
    print("noiseBudget after addition:", noiseBudget)
    // snippet.show
}

// One more addition yields incorrect results
ciphertext = try ciphertext + ciphertext
try expected += expected
let decrypted = try ciphertext.decrypt(using: secretKey)
precondition(decrypted != expected)
