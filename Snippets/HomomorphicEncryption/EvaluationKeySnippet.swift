// Example using an ``EvaluationKey``.

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

// We start by choosing some encryption parameters for the Bfv<UInt32> scheme.
precondition(PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
    .supportsScalar(Bfv<UInt32>.Scalar.self))
let encryptionParameters =
    try EncryptionParameters<Bfv<UInt32>>(from: .insecure_n_8_logq_5x18_logt_5)
precondition(encryptionParameters.plaintextModulus == 17)
// Perform pre-computation for HE computation with these parameters.
let context = try Context(encryptionParameters: encryptionParameters)

// We encode N values using SIMD encoding.
// Each value is a Bfv<UInt32>.Scalar, which is UInt32.
let values = (0..<8).map { Bfv<UInt32>.Scalar($0) }
let plaintext: Bfv<UInt32>.CoeffPlaintext = try context.encode(
    values: values,
    format: .simd)

// We generate a secret key and encrypt the plaintext.
let secretKey = try context.generateSecretKey()
var ciphertext = try plaintext.encrypt(using: secretKey)

// We generate an evaluation key. This is a key used in some HE operations.
// The evaluation key is derived from a secret key, but is itself public, i.e.,
// doesn't reveal anything about the secret key. The encryption parameters
// must have at least 2 ciphertext moduli,to be compatible with evaluation key
// generation and operations.
//
// With SIMD encoding, the plaintext can be viewed as a 2 x (N / 2) matrix,
// where N is the encryptionParameters.polyDegree. Then, the evaluation key can
// be used to:
// * swap the rows
// * cyclically rotate the columns left or right by fixed amounts
// The evaluation key can also be used used to perform relinearization after
// ciphertext multiplication.
// We generate the evaluation key which can:
// * swap the rows
// * rotate columns by 1, indicating a right rotation
// * rotate the columns by -2, indicating a left rotation
// * relinearize.
let evaluationKeyConfig = try EvaluationKeyConfiguration(
    galoisElements: [
        GaloisElement.swappingRows(degree: encryptionParameters.polyDegree),
        GaloisElement.rotatingColumns(
            by: 1,
            degree: encryptionParameters.polyDegree),
        GaloisElement.rotatingColumns(
            by: -2,
            degree: encryptionParameters.polyDegree),
    ],
    hasRelinearizationKey: true)
let evaluationKey = try context.generateEvaluationKey(
    configuration: evaluationKeyConfig,
    using: secretKey)

// We swap the first row, [0, 1, 2, 3] and the second row, [4, 5, 6, 7].
try ciphertext.swapRows(using: evaluationKey)
try checkDecryptsDecodes(
    ciphertext,
    using: secretKey,
    format: .simd,
    to: [4, 5, 6, 7, 0, 1, 2, 3])

// We swap the rows back to original order.
try ciphertext.swapRows(using: evaluationKey)
try checkDecryptsDecodes(
    ciphertext,
    using: secretKey,
    format: .simd,
    to: [0, 1, 2, 3, 4, 5, 6, 7])

// We can also rotate columns, e.g. right by one.
// So the first row, [0, 1, 2, 3], becomes [3, 0, 1, 2],
// and the second row, [4, 5, 6, 7], becomes [7, 4, 5, 6].
try ciphertext.rotateColumns(by: 1, using: evaluationKey)
try checkDecryptsDecodes(
    ciphertext,
    using: secretKey,
    format: .simd,
    to: [3, 0, 1, 2, 7, 4, 5, 6])
// Rotating again, yields rows [2, 3, 0, 1] and [6, 7, 4, 5].
try ciphertext.rotateColumns(by: 1, using: evaluationKey)
try checkDecryptsDecodes(
    ciphertext,
    using: secretKey,
    format: .simd,
    to: [2, 3, 0, 1, 6, 7, 4, 5])

// We can also rotate left by 2 to recover the original value.
try ciphertext.rotateColumns(by: -2, using: evaluationKey)
try checkDecryptsDecodes(
    ciphertext,
    using: secretKey,
    format: .simd,
    to: [0, 1, 2, 3, 4, 5, 6, 7])
// However, we can't rotate left by 1, since our evaluationKeyConfig didn't
// include a step of -1.

// The evaluation key can also be used to "relinearize" ciphertexts after
// ciphertext multiplication. During ciphertext multiplication, the number
// of polynomials in the ciphertext has increased from the original count
// after encryption.
precondition(ciphertext.polyCount == Bfv<UInt32>.freshCiphertextPolyCount)
try ciphertext *= ciphertext
try checkDecryptsDecodes(
    ciphertext,
    using: secretKey,
    format: .simd,
    to: values.map { value in (value * value) % 17 })
precondition(ciphertext.polyCount == Bfv<UInt32>.freshCiphertextPolyCount + 1)

// We can use an evaluation key with a relinearization key to relinearize the
// ciphertext. This performs a "key switching" operation that brings the
// ciphertext polynomial count back to the original count. Relinearization should
// typically be performed immediately after ciphertext multiplication, since
// reducing the polynomial count will make subsequent HE operations on the
// ciphertext faster. However, since relinearization is an expensive operation, a
// common scenario where "lazy relinearization" is ideal is when summing
// together many ciphertext products. In this case, the relinearization can be
// delayed until after the summation, so the relinearization operation is only
// performed once, rather than on every intermediate product.
precondition(evaluationKey.configuration.hasRelinearizationKey)
try ciphertext.relinearize(using: evaluationKey)
precondition(ciphertext.polyCount == Bfv<UInt32>.freshCiphertextPolyCount)
try checkDecryptsDecodes(
    ciphertext,
    using: secretKey,
    format: .simd,
    to: values.map { value in (value * value) % 17 })
