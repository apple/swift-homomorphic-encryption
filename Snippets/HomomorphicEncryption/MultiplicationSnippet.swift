// Example showing HE multiplication.

// snippet.hide
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
// snippet.show

import HomomorphicEncryption

// For this example, we make use of SIMD encoding. In SIMD format, addition and
// multiplication are performed element-wise on the encoded values. By contrast,
// in coefficient format, addition is element-wise, but multiplication is a
// negacyclic convolution of coefficients.
precondition(PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
    .supportsSimdEncoding)

// We start by choosing some encryption parameters for the Bfv<UInt32> scheme.
// When all the coefficient moduli are small enough, using UInt32 can yield
// significant speedups compared to UInt64.
precondition(PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
    .supportsScalar(UInt32.self))
let encryptParams =
    try EncryptionParameters<UInt32>(from: .insecure_n_8_logq_5x18_logt_5)
precondition(encryptParams.plaintextModulus == 17)
// Perform pre-computation for HE computation with these parameters.
let context = try Bfv<UInt32>.Context(encryptionParameters: encryptParams)

// We don't need to use all the slots in the encoding.
// However, performing HE operations on ciphertexts with fewer slots doesn't give
// any runtime savings.
let valueCount = encryptParams.polyDegree / 2
let values = (0..<valueCount).map { UInt32($0) }
let plaintext = try context.encode(values: values, format: .simd)

// We generate a secret key and encrypt the plaintext.
let secretKey = try context.generateSecretKey()
let ciphertext = try plaintext.encrypt(using: secretKey)

// Multiplication requires the ciphertext and plaintext to be in Evaluation
// format.
let evalCiphertext = try ciphertext.convertToEvalFormat()
let evalPlaintext = try plaintext.convertToEvalFormat()

// The result decrypts to an element-wise product of the values,
// mod the plaintext modulus, 17 in this case.
let product = try evalCiphertext * evalPlaintext
var plaintextProduct = try product.decrypt(using: secretKey)
var decoded: [UInt32] = try plaintextProduct.decode(format: .simd)
precondition(Array(decoded[0..<valueCount]) == values.map { ($0 * $0) % 17 })

// We can also multiply two ciphertexts, which requires changing back to the
// canonical format.
var canonicalProduct = try product.convertToCanonicalFormat()
try canonicalProduct *= ciphertext
plaintextProduct = try canonicalProduct.decrypt(using: secretKey)
decoded = try plaintextProduct.decode(format: .simd)
precondition(Array(decoded[0..<valueCount]) == values
    .map { ($0 * $0 * $0) % 17 })
