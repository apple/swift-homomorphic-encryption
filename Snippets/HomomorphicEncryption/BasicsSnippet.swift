// Example showing the basics.

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

// snippet.encryption
import HomomorphicEncryption

// We start by choosing some encryption parameters for the Bfv<UInt64> scheme.
// *These encryption parameters are insecure, suitable for testing only.*
let encryptParams =
    try EncryptionParameters<Bfv<UInt64>>(from: .insecure_n_8_logq_5x18_logt_5)
// Perform pre-computation for HE computation with these parameters.
let context = try Context(encryptionParameters: encryptParams)

// We encode N values using coefficient encoding.
let values: [UInt64] = [8, 5, 12, 12, 15, 0, 8, 5]
let plaintext: Bfv<UInt64>.CoeffPlaintext = try context.encode(
    values: values,
    format: .coefficient)

// We generate a secret key and use it to encrypt the plaintext.
let secretKey = try context.generateSecretKey()
var ciphertext = try plaintext.encrypt(using: secretKey)

// Decrypting the plaintext yields the original values.
var decrypted = try ciphertext.decrypt(using: secretKey)
var decoded: [UInt64] = try context.decode(
    plaintext: decrypted,
    format: .coefficient)
precondition(decoded == values)

// Mixing formats between encoding and decoding yields incorrect results.
decoded = try context.decode(plaintext: decrypted, format: .simd)
precondition(decoded != values)

// snippet.addition
// We add the ciphertext with the plaintext, yielding another ciphertext.
var sum = try ciphertext + plaintext
// The ciphertext decrypts to the element-wise sum of the ciphertext's
// and plaintext's values, mod 17, the plaintext modulus.
precondition(encryptParams.plaintextModulus == 17)
var plaintextSum = try sum.decrypt(using: secretKey)
decoded = try context.decode(
    plaintext: plaintextSum,
    format: .coefficient)
precondition(decoded == [16, 10, 7, 7, 13, 0, 16, 10])

// We can also add ciphertexts.
try sum += ciphertext
plaintextSum = try sum.decrypt(using: secretKey)
decoded = try context.decode(
    plaintext: plaintextSum,
    format: .coefficient)
precondition(decoded == [7, 15, 2, 2, 11, 0, 7, 15])
// snippet.end

// snippet.subtraction
// We can subtract a plaintext from a ciphertext.
try sum -= plaintext
plaintextSum = try sum.decrypt(using: secretKey)
decoded = try context.decode(
    plaintext: plaintextSum,
    format: .coefficient)
precondition(decoded == [16, 10, 7, 7, 13, 0, 16, 10])

// We can also subtract a ciphertext from a ciphertext.
try sum -= ciphertext
plaintextSum = try sum.decrypt(using: secretKey)
decoded = try context.decode(
    plaintext: plaintextSum,
    format: .coefficient)
precondition(decoded == [8, 5, 12, 12, 15, 0, 8, 5])

// One special case is when subtracting a ciphertext from itself.
// This yields a "transparent ciphertext", which reveals the underlying
// plaintext to any observer. The observed value in this case is zero.
try sum -= sum
precondition(sum.isTransparent())
