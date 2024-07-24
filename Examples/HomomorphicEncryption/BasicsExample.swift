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

func runBasicsExample() throws {
    // We start by choosing some encryption parameters for the ``Bfv<UInt64>`` scheme.
    let encryptionParameters = try EncryptionParameters<Bfv<UInt64>>(from: .insecure_n_8_logq_5x18_logt_5)
    precondition(encryptionParameters.plaintextModulus == 17)
    // Perform pre-computation for the HE compute.
    let context = try Context(encryptionParameters: encryptionParameters)

    // We encode `N` values in ``CoeffPlaintext`` format and ``.coefficient`` encoding.
    // The plaintext's coefficients are simply a list of the encoded values.
    let values = (0..<8).map { UInt64($0) }
    let plaintext: Bfv<UInt64>.CoeffPlaintext = try context.encode(values: values, format: .coefficient)
    precondition(plaintext.poly.poly(rnsIndex: 0) == values)

    // We generate a secret key and encrypt the plaintext.
    let secretKey = try context.generateSecretKey()
    let ciphertext = try plaintext.encrypt(using: secretKey)

    // Adding the ciphertext with the plaintext yields decrypted values with
    // element-wise summation mod 17, the plaintext modulus.
    var sum = try ciphertext + plaintext
    var plaintextSum = try sum.decrypt(using: secretKey)
    var decoded: [UInt64] = try context.decode(plaintext: plaintextSum, format: .coefficient)
    precondition(decoded == [0, 2, 4, 6, 8, 10, 12, 14])

    // Adding the plaintext once more, yields values which wrap around the plaintext modulus.
    try sum += plaintext
    plaintextSum = try sum.decrypt(using: secretKey)
    decoded = try context.decode(plaintext: plaintextSum, format: .coefficient)
    precondition(decoded == [0, 3, 6, 9, 12, 15, 1, 4])

    // Mixing formats between encoding and decoding yields incorrect results.
    decoded = try context.decode(plaintext: plaintextSum, format: .simd)
    precondition(decoded != [0, 3, 6, 9, 12, 15, 1, 4])
}
