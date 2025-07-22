// Example for serialization.

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

// We use protocol buffers as a serialization format.
import HomomorphicEncryptionProtobuf

extension SerializedCiphertext {
    /// Returns the approximate size in bytes of the serialized ciphertext.
    ///
    /// As an approximation for compression of zero bytes, ignores zero bytes
    /// from the size.
    func size() throws -> Int {
        let data = try proto().serializedData()
        return data.count { byte in byte != 0 }
    }
}

// We start by choosing some encryption parameters for the Bfv<UInt32> scheme.
let encryptionParameters =
    try EncryptionParameters<UInt32>(from: .n_4096_logq_27_28_28_logt_5)
// Perform pre-computation for HE computation with these parameters.
let context = try Context<Bfv<UInt32>>(encryptionParameters: encryptionParameters)

// We encode some values in coefficient format and coefficient encoding.
let values = (0..<8).map { UInt32($0) }
let plaintext: Bfv<UInt32>.CoeffPlaintext = try context.encode(
    values: values,
    format: .coefficient)

// We generate a secret key and encrypt the plaintext.
let secretKey = try context.generateSecretKey()
var ciphertext: Bfv<UInt32>.CanonicalCiphertext = try plaintext
    .encrypt(using: secretKey)

// A freshly-encrypted ciphertext has one of its 2 polynomials sampled uniformly
// randomly from a seeded random number generator (RNG). We compress such
// ciphertexts by serializing the RNG seed instead of serializing all the
// coefficients for this polynomial.
let serialized = try ciphertext.serialize()
let sizeAfterEncryption = try serialized.size()
// snippet.hide
print("Serialized size after")
print("\tencryption:                        \(sizeAfterEncryption) bytes")
// snippet.show

// We can deserialize the ciphertext, making sure its format is the same as the
// serialized ciphertext.
var deserialized: Bfv<UInt32>.CanonicalCiphertext = try Ciphertext(
    deserialize: serialized,
    context: context)
precondition(deserialized == ciphertext)

// After computing on the ciphertext, we lose the benefit of compressing the
// seed, yielding nearly 2x larger serialization size.
try ciphertext += ciphertext
let expectedValues = values.map { value in (value + value) % 17 }
let sizeAfterAdd = try ciphertext.serialize().size()
// snippet.hide
print("\taddition:                          \(sizeAfterAdd) bytes")
// snippet.show
precondition(sizeAfterAdd > 2 * sizeAfterEncryption - 200)

// After completing an HE computation, we can reduce final ciphertext size by
// mod-switching to a single modulus. This reduces the number of moduli in the
// ciphertext down to one modulus. HE computation on mod-switched ciphertexts
// is typically faster, but with the downside of lower noise budget. The optimal
// time to mod-switch depends on the encrypted computation. But a general
// guideline is to mod-switch to a single ciphertext modulus when no more HE
// computation needs to occur.
try ciphertext.modSwitchDownToSingle()
let sizeAfterModSwitch = try ciphertext.serialize().size()
// snippet.hide
print("\tmod switching:                     \(sizeAfterModSwitch) bytes")
// snippet.show
precondition(sizeAfterModSwitch < sizeAfterAdd)

// If the only operations performed on the ciphertext after serialization are
// deserialization and decryption, we can reduce the serialized size further.
// This setting occurs when a server performs HE computation, and sends the
// result to a client, which decrypts to learn the result.
let serializedForDecryption = try ciphertext.serialize(forDecryption: true)
let sizeForDecryption = try serializedForDecryption.size()
// snippet.hide
print("\tserializing for decryption:        \(sizeForDecryption) bytes")
// snippet.show
precondition(sizeAfterModSwitch < sizeAfterAdd)

var decrypted = try ciphertext.decrypt(using: secretKey)
deserialized = try Ciphertext(
    deserialize: serializedForDecryption,
    context: context,
    moduliCount: 1)
let clientDecryption = try deserialized.decrypt(using: secretKey)
precondition(decrypted == clientDecryption)

// If we additionally only care about certain encrypted indices and use
// coefficient encoding, we can make a more compressible ciphertext.
let indices = [1, 3, 5]
let serializedIndicesForDecryption = try ciphertext.serialize(
    indices: indices,
    forDecryption: true)
let sizeIndicesForDecryption = try serializedIndicesForDecryption.size()
// snippet.hide
print("\tserializing indices for decryption: \(sizeIndicesForDecryption) bytes")
// snippet.show
precondition(sizeIndicesForDecryption < sizeForDecryption)

deserialized = try Ciphertext(
    deserialize: serializedIndicesForDecryption,
    context: context,
    moduliCount: 1)
let decryptedIndices = try deserialized.decrypt(using: secretKey)
let clientDecoded: [UInt32] = try decryptedIndices.decode(format: .coefficient)
for index in indices {
    precondition(clientDecoded[index] == expectedValues[index])
}
