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

import _CryptoExtras
import Crypto
import Foundation

/// Random number generator.
///
/// Implements the NIST `CTR_DRBG` using AES without derivation function.
/// Description is in NIST SP 800-90A:
/// <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf>.
public struct NistCtrDrbg {
    static let ReseedInterval: Int64 = 1 << 48
    static let MaxByteCountPerRequest: Int = 1 << 16
    /// Size of AES block.
    static let BlockCount: Int = 16
    /// Size of AES key.
    static let KeyCount: Int = 16
    /// Size of the seed.
    static let SeedCount: Int = KeyCount + BlockCount

    var key: SymmetricKey
    /// This is called `V` in the NIST specification.
    var nonce: DWUInt128
    var reseedCounter: Int64

    var nonceBytes: [UInt8] {
        // Because of a mismatch between pre-increment & post-increment we always implicitly add one to the nonce before
        // we call `AES._CTR.encrypt()`
        (nonce &+ 1).bigEndianBytes
    }

    init(entropy: [UInt8] = [UInt8](
        randomByteCount: Self.SeedCount)) throws
    {
        self.key = SymmetricKey(data: [UInt8](repeating: 0, count: Self.KeyCount))
        self.nonce = 0
        self.reseedCounter = 1
        try ctrDrbgUpdate(providedData: entropy)
    }

    mutating func ctrDrbgUpdate(providedData: [UInt8]) throws {
        precondition(providedData.count == Self.SeedCount)

        let xor = try AES._CTR.encrypt(providedData, using: key, nonce: .init(nonceBytes:
            nonceBytes))
        key = SymmetricKey(data: xor.prefix(Self.KeyCount))
        nonce = .init(bigEndianBytes: xor.suffix(Self.BlockCount))
    }

    mutating func ctrDrbgGenerate(count: Int) throws -> [UInt8] {
        let requestedByteCount = count
        precondition(reseedCounter <= Self.ReseedInterval)
        precondition(requestedByteCount <= Self.MaxByteCountPerRequest)

        let zeroes = [UInt8](repeating: 0, count: requestedByteCount)
        let output = try AES._CTR.encrypt(zeroes, using: key, nonce: .init(nonceBytes: nonceBytes))
        nonce &+= DWUInt128(requestedByteCount.dividingCeil(Self.BlockCount, variableTime: true))

        let additionalInput = [UInt8](repeating: 0, count: Self.SeedCount)
        try ctrDrbgUpdate(providedData: additionalInput)

        reseedCounter &+= 1
        return Array(output)
    }
}

extension NistCtrDrbg: PseudoRandomNumberGenerator {
    /// Fills a buffer with random values.
    /// - Parameter bufferPointer: Buffer to fill.
    public mutating func fill(_ bufferPointer: UnsafeMutableRawBufferPointer) {
        do {
            let data = try ctrDrbgGenerate(count: bufferPointer.count)
            data.withUnsafeBytes { dataPointer in
                bufferPointer.copyMemory(from: dataPointer)
            }
        } catch {
            preconditionFailure("NistCtrDrbg failed: \(error)")
        }
    }
}

extension [UInt8] {
    @inlinable
    init(randomByteCount: Int) {
        self = .init(repeating: 0, count: randomByteCount)
        var rng = SystemRandomNumberGenerator()
        rng.fill(&self)
    }
}
