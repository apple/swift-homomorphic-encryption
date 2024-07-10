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

/// Random number generator using AES-128 NIST `CTR_DRBG` mode, without derivation function.
public typealias NistAes128Ctr = BufferedRng<NistCtrDrbg>

extension NistAes128Ctr {
    /// Number of bytes in the AES-128 seed.
    public static let SeedCount: Int = NistCtrDrbg.SeedCount

    /// Initializes a ``NistAes128Ctr``.
    public convenience init() {
        do {
            try self.init(rng: NistCtrDrbg(), bufferCount: 4096)
        } catch {
            preconditionFailure("NistAes128Ctr.init failed: \(error)")
        }
    }

    /// Initializes a ``NistAes128Ctr`` with a seed.
    /// - Parameter seed: Seed for the random number generator. Must have ``SeedCount`` bytes.
    /// - Throws: Error upon failure to initialize the random number generator.
    public convenience init(seed: [UInt8]) throws {
        try self.init(rng: NistCtrDrbg(entropy: seed), bufferCount: 4096)
    }
}
