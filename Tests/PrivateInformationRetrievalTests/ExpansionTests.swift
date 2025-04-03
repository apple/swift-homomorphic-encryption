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

import _TestUtilities
import HomomorphicEncryption
import PrivateInformationRetrieval
import Testing

@Suite
struct ExpansionTests {
    @Test(arguments: PirKeyCompressionStrategy.allCases)
    func expandCiphertextForOneStepTest(keyCompression: PirKeyCompressionStrategy) throws {
        try PirTestUtils.ExpansionTests.expandCiphertextForOneStep(scheme: NoOpScheme.self, keyCompression)
        try PirTestUtils.ExpansionTests.expandCiphertextForOneStep(scheme: Bfv<UInt32>.self, keyCompression)
        try PirTestUtils.ExpansionTests.expandCiphertextForOneStep(scheme: Bfv<UInt64>.self, keyCompression)
    }

    @Test
    func oneCiphertextRoundtrip() throws {
        try PirTestUtils.ExpansionTests.oneCiphertextRoundtrip(scheme: NoOpScheme.self)
        try PirTestUtils.ExpansionTests.oneCiphertextRoundtrip(scheme: Bfv<UInt32>.self)
        try PirTestUtils.ExpansionTests.oneCiphertextRoundtrip(scheme: Bfv<UInt64>.self)
    }

    @Test
    func multipleCiphertextsRoundtrip() throws {
        try PirTestUtils.ExpansionTests.multipleCiphertextsRoundtrip(scheme: NoOpScheme.self)
        try PirTestUtils.ExpansionTests.multipleCiphertextsRoundtrip(scheme: Bfv<UInt32>.self)
        try PirTestUtils.ExpansionTests.multipleCiphertextsRoundtrip(scheme: Bfv<UInt64>.self)
    }
}
