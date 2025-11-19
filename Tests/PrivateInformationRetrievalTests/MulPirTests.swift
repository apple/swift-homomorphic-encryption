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
@testable import PrivateInformationRetrieval
import Testing

@Suite
struct MulPirTests {
    @Test
    func evaluationKeyConfig() throws {
        try PirTestUtils.MulPirTests.evaluationKeyConfig(scheme: NoOpScheme.self)
        try PirTestUtils.MulPirTests.evaluationKeyConfig(scheme: Bfv<UInt32>.self)
        try PirTestUtils.MulPirTests.evaluationKeyConfig(scheme: Bfv<UInt64>.self)
    }

    @Test(arguments: PirKeyCompressionStrategy.allCases)
    func queryGeneration(keyCompression: PirKeyCompressionStrategy) async throws {
        try await PirTestUtils.MulPirTests.queryGenerationTest(pirUtil: PirUtil<NoOpScheme>.self, keyCompression)
        try await PirTestUtils.MulPirTests.queryGenerationTest(pirUtil: PirUtil<Bfv<UInt32>>.self, keyCompression)
        try await PirTestUtils.MulPirTests.queryGenerationTest(pirUtil: PirUtil<Bfv<UInt64>>.self, keyCompression)
    }

    @Test
    func computeCoordinates() throws {
        try PirTestUtils.MulPirTests.computeCoordinates(pirUtil: PirUtil<NoOpScheme>.self)
        try PirTestUtils.MulPirTests.computeCoordinates(pirUtil: PirUtil<Bfv<UInt32>>.self)
        try PirTestUtils.MulPirTests.computeCoordinates(pirUtil: PirUtil<Bfv<UInt64>>.self)
    }
}
