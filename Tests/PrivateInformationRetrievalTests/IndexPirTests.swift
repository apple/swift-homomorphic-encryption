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
struct IndexPirTests {
    @Test
    func generateParameter() throws {
        let context: Context<UInt64> = try TestUtils.getTestContext()
        // unevenDimensions: false
        do {
            let config = try IndexPirConfig(entryCount: 16,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 1,
                                            unevenDimensions: false,
                                            keyCompression: .noCompression)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            #expect(parameter.dimensions == [4, 4])
        }
        do {
            let config = try IndexPirConfig(entryCount: 10,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: false,
                                            keyCompression: .noCompression)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            #expect(parameter.dimensions == [4, 3])
        }
        // unevenDimensions: true
        do {
            let config = try IndexPirConfig(entryCount: 15,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 1,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            #expect(parameter.dimensions == [5, 3])
        }
        do {
            let config = try IndexPirConfig(entryCount: 15,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            #expect(parameter.dimensions == [5, 3])
        }
        do {
            let config = try IndexPirConfig(entryCount: 17,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            #expect(parameter.dimensions == [9, 2])
        }
        // no key compression
        do {
            let config = try IndexPirConfig(entryCount: 100,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .noCompression)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            let evalKeyConfig = EvaluationKeyConfig(
                galoisElements: [3, 5, 9, 17],
                hasRelinearizationKey: true)
            #expect(parameter.evaluationKeyConfig == evalKeyConfig)
        }
        // hybrid key compression
        do {
            let config = try IndexPirConfig(entryCount: 100,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .hybridCompression)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            let evalKeyConfig = EvaluationKeyConfig(
                galoisElements: [3, 5, 9, 17],
                hasRelinearizationKey: true)
            #expect(parameter.evaluationKeyConfig == evalKeyConfig)
        }
        // max key compression
        do {
            let config = try IndexPirConfig(entryCount: 100,
                                            entrySizeInBytes: context.bytesPerPlaintext,
                                            dimensionCount: 2,
                                            batchSize: 2,
                                            unevenDimensions: true,
                                            keyCompression: .maxCompression)
            let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: config, with: context)
            let evalKeyConfig = EvaluationKeyConfig(
                galoisElements: [3, 5, 9],
                hasRelinearizationKey: true)
            #expect(parameter.evaluationKeyConfig == evalKeyConfig)
        }
    }

    @Test
    func indexPir() throws {
        try PirTestUtils.IndexPirTests.indexPir(scheme: NoOpScheme.self)
        try PirTestUtils.IndexPirTests.indexPir(scheme: Bfv<UInt32>.self)
        try PirTestUtils.IndexPirTests.indexPir(scheme: Bfv<UInt64>.self)
    }
}
