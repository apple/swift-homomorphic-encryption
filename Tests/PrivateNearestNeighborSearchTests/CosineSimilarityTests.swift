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
@testable import PrivateNearestNeighborSearch
import Testing

@Suite
struct CosineSimilarityTests {
    @Test
    func normalizeRowsAndScale() throws {
        struct TestCase<T: SignedScalarType> {
            let scalingFactor: Float
            let norm: Array2d<Float>.Norm
            let input: [[Float]]
            let normalized: [[Float]]
            let scaled: [[Float]]
            let rounded: [[T]]
        }

        func runTestCase<T: SignedScalarType>(testCase: TestCase<T>) throws {
            let floatMatrix = Array2d<Float>(data: testCase.input)
            let normalized = floatMatrix.normalizedRows(norm: testCase.norm)
            for (normalized, expected) in zip(normalized.data, testCase.normalized.flatMap { $0 }) {
                #expect(normalized.isClose(to: expected))
            }

            let scaled = normalized.scaled(by: testCase.scalingFactor)
            for (scaled, expected) in zip(scaled.data, testCase.scaled.flatMap { $0 }) {
                #expect(scaled.isClose(to: expected))
            }
            let rounded: Array2d<T> = scaled.rounded()
            #expect(rounded.data == testCase.rounded.flatMap { $0 })
        }

        let testCases: [TestCase<Int32>] = [
            TestCase(scalingFactor: 10.0,
                     norm: Array2d<Float>.Norm.Lp(p: 1.0),
                     input: [[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]],
                     normalized: [[1.0 / 3.0, 2.0 / 3.0], [3.0 / 7.0, 4.0 / 7.0], [5.0 / 11.0, 6.0 / 11.0]],
                     scaled: [[10.0 / 3.0, 20.0 / 3.0], [30.0 / 7.0, 40.0 / 7.0], [50.0 / 11.0, 60.0 / 11.0]],
                     rounded: [[3, 7], [4, 6], [5, 5]]),
            TestCase(scalingFactor: 100.0,
                     norm: Array2d<Float>.Norm.Lp(p: 2.0),
                     input: [[3.0, 4.0], [-5.0, 12.0]],
                     normalized: [[3.0 / 5.0, 4.0 / 5.0], [-5.0 / 13.0, 12.0 / 13.0]],
                     scaled: [[300.0 / 5.0, 400.0 / 5.0], [-500.0 / 13.0, 1200.0 / 13.0]],
                     rounded: [[60, 80], [-38, 92]]),
        ]
        for testCase in testCases {
            try runTestCase(testCase: testCase)
        }
    }
}
