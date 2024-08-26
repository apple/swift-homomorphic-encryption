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
@testable import PrivateNearestNeighborsSearch
import TestUtilities
import XCTest

final class UtilsTests: XCTestCase {
    func testdMatrixMultiplication() throws {
        // Int64
        do {
            let x = Array2d<Int64>(data: Array(-3..<3), rowCount: 2, columnCount: 3)
            let y = Array2d<Int64>(data: Array(-6..<6), rowCount: 3, columnCount: 4)
            XCTAssertEqual(x.mul(y, modulus: 100), Array2d(data: [[20, 14, 8, 2], [2, 5, 8, 11]]))
            // Values in [-floor(modulus/2), floor(modulus-1)/2]
            XCTAssertEqual(x.mul(y, modulus: 10), Array2d(data: [[0, 4, -2, 2], [2, -5, -2, 1]]))
        }
        // Float
        do {
            let x = Array2d<Float>(data: Array(-3..<3).map { Float($0) }, rowCount: 2, columnCount: 3)
            let y = Array2d<Float>(data: Array(-6..<6).map { Float($0) }, rowCount: 3, columnCount: 4)
            XCTAssertEqual(x.mul(y), Array2d<Float>(data: [[20.0, 14.0, 8.0, 2.0], [2.0, 5.0, 8.0, 11.0]]))
        }
    }

    func testFixedPointCosineSimilarity() throws {
        let innerDimension = 3
        let x = Array2d<Float>(data: Array(-3..<3).map { Float($0) }, rowCount: 2, columnCount: innerDimension)
        let y = Array2d<Float>(data: Array(-6..<6).map { Float($0) }, rowCount: innerDimension, columnCount: 4)

        let norm = Array2d<Float>.Norm.Lp(p: 2.0)
        let xNormalized = x.normalizedRows(norm: norm)
        let yNormalized = y.transposed().normalizedRows(norm: norm).transposed()
        let expected = xNormalized.mul(yNormalized)

        let scalingFactor = 100
        let modulus = UInt32(scalingFactor * scalingFactor * innerDimension + 1)
        let z = try x.fixedPointCosineSimilarity(y, modulus: modulus, scalingFactor: Float(scalingFactor))

        XCTAssertIsClose(fixedPointCosineSimilarityError(innerDimension: 3, scalingFactor: 100), 0.010025)
        let absoluteError = fixedPointCosineSimilarityError(
            innerDimension: innerDimension,
            scalingFactor: scalingFactor)
        for (got, expected) in zip(z.data, expected.data) {
            XCTAssertIsClose(got, expected, absoluteTolerance: absoluteError)
        }
    }
}
