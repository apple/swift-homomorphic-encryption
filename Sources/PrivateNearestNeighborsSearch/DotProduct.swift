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

import Foundation

/// Pre-computed values for matrix-vector multiplication using baby-step, giant-step algorithm.
///
/// - seealso: Section 6.3 of <https://eprint.iacr.org/2018/244.pdf>.
public struct BabyStepGiantStep: Codable, Equatable, Hashable, Sendable {
    /// Dimension of the vector; "D" in the reference.
    public let vectorDimension: Int
    /// Baby step; "g" in the reference.
    public let babyStep: Int
    /// Giant step; "h" in the reference.
    public let giantStep: Int

    /// Creates a new ``BabyStepGiantStep``.
    /// - Parameters:
    ///   - vectorDimension: Number of entries in each vector.
    ///   - babyStep: Baby step.
    ///   - giantStep: Giant step.
    public init(vectorDimension: Int, babyStep: Int, giantStep: Int) {
        self.vectorDimension = vectorDimension
        self.babyStep = babyStep
        self.giantStep = giantStep
    }

    /// Creates a new ``BabyStepGiantStep``.
    /// - Parameter vectorDimension: Number of entries in each vector.
    public init(vectorDimension: Int) {
        let dimension = Int32(vectorDimension).nextPowerOfTwo
        let babyStep = Int32(Double(dimension).squareRoot().rounded(.up))
        let giantStep = dimension.dividingCeil(babyStep, variableTime: true)

        self.init(vectorDimension: Int(dimension), babyStep: Int(babyStep), giantStep: Int(giantStep))
    }
}
