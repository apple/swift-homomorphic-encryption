// Copyright 2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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
public import HomomorphicEncryption

/// Validation results for a single shard.
public struct ShardValidationResult<Scheme: HeScheme> {
    /// An evaluation key.
    public let evaluationKey: EvaluationKey<Scheme>
    /// A query.
    public let query: Query<Scheme>
    /// A response.
    public let response: Response<Scheme>
    /// Minimum noise budget over all responses.
    public let noiseBudget: Double
    /// Server runtimes.
    public let computeTimes: [Duration]
    /// Number of entries per response.
    public let entryCountPerResponse: [Int]

    /// Initializes a ``ShardValidationResult``.
    /// - Parameters:
    ///   - evaluationKey: Evaluation key.
    ///   - query: Query.
    ///   - response: Response.
    ///   - noiseBudget: Noise budget of the response.
    ///   - computeTimes: Server runtime for each trial.
    ///   - entryCountPerResponse: Number of entries in a single PIR response.
    public init(
        evaluationKey: EvaluationKey<Scheme>,
        query: Query<Scheme>,
        response: Response<Scheme>,
        noiseBudget: Double,
        computeTimes: [Duration],
        entryCountPerResponse: [Int])
    {
        self.evaluationKey = evaluationKey
        self.query = query
        self.response = response
        self.noiseBudget = noiseBudget
        self.computeTimes = computeTimes
        self.entryCountPerResponse = entryCountPerResponse
    }
}
