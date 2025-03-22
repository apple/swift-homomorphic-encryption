// Copyright 2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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

import Benchmark

let noiseBudgetScale = 10

extension BenchmarkMetric {
    static var querySize: Self { .custom("Query byte size") }
    static var queryCiphertextCount: Self { .custom("Query ciphertext count") }
    static var evaluationKeySize: Self { .custom("Evaluation key byte size") }
    static var evaluationKeyCount: Self { .custom("Evaluation key count") }
    static var responseSize: Self { .custom("Response byte size") }
    static var responseCiphertextCount: Self { .custom("Response ciphertext count") }
    static var noiseBudget: Self { .custom("Noise budget x \(noiseBudgetScale)") }
}
