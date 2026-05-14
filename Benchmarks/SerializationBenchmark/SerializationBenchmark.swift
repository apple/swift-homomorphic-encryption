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

// App-level serialization / protobuf-conversion benchmarks for query,
// evaluation key, and response. Use these to measure the effect of @inlinable
// on the client/server serialize paths.
//
// SWIFT_HOMOMORPHIC_ENCRYPTION_ENABLE_BENCHMARKING=1 \
//   swift package benchmark --target SerializationBenchmark

import _BenchmarkUtilities
import HomomorphicEncryption
import PrivateInformationRetrieval

nonisolated(unsafe) let benchmarks: () -> Void = {
    // EvaluationKey serialize + proto/native
    evaluationKeySerializationBenchmarks(Bfv<UInt32>.self)()
    evaluationKeySerializationBenchmarks(Bfv<UInt64>.self)()

    // IndexPir Query / Response proto/native
    indexPirProtoBenchmarks(PirUtil<Bfv<UInt32>>.self)()
    indexPirProtoBenchmarks(PirUtil<Bfv<UInt64>>.self)()

    // PNNS Query / Response proto/native
    pnnsProtoBenchmarks(Bfv<UInt32>.self)()
    pnnsProtoBenchmarks(Bfv<UInt64>.self)()
}
