// Copyright 2024-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

// Benchmarks for Pir functions.
// These benchmarks can be triggered with
// SWIFT_HOMOMORPHIC_ENCRYPTION_ENABLE_BENCHMARKING=1 swift package benchmark --target PIRBenchmark

import _BenchmarkUtilities
import HomomorphicEncryption
import PrivateInformationRetrieval

nonisolated(unsafe) let benchmarks: () -> Void = {
    pirProcessBenchmark(PirUtil<Bfv<UInt32>>.self)()
    pirProcessBenchmark(PirUtil<Bfv<UInt64>>.self)()

    indexPirBenchmark(PirUtil<Bfv<UInt32>>.self, callOptions: .multiThreaded)()
    indexPirBenchmark(PirUtil<Bfv<UInt32>>.self, callOptions: .singleThreaded)()
    indexPirBenchmark(PirUtil<Bfv<UInt64>>.self, callOptions: .multiThreaded)()
    indexPirBenchmark(PirUtil<Bfv<UInt64>>.self, callOptions: .singleThreaded)()

    keywordPirBenchmark(PirUtil<Bfv<UInt32>>.self, callOptions: .multiThreaded)()
    keywordPirBenchmark(PirUtil<Bfv<UInt32>>.self, callOptions: .singleThreaded)()
    keywordPirBenchmark(PirUtil<Bfv<UInt64>>.self, callOptions: .multiThreaded)()
    keywordPirBenchmark(PirUtil<Bfv<UInt64>>.self, callOptions: .singleThreaded)()

    // Keyword PIR benchmark with 8K entries of 8KB each.
    // swiftlint:disable:next force_try
    let largeEntryConfig = try! PirBenchmarkConfig<UInt32>(
        databaseConfig: .init(entryCount: 8000, entrySizeInBytes: 8000))
    keywordPirBenchmark(PirUtil<Bfv<UInt32>>.self,
                        config: largeEntryConfig,
                        callOptions: .multiThreaded)()
    keywordPirBenchmark(PirUtil<Bfv<UInt32>>.self,
                        config: largeEntryConfig,
                        callOptions: .singleThreaded)()
}
