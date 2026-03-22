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

// Copyright 2025 Apple Inc. and the Swift Homomorphic Encryption project authors
//
// Licensed under the Apache License, Version 2.0 (the "License")

import HomomorphicEncryption
import PrivateInformationRetrieval
import Testing

struct IndexPirBenchmarkTests {
    @Test
    func pirScaling() async throws {
        // Use parameters from the ParameterTuning doc:
        // n_4096_logq_27_28_28_logt_5 works for wide databases (large values)
        // logt_5 gives enough noise budget for 2D PIR with ct×ct multiply
        let rlweParams: [(PredefinedRlweParameters, String)] = [
            (.n_4096_logq_27_28_28_logt_5, "n4096_logt5"),
        ]

        struct BenchConfig {
            let entryCount: Int
            let entrySize: Int
            let label: String
        }
        let configs: [BenchConfig] = [
            // 500B entries (short passages)
            BenchConfig(entryCount: 3000, entrySize: 500, label: "3K x 500B"),
            BenchConfig(entryCount: 10000, entrySize: 500, label: "10K x 500B"),
            // 2KB entries (longer text)
            BenchConfig(entryCount: 3000, entrySize: 2000, label: "3K x 2KB"),
            BenchConfig(entryCount: 10000, entrySize: 2000, label: "10K x 2KB"),
            // 10KB entries (rich metadata)
            BenchConfig(entryCount: 1000, entrySize: 10000, label: "1K x 10KB"),
            BenchConfig(entryCount: 3000, entrySize: 10000, label: "3K x 10KB"),
            BenchConfig(entryCount: 10000, entrySize: 10000, label: "10K x 10KB"),
        ]

        let clock = ContinuousClock()

        for (params, paramsLabel) in rlweParams {
            let encryptionParameters = try EncryptionParameters<UInt64>(from: params)
            let context = try Bfv<UInt64>.Context(encryptionParameters: encryptionParameters)

            print()
            print("IndexPIR Benchmark (\(paramsLabel))")
            print("  polyDegree=\(context.degree), bytesPerPlaintext=\(context.bytesPerPlaintext)")
            print(String(repeating: "=", count: 100))

            for config in configs {
                let entryCount = config.entryCount
                let entrySize = config.entrySize
                let label = config.label
                let pirConfig = try IndexPirConfig(
                    entryCount: entryCount,
                    entrySizeInBytes: entrySize,
                    dimensionCount: 2,
                    batchSize: 1,
                    unevenDimensions: true,
                    keyCompression: .noCompression,
                    encodingEntrySize: false)

                let parameter = MulPir<Bfv<UInt64>>.generateParameter(config: pirConfig, with: context)

                let database: [[UInt8]] = (0..<entryCount).map { _ in
                    (0..<entrySize).map { _ in UInt8.random(in: 0...255) }
                }

                var processedDb: MulPirServer<PirUtil<Bfv<UInt64>>>.Database?
                let dbTime = try await clock.measure {
                    processedDb = try await MulPirServer<PirUtil<Bfv<UInt64>>>.process(
                        database: database, with: context, using: parameter)
                }
                let unwrappedDb = try #require(processedDb)

                let server = try MulPirServer<PirUtil<Bfv<UInt64>>>(
                    parameter: parameter, context: context, database: unwrappedDb)
                let client = MulPirClient<PirUtil<Bfv<UInt64>>>(parameter: parameter, context: context)

                let secretKey = try context.generateSecretKey()
                let evalKey = try client.generateEvaluationKey(using: secretKey)
                let queryIndex = Int.random(in: 0..<entryCount)

                // Warmup
                let warmupQuery = try client.generateQuery(at: [queryIndex], using: secretKey)
                _ = try await server.computeResponse(to: warmupQuery, using: evalKey)

                // Measured
                var query: PrivateInformationRetrieval.Query<Bfv<UInt64>>?
                let queryTime = try clock.measure {
                    query = try client.generateQuery(at: [queryIndex], using: secretKey)
                }
                let unwrappedQuery = try #require(query)

                var response: PrivateInformationRetrieval.Response<Bfv<UInt64>>?
                let serverTime = try await clock.measure {
                    response = try await server.computeResponse(to: unwrappedQuery, using: evalKey)
                }
                let unwrappedResponse = try #require(response)

                let decrypted = try client.decrypt(
                    response: unwrappedResponse, at: [queryIndex], using: secretKey)
                #expect(decrypted[0] == database[queryIndex])

                print("\(label): dbProc=\(dbTime), server=\(serverTime), dims=\(parameter.dimensions)")
            }
            print(String(repeating: "=", count: 100))
        } // end rlweParams loop
    }
}
