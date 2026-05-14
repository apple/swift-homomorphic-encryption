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

public import Benchmark
public import HomomorphicEncryption
public import HomomorphicEncryptionProtobuf

@usableFromInline nonisolated(unsafe) let rlweSerializationBenchmarkConfiguration = Benchmark.Configuration(
    metrics: [.wallClock, .mallocCountTotal, .peakMemoryResident],
    maxDuration: .seconds(3))

func getCoefficientModuli<T: ScalarType>(_: T.Type) -> [T] {
    switch T.self {
    case is UInt32.Type: [(1 << 27) - 360_447, (1 << 28) - 65535, (1 << 28) - 163_839]
    case is UInt64.Type: [(1 << 55) - 311_295, (1 << 55) - 1_392_639, (1 << 55) - 1_507_327]
    default: preconditionFailure("Unsupported scalar type \(T.self)")
    }
}

struct EvaluationKeyFixture<Scheme: HeScheme> {
    let context: Scheme.Context
    let evaluationKey: EvaluationKey<Scheme>
    let serialized: SerializedEvaluationKey<Scheme.Scalar>
    let proto: Apple_SwiftHomomorphicEncryption_V1_SerializedEvaluationKey

    init() throws {
        let polyDegree = 8192
        let plaintextModulus = try Scheme.Scalar.generatePrimes(
            significantBitCounts: [20],
            preferringSmall: true,
            nttDegree: polyDegree)[0]
        let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
            polyDegree: polyDegree,
            plaintextModulus: plaintextModulus,
            coefficientModuli: getCoefficientModuli(Scheme.Scalar.self),
            errorStdDev: .stdDev32,
            securityLevel: .quantum128)
        self.context = try Scheme.Context(encryptionParameters: encryptionParameters)
        let secretKey = try context.generateSecretKey()
        let columnElement = GaloisElement.swappingRows(degree: polyDegree)
        let rowElement = try GaloisElement.rotatingColumns(by: 1, degree: polyDegree)
        self.evaluationKey = try context.generateEvaluationKey(
            config: EvaluationKeyConfig(
                galoisElements: [3, rowElement, columnElement],
                hasRelinearizationKey: true),
            using: secretKey)
        self.serialized = evaluationKey.serialize()
        self.proto = serialized.proto()
    }
}

/// Benchmarks the `EvaluationKey` serialize + protobuf round-trip used by PIR/PNNS client apps.
public func evaluationKeySerializationBenchmarks<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        let scheme = String(describing: Scheme.self)

        // swiftlint:disable closure_parameter_position

        Benchmark("EvaluationKeySerialize/\(scheme)",
                  configuration: rlweSerializationBenchmarkConfiguration)
        { (
            benchmark,
            fixture: EvaluationKeyFixture<Scheme>) in
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(fixture.evaluationKey.serialize())
            }
        } setup: {
            try EvaluationKeyFixture<Scheme>()
        }

        Benchmark("SerializedEvaluationKeyProto/\(scheme)",
                  configuration: rlweSerializationBenchmarkConfiguration)
        { (
            benchmark,
            fixture: EvaluationKeyFixture<Scheme>) in
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(fixture.serialized.proto())
            }
        } setup: {
            try EvaluationKeyFixture<Scheme>()
        }

        Benchmark("SerializedEvaluationKeyNative/\(scheme)",
                  configuration: rlweSerializationBenchmarkConfiguration)
        { (
            benchmark,
            fixture: EvaluationKeyFixture<Scheme>) in
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(_ = fixture.proto.native() as SerializedEvaluationKey<Scheme.Scalar>)
            }
        } setup: {
            try EvaluationKeyFixture<Scheme>()
        }
        // swiftlint:enable closure_parameter_position
    }
}
