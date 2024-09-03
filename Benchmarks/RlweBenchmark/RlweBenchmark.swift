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

// Benchmarks for Rlwe functions.
// These benchmarks can be triggered with `swift package benchmark --target RlweBenchmark`

import Benchmark
import HomomorphicEncryption

@usableFromInline nonisolated(unsafe) let benchmarkConfiguration = Benchmark.Configuration(
    metrics: [.wallClock, .mallocCountTotal, .peakMemoryResident],
    maxDuration: .seconds(3))

@inlinable
func benchmark<Scheme: HeScheme>(_ name: String, _: Scheme.Type, body: @escaping Benchmark.BenchmarkThrowingClosure) {
    let name = "\(name) \(String(describing: Scheme.self))"
    Benchmark(name, configuration: benchmarkConfiguration, closure: body)
}

func getModuliForBenchmark<T: ScalarType>(_: T.Type) -> [T] {
    switch T.self {
    case is UInt32.Type: return [(1 << 27) - 360_447, (1 << 28) - 65535, (1 << 28) - 163_839]
    case is UInt64.Type: return [(1 << 55) - 311_295, (1 << 55) - 1_392_639, (1 << 55) - 1_507_327]
    default: preconditionFailure("Unsupported scalar type \(T.self)")
    }
}

func getRandomPlaintextData<T: ScalarType>(count: Int,
                                           in range: Range<T>) -> [T]
{
    (0..<count).map { _ in
        T.random(in: range)
    }
}

struct RlweBenchmarkContext<Scheme: HeScheme>: Sendable {
    var encryptionParameters: EncryptionParameters<Scheme>
    var context: Context<Scheme>

    let data: [Scheme.Scalar]
    let coeffPlaintext: Plaintext<Scheme, Coeff>
    let evalPlaintext: Plaintext<Scheme, Eval>
    let ciphertext: Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>
    let evalCiphertext: Ciphertext<Scheme, Eval>
    let secretKey: SecretKey<Scheme>
    let evaluationKey: EvaluationKey<Scheme>
    let serializedEvaluationKey: SerializedEvaluationKey<Scheme.Scalar>
    let applyGaloisElement: Int = 3
    let rotateColumnsStep: Int = 1

    init() throws {
        let polyDegree = 8192
        let plaintextModulus = try Scheme.Scalar.generatePrimes(
            significantBitCounts: [20],
            preferringSmall: true,
            nttDegree: polyDegree)[0]
        self.encryptionParameters = try EncryptionParameters(polyDegree: polyDegree,
                                                             plaintextModulus: plaintextModulus,
                                                             coefficientModuli: getModuliForBenchmark(
                                                                 Scheme.Scalar.self),
                                                             errorStdDev: ErrorStdDev.stdDev32,
                                                             securityLevel: SecurityLevel.quantum128)
        self.context = try Context(encryptionParameters: encryptionParameters)
        self.secretKey = try context.generateSecretKey()
        let columnElement = GaloisElement.swappingRows(degree: polyDegree)
        let rowElement = try GaloisElement.rotatingColumns(by: rotateColumnsStep, degree: polyDegree)
        self.evaluationKey = try context.generateEvaluationKey(
            config: EvaluationKeyConfig(galoisElements: [
                applyGaloisElement,
                rowElement,
                columnElement,
            ], hasRelinearizationKey: true), using: secretKey)
        self.serializedEvaluationKey = evaluationKey.serialize()

        self.data = getRandomPlaintextData(count: polyDegree, in: 0..<Scheme.Scalar(plaintextModulus))
        self.coeffPlaintext = try context.encode(values: data, format: .simd)
        self.evalPlaintext = try coeffPlaintext.convertToEvalFormat()
        self.ciphertext = try coeffPlaintext.encrypt(using: secretKey)
        self.evalCiphertext = try ciphertext.convertToEvalFormat()
    }
}

enum StaticRlweBenchmarkContext {
    // Can't have throwing statics
    // swiftlint:disable force_try
    static let sharedBfvUInt32 = try! RlweBenchmarkContext<Bfv<UInt32>>()
    static let sharedBfvUInt64 = try! RlweBenchmarkContext<Bfv<UInt64>>()
    // swiftlint:enable force_try

    static func getBenchmarkContext<Scheme: HeScheme>() throws -> RlweBenchmarkContext<Scheme> {
        switch Scheme.self {
        case is Bfv<UInt32>.Type:
            if let benchmarkContext = sharedBfvUInt32 as? RlweBenchmarkContext<Scheme> {
                return benchmarkContext
            }
        case is Bfv<UInt64>.Type:
            if let benchmarkContext = sharedBfvUInt64 as? RlweBenchmarkContext<Scheme> {
                return benchmarkContext
            }
        default:
            preconditionFailure("Unsupported Scheme \(Scheme.self)")
        }
        preconditionFailure("Unsupported Scheme \(Scheme.self)")
    }
}

func encodeCoefficientBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("EncodeCoefficient", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            var plaintext: Scheme.CoeffPlaintext?
            for _ in benchmark.scaledIterations {
                try blackHole(plaintext = benchmarkContext.context.encode(values: benchmarkContext.data,
                                                                          format: .coefficient))
            }
            // Avoid warning about variable written to, but never read
            withExtendedLifetime(plaintext) {}
        }
    }
}

func encodeSimdBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("EncodeSimd", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            var plaintext: Scheme.CoeffPlaintext?
            for _ in benchmark.scaledIterations {
                try blackHole(plaintext = benchmarkContext.context.encode(values: benchmarkContext.data,
                                                                          format: .simd))
            }
            // Avoid warning about variable written to, but never read
            withExtendedLifetime(plaintext) {}
        }
    }
}

func decodeCoefficientBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("DecodeCoefficient", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(
                    benchmarkContext.coeffPlaintext.decode(format: .coefficient) as [Scheme.Scalar])
            }
        }
    }
}

func decodeSimdBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("DecodeSimd", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(
                    benchmarkContext.coeffPlaintext.decode(format: .simd) as [Scheme.Scalar])
            }
        }
    }
}

func generateSecretKeyBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("generateSecretKey", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(benchmarkContext.context.generateSecretKey())
            }
        }
    }
}

func generateEvaluationKeyBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("generateEvaluationKey", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            let config = EvaluationKeyConfig(galoisElements: [3], hasRelinearizationKey: true)
            for _ in benchmark.scaledIterations {
                try blackHole(
                    benchmarkContext.context.generateEvaluationKey(
                        config: config,
                        using: benchmarkContext.secretKey))
            }
        }
    }
}

func encryptBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("Encrypt", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(
                    benchmarkContext.coeffPlaintext.encrypt(using: benchmarkContext.secretKey))
            }
        }
    }
}

func decryptBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("Decrypt", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(
                    benchmarkContext.evalCiphertext.decrypt(
                        using: benchmarkContext.secretKey))
            }
        }
    }
}

func noiseBudgetBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("NoiseBudget", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(
                    benchmarkContext.ciphertext
                        .noiseBudget(using: benchmarkContext.secretKey, variableTime: true))
            }
        }
    }
}

func ciphertextAddBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextAdd", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.configuration.scalingFactor = .kilo
            benchmark.startMeasurement()
            let ciphertext = benchmarkContext.evalCiphertext
            var ciphertextSum = ciphertext
            for _ in benchmark.scaledIterations {
                try blackHole(ciphertextSum += ciphertext)
            }
        }
    }
}

func ciphertextSubtractBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextSubtract", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.configuration.scalingFactor = .kilo
            benchmark.startMeasurement()
            let ciphertext = benchmarkContext.evalCiphertext
            var ciphertextDifference = ciphertext
            for _ in benchmark.scaledIterations {
                try blackHole(ciphertextDifference -= ciphertext)
            }
        }
    }
}

func ciphertextMultiplyBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextMultiply", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                var ciphertext = benchmarkContext.ciphertext
                let ciphertext2 = benchmarkContext.ciphertext
                try blackHole(ciphertext *= ciphertext2)
            }
        }
    }
}

func ciphertextRelinearizeBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextRelinearize", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            var ciphertext = benchmarkContext.ciphertext
            try ciphertext *= ciphertext
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                var product = ciphertext
                try blackHole(
                    product.relinearize(using: benchmarkContext.evaluationKey))
            }
        }
    }
}

func ciphertextPlaintextAddBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextPlaintextAdd", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            var ciphertext = benchmarkContext.ciphertext
            for _ in benchmark.scaledIterations {
                try blackHole(ciphertext += benchmarkContext.coeffPlaintext)
            }
        }
    }
}

func ciphertextPlaintextSubtractBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextPlaintextSubtract", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            var ciphertext = benchmarkContext.ciphertext
            for _ in benchmark.scaledIterations {
                try blackHole(ciphertext -= benchmarkContext.coeffPlaintext)
            }
        }
    }
}

func ciphertextPlaintextMultiplyBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextPlaintextMultiply", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.configuration.scalingFactor = .kilo
            benchmark.startMeasurement()
            var ciphertext = benchmarkContext.evalCiphertext
            for _ in benchmark.scaledIterations {
                try blackHole(ciphertext *= benchmarkContext.evalPlaintext)
            }
        }
    }
}

func ciphertextModSwitchDownBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextModSwitchDown", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                var ciphertext = benchmarkContext.ciphertext
                try blackHole(ciphertext.modSwitchDown())
            }
        }
    }
}

func ciphertextNegateBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextNegate", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            var ciphertext = benchmarkContext.evalCiphertext
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(ciphertext = -ciphertext)
            }
        }
    }
}

func ciphertextApplyGaloisBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextApplyGalois", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            var ciphertext = benchmarkContext.ciphertext
            for _ in benchmark.scaledIterations {
                try blackHole(ciphertext.applyGalois(
                    element: benchmarkContext.applyGaloisElement,
                    using: benchmarkContext.evaluationKey))
            }
        }
    }
}

func ciphertextRotateColumnsBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextRotateColumns", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            var ciphertext = benchmarkContext.ciphertext
            for _ in benchmark.scaledIterations {
                try blackHole(ciphertext.rotateColumns(
                    by: benchmarkContext.rotateColumnsStep,
                    using: benchmarkContext.evaluationKey))
            }
        }
    }
}

func ciphertextSwapRowsBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextSwapRows", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            var ciphertext = benchmarkContext.ciphertext
            for _ in benchmark.scaledIterations {
                try blackHole(ciphertext.swapRows(using: benchmarkContext.evaluationKey))
            }
        }
    }
}

func ciphertextSerializeFullBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextSerializeFull", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            var ciphertext = benchmarkContext.ciphertext
            ciphertext.clearSeed()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(ciphertext.serialize())
            }
        }
    }
}

func ciphertextSerializeSeedBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextSerializeSeed", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(benchmarkContext.ciphertext.serialize())
            }
        }
    }
}

func ciphertextDeserializeFullBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextDeserializeFull", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            var ciphertext = benchmarkContext.ciphertext
            ciphertext.clearSeed()
            let serializedCiphertext = try ciphertext.serialize()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(
                    _ = Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>(
                        deserialize: serializedCiphertext,
                        context: benchmarkContext.context))
            }
        }
    }
}

func ciphertextDeserializeSeedBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("CiphertextDeserializeSeed", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            let serializedSeededCiphertext = try benchmarkContext.ciphertext.serialize()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(
                    _ = Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>(
                        deserialize: serializedSeededCiphertext,
                        context: benchmarkContext.context))
            }
        }
    }
}

func evaluationKeyDeserializeSeedBenchmark<Scheme: HeScheme>(_: Scheme.Type) -> () -> Void {
    {
        benchmark("EvaluationKeyDeserializeSeed", Scheme.self) { benchmark in
            let benchmarkContext: RlweBenchmarkContext<Scheme> = try StaticRlweBenchmarkContext.getBenchmarkContext()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(
                    _ = EvaluationKey<Scheme>(
                        deserialize: benchmarkContext.serializedEvaluationKey,
                        context: benchmarkContext.context))
            }
        }
    }
}

// swiftlint:disable:next closure_body_length
nonisolated(unsafe) let benchmarks: () -> Void = {
    // Encode/decode
    encodeSimdBenchmark(Bfv<UInt32>.self)()
    encodeSimdBenchmark(Bfv<UInt64>.self)()
    decodeSimdBenchmark(Bfv<UInt32>.self)()
    decodeSimdBenchmark(Bfv<UInt64>.self)()

    encodeCoefficientBenchmark(Bfv<UInt32>.self)()
    encodeCoefficientBenchmark(Bfv<UInt64>.self)()
    decodeCoefficientBenchmark(Bfv<UInt32>.self)()
    decodeCoefficientBenchmark(Bfv<UInt64>.self)()

    // Keygen
    generateSecretKeyBenchmark(Bfv<UInt32>.self)()
    generateSecretKeyBenchmark(Bfv<UInt64>.self)()
    generateEvaluationKeyBenchmark(Bfv<UInt32>.self)()
    generateEvaluationKeyBenchmark(Bfv<UInt64>.self)()

    // Encrypt/decrypt
    encryptBenchmark(Bfv<UInt32>.self)()
    encryptBenchmark(Bfv<UInt64>.self)()
    decryptBenchmark(Bfv<UInt32>.self)()
    decryptBenchmark(Bfv<UInt64>.self)()

    // Noise budget
    noiseBudgetBenchmark(Bfv<UInt32>.self)()
    noiseBudgetBenchmark(Bfv<UInt64>.self)()

    // HE ops
    ciphertextAddBenchmark(Bfv<UInt32>.self)()
    ciphertextAddBenchmark(Bfv<UInt64>.self)()

    ciphertextSubtractBenchmark(Bfv<UInt32>.self)()
    ciphertextSubtractBenchmark(Bfv<UInt64>.self)()

    ciphertextMultiplyBenchmark(Bfv<UInt32>.self)()
    ciphertextMultiplyBenchmark(Bfv<UInt64>.self)()

    ciphertextRelinearizeBenchmark(Bfv<UInt32>.self)()
    ciphertextRelinearizeBenchmark(Bfv<UInt64>.self)()

    ciphertextPlaintextAddBenchmark(Bfv<UInt32>.self)()
    ciphertextPlaintextAddBenchmark(Bfv<UInt64>.self)()

    ciphertextPlaintextSubtractBenchmark(Bfv<UInt32>.self)()
    ciphertextPlaintextSubtractBenchmark(Bfv<UInt64>.self)()

    ciphertextPlaintextMultiplyBenchmark(Bfv<UInt32>.self)()
    ciphertextPlaintextMultiplyBenchmark(Bfv<UInt64>.self)()

    ciphertextModSwitchDownBenchmark(Bfv<UInt32>.self)()
    ciphertextModSwitchDownBenchmark(Bfv<UInt64>.self)()

    ciphertextNegateBenchmark(Bfv<UInt32>.self)()
    ciphertextNegateBenchmark(Bfv<UInt64>.self)()

    ciphertextApplyGaloisBenchmark(Bfv<UInt32>.self)()
    ciphertextApplyGaloisBenchmark(Bfv<UInt64>.self)()

    ciphertextRotateColumnsBenchmark(Bfv<UInt32>.self)()
    ciphertextRotateColumnsBenchmark(Bfv<UInt64>.self)()

    ciphertextSwapRowsBenchmark(Bfv<UInt32>.self)()
    ciphertextSwapRowsBenchmark(Bfv<UInt64>.self)()

    // Serialization
    ciphertextSerializeFullBenchmark(Bfv<UInt32>.self)()
    ciphertextSerializeFullBenchmark(Bfv<UInt64>.self)()
    ciphertextSerializeSeedBenchmark(Bfv<UInt32>.self)()
    ciphertextSerializeSeedBenchmark(Bfv<UInt64>.self)()

    ciphertextDeserializeFullBenchmark(Bfv<UInt32>.self)()
    ciphertextDeserializeFullBenchmark(Bfv<UInt64>.self)()
    ciphertextDeserializeSeedBenchmark(Bfv<UInt32>.self)()
    ciphertextDeserializeSeedBenchmark(Bfv<UInt64>.self)()

    evaluationKeyDeserializeSeedBenchmark(Bfv<UInt32>.self)()
    evaluationKeyDeserializeSeedBenchmark(Bfv<UInt64>.self)()
}
