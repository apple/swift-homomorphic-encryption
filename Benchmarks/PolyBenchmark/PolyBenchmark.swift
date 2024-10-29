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

// Benchmarks for PolyRq functions.
// These benchmarks can be triggered with
// swift package benchmark --target PolyBenchmark

import Benchmark
import HomomorphicEncryption

@usableFromInline nonisolated(unsafe) let benchmarkConfiguration = Benchmark.Configuration(
    metrics: [.wallClock, .mallocCountTotal, .peakMemoryResident],
    scalingFactor: .kilo,
    maxDuration: .seconds(3))

@inlinable
func benchmark<T: ScalarType>(_ name: String, _: T.Type, body: @escaping Benchmark.BenchmarkThrowingClosure) {
    let name = "\(name) \(String(describing: T.self))"
    Benchmark(name, configuration: benchmarkConfiguration, closure: body)
}

func getModuliForBenchmark<T: ScalarType>(_: T.Type) -> [T] {
    switch T.self {
    case is UInt32.Type: return [(1 << 28) - 65535]
    case is UInt64.Type: return [(1 << 55) - 311_295]
    default: preconditionFailure("Unsupported scalar type \(T.self)")
    }
}

struct PolyBenchmarkContext<T: ScalarType> {
    let moduli: [T]
    let context: PolyContext<T>?

    init() {
        self.moduli = getModuliForBenchmark(T.self)
        do {
            self.context = try PolyContext(
                degree: 8192,
                moduli: getModuliForBenchmark(T.self))
        } catch {
            assertionFailure("Error in context creation \(error) for type \(T.self)")
            self.context = nil
        }
    }
}

enum StaticPolyBenchmarkContext {
    static let sharedUInt32 = PolyBenchmarkContext<UInt32>()
    static let sharedUInt64 = PolyBenchmarkContext<UInt64>()
}

func getPolysForBenchmark<T: ScalarType, F: PolyFormat>(_: T.Type, _: F.Type) throws -> (PolyRq<T, F>, PolyRq<T, F>) {
    switch T.self {
    case is UInt32.Type:
        if let context = StaticPolyBenchmarkContext.sharedUInt32.context,
           let x = PolyRq<_, F>.random(context: context) as? PolyRq<T, F>,
           let y = PolyRq<_, F>.random(context: context) as? PolyRq<T, F>
        {
            return (x, y)
        }
        preconditionFailure("Error getting PolyRq<\(T.self), \(F.self)> for benchmark")
    case is UInt64.Type:
        if let context = StaticPolyBenchmarkContext.sharedUInt64.context,
           let x = PolyRq<_, F>.random(context: context) as? PolyRq<T, F>,
           let y = PolyRq<_, F>.random(context: context) as? PolyRq<T, F>
        {
            return (x, y)
        }
        preconditionFailure("Error getting PolyRq<\(T.self), \(F.self)> for benchmark")
    default:
        preconditionFailure("Unsupported scalar type \(T.self)")
    }
}

func additionBenchmark<T: ScalarType>(_: T.Type) -> () -> Void {
    {
        benchmark("Add", T.self) { benchmark in
            var (x, y) = try getPolysForBenchmark(T.self, Coeff.self)
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(x += y)
            }
        }
    }
}

func constMultiplicationBenchmark<T: ScalarType>(_: T.Type) -> () -> Void {
    {
        benchmark("MultiplyConstant", T.self) { benchmark in
            var (x, _) = try getPolysForBenchmark(T.self, Coeff.self)
            benchmark.startMeasurement()
            let y: T = 12
            let yResidues = x.moduli.map { modulus in y % modulus }
            for _ in benchmark.scaledIterations {
                blackHole(x *= yResidues)
            }
        }
    }
}

func multiplicationBenchmark<T: ScalarType>(_: T.Type) -> () -> Void {
    {
        benchmark("Multiply", T.self) { benchmark in
            var (x, y) = try getPolysForBenchmark(T.self, Eval.self)
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(x *= y)
            }
        }
    }
}

func negationBenchmark<T: ScalarType>(_: T.Type) -> () -> Void {
    {
        benchmark("Negate", T.self) { benchmark in
            var (x, _) = try getPolysForBenchmark(T.self, Coeff.self)
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(x = -x)
            }
        }
    }
}

func subtractionBenchmark<T: ScalarType>(_: T.Type) -> () -> Void {
    {
        benchmark("Subtract", T.self) { benchmark in
            var (x, y) = try getPolysForBenchmark(T.self, Coeff.self)
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(x -= y)
            }
        }
    }
}

func forwardNttBenchmark<T: ScalarType>(_: T.Type) -> () -> Void {
    {
        benchmark("ForwardNtt", T.self) { benchmark in
            let (x, _) = try getPolysForBenchmark(T.self, Coeff.self)
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(x.forwardNtt())
            }
        }
    }
}

func inverseNttBenchmark<T: ScalarType>(_: T.Type) -> () -> Void {
    {
        benchmark("InverseNtt", T.self) { benchmark in
            let (x, _) = try getPolysForBenchmark(T.self, Eval.self)
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                try blackHole(x.inverseNtt())
            }
        }
    }
}

func randomizeCenteredBinomialDistributionBenchmark<T: ScalarType>(_: T.Type) -> () -> Void {
    {
        benchmark("RandomizeCenteredBinomialDistribution", T.self) { benchmark in
            var (x, _) = try getPolysForBenchmark(T.self, Coeff.self)
            var rng = NistAes128Ctr()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(x.randomizeCenteredBinomialDistribution(
                    standardDeviation: ErrorStdDev.stdDev32.toDouble,
                    using: &rng))
            }
        }
    }
}

func randomizeTernaryBenchmark<T: ScalarType>(_: T.Type) -> () -> Void {
    {
        benchmark("RandomizeTernary", T.self) { benchmark in
            var (x, _) = try getPolysForBenchmark(T.self, Coeff.self)
            var rng = NistAes128Ctr()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(x.randomizeTernary(using: &rng))
            }
        }
    }
}

func randomizeUniformBenchmark<T: ScalarType>(_: T.Type) -> () -> Void {
    {
        benchmark("RandomizeUniform", T.self) { benchmark in
            var (x, _) = try getPolysForBenchmark(T.self, Coeff.self)
            var rng = NistAes128Ctr()
            benchmark.startMeasurement()
            for _ in benchmark.scaledIterations {
                blackHole(x.randomizeUniform(using: &rng))
            }
        }
    }
}

nonisolated(unsafe) let benchmarks: () -> Void = {
    additionBenchmark(UInt32.self)()
    additionBenchmark(UInt64.self)()
    constMultiplicationBenchmark(UInt32.self)()
    constMultiplicationBenchmark(UInt64.self)()
    multiplicationBenchmark(UInt32.self)()
    multiplicationBenchmark(UInt64.self)()
    negationBenchmark(UInt32.self)()
    negationBenchmark(UInt64.self)()
    subtractionBenchmark(UInt32.self)()
    subtractionBenchmark(UInt64.self)()

    // NTT
    forwardNttBenchmark(UInt32.self)()
    forwardNttBenchmark(UInt64.self)()
    inverseNttBenchmark(UInt32.self)()
    inverseNttBenchmark(UInt64.self)()

    // Random
    randomizeTernaryBenchmark(UInt32.self)()
    randomizeTernaryBenchmark(UInt64.self)()
    randomizeUniformBenchmark(UInt32.self)()
    randomizeUniformBenchmark(UInt64.self)()
    randomizeCenteredBinomialDistributionBenchmark(UInt32.self)()
    randomizeCenteredBinomialDistributionBenchmark(UInt64.self)()
}
