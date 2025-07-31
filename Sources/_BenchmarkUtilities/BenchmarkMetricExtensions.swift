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
import HomomorphicEncryption

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

/// Encryption parameters configuration for benchmarks.
public struct EncryptionParametersConfig {
    /// Default configuration for PNNS benchmarks
    public nonisolated(unsafe) static let defaultPnns = EncryptionParametersConfig(
        polyDegree: 4096,
        // use plaintextModulusBits: [16, 17] for plaintext CRT
        plaintextModulusBits: [17],
        coefficientModulusBits: [27, 28, 28])

    /// Default configuration for PIR benchmarks
    public nonisolated(unsafe) static let defaultPir = EncryptionParametersConfig(
        polyDegree: 4096,
        plaintextModulusBits: [5],
        coefficientModulusBits: [27, 28, 28])

    /// Polynomial degree.
    public let polyDegree: Int
    /// Number of significant bits in each plaintext modulus.
    public let plaintextModulusBits: [Int]
    /// Number of significant bits in each ciphertext modulus.
    public let coefficientModulusBits: [Int]

    /// Creates a new ``EncryptionParametersConfig``
    /// - Parameters:
    ///   - polyDegree: Polynomial degree
    ///   - plaintextModulusBits: Number of significant bits in each plaintext modulus.
    ///   - coefficientModulusBits: Number of significant bits in each ciphertext modulus.
    public init(polyDegree: Int, plaintextModulusBits: [Int], coefficientModulusBits: [Int]) {
        self.polyDegree = polyDegree
        self.plaintextModulusBits = plaintextModulusBits
        self.coefficientModulusBits = coefficientModulusBits
    }
}

extension EncryptionParametersConfig: CustomStringConvertible {
    public var description: String {
        "N=\(polyDegree)/logt=\(plaintextModulusBits)/logq=\(coefficientModulusBits.description)"
    }
}

extension EncryptionParameters {
    ///  Creates a new ``EncryptionParameters`` from the configuration.
    /// - Parameter config: Configuration.
    /// - Throws: Upon failure to initialize encryption parameters.
    public init(from config: EncryptionParametersConfig) throws {
        let plaintextModulus = try Scalar.generatePrimes(
            significantBitCounts: config.plaintextModulusBits,
            preferringSmall: true)[0]
        let coefficientModuli = try Scalar.generatePrimes(
            significantBitCounts: config.coefficientModulusBits,
            preferringSmall: false,
            nttDegree: config.polyDegree)
        try self.init(
            polyDegree: config.polyDegree,
            plaintextModulus: plaintextModulus,
            coefficientModuli: coefficientModuli,
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.quantum128)
    }
}
