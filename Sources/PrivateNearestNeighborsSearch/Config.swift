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

import HomomorphicEncryption

/// Metric for distances between vectors.
public enum DistanceMetric: CaseIterable, Codable, Equatable, Hashable, Sendable {
    /// Cosine similarity.
    case cosineSimilarity
}

/// Client configuration.
public struct ClientConfig<Scheme: HeScheme>: Codable, Equatable, Hashable, Sendable {
    /// Encryption parameters.
    public let encryptionParameters: [EncryptionParameters<Scheme>]
    /// Factor by which to scale floating-point entries before rounding to integers.
    public let scalingFactor: Int
    /// Packing for the query.
    public let queryPacking: MatrixPacking
    /// Number of entries in each vector vector.
    public let vectorDimension: Int
    /// Evaluation key configuration for nearest neighbors computation.
    public let evaluationKeyConfig: EvaluationKeyConfiguration
    /// Metric for distances between vectors.
    public let distanceMetric: DistanceMetric
    /// For plaintext CRT, the list of extra plaintext moduli.
    ///
    /// The first plaintext modulus will be the one in ``ClientConfig/encryptionParams``.
    public let extraPlaintextModuli: [Scheme.Scalar]

    /// The plaintext CRT moduli.
    public var plaintextModuli: [Scheme.Scalar] { encryptionParameters.map(\.plaintextModulus) }

    /// Creates a new ``ClientConfig``.
    /// - Parameters:
    ///   - encryptionParams: Encryption parameters.
    ///   - scalingFactor: Factor by which to scale floating-point entries before rounding to integers.
    ///   - queryPacking: Packing for the query.
    ///   - vectorDimension: Number of entries in each vector vector.
    ///   - evaluationKeyConfig: Evaluation key configuration for nearest neighbors computation.
    ///   - distanceMetric: Metric for nearest neighbors computation
    ///   - extraPlaintextModuli: For plaintext CRT, the list of extra plaintext moduli. The first plaintext modulus
    /// will be the one in ``ClientConfig/encryptionParams``.
    /// - Throws: Error upon failure to create a new client config.
    public init(
        encryptionParams: EncryptionParameters<Scheme>,
        scalingFactor: Int,
        queryPacking: MatrixPacking,
        vectorDimension: Int,
        evaluationKeyConfig: EvaluationKeyConfiguration,
        distanceMetric: DistanceMetric,
        extraPlaintextModuli: [Scheme.Scalar] = []) throws
    {
        let extraEncryptionParams = try extraPlaintextModuli.map { plaintextModulus in
            try EncryptionParameters<Scheme>(
                polyDegree: encryptionParams.polyDegree,
                plaintextModulus: plaintextModulus,
                coefficientModuli: encryptionParams.coefficientModuli,
                errorStdDev: encryptionParams.errorStdDev,
                securityLevel: encryptionParams.securityLevel)
        }
        self.encryptionParameters = [encryptionParams] + extraEncryptionParams
        self.scalingFactor = scalingFactor
        self.queryPacking = queryPacking
        self.vectorDimension = vectorDimension
        self.evaluationKeyConfig = evaluationKeyConfig
        self.distanceMetric = distanceMetric
        self.extraPlaintextModuli = extraPlaintextModuli
    }

    @inlinable
    package static func maxScalingFactor(distanceMetric: DistanceMetric, vectorDimension: Int,
                                         plaintextModuli: [Scheme.Scalar]) -> Int
    {
        precondition(distanceMetric == .cosineSimilarity)
        let t = plaintextModuli.map { Float($0) }.reduce(1, *)
        let scalingFactor = (((t - 1) / 2).squareRoot() - Float(vectorDimension).squareRoot() / 2).rounded(.down)
        return Int(scalingFactor)
    }
}

/// Server configuration.
public struct ServerConfig<Scheme: HeScheme>: Codable, Equatable, Hashable, Sendable {
    /// Configuration shared with the client.
    public let clientConfig: ClientConfig<Scheme>
    /// Packing for the plaintext database.
    public let databasePacking: MatrixPacking
    /// Factor by which to scale floating-point entries before rounding to integers.
    public var scalingFactor: Int { clientConfig.scalingFactor }
    /// The plaintext CRT moduli.
    public var plaintextModuli: [Scheme.Scalar] { clientConfig.plaintextModuli }
    /// Distance metric.
    public var distanceMetric: DistanceMetric { clientConfig.distanceMetric }
    /// The encryption parameters, one per plaintext modulus.
    public var encryptionParameters: [EncryptionParameters<Scheme>] {
        clientConfig.encryptionParameters
    }

    /// Creates a new ``ServerConfig``.
    /// - Parameters:
    ///   - clientConfig: Configuration shared with the client.
    ///   - databasePacking: Packing for the plaintext database.
    public init(
        clientConfig: ClientConfig<Scheme>,
        databasePacking: MatrixPacking)
    {
        self.clientConfig = clientConfig
        self.databasePacking = databasePacking
    }
}
