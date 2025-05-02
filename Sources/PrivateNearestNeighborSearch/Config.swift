// Copyright 2024-2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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
    ///
    /// The cosine similarity between zero vectors is defined as zero.
    case cosineSimilarity
}

/// CosineSimilarity configuration.
public enum CosineSimilarity {
    /// Computes the evaluation key configuration for matrix multiplication.
    /// - Parameters:
    ///   - plaintextMatrixDimensions: Dimensions of the plaintext matrix.
    ///   - maxQueryCount: Maximum number of queries in one batch. The returned`EvaluationKeyConfig` will support all
    ///     batch sizes up to and including `maxQueryCount`.
    ///   - encryptionParameters: Encryption parameters..
    ///   - scheme: The HE scheme.
    /// - Throws: Error upon failure to compute the configuration.
    /// - Returns: The evaluation key configuration.
    public static func evaluationKeyConfig<Scheme: HeScheme>(
        plaintextMatrixDimensions: MatrixDimensions,
        maxQueryCount: Int,
        encryptionParameters: EncryptionParameters<Scheme.Scalar>,
        scheme: Scheme.Type) throws -> EvaluationKeyConfig
    {
        try MatrixMultiplication.evaluationKeyConfig(
            plaintextMatrixDimensions: plaintextMatrixDimensions,
            maxQueryCount: maxQueryCount,
            encryptionParameters: encryptionParameters,
            scheme: scheme)
    }
}

/// Client configuration.
public struct ClientConfig<Scheme: HeScheme>: Codable, Equatable, Hashable, Sendable {
    public typealias Scalar = Scheme.Scalar
    /// Encryption parameters.
    public let encryptionParameters: [EncryptionParameters<Scalar>]
    /// Factor by which to scale floating-point entries before rounding to integers.
    public let scalingFactor: Int
    /// Packing for the query.
    public let queryPacking: MatrixPacking
    /// Number of entries in each vector.
    public let vectorDimension: Int
    /// Evaluation key configuration for nearest neighbor search.
    public let evaluationKeyConfig: EvaluationKeyConfig
    /// Metric for distances between vectors.
    public let distanceMetric: DistanceMetric
    /// For plaintext CRT, the list of extra plaintext moduli.
    ///
    /// The first plaintext modulus will be the one in ``ClientConfig/encryptionParameters``.
    public let extraPlaintextModuli: [Scalar]

    /// The plaintext CRT moduli.
    public var plaintextModuli: [Scalar] { encryptionParameters.map(\.plaintextModulus) }

    /// Creates a new ``ClientConfig``.
    /// - Parameters:
    ///   - encryptionParameters: Encryption parameters.
    ///   - scalingFactor: Factor by which to scale floating-point entries before rounding to integers.
    ///   - queryPacking: Packing for the query.
    ///   - vectorDimension: Number of entries in each vector.
    ///   - evaluationKeyConfig: Evaluation key configuration for nearest neighbor search.
    ///   - distanceMetric: Metric for nearest neighbor search.
    ///   - extraPlaintextModuli: For plaintext CRT, the list of extra plaintext moduli. The first plaintext modulus
    /// will be the one in ``ClientConfig/encryptionParameters``.
    /// - Throws: Error upon failure to create a new client config.
    public init(
        encryptionParameters: EncryptionParameters<Scheme.Scalar>,
        scalingFactor: Int,
        queryPacking: MatrixPacking,
        vectorDimension: Int,
        evaluationKeyConfig: EvaluationKeyConfig,
        distanceMetric: DistanceMetric,
        extraPlaintextModuli: [Scalar] = []) throws
    {
        let extraEncryptionParams = try extraPlaintextModuli.map { plaintextModulus in
            try EncryptionParameters<Scheme.Scalar>(
                polyDegree: encryptionParameters.polyDegree,
                plaintextModulus: plaintextModulus,
                coefficientModuli: encryptionParameters.coefficientModuli,
                errorStdDev: encryptionParameters.errorStdDev,
                securityLevel: encryptionParameters.securityLevel)
        }
        self.encryptionParameters = [encryptionParameters] + extraEncryptionParams
        self.scalingFactor = scalingFactor
        self.queryPacking = queryPacking
        self.vectorDimension = vectorDimension
        self.evaluationKeyConfig = evaluationKeyConfig
        self.distanceMetric = distanceMetric
        self.extraPlaintextModuli = extraPlaintextModuli
    }

    @inlinable
    public static func maxScalingFactor(distanceMetric: DistanceMetric, vectorDimension: Int,
                                        plaintextModuli: [Scalar]) -> Int
    {
        precondition(distanceMetric == .cosineSimilarity)
        let t = plaintextModuli.map { Float($0) }.reduce(1, *)
        let scalingFactor = (((t - 1) / 2).squareRoot() - Float(vectorDimension).squareRoot() / 2).rounded(.down)
        return Int(scalingFactor)
    }

    /// Validates the contexts are suitable for computing with this configuration.
    /// - Parameter contexts: Contexts; one per plaintext modulus.
    /// - Throws: Error if the contexts are not valid.
    @inlinable
    func validateContexts(contexts: [Context<Scheme>]) throws {
        guard contexts.count == encryptionParameters.count else {
            throw PnnsError.wrongContextsCount(got: contexts.count, expected: encryptionParameters.count)
        }
        for (context, params) in zip(contexts, encryptionParameters) {
            guard context.encryptionParameters == params else {
                throw PnnsError.wrongEncryptionParameters(got: context.encryptionParameters, expected: params)
            }
        }
    }
}

/// Server configuration.
public struct ServerConfig<Scheme: HeScheme>: Codable, Equatable, Hashable, Sendable {
    public typealias Scalar = Scheme.Scalar

    /// Configuration shared with the client.
    public let clientConfig: ClientConfig<Scheme>

    /// Packing for the plaintext database.
    public let databasePacking: MatrixPacking

    /// Factor by which to scale floating-point entries before rounding to integers.
    public var scalingFactor: Int { clientConfig.scalingFactor }

    /// The plaintext CRT moduli.
    public var plaintextModuli: [Scalar] { clientConfig.plaintextModuli }

    /// For plaintext CRT, the list of extra plaintext moduli.
    ///
    /// The first plaintext modulus will be the one in ``ClientConfig/encryptionParameters``.
    public var extraPlaintextModuli: [Scalar] {
        clientConfig.extraPlaintextModuli
    }

    /// Distance metric.
    public var distanceMetric: DistanceMetric { clientConfig.distanceMetric }

    /// The encryption parameters, one per plaintext modulus.
    public var encryptionParameters: [EncryptionParameters<Scalar>] {
        clientConfig.encryptionParameters
    }

    /// Number of entries in each vector.
    public var vectorDimension: Int {
        clientConfig.vectorDimension
    }

    /// Packing for the query.
    public var queryPacking: MatrixPacking {
        clientConfig.queryPacking
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

    /// Validates the contexts are suitable for computing with this configuration.
    /// - Parameter contexts: Contexts; one per plaintext modulus.
    /// - Throws: Error if the contexts are not valid.
    @inlinable
    func validateContexts(contexts: [Context<Scheme>]) throws {
        try clientConfig.validateContexts(contexts: contexts)
    }
}
