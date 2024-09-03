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

import Foundation
import HomomorphicEncryption

/// Private nearest neighbors client.
public struct Client<Scheme: HeScheme> {
    /// Configuration.
    public let config: ClientConfig<Scheme>

    /// One context per plaintext modulus.
    @usableFromInline let contexts: [Context<Scheme>]

    /// Performs composition of the plaintext CRT responses.
    @usableFromInline let crtComposer: CrtComposer<Scheme.Scalar>

    /// Context for the plaintext CRT moduli.
    @usableFromInline let plaintextContext: PolyContext<Scheme.Scalar>

    /// The evaluation key configuration used by the ``Server``.
    public var evaluationKeyConfig: EvaluationKeyConfig {
        config.evaluationKeyConfig
    }

    /// Creates a new ``Client``.
    /// - Parameters:
    ///   - config: Client configuration.
    ///   - contexts: Contexts for HE computation, one per plaintext modulus.
    /// - Throws: Error upon failure to create the client.
    @inlinable
    public init(config: ClientConfig<Scheme>, contexts: [Context<Scheme>] = []) throws {
        guard config.distanceMetric == .cosineSimilarity else {
            throw PnnsError.wrongDistanceMetric(got: config.distanceMetric, expected: .cosineSimilarity)
        }
        self.config = config

        var contexts = contexts
        if contexts.isEmpty {
            contexts = try config.encryptionParameters.map { encryptionParams in
                try Context(encryptionParameters: encryptionParams)
            }
        }
        try config.validateContexts(contexts: contexts)
        self.contexts = contexts

        self.plaintextContext = try PolyContext(
            degree: config.encryptionParameters[0].polyDegree,
            moduli: config.plaintextModuli)
        self.crtComposer = try CrtComposer(polyContext: plaintextContext)
    }

    /// Generates a nearest neighbor search query.
    /// - Parameters:
    ///   - vectors: Vectors.
    ///   - secretKey: Secret key to encrypt with.
    /// - Returns: The query.
    /// - Throws: Error upon failure to generate the query.
    @inlinable
    public func generateQuery(for vectors: Array2d<Float>,
                              using secretKey: SecretKey<Scheme>) throws -> Query<Scheme>
    {
        let scaledVectors: Array2d<Scheme.SignedScalar> = vectors
            .normalizedScaledAndRounded(scalingFactor: Float(config.scalingFactor))
        let matrices = try contexts.map { context in
            // For a single plaintext modulus, reduction isn't necessary
            let shouldReduce = contexts.count > 1
            let plaintextMatrix = try PlaintextMatrix(
                context: context,
                dimensions: MatrixDimensions(vectors.shape),
                packing: config.queryPacking,
                signedValues: scaledVectors.data,
                reduce: shouldReduce)
            return try plaintextMatrix.encrypt(using: secretKey).convertToCoeffFormat()
        }
        return Query(ciphertextMatrices: matrices)
    }

    /// Decrypts a nearest neighbors search response.
    /// - Parameters:
    ///   - response: The response.
    ///   - secretKey: Secret key to decrypt with.
    /// - Returns: The distances from the query vectors to the database rows.
    /// - Throws: Error upon failure to decrypt the response.
    @inlinable
    public func decrypt(response: Response<Scheme>, using secretKey: SecretKey<Scheme>) throws -> DatabaseDistances {
        guard let dimensions = response.ciphertextMatrices.first?.dimensions else {
            throw PnnsError.emptyCiphertextArray
        }
        let decoded: [[Scheme.Scalar]] = try response.ciphertextMatrices.map { ciphertextMatrix in
            try ciphertextMatrix.decrypt(using: secretKey).unpack()
        }
        // CRT-decomposed scores
        let values = Array2d<Scheme.Scalar>(data: decoded)
        // Plaintext CRT modulus must be < `UInt64.max`
        let composedDistances: [UInt64] = try crtComposer.compose(data: values)

        let modulus: UInt64 = plaintextContext.moduli.product()
        // Encrypted distances are scaled by config.scalingFactor^2, so we undo the scaling here.
        let distanceValues = composedDistances.map { unsigned in
            let signed = unsigned.remainderToCentered(modulus: modulus)
            return Float(signed) / (Float(config.scalingFactor) * Float(config.scalingFactor))
        }

        let distances = Array2d(
            data: distanceValues,
            rowCount: dimensions.rowCount,
            columnCount: dimensions.columnCount)
        return DatabaseDistances(
            distances: distances,
            entryIds: response.entryIds,
            entryMetadatas: response.entryMetadatas)
    }

    /// Generates a secret key for query encryption and response decryption.
    /// - Returns: A freshly generated secret key.
    /// - Throws: Error upon failure to generate a secret key.
    @inlinable
    public func generateSecretKey() throws -> SecretKey<Scheme> {
        try contexts[0].generateSecretKey()
    }

    /// Generates an ``EvaluationKey`` for use in nearest neighbors search.
    /// - Parameter secretKey: Secret key used to generate the evaluation key.
    /// - Returns: The evaluation key.
    /// - Throws: Error upon failure to generate the evaluation key.
    /// - Warning: Uses the first context to generate the evaluation key. So either the HE scheme should generate
    /// evaluation keys independent of the plaintext modulus (as in BFV), or there should be just one plaintext modulus.
    @inlinable
    public func generateEvaluationKey(using secretKey: SecretKey<Scheme>) throws -> EvaluationKey<Scheme> {
        try contexts[0].generateEvaluationKey(config: evaluationKeyConfig, using: secretKey)
    }
}
