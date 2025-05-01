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

/// A serialized ``SecretKey``.
public struct SerializedSecretKey: Hashable, Codable, Sendable {
    /// Serialized polynomials in the secret key.
    public let polys: [UInt8]

    /// Initializes a ``SerializedSecretKey`` from serialized polynomials.
    /// - Parameter polys: Serialized secret key polynomials.
    public init(polys: [UInt8]) {
        self.polys = polys
    }
}

extension SecretKey {
    /// Deserializes a secret key.
    /// - Parameters:
    ///   - serialized: Serialized secret key.
    ///   - context: Context to associate with the secret key.
    /// - Throws: ``HeError`` upon failure to deserialize.
    public convenience init(deserialize serialized: SerializedSecretKey, context: Context<Scheme.Scalar>) throws {
        let polys: [PolyRq<Scalar, Eval>] = try Serialize.deserializePolys(
            from: serialized.polys,
            context: context.secretKeyContext)
        self.init(poly: polys[0])
    }

    /// Serializes the secret key.
    /// - Returns: The serialized secret key.
    public func serialize() -> SerializedSecretKey {
        var polys = [UInt8](
            repeating: 0,
            count: MemoryLayout<UInt16>.size + polyContext().serializationByteCount())
        // safe because we initialize the buffer with correct count
        // swiftlint:disable:next force_try
        try! Serialize.serializePolys(CollectionOfOne(poly), to: &polys, context: polyContext())
        return SerializedSecretKey(polys: polys)
    }
}

extension KeySwitchKey {
    @inlinable
    init(deserialize ciphertexts: [SerializedCiphertext<Scalar>], context: Context<Scheme.Scalar>) throws {
        self.context = context
        self.ciphers = try ciphertexts.map { serializedCiphertext in
            try Ciphertext(
                deserialize: serializedCiphertext,
                context: context,
                moduliCount: context.secretKeyContext.moduli.count)
        }
    }

    func serialize() -> [SerializedCiphertext<Scalar>] {
        ciphers.map { $0.serialize() }
    }
}

/// A serialized `GaloisKey`.
public struct SerializedGaloisKey<Scalar: ScalarType>: Hashable, Codable, Sendable {
    /// Maps the galois element to the ciphertexts of the corresponding serialized galois key.
    public let galoisKey: [Int: [SerializedCiphertext<Scalar>]]

    /// Initializes a `GaloisKey`.
    /// - Parameter galoisKey: Map of galois element to the ciphertexts of the corresponding serialized galois key.
    public init(galoisKey: [Int: [SerializedCiphertext<Scalar>]]) {
        self.galoisKey = galoisKey
    }
}

extension GaloisKey {
    @inlinable
    init(deserialize serialized: SerializedGaloisKey<Scalar>, context: Context<Scheme.Scalar>) throws {
        self.keys = try serialized.galoisKey.mapValues { serializedKeySwitchKey in
            try KeySwitchKey(deserialize: serializedKeySwitchKey, context: context)
        }
    }

    func serialize() -> SerializedGaloisKey<Scalar> {
        SerializedGaloisKey(galoisKey: keys.mapValues { $0.serialize() })
    }
}

/// A serialized `RelinearizationKey`.
public struct SerializedRelinearizationKey<Scalar: ScalarType>: Hashable, Codable, Sendable {
    /// Ciphertexts in the relinearization key.
    public let relinKey: [SerializedCiphertext<Scalar>]

    /// Initializes a ``SerializedRelinearizationKey``.
    /// - Parameter relinKey: Serialized `RelinearizationKey`.
    public init(relinKey: [SerializedCiphertext<Scalar>]) {
        self.relinKey = relinKey
    }
}

extension RelinearizationKey {
    @inlinable
    init(deserialize serialized: SerializedRelinearizationKey<Scalar>, context: Context<Scheme.Scalar>) throws {
        self.keySwitchKey = try KeySwitchKey(deserialize: serialized.relinKey, context: context)
    }

    func serialize() -> SerializedRelinearizationKey<Scalar> {
        SerializedRelinearizationKey(relinKey: keySwitchKey.serialize())
    }
}

/// Serialized ``EvaluationKey``.
public struct SerializedEvaluationKey<Scalar: ScalarType>: Hashable, Codable, Sendable {
    /// Serialized `GaloisKey`.
    public let galoisKey: SerializedGaloisKey<Scalar>?
    /// Serialied `RelinearizationKey`.
    public let relinearizationKey: SerializedRelinearizationKey<Scalar>?

    /// Initializes a ``SerializedEvaluationKey``.
    /// - Parameters:
    ///   - galoisKey: An optional serialized `GaloisKey`.
    ///   - relinearizationKey: An optional serialized `RelinearizationKey`.
    public init(galoisKey: SerializedGaloisKey<Scalar>?, relinearizationKey: SerializedRelinearizationKey<Scalar>?) {
        self.galoisKey = galoisKey
        self.relinearizationKey = relinearizationKey
    }
}

extension EvaluationKey {
    /// Initializes an ``EvaluationKey`` from a serialized evaluation key.
    /// - Parameters:
    ///   - serialized: Serialized evaluation key.
    ///   - context: Context to associate with the evaluation key.
    /// - Throws: ``HeError`` upon failure to deserialize.
    @inlinable
    public init(deserialize serialized: SerializedEvaluationKey<Scheme.Scalar>,
                context: Context<Scheme.Scalar>) throws
    {
        self.galoisKey = try serialized.galoisKey.map { serialized in
            try GaloisKey(deserialize: serialized, context: context)
        }
        self.relinearizationKey = try serialized.relinearizationKey.map { serialized in
            try RelinearizationKey(deserialize: serialized, context: context)
        }
    }

    /// Serializes the evaluation key.
    /// - Returns: The serialized evaluation key.
    public func serialize() -> SerializedEvaluationKey<Scheme.Scalar> {
        SerializedEvaluationKey(galoisKey: galoisKey.map { $0.serialize() },
                                relinearizationKey: relinearizationKey.map { $0.serialize() })
    }
}
