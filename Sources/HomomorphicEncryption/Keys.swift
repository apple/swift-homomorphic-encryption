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

/// Secret key.
///
/// - seealso: ``HeScheme/generateSecretKey(context:)`` or ``Context/generateSecretKey()`` can be used to generate a
/// secret key.
public final class SecretKey<Scheme: HeScheme>: Equatable, @unchecked Sendable {
    // This should be safely `@unchecked Sendable`, because poly is only mutated in `deinit`.

    @usableFromInline var poly: PolyRq<Scheme.Scalar, Eval>

    @inlinable
    init(poly: consuming PolyRq<Scheme.Scalar, Eval>) {
        self.poly = poly
    }

    public static func == (lhs: SecretKey<Scheme>, rhs: SecretKey<Scheme>) -> Bool {
        lhs.poly == rhs.poly
    }

    deinit {
        poly.zeroize()
    }
}

extension SecretKey: PolyCollection {
    public typealias Scalar = Scheme.Scalar

    @inlinable
    public func polyContext() -> PolyContext<Scheme.Scalar> {
        poly.context
    }
}

/// A cryptographic key used for key-switching operations.
///
/// Key-switching operations include relinearization and Galois transformations.
/// - seealso: ``HeScheme/relinearize(_:using:)`` and ``HeScheme/applyGalois(ciphertext:element:using:)`` for more
/// details.
@usableFromInline
struct KeySwitchKey<Scheme: HeScheme>: Equatable, Sendable {
    /// The context used for key-switching operations.
    @usableFromInline let context: Context<Scheme>
    /// The ciphertexts of the key-switching key.
    @usableFromInline let ciphers: [Ciphertext<Scheme, Eval>]

    @inlinable
    init(context: Context<Scheme>, ciphers: [Ciphertext<Scheme, Eval>]) {
        self.context = context
        self.ciphers = ciphers
    }
}

extension KeySwitchKey: PolyCollection {
    public typealias Scalar = Scheme.Scalar

    @inlinable
    public func polyContext() -> PolyContext<Scheme.Scalar> {
        ciphers[0].polyContext()
    }
}

@usableFromInline
struct RelinearizationKey<Scheme: HeScheme>: Equatable, Sendable {
    @usableFromInline let keySwitchKey: KeySwitchKey<Scheme>

    @inlinable
    init(keySwitchKey: KeySwitchKey<Scheme>) {
        self.keySwitchKey = keySwitchKey
    }
}

extension RelinearizationKey: PolyCollection {
    public typealias Scalar = Scheme.Scalar

    @inlinable
    public func polyContext() -> PolyContext<Scheme.Scalar> {
        keySwitchKey.ciphers[0].polyContext()
    }
}

@usableFromInline
struct GaloisKey<Scheme: HeScheme>: Equatable, Sendable {
    @usableFromInline let keys: [Int: KeySwitchKey<Scheme>]

    @inlinable
    init(keys: [Int: KeySwitchKey<Scheme>]) {
        self.keys = keys
    }
}

extension GaloisKey: PolyCollection {
    public typealias Scalar = Scheme.Scalar

    @inlinable
    public func polyContext() -> PolyContext<Scheme.Scalar> {
        if let firstKey = keys.values.first {
            firstKey.ciphers[0].polyContext()
        } else {
            preconditionFailure("Empty Galois key")
        }
    }
}

/// Cryptographic key used in performing some HE operations.
///
/// Associated with a ``SecretKey``.
public struct EvaluationKey<Scheme: HeScheme>: Equatable, Sendable {
    @usableFromInline let galoisKey: GaloisKey<Scheme>?
    @usableFromInline let relinearizationKey: RelinearizationKey<Scheme>?

    /// Returns the configuration for the evaluation key.
    public var config: EvaluationKeyConfig {
        EvaluationKeyConfig(
            // swiftlint:disable:next array_init
            galoisElements: galoisKey?.keys.keys.map { $0 } ?? [],
            hasRelinearizationKey: relinearizationKey != nil)
    }

    @inlinable
    init(
        galoisKey: GaloisKey<Scheme>?,
        relinearizationKey: RelinearizationKey<Scheme>?)
    {
        self.galoisKey = galoisKey
        self.relinearizationKey = relinearizationKey
    }
}

/// A configuration for generating an evaluation key.
public struct EvaluationKeyConfig: Codable, Equatable, Hashable, Sendable {
    /// Galois elements.
    /// - seealso: ``GaloisElement``and ``HeScheme/applyGalois(ciphertext:element:using:)`` for more information.
    public let galoisElements: [Int]
    /// Whether to generate a `RelinearizationKey`.
    ///
    /// - seealso: ``HeScheme/relinearize(_:using:)`` for more information.
    public let hasRelinearizationKey: Bool

    /// Returns the number of key-switching keys in the configuration.
    ///
    /// Each Galois element and the relinearization yield a single key-switching key.
    public var keyCount: Int {
        galoisElements.count + (hasRelinearizationKey ? 1 : 0)
    }

    /// Initializes an ``EvaluationKeyConfig``.
    /// - Parameters:
    ///   - galoisElements: Galois elements.
    ///   - hasRelinearizationKey: Whether the configuration includes a relinearization key.
    /// - seealso: ``GaloisElement``, ``HeScheme/relinearize(_:using:)``,
    /// ``HeScheme/applyGalois(ciphertext:element:using:)`` for more information.
    public init(galoisElements: [Int] = [], hasRelinearizationKey: Bool = false) {
        self.galoisElements = galoisElements
        self.hasRelinearizationKey = hasRelinearizationKey
    }
}

extension Sequence<EvaluationKeyConfig> {
    /// Computes the union of evaluation key configurations.
    ///
    /// The union of ``EvaluationKeyConfig``s is a configuration whose:
    ///  * Galois elements is a union of each configuration's Galois elements
    ///  * `hasRelinearizationKey` is true when any of the sequence of configurations has
    /// `hasRelinearizationKey: true`.
    ///
    ///  > Note: The union can be used to generate an `EvaluationKey` which supports the HE operations of any of the
    /// evaluation key configurations.
    /// - Returns: The joint evaluation configuration
    public func union() -> EvaluationKeyConfig {
        var galoisElements: Set<Int> = []
        var hasRelinearizationKey = false
        for config in self {
            galoisElements.formUnion(config.galoisElements)
            hasRelinearizationKey = hasRelinearizationKey || config.hasRelinearizationKey
        }
        return .init(galoisElements: galoisElements.sorted(), hasRelinearizationKey: hasRelinearizationKey)
    }
}

extension EvaluationKeyConfig {
    /// Checks if this configuration contains the `other` evaluation key configuration.
    ///
    /// If true, this configuration can be used whenever `other` is used.
    /// - Parameter other: The `EvaluationKeyConfig` to check containment with.
    /// - Returns: `true` if containment holds, `false` otherwise.
    package func contains(_ other: EvaluationKeyConfig) -> Bool {
        let containsRelinearizationKey: Bool = hasRelinearizationKey || !other.hasRelinearizationKey
        let containsGaloisElements: Bool = Set(galoisElements).isSuperset(of: other.galoisElements)
        return containsRelinearizationKey && containsGaloisElements
    }
}
