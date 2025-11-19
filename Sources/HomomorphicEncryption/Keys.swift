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

    @usableFromInline var poly: PolyRq<Scalar, Eval>

    /// public access to poly.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    public var _poly: PolyRq<Scheme.Scalar, Eval> { poly }

    /// Create a secret key by providing its content.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    /// - Parameter _poly: the polynomial for the secret key.
    @inlinable
    public convenience init(_poly: consuming PolyRq<Scheme.Scalar, Eval>) {
        self.init(poly: _poly)
    }

    @inlinable
    init(poly: consuming PolyRq<Scalar, Eval>) {
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
    public func polyContext() -> PolyContext<Scalar> {
        poly.context
    }
}

/// A cryptographic key used for key-switching operations.
///
/// Key-switching operations include relinearization and Galois transformations.
/// - seealso: ``HeScheme/relinearize(_:using:)`` and ``HeScheme/applyGalois(ciphertext:element:using:)`` for more
/// details.
public struct _KeySwitchKey<Scheme: HeScheme>: HeKeySwitchKey {
    /// The context used for key-switching operations.
    @usableFromInline let context: Scheme.Context
    /// The ciphertexts of the key-switching key.
    @usableFromInline let ciphertexts: [Ciphertext<Scheme, Eval>]

    /// public access to context.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    public var _context: Scheme.Context { context }
    /// public access to ciphertexts.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    public var _ciphertexts: [Ciphertext<Scheme, Eval>] { ciphertexts }

    /// Create a key-switching key by providing its ontent.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    /// - Parameters:
    ///   - _context: the context of key switching key.
    ///   - _ciphertexts: the ciphertexts of key switching key.
    @inlinable
    public init(_context: Scheme.Context, _ciphertexts: [Ciphertext<Scheme, Eval>]) {
        self.init(context: _context, ciphertexts: _ciphertexts)
    }

    @inlinable
    init(context: Scheme.Context, ciphertexts: [Ciphertext<Scheme, Eval>]) {
        self.context = context
        self.ciphertexts = ciphertexts
    }
}

extension _KeySwitchKey: PolyCollection {
    public typealias Scalar = Scheme.Scalar

    @inlinable
    public func polyContext() -> PolyContext<Scalar> {
        ciphertexts[0].polyContext()
    }
}

/// A cryptographic key used for relinearization operations.
public struct _RelinearizationKey<Scheme: HeScheme>: Equatable, Sendable {
    @usableFromInline let keySwitchKey: Scheme.KeySwitchKey
    /// public access to key-switching key.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    public var _keySwitchKey: Scheme.KeySwitchKey { keySwitchKey }

    /// Create a relinearization key by providing its content.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    /// - Parameter _keySwitchKey:  the key-switching key for relinearization key.
    @inlinable
    public init(_keySwitchKey: Scheme.KeySwitchKey) {
        self.init(keySwitchKey: _keySwitchKey)
    }

    @inlinable
    init(keySwitchKey: Scheme.KeySwitchKey) {
        self.keySwitchKey = keySwitchKey
    }
}

extension _RelinearizationKey: PolyCollection {
    public typealias Scalar = Scheme.Scalar

    @inlinable
    public func polyContext() -> PolyContext<Scalar> {
        keySwitchKey.ciphertexts[0].polyContext()
    }
}

/// A cryptographic key used for ciphertext rotation operation.
public struct _GaloisKey<Scheme: HeScheme>: HeGaloisKey {
    @usableFromInline let keys: [Int: Scheme.KeySwitchKey]
    /// public access to key-switching keys.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    public var _keys: [Int: Scheme.KeySwitchKey] { keys }

    /// Create a Galois key by providing its content.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    /// - Parameter _keys:  the key-switching keys of Galois key.
    @inlinable
    public init(_keys: [Int: Scheme.KeySwitchKey]) {
        self.init(keys: _keys)
    }

    @inlinable
    init(keys: [Int: Scheme.KeySwitchKey]) {
        self.keys = keys
    }
}

extension _GaloisKey: PolyCollection {
    public typealias Scalar = Scheme.Scalar

    @inlinable
    public func polyContext() -> PolyContext<Scalar> {
        if let firstKey = keys.values.first {
            firstKey.ciphertexts[0].polyContext()
        } else {
            preconditionFailure("Empty Galois key")
        }
    }
}

/// Cryptographic key used in performing some HE operations.
///
/// Associated with a ``SecretKey``.
public struct EvaluationKey<Scheme: HeScheme>: Equatable, Sendable {
    @usableFromInline package let galoisKey: _GaloisKey<Scheme>?
    @usableFromInline package let relinearizationKey: _RelinearizationKey<Scheme>?

    /// public access to Galois key.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    public var _galoisKey: _GaloisKey<Scheme>? { galoisKey }
    /// public access to relineraization key.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    public var _relinearizationKey: _RelinearizationKey<Scheme>? { relinearizationKey }

    /// Returns the configuration for the evaluation key.
    public var config: EvaluationKeyConfig {
        EvaluationKeyConfig(
            galoisElements: galoisKey?.keys.keys.map(\.self) ?? [],
            hasRelinearizationKey: relinearizationKey != nil)
    }

    /// Create a evaluation key by providing its content.
    /// - Warning: This API is not subject to semantic versioning: these APIs may change without warning.
    /// - Parameters:
    ///   - _galoisKey: the Galois key of the evaluation key.
    ///   - _relinearizationKey:  the relinearization key of the evaluation key.
    @inlinable
    public init(_galoisKey: _GaloisKey<Scheme>?, _relinearizationKey: _RelinearizationKey<Scheme>?) {
        self.init(galoisKey: _galoisKey, relinearizationKey: _relinearizationKey)
    }

    @inlinable
    init(galoisKey: _GaloisKey<Scheme>?, relinearizationKey: _RelinearizationKey<Scheme>?) {
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
    /// - Returns: The joint evaluation configuration.
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
