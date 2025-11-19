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

/// Serialized ``Plaintext`` type.
public struct SerializedPlaintext: Hashable, Codable, Sendable {
    /// The serialized polynomial.
    public let poly: [UInt8]

    /// Initializes a serialized plaintext.
    /// - Parameter poly: Serialized polynomial.
    public init(poly: [UInt8]) {
        self.poly = poly
    }
}

extension Plaintext {
    /// Serializes the plaintext.
    public func serialize() -> SerializedPlaintext {
        SerializedPlaintext(poly: poly.serialize())
    }
}

extension Plaintext where Format == Coeff {
    /// Deserializes a plaintext.
    /// - Parameters:
    ///   - serialized: Serialized plaintext.
    ///   - context: Context to associate with the plaintext.
    /// - Throws: Error upon failure to deserialize.
    @inlinable
    public init(deserialize serialized: SerializedPlaintext, context: Scheme.Context) throws {
        self.context = context
        self.poly = try PolyRq(deserialize: serialized.poly, context: context.plaintextContext)
        self.auxiliaryData = try Scheme.PlaintextAuxiliaryData(context: context, poly: poly)
    }
}

extension Plaintext where Format == Eval {
    /// Deserializes a plaintext.
    /// - Parameters:
    ///   - serialized: Serialized plaintext.
    ///   - context: Context to associate with the plaintext.
    ///   - moduliCount: Optional number of moduli to associate with the plaintext. If not set, the plaintext will have
    /// the top-level ciphertext context with all the moduli.
    /// - Throws: Error upon failure to deserialize.
    @inlinable
    public init(
        deserialize serialized: SerializedPlaintext,
        context: Scheme.Context,
        moduliCount: Int? = nil) throws
    {
        self.context = context
        let moduliCount = moduliCount ?? context.ciphertextContext.moduli.count
        let plaintextContext = try context.ciphertextContext.getContext(moduliCount: moduliCount)
        self.poly = try PolyRq(deserialize: serialized.poly, context: plaintextContext)
        self.auxiliaryData = try Scheme.PlaintextAuxiliaryData(context: context, poly: poly)
    }
}
