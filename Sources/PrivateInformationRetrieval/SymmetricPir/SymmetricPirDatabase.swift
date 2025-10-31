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

import _CryptoExtras
import Crypto
import Foundation
import HomomorphicEncryption

/// Symmetric PIR config type specifying config for OPRF and keyword entry encryption.
public enum SymmetricPirConfigType: String, CaseIterable, Codable, Hashable, Sendable {
    case OPRF_P384_AES_GCM_192_NONCE_96_TAG_128

    /// Size in bytes of OPRF key.
    public var oprfKeySize: Int {
        switch self {
        case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128: 48
        }
    }

    /// Size in bytes of OPRF output.
    public var oprfOutputSize: Int {
        switch self {
        case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128: 48
        }
    }

    /// Size in bytes of oblivious keyword.
    public var obliviousKeywordSize: Int {
        switch self {
        case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128: 16
        }
    }

    /// Size in bytes of encryption key used in encrypting database entries.
    public var entryEncryptionKeySize: Int {
        switch self {
        case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128: 24
        }
    }

    /// Size in bytes of nonce used in encryption.
    public var nonceSize: Int {
        switch self {
        case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128: 12
        }
    }

    /// Size in bytes of tag used in entry encryption.
    public var tagSize: Int {
        switch self {
        case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128: 16
        }
    }
}

extension SymmetricPirConfigType {
    /// Validates that a given byte array is a valid encryption key.
    /// - Parameter encryptionKey: Encryption key as byte array.
    /// - Throws: Error if key is invalid.
    public func validateEncryptionKey(_ encryptionKey: [UInt8]) throws {
        switch self {
        case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128:
            _ = try OprfPrivateKey(rawRepresentation: encryptionKey)
        }
    }
}

/// Client configuration for Symmetric PIR.
public struct SymmetricPirClientConfig: Codable, Hashable, Sendable {
    /// OPRF server public key.
    public let serverPublicKey: [UInt8]
    /// Symmetric PIR config type.
    public let configType: SymmetricPirConfigType

    /// Initialize ``SymmetricPirClientConfig``.`
    /// - Parameters:
    ///   - serverPublicKey: Public key for OPRF server.
    ///   - configType: Config type for Symmetric PIR.
    @inlinable
    public init(serverPublicKey: [UInt8], configType: SymmetricPirConfigType) {
        self.serverPublicKey = serverPublicKey
        self.configType = configType
    }
}

/// A wrapper for secret values.
public final class Secret: Equatable, Hashable, @unchecked Sendable {
    /// Secret value bytes.
    public var value: [UInt8]

    @inlinable
    public init(value: [UInt8]) {
        self.value = value
    }

    public static func == (lhs: Secret, rhs: Secret) -> Bool {
        lhs.value == rhs.value
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(value)
    }

    // Sets all bytes to zero.
    @inlinable
    public func zeroize() {
        let zeroizeSize = value.count * MemoryLayout<UInt8>.size
        value.withUnsafeMutableBytes { dataPointer in
            // swiftlint:disable:next force_unwrapping
            HomomorphicEncryption.zeroize(dataPointer.baseAddress!, zeroizeSize)
        }
    }

    deinit {
        zeroize()
    }
}

extension Secret: Codable {
    enum CodingKeys: String, CodingKey {
        case value
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("****", forKey: .value)
    }
}

extension Secret: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "Secret(value: ****)"
    }

    public var debugDescription: String {
        "Secret(value: ****)"
    }
}

/// Configuration for Symmetric PIR.
public struct SymmetricPirConfig: Codable, Hashable, Sendable {
    /// Secret key for keyword database encryption.
    public let oprfSecretKey: Secret
    /// Symmetric PIR config type.
    public let configType: SymmetricPirConfigType

    /// Initializes a ``SymmetricPirConfig``.
    /// - Parameters:
    ///   - oprfSecretKey: Secret key for encrypting keyword database.
    ///   - configType: Symmetric PIR config type.
    /// - Throws: Error on invalid key size.
    @inlinable
    public init(
        oprfSecretKey: Secret,
        configType: SymmetricPirConfigType = .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128) throws
    {
        guard oprfSecretKey.value.count == configType.oprfKeySize else {
            throw PirError.invalidOPRFKeySize(oprfSecretKey.value.count, expectedSize: Int(configType.oprfKeySize))
        }
        self.oprfSecretKey = oprfSecretKey
        self.configType = configType
    }

    /// SymmetricPir configuration for the client.
    public func clientConfig() throws -> SymmetricPirClientConfig {
        switch configType {
        case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128:
            let serverPublicKey = try OprfPrivateKey(rawRepresentation: oprfSecretKey.value).publicKey
                .oprfRepresentation
            return SymmetricPirClientConfig(serverPublicKey: [UInt8](serverPublicKey), configType: configType)
        }
    }
}

extension KeywordDatabase {
    /// Encrypts ``KeywordDatabase`` for database privacy.
    /// - Parameters:
    ///   - database: Rows in the database.
    ///   - config: SymmetricPIR configuration.
    /// - Returns: Encrypted database entries.
    /// - Throws: Error on processing failure.
    public static func symmetricPIRProcess(database: some Collection<KeywordValuePair>,
                                           config: SymmetricPirConfig) throws -> [KeywordValuePair]
    {
        guard case .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128 = config.configType else {
            throw PirError.invalidSymmetricPirConfig(symmetricPirConfig: config)
        }
        let oprfSecretKey = try OprfPrivateKey(rawRepresentation: config.oprfSecretKey.value)

        return try database.map { entry in
            let oprfOutputHash = try [UInt8](oprfSecretKey.evaluate(Data(entry.keyword)))
            precondition(oprfOutputHash.count == config.configType.oprfOutputSize)
            let newKeyword = [UInt8](oprfOutputHash.prefix(config.configType.obliviousKeywordSize))
            let key = SymmetricKey(data: oprfOutputHash.suffix(config.configType.entryEncryptionKeySize))
            let nonce = try AES.GCM.Nonce(data: oprfOutputHash.prefix(config.configType.nonceSize))
            let encryptedValue = try AES.GCM.seal(entry.value, using: key, nonce: nonce)
            let newValue = encryptedValue.ciphertext + encryptedValue.tag
            return KeywordValuePair(keyword: newKeyword, value: [UInt8](newValue))
        }
    }
}
