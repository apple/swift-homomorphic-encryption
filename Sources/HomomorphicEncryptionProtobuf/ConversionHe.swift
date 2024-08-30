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

extension Apple_SwiftHomomorphicEncryption_V1_ErrorStdDev {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon unsupported object.
    public func native() throws -> ErrorStdDev {
        switch self {
        case .stddev32:
            .stdDev32
        case let .UNRECOGNIZED(value):
            throw ConversionError.unrecognizedEnumValue(enum: Self.self, value: value)
        }
    }
}

extension ErrorStdDev {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_V1_ErrorStdDev {
        switch self {
        case .stdDev32:
            Apple_SwiftHomomorphicEncryption_V1_ErrorStdDev.stddev32
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedPlaintext {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() -> SerializedPlaintext {
        SerializedPlaintext(poly: Array(poly))
    }
}

extension SerializedPlaintext {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_V1_SerializedPlaintext {
        Apple_SwiftHomomorphicEncryption_V1_SerializedPlaintext.with { $0.poly = Data(poly) }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertextVec {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native<T: ScalarType>() throws -> [SerializedCiphertext<T>] {
        try ciphertexts.map { try $0.native() }
    }
}

extension Sequence {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto<T: ScalarType>() -> Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertextVec
        where Element == SerializedCiphertext<T>
    {
        Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertextVec.with { $0.ciphertexts = self.map { $0.proto() } }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native<T: ScalarType>() throws -> SerializedCiphertext<T> {
        guard let serializedCiphertextType else {
            throw ConversionError.unsetOneof(oneof: Self.self, field: \Self.serializedCiphertextType)
        }
        return switch serializedCiphertextType {
        case let .seeded(seeded):
            SerializedCiphertext.seeded(poly0: Array(seeded.poly0), seed: Array(seeded.seed))
        case let .full(full):
            SerializedCiphertext.full(
                polys: Array(full.polys),
                skipLSBs: full.skipLsbs.map(Int.init),
                correctionFactor: T(full.correctionFactor))
        }
    }
}

extension SerializedCiphertext {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext {
        switch self {
        case let .full(polys: polys, skipLSBs: skipLSBs, correctionFactor: correctionFactor):
            Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext.with { ciphertext in
                ciphertext.full = Apple_SwiftHomomorphicEncryption_V1_SerializedFullCiphertext.with { fullCiphertext in
                    fullCiphertext.polys = Data(polys)
                    fullCiphertext.skipLsbs = skipLSBs.map(UInt32.init)
                    fullCiphertext.correctionFactor = UInt64(correctionFactor)
                }
            }
        case let .seeded(poly0: poly0, seed: seed):
            Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext.with { ciphertext in
                ciphertext.seeded = Apple_SwiftHomomorphicEncryption_V1_SerializedSeededCiphertext
                    .with { seededCiphertext in
                        seededCiphertext.poly0 = Data(poly0)
                        seededCiphertext.seed = Data(seed)
                    }
            }
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native<T: ScalarType>() throws -> [SerializedCiphertext<T>] {
        try keySwitchKey.native()
    }
}

extension Sequence {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto<T: ScalarType>() -> Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey
        where Element == SerializedCiphertext<T>
    {
        Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey.with { $0.keySwitchKey = self.proto() }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedGaloisKey {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native<T: ScalarType>() throws -> SerializedGaloisKey<T> {
        var nativeKeySwitchKeys: [Int: [SerializedCiphertext<T>]] = [:]
        for (key, value) in keySwitchKeys {
            nativeKeySwitchKeys[Int(key)] = try value.native()
        }
        return SerializedGaloisKey(galoisKey: nativeKeySwitchKeys)
    }
}

extension SerializedGaloisKey {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_V1_SerializedGaloisKey {
        var protoKeySwitchKeys: [UInt64: Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey] = [:]
        for (key, value) in galoisKey {
            protoKeySwitchKeys[UInt64(key)] = value.proto()
        }
        return Apple_SwiftHomomorphicEncryption_V1_SerializedGaloisKey.with { galoisKey in
            galoisKey.keySwitchKeys = protoKeySwitchKeys
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedRelinKey {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native<T: ScalarType>() throws -> SerializedRelinearizationKey<T> {
        try SerializedRelinearizationKey(relinKey: relinKey.native())
    }
}

extension SerializedRelinearizationKey {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_V1_SerializedRelinKey {
        Apple_SwiftHomomorphicEncryption_V1_SerializedRelinKey.with { relinKey in
            relinKey.relinKey = self.relinKey.proto()
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedSecretKey {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native() throws -> SerializedSecretKey {
        SerializedSecretKey(polys: Array(polys))
    }
}

extension SerializedSecretKey {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_V1_SerializedSecretKey {
        Apple_SwiftHomomorphicEncryption_V1_SerializedSecretKey.with { secretKey in
            secretKey.polys = Data(polys)
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedEvaluationKey {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native<T: ScalarType>() throws -> SerializedEvaluationKey<T> {
        try SerializedEvaluationKey(galoisKey: galoisKey.native(), relinearizationKey: relinKey.native())
    }

    /// Converts the protobuf object to a native type.
    /// - Parameter context: Context to associate with the native object.
    /// - Returns: The converted native type.
    /// - Throws: Error upon upon invalid object.
    public func native<Scheme: HeScheme>(context: Context<Scheme>) throws -> EvaluationKey<Scheme> {
        let serialized: SerializedEvaluationKey<Scheme.Scalar> = try native()
        return try EvaluationKey(deserialize: serialized, context: context)
    }
}

extension SerializedEvaluationKey {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_V1_SerializedEvaluationKey {
        Apple_SwiftHomomorphicEncryption_V1_SerializedEvaluationKey.with { evalKey in
            if let galoisKey {
                evalKey.galoisKey = galoisKey.proto()
            }
            if let relinearizationKey {
                evalKey.relinKey = relinearizationKey.proto()
            }
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_EvaluationKeyConfig {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    public func native() -> EvaluationKeyConfig {
        .init(galoisElements: galoisElements.map(Int.init), hasRelinearizationKey: hasRelinKey_p)
    }
}

extension EvaluationKeyConfig {
    /// Converts the native object into a protobuf object.
    /// - Parameter encryptionParameters: Encryption parameters to associate with the protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported encryption parameters.
    public func proto(encryptionParameters: EncryptionParameters<some HeScheme>) throws
        -> Apple_SwiftHomomorphicEncryption_V1_EvaluationKeyConfig
    {
        try Apple_SwiftHomomorphicEncryption_V1_EvaluationKeyConfig.with { evalKeyConfig in
            evalKeyConfig.encryptionParameters = try encryptionParameters.proto()
            evalKeyConfig.galoisElements = galoisElements.map(UInt32.init)
            evalKeyConfig.hasRelinKey_p = hasRelinearizationKey
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_SecurityLevel {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon unsupported object.
    public func native() throws -> SecurityLevel {
        switch self {
        case .unspecified:
            .unchecked
        case .quantum128:
            .quantum128
        case let .UNRECOGNIZED(value):
            throw ConversionError.unrecognizedEnumValue(enum: Self.self, value: value)
        }
    }
}

extension SecurityLevel {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    public func proto() -> Apple_SwiftHomomorphicEncryption_V1_SecurityLevel {
        switch self {
        case .quantum128:
            .quantum128
        case .unchecked:
            .unspecified
        }
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_HeScheme {
    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon unsupported object.
    public func native() throws -> any HeScheme.Type {
        switch self {
        case .unspecified:
            return NoOpScheme.self
        case .bfv:
            return Bfv<UInt64>.self
        case .bgv:
            throw ConversionError.unimplementedScheme(scheme: "BGV")
        case let .UNRECOGNIZED(value):
            throw ConversionError.unrecognizedEnumValue(enum: Self.self, value: value)
        }
    }
}

extension HeScheme {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public static func proto() throws -> Apple_SwiftHomomorphicEncryption_V1_HeScheme {
        if Self.self is Bfv<UInt32>.Type || self is Bfv<UInt64>.Type {
            return .bfv
        }
        throw ConversionError.invalidScheme
    }
}

extension Apple_SwiftHomomorphicEncryption_V1_EncryptionParameters {
    /// Validates the encryption parameters are valid for the given `scheme` and `schemeType``.
    /// - Parameters:
    ///   - scheme: HE scheme to associate with the encryption parameters.
    ///   - schemeType: `HeScheme` type to associate with the encryption parameters.
    /// - Throws: Error upon invalid encryption parameters.
    public func validate(scheme: Apple_SwiftHomomorphicEncryption_V1_HeScheme,
                         schemeType: (some HeScheme).Type) throws
    {
        switch scheme {
        case .unspecified:
            return
        case .bfv:
            guard schemeType.self is Bfv<UInt32>.Type || schemeType.self is Bfv<UInt64>.Type else {
                throw ConversionError.invalidScheme
            }
        case .bgv:
            throw ConversionError.invalidScheme
        case let .UNRECOGNIZED(value):
            throw ConversionError.unrecognizedEnumValue(
                enum: Apple_SwiftHomomorphicEncryption_V1_HeScheme.self,
                value: value)
        }
    }

    /// Converts the protobuf object to a native type.
    /// - Returns: The converted native type.
    /// - Throws: Error upon invalid object.
    public func native<Scheme: HeScheme>() throws -> EncryptionParameters<Scheme> {
        try validate(scheme: heScheme, schemeType: Scheme.self)
        guard plaintextModulus < Scheme.Scalar.max, coefficientModuli.allSatisfy({ $0 < Scheme.Scalar.max }) else {
            throw ConversionError.invalidScheme
        }
        return try EncryptionParameters(polyDegree: Int(polynomialDegree),
                                        plaintextModulus: Scheme.Scalar(plaintextModulus),
                                        coefficientModuli: coefficientModuli.map { Scheme.Scalar($0) },
                                        errorStdDev: errorStdDev.native(),
                                        securityLevel: securityLevel.native())
    }
}

extension EncryptionParameters {
    /// Converts the native object into a protobuf object.
    /// - Returns: The converted protobuf object.
    /// - Throws: Error upon unsupported object.
    public func proto() throws -> Apple_SwiftHomomorphicEncryption_V1_EncryptionParameters {
        try Apple_SwiftHomomorphicEncryption_V1_EncryptionParameters.with { encParams in
            encParams.polynomialDegree = UInt64(polyDegree)
            encParams.plaintextModulus = UInt64(plaintextModulus)
            encParams.coefficientModuli = coefficientModuli.map(UInt64.init)
            encParams.errorStdDev = errorStdDev.proto()
            encParams.securityLevel = securityLevel.proto()
            encParams.heScheme = try Scheme.proto()
        }
    }
}
