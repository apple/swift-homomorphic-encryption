// DO NOT EDIT.
// swift-format-ignore-file
// swiftlint:disable all
//
// Generated by the Swift generator plugin for the protocol buffer compiler.
// Source: apple/swift_homomorphic_encryption/v1/he.proto
//
// For information on using the generated types, please see the documentation:
//   https://github.com/apple/swift-protobuf/

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
import SwiftProtobuf

// If the compiler emits an error on this type, it is because this file
// was generated by a version of the `protoc` Swift plug-in that is
// incompatible with the version of SwiftProtobuf to which you are linking.
// Please ensure that you are building against the same version of the API
// that was used to generate this file.
fileprivate struct _GeneratedWithProtocGenSwiftVersion: SwiftProtobuf.ProtobufAPIVersionCheck {
  struct _2: SwiftProtobuf.ProtobufAPIVersion_2 {}
  typealias Version = _2
}

/// The security level for encryption parameters based on ternary secrets.
public enum Apple_SwiftHomomorphicEncryption_V1_SecurityLevel: SwiftProtobuf.Enum, Swift.CaseIterable {
  public typealias RawValue = Int

  /// No security enforced.
  case unspecified // = 0

  /// Post-quantum 128-bit security.
  case quantum128 // = 1
  case UNRECOGNIZED(Int)

  public init() {
    self = .unspecified
  }

  public init?(rawValue: Int) {
    switch rawValue {
    case 0: self = .unspecified
    case 1: self = .quantum128
    default: self = .UNRECOGNIZED(rawValue)
    }
  }

  public var rawValue: Int {
    switch self {
    case .unspecified: return 0
    case .quantum128: return 1
    case .UNRECOGNIZED(let i): return i
    }
  }

  // The compiler won't synthesize support with the UNRECOGNIZED case.
  public static let allCases: [Apple_SwiftHomomorphicEncryption_V1_SecurityLevel] = [
    .unspecified,
    .quantum128,
  ]

}

/// HE scheme.
public enum Apple_SwiftHomomorphicEncryption_V1_HeScheme: SwiftProtobuf.Enum, Swift.CaseIterable {
  public typealias RawValue = Int

  /// Unspecified.
  case unspecified // = 0

  /// Brakerski-Fan-Vercauteren.
  case bfv // = 1

  /// Brakerski-Gentry-Vaikuntanathan.
  case bgv // = 2
  case UNRECOGNIZED(Int)

  public init() {
    self = .unspecified
  }

  public init?(rawValue: Int) {
    switch rawValue {
    case 0: self = .unspecified
    case 1: self = .bfv
    case 2: self = .bgv
    default: self = .UNRECOGNIZED(rawValue)
    }
  }

  public var rawValue: Int {
    switch self {
    case .unspecified: return 0
    case .bfv: return 1
    case .bgv: return 2
    case .UNRECOGNIZED(let i): return i
    }
  }

  // The compiler won't synthesize support with the UNRECOGNIZED case.
  public static let allCases: [Apple_SwiftHomomorphicEncryption_V1_HeScheme] = [
    .unspecified,
    .bfv,
    .bgv,
  ]

}

/// A serialized `Plaintext`.
public struct Apple_SwiftHomomorphicEncryption_V1_SerializedPlaintext: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// A serialized polynomial.
  public var poly: Data = Data()

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

/// A vector of serialized `Ciphertext`s.
public struct Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertextVec: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Serialized ciphertexts.
  public var ciphertexts: [Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext] = []

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

/// A serialized `Ciphertext`.
public struct Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Represents different serialized ciphertext types.
  public var serializedCiphertextType: Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext.OneOf_SerializedCiphertextType? = nil

  /// Serialized ciphertext where a RNG seed is used to store a polynomial in a compressed form.
  public var seeded: Apple_SwiftHomomorphicEncryption_V1_SerializedSeededCiphertext {
    get {
      if case .seeded(let v)? = serializedCiphertextType {return v}
      return Apple_SwiftHomomorphicEncryption_V1_SerializedSeededCiphertext()
    }
    set {serializedCiphertextType = .seeded(newValue)}
  }

  /// Serialized ciphertext where each coefficient of each polynomial is serialized.
  public var full: Apple_SwiftHomomorphicEncryption_V1_SerializedFullCiphertext {
    get {
      if case .full(let v)? = serializedCiphertextType {return v}
      return Apple_SwiftHomomorphicEncryption_V1_SerializedFullCiphertext()
    }
    set {serializedCiphertextType = .full(newValue)}
  }

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  /// Represents different serialized ciphertext types.
  public enum OneOf_SerializedCiphertextType: Equatable, Sendable {
    /// Serialized ciphertext where a RNG seed is used to store a polynomial in a compressed form.
    case seeded(Apple_SwiftHomomorphicEncryption_V1_SerializedSeededCiphertext)
    /// Serialized ciphertext where each coefficient of each polynomial is serialized.
    case full(Apple_SwiftHomomorphicEncryption_V1_SerializedFullCiphertext)

  }

  public init() {}
}

/// A serialized `Ciphertext` using a seed in place of the second polynomial.
public struct Apple_SwiftHomomorphicEncryption_V1_SerializedSeededCiphertext: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// The serialized first polynomial.
  public var poly0: Data = Data()

  /// The seed for the second polynomial.
  public var seed: Data = Data()

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

/// A serialized `Ciphertext` with all polynomials expanded.
public struct Apple_SwiftHomomorphicEncryption_V1_SerializedFullCiphertext: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// The polynomials in the ciphertext.
  public var polys: Data = Data()

  /// Serialization may exclude low bits from each polyomial's coefficients, yielding reduced serialization size.
  ///
  /// The i'th entry tells how many bits to exclude from each coefficient of the i'th polynomial
  /// This is useful when the ciphertext is immediately decrypted upon deserialization.
  /// See Section 5.2 of <https://eprint.iacr.org/2022/207.pdf>.
  public var skipLsbs: [UInt32] = []

  /// Correction factor.
  ///
  /// See Section 4 of <https://eprint.iacr.org/2020/1481.pdf>.
  public var correctionFactor: UInt64 = 0

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

/// A serialized `KeySwitchKey`.
public struct Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// The key-switching key.
  public var keySwitchKey: Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertextVec {
    get {return _keySwitchKey ?? Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertextVec()}
    set {_keySwitchKey = newValue}
  }
  /// Returns true if `keySwitchKey` has been explicitly set.
  public var hasKeySwitchKey: Bool {return self._keySwitchKey != nil}
  /// Clears the value of `keySwitchKey`. Subsequent reads from it will return its default value.
  public mutating func clearKeySwitchKey() {self._keySwitchKey = nil}

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}

  fileprivate var _keySwitchKey: Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertextVec? = nil
}

/// A serialized `GaloisKey`.
public struct Apple_SwiftHomomorphicEncryption_V1_SerializedGaloisKey: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Maps each Galois element to its key-switching key.
  public var keySwitchKeys: Dictionary<UInt64,Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey> = [:]

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

/// A serialized `RelinearizationKey`.
public struct Apple_SwiftHomomorphicEncryption_V1_SerializedRelinKey: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// The relinearization key.
  public var relinKey: Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey {
    get {return _relinKey ?? Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey()}
    set {_relinKey = newValue}
  }
  /// Returns true if `relinKey` has been explicitly set.
  public var hasRelinKey: Bool {return self._relinKey != nil}
  /// Clears the value of `relinKey`. Subsequent reads from it will return its default value.
  public mutating func clearRelinKey() {self._relinKey = nil}

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}

  fileprivate var _relinKey: Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey? = nil
}

/// A serialized `SecretKey`.
public struct Apple_SwiftHomomorphicEncryption_V1_SerializedSecretKey: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// The polynomials in the secret key.
  public var polys: Data = Data()

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

/// A serialized `EvaluationKey`.
public struct Apple_SwiftHomomorphicEncryption_V1_SerializedEvaluationKey: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// The Galois key.
  public var galoisKey: Apple_SwiftHomomorphicEncryption_V1_SerializedGaloisKey {
    get {return _galoisKey ?? Apple_SwiftHomomorphicEncryption_V1_SerializedGaloisKey()}
    set {_galoisKey = newValue}
  }
  /// Returns true if `galoisKey` has been explicitly set.
  public var hasGaloisKey: Bool {return self._galoisKey != nil}
  /// Clears the value of `galoisKey`. Subsequent reads from it will return its default value.
  public mutating func clearGaloisKey() {self._galoisKey = nil}

  /// The relinearization key.
  public var relinKey: Apple_SwiftHomomorphicEncryption_V1_SerializedRelinKey {
    get {return _relinKey ?? Apple_SwiftHomomorphicEncryption_V1_SerializedRelinKey()}
    set {_relinKey = newValue}
  }
  /// Returns true if `relinKey` has been explicitly set.
  public var hasRelinKey: Bool {return self._relinKey != nil}
  /// Clears the value of `relinKey`. Subsequent reads from it will return its default value.
  public mutating func clearRelinKey() {self._relinKey = nil}

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}

  fileprivate var _galoisKey: Apple_SwiftHomomorphicEncryption_V1_SerializedGaloisKey? = nil
  fileprivate var _relinKey: Apple_SwiftHomomorphicEncryption_V1_SerializedRelinKey? = nil
}

/// Configuration needed to generate a new evaluation key.
public struct Apple_SwiftHomomorphicEncryption_V1_EvaluationKeyConfig: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Encryption parameters.
  public var encryptionParameters: Apple_SwiftHomomorphicEncryption_V1_EncryptionParameters {
    get {return _encryptionParameters ?? Apple_SwiftHomomorphicEncryption_V1_EncryptionParameters()}
    set {_encryptionParameters = newValue}
  }
  /// Returns true if `encryptionParameters` has been explicitly set.
  public var hasEncryptionParameters: Bool {return self._encryptionParameters != nil}
  /// Clears the value of `encryptionParameters`. Subsequent reads from it will return its default value.
  public mutating func clearEncryptionParameters() {self._encryptionParameters = nil}

  /// Galois elements required for server compute.
  /// Sorted in increasing order to ensure uniqueness of hash.
  public var galoisElements: [UInt32] = []

  /// Whether or not the relinearization key is required.
  public var hasRelinKey_p: Bool = false

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}

  fileprivate var _encryptionParameters: Apple_SwiftHomomorphicEncryption_V1_EncryptionParameters? = nil
}

/// Holds important parameters that instantiate the encryption scheme.
public struct Apple_SwiftHomomorphicEncryption_V1_EncryptionParameters: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Number of coefficients in a polynomial.
  public var polynomialDegree: UInt64 = 0

  /// Plaintext coefficients use this modulus. Homomorphic operations are done
  /// using this modulus.
  public var plaintextModulus: UInt64 = 0

  /// A vector of `q_0, q_1, ..., q_n`, where the ciphertext modulus `q` is equal
  /// to the product of the coefficient_moduli `q_i`.
  public var coefficientModuli: [UInt64] = []

  /// Standard deviation of the error distribution.
  public var errorStdDev: Apple_SwiftHomomorphicEncryption_V1_ErrorStdDev = .stddev32

  /// Security level.
  public var securityLevel: Apple_SwiftHomomorphicEncryption_V1_SecurityLevel = .unspecified

  /// HE scheme.
  public var heScheme: Apple_SwiftHomomorphicEncryption_V1_HeScheme = .unspecified

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

// MARK: - Code below here is support for the SwiftProtobuf runtime.

fileprivate let _protobuf_package = "apple.swift_homomorphic_encryption.v1"

extension Apple_SwiftHomomorphicEncryption_V1_SecurityLevel: SwiftProtobuf._ProtoNameProviding {
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    0: .same(proto: "SECURITY_LEVEL_UNSPECIFIED"),
    1: .same(proto: "SECURITY_LEVEL_QUANTUM128"),
  ]
}

extension Apple_SwiftHomomorphicEncryption_V1_HeScheme: SwiftProtobuf._ProtoNameProviding {
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    0: .same(proto: "HE_SCHEME_UNSPECIFIED"),
    1: .same(proto: "HE_SCHEME_BFV"),
    2: .same(proto: "HE_SCHEME_BGV"),
  ]
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedPlaintext: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedPlaintext"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "poly"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBytesField(value: &self.poly) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.poly.isEmpty {
      try visitor.visitSingularBytesField(value: self.poly, fieldNumber: 1)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_SerializedPlaintext, rhs: Apple_SwiftHomomorphicEncryption_V1_SerializedPlaintext) -> Bool {
    if lhs.poly != rhs.poly {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertextVec: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedCiphertextVec"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "ciphertexts"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeRepeatedMessageField(value: &self.ciphertexts) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.ciphertexts.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.ciphertexts, fieldNumber: 1)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertextVec, rhs: Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertextVec) -> Bool {
    if lhs.ciphertexts != rhs.ciphertexts {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedCiphertext"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "seeded"),
    2: .same(proto: "full"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try {
        var v: Apple_SwiftHomomorphicEncryption_V1_SerializedSeededCiphertext?
        var hadOneofValue = false
        if let current = self.serializedCiphertextType {
          hadOneofValue = true
          if case .seeded(let m) = current {v = m}
        }
        try decoder.decodeSingularMessageField(value: &v)
        if let v = v {
          if hadOneofValue {try decoder.handleConflictingOneOf()}
          self.serializedCiphertextType = .seeded(v)
        }
      }()
      case 2: try {
        var v: Apple_SwiftHomomorphicEncryption_V1_SerializedFullCiphertext?
        var hadOneofValue = false
        if let current = self.serializedCiphertextType {
          hadOneofValue = true
          if case .full(let m) = current {v = m}
        }
        try decoder.decodeSingularMessageField(value: &v)
        if let v = v {
          if hadOneofValue {try decoder.handleConflictingOneOf()}
          self.serializedCiphertextType = .full(v)
        }
      }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    switch self.serializedCiphertextType {
    case .seeded?: try {
      guard case .seeded(let v)? = self.serializedCiphertextType else { preconditionFailure() }
      try visitor.visitSingularMessageField(value: v, fieldNumber: 1)
    }()
    case .full?: try {
      guard case .full(let v)? = self.serializedCiphertextType else { preconditionFailure() }
      try visitor.visitSingularMessageField(value: v, fieldNumber: 2)
    }()
    case nil: break
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext, rhs: Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext) -> Bool {
    if lhs.serializedCiphertextType != rhs.serializedCiphertextType {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedSeededCiphertext: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedSeededCiphertext"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "poly0"),
    2: .same(proto: "seed"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBytesField(value: &self.poly0) }()
      case 2: try { try decoder.decodeSingularBytesField(value: &self.seed) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.poly0.isEmpty {
      try visitor.visitSingularBytesField(value: self.poly0, fieldNumber: 1)
    }
    if !self.seed.isEmpty {
      try visitor.visitSingularBytesField(value: self.seed, fieldNumber: 2)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_SerializedSeededCiphertext, rhs: Apple_SwiftHomomorphicEncryption_V1_SerializedSeededCiphertext) -> Bool {
    if lhs.poly0 != rhs.poly0 {return false}
    if lhs.seed != rhs.seed {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedFullCiphertext: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedFullCiphertext"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "polys"),
    2: .standard(proto: "skip_lsbs"),
    3: .standard(proto: "correction_factor"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBytesField(value: &self.polys) }()
      case 2: try { try decoder.decodeRepeatedUInt32Field(value: &self.skipLsbs) }()
      case 3: try { try decoder.decodeSingularUInt64Field(value: &self.correctionFactor) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.polys.isEmpty {
      try visitor.visitSingularBytesField(value: self.polys, fieldNumber: 1)
    }
    if !self.skipLsbs.isEmpty {
      try visitor.visitPackedUInt32Field(value: self.skipLsbs, fieldNumber: 2)
    }
    if self.correctionFactor != 0 {
      try visitor.visitSingularUInt64Field(value: self.correctionFactor, fieldNumber: 3)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_SerializedFullCiphertext, rhs: Apple_SwiftHomomorphicEncryption_V1_SerializedFullCiphertext) -> Bool {
    if lhs.polys != rhs.polys {return false}
    if lhs.skipLsbs != rhs.skipLsbs {return false}
    if lhs.correctionFactor != rhs.correctionFactor {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedKeySwitchKey"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "key_switch_key"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularMessageField(value: &self._keySwitchKey) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    try { if let v = self._keySwitchKey {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 1)
    } }()
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey, rhs: Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey) -> Bool {
    if lhs._keySwitchKey != rhs._keySwitchKey {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedGaloisKey: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedGaloisKey"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "key_switch_keys"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeMapField(fieldType: SwiftProtobuf._ProtobufMessageMap<SwiftProtobuf.ProtobufUInt64,Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey>.self, value: &self.keySwitchKeys) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.keySwitchKeys.isEmpty {
      try visitor.visitMapField(fieldType: SwiftProtobuf._ProtobufMessageMap<SwiftProtobuf.ProtobufUInt64,Apple_SwiftHomomorphicEncryption_V1_SerializedKeySwitchKey>.self, value: self.keySwitchKeys, fieldNumber: 1)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_SerializedGaloisKey, rhs: Apple_SwiftHomomorphicEncryption_V1_SerializedGaloisKey) -> Bool {
    if lhs.keySwitchKeys != rhs.keySwitchKeys {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedRelinKey: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedRelinKey"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "relin_key"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularMessageField(value: &self._relinKey) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    try { if let v = self._relinKey {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 1)
    } }()
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_SerializedRelinKey, rhs: Apple_SwiftHomomorphicEncryption_V1_SerializedRelinKey) -> Bool {
    if lhs._relinKey != rhs._relinKey {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedSecretKey: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedSecretKey"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "polys"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBytesField(value: &self.polys) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.polys.isEmpty {
      try visitor.visitSingularBytesField(value: self.polys, fieldNumber: 1)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_SerializedSecretKey, rhs: Apple_SwiftHomomorphicEncryption_V1_SerializedSecretKey) -> Bool {
    if lhs.polys != rhs.polys {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_SerializedEvaluationKey: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedEvaluationKey"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "galois_key"),
    2: .standard(proto: "relin_key"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularMessageField(value: &self._galoisKey) }()
      case 2: try { try decoder.decodeSingularMessageField(value: &self._relinKey) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    try { if let v = self._galoisKey {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 1)
    } }()
    try { if let v = self._relinKey {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 2)
    } }()
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_SerializedEvaluationKey, rhs: Apple_SwiftHomomorphicEncryption_V1_SerializedEvaluationKey) -> Bool {
    if lhs._galoisKey != rhs._galoisKey {return false}
    if lhs._relinKey != rhs._relinKey {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_EvaluationKeyConfig: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".EvaluationKeyConfig"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "encryption_parameters"),
    2: .standard(proto: "galois_elements"),
    3: .standard(proto: "has_relin_key"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularMessageField(value: &self._encryptionParameters) }()
      case 2: try { try decoder.decodeRepeatedUInt32Field(value: &self.galoisElements) }()
      case 3: try { try decoder.decodeSingularBoolField(value: &self.hasRelinKey_p) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    try { if let v = self._encryptionParameters {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 1)
    } }()
    if !self.galoisElements.isEmpty {
      try visitor.visitPackedUInt32Field(value: self.galoisElements, fieldNumber: 2)
    }
    if self.hasRelinKey_p != false {
      try visitor.visitSingularBoolField(value: self.hasRelinKey_p, fieldNumber: 3)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_EvaluationKeyConfig, rhs: Apple_SwiftHomomorphicEncryption_V1_EvaluationKeyConfig) -> Bool {
    if lhs._encryptionParameters != rhs._encryptionParameters {return false}
    if lhs.galoisElements != rhs.galoisElements {return false}
    if lhs.hasRelinKey_p != rhs.hasRelinKey_p {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_V1_EncryptionParameters: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".EncryptionParameters"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "polynomial_degree"),
    2: .standard(proto: "plaintext_modulus"),
    3: .standard(proto: "coefficient_moduli"),
    4: .standard(proto: "error_std_dev"),
    5: .standard(proto: "security_level"),
    6: .standard(proto: "he_scheme"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularUInt64Field(value: &self.polynomialDegree) }()
      case 2: try { try decoder.decodeSingularUInt64Field(value: &self.plaintextModulus) }()
      case 3: try { try decoder.decodeRepeatedUInt64Field(value: &self.coefficientModuli) }()
      case 4: try { try decoder.decodeSingularEnumField(value: &self.errorStdDev) }()
      case 5: try { try decoder.decodeSingularEnumField(value: &self.securityLevel) }()
      case 6: try { try decoder.decodeSingularEnumField(value: &self.heScheme) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if self.polynomialDegree != 0 {
      try visitor.visitSingularUInt64Field(value: self.polynomialDegree, fieldNumber: 1)
    }
    if self.plaintextModulus != 0 {
      try visitor.visitSingularUInt64Field(value: self.plaintextModulus, fieldNumber: 2)
    }
    if !self.coefficientModuli.isEmpty {
      try visitor.visitPackedUInt64Field(value: self.coefficientModuli, fieldNumber: 3)
    }
    if self.errorStdDev != .stddev32 {
      try visitor.visitSingularEnumField(value: self.errorStdDev, fieldNumber: 4)
    }
    if self.securityLevel != .unspecified {
      try visitor.visitSingularEnumField(value: self.securityLevel, fieldNumber: 5)
    }
    if self.heScheme != .unspecified {
      try visitor.visitSingularEnumField(value: self.heScheme, fieldNumber: 6)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_V1_EncryptionParameters, rhs: Apple_SwiftHomomorphicEncryption_V1_EncryptionParameters) -> Bool {
    if lhs.polynomialDegree != rhs.polynomialDegree {return false}
    if lhs.plaintextModulus != rhs.plaintextModulus {return false}
    if lhs.coefficientModuli != rhs.coefficientModuli {return false}
    if lhs.errorStdDev != rhs.errorStdDev {return false}
    if lhs.securityLevel != rhs.securityLevel {return false}
    if lhs.heScheme != rhs.heScheme {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}
