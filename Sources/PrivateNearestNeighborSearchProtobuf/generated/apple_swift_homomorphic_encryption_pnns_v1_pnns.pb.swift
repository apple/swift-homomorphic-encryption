// DO NOT EDIT.
// swift-format-ignore-file
// swiftlint:disable all
//
// Generated by the Swift generator plugin for the protocol buffer compiler.
// Source: apple/swift_homomorphic_encryption/pnns/v1/pnns.proto
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

import SwiftProtobuf

import HomomorphicEncryptionProtobuf

// If the compiler emits an error on this type, it is because this file
// was generated by a version of the `protoc` Swift plug-in that is
// incompatible with the version of SwiftProtobuf to which you are linking.
// Please ensure that you are building against the same version of the API
// that was used to generate this file.
fileprivate struct _GeneratedWithProtocGenSwiftVersion: SwiftProtobuf.ProtobufAPIVersionCheck {
  struct _2: SwiftProtobuf.ProtobufAPIVersion_2 {}
  typealias Version = _2
}

/// Stores a matrix of encrypted values in a serialized ciphertext for use in linear algebra
/// operations
public struct Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedCiphertextMatrix: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Number of data rows stored in the ciphertext.
  public var numRows: UInt32 = 0

  /// Number of data columns stored in the ciphertext.
  public var numColumns: UInt32 = 0

  /// Stores the encrypted data.
  public var ciphertexts: [HomomorphicEncryptionProtobuf.Apple_SwiftHomomorphicEncryption_V1_SerializedCiphertext] = []

  /// Packing algorithm for the plaintext data.
  public var packing: Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking {
    get {return _packing ?? Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking()}
    set {_packing = newValue}
  }
  /// Returns true if `packing` has been explicitly set.
  public var hasPacking: Bool {return self._packing != nil}
  /// Clears the value of `packing`. Subsequent reads from it will return its default value.
  public mutating func clearPacking() {self._packing = nil}

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}

  fileprivate var _packing: Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking? = nil
}

/// Serialized plaintext matrix
public struct Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedPlaintextMatrix: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Number of rows in the data encoded in the plaintext matrix.
  public var numRows: UInt32 = 0

  /// Number of columns in the data encoded in the plaintext matrix.
  public var numColumns: UInt32 = 0

  /// Encoded values.
  public var plaintexts: [HomomorphicEncryptionProtobuf.Apple_SwiftHomomorphicEncryption_V1_SerializedPlaintext] = []

  /// Plaintext packing.
  public var packing: Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking {
    get {return _packing ?? Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking()}
    set {_packing = newValue}
  }
  /// Returns true if `packing` has been explicitly set.
  public var hasPacking: Bool {return self._packing != nil}
  /// Clears the value of `packing`. Subsequent reads from it will return its default value.
  public mutating func clearPacking() {self._packing = nil}

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}

  fileprivate var _packing: Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking? = nil
}

// MARK: - Code below here is support for the SwiftProtobuf runtime.

fileprivate let _protobuf_package = "apple.swift_homomorphic_encryption.pnns.v1"

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedCiphertextMatrix: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedCiphertextMatrix"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "num_rows"),
    2: .standard(proto: "num_columns"),
    3: .same(proto: "ciphertexts"),
    4: .same(proto: "packing"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularUInt32Field(value: &self.numRows) }()
      case 2: try { try decoder.decodeSingularUInt32Field(value: &self.numColumns) }()
      case 3: try { try decoder.decodeRepeatedMessageField(value: &self.ciphertexts) }()
      case 4: try { try decoder.decodeSingularMessageField(value: &self._packing) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    if self.numRows != 0 {
      try visitor.visitSingularUInt32Field(value: self.numRows, fieldNumber: 1)
    }
    if self.numColumns != 0 {
      try visitor.visitSingularUInt32Field(value: self.numColumns, fieldNumber: 2)
    }
    if !self.ciphertexts.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.ciphertexts, fieldNumber: 3)
    }
    try { if let v = self._packing {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 4)
    } }()
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedCiphertextMatrix, rhs: Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedCiphertextMatrix) -> Bool {
    if lhs.numRows != rhs.numRows {return false}
    if lhs.numColumns != rhs.numColumns {return false}
    if lhs.ciphertexts != rhs.ciphertexts {return false}
    if lhs._packing != rhs._packing {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedPlaintextMatrix: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".SerializedPlaintextMatrix"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "num_rows"),
    2: .standard(proto: "num_columns"),
    3: .same(proto: "plaintexts"),
    4: .same(proto: "packing"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularUInt32Field(value: &self.numRows) }()
      case 2: try { try decoder.decodeSingularUInt32Field(value: &self.numColumns) }()
      case 3: try { try decoder.decodeRepeatedMessageField(value: &self.plaintexts) }()
      case 4: try { try decoder.decodeSingularMessageField(value: &self._packing) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    if self.numRows != 0 {
      try visitor.visitSingularUInt32Field(value: self.numRows, fieldNumber: 1)
    }
    if self.numColumns != 0 {
      try visitor.visitSingularUInt32Field(value: self.numColumns, fieldNumber: 2)
    }
    if !self.plaintexts.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.plaintexts, fieldNumber: 3)
    }
    try { if let v = self._packing {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 4)
    } }()
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedPlaintextMatrix, rhs: Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedPlaintextMatrix) -> Bool {
    if lhs.numRows != rhs.numRows {return false}
    if lhs.numColumns != rhs.numColumns {return false}
    if lhs.plaintexts != rhs.plaintexts {return false}
    if lhs._packing != rhs._packing {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}
