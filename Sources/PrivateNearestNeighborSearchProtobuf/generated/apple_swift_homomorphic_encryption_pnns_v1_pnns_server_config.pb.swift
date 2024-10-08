// DO NOT EDIT.
// swift-format-ignore-file
// swiftlint:disable all
//
// Generated by the Swift generator plugin for the protocol buffer compiler.
// Source: apple/swift_homomorphic_encryption/pnns/v1/pnns_server_config.proto
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

// If the compiler emits an error on this type, it is because this file
// was generated by a version of the `protoc` Swift plug-in that is
// incompatible with the version of SwiftProtobuf to which you are linking.
// Please ensure that you are building against the same version of the API
// that was used to generate this file.
fileprivate struct _GeneratedWithProtocGenSwiftVersion: SwiftProtobuf.ProtobufAPIVersionCheck {
  struct _2: SwiftProtobuf.ProtobufAPIVersion_2 {}
  typealias Version = _2
}

/// The server configuration.
public struct Apple_SwiftHomomorphicEncryption_Pnns_V1_ServerConfig: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Configuration shared with the client.
  public var clientConfig: Apple_SwiftHomomorphicEncryption_Pnns_V1_ClientConfig {
    get {return _storage._clientConfig ?? Apple_SwiftHomomorphicEncryption_Pnns_V1_ClientConfig()}
    set {_uniqueStorage()._clientConfig = newValue}
  }
  /// Returns true if `clientConfig` has been explicitly set.
  public var hasClientConfig: Bool {return _storage._clientConfig != nil}
  /// Clears the value of `clientConfig`. Subsequent reads from it will return its default value.
  public mutating func clearClientConfig() {_uniqueStorage()._clientConfig = nil}

  /// Packing for the plaintext database.
  public var databasePacking: Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking {
    get {return _storage._databasePacking ?? Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking()}
    set {_uniqueStorage()._databasePacking = newValue}
  }
  /// Returns true if `databasePacking` has been explicitly set.
  public var hasDatabasePacking: Bool {return _storage._databasePacking != nil}
  /// Clears the value of `databasePacking`. Subsequent reads from it will return its default value.
  public mutating func clearDatabasePacking() {_uniqueStorage()._databasePacking = nil}

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}

  fileprivate var _storage = _StorageClass.defaultInstance
}

// MARK: - Code below here is support for the SwiftProtobuf runtime.

fileprivate let _protobuf_package = "apple.swift_homomorphic_encryption.pnns.v1"

extension Apple_SwiftHomomorphicEncryption_Pnns_V1_ServerConfig: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".ServerConfig"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "client_config"),
    2: .standard(proto: "database_packing"),
  ]

  fileprivate class _StorageClass {
    var _clientConfig: Apple_SwiftHomomorphicEncryption_Pnns_V1_ClientConfig? = nil
    var _databasePacking: Apple_SwiftHomomorphicEncryption_Pnns_V1_MatrixPacking? = nil

    #if swift(>=5.10)
      // This property is used as the initial default value for new instances of the type.
      // The type itself is protecting the reference to its storage via CoW semantics.
      // This will force a copy to be made of this reference when the first mutation occurs;
      // hence, it is safe to mark this as `nonisolated(unsafe)`.
      static nonisolated(unsafe) let defaultInstance = _StorageClass()
    #else
      static let defaultInstance = _StorageClass()
    #endif

    private init() {}

    init(copying source: _StorageClass) {
      _clientConfig = source._clientConfig
      _databasePacking = source._databasePacking
    }
  }

  fileprivate mutating func _uniqueStorage() -> _StorageClass {
    if !isKnownUniquelyReferenced(&_storage) {
      _storage = _StorageClass(copying: _storage)
    }
    return _storage
  }

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    _ = _uniqueStorage()
    try withExtendedLifetime(_storage) { (_storage: _StorageClass) in
      while let fieldNumber = try decoder.nextFieldNumber() {
        // The use of inline closures is to circumvent an issue where the compiler
        // allocates stack space for every case branch when no optimizations are
        // enabled. https://github.com/apple/swift-protobuf/issues/1034
        switch fieldNumber {
        case 1: try { try decoder.decodeSingularMessageField(value: &_storage._clientConfig) }()
        case 2: try { try decoder.decodeSingularMessageField(value: &_storage._databasePacking) }()
        default: break
        }
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    try withExtendedLifetime(_storage) { (_storage: _StorageClass) in
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every if/case branch local when no optimizations
      // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
      // https://github.com/apple/swift-protobuf/issues/1182
      try { if let v = _storage._clientConfig {
        try visitor.visitSingularMessageField(value: v, fieldNumber: 1)
      } }()
      try { if let v = _storage._databasePacking {
        try visitor.visitSingularMessageField(value: v, fieldNumber: 2)
      } }()
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_Pnns_V1_ServerConfig, rhs: Apple_SwiftHomomorphicEncryption_Pnns_V1_ServerConfig) -> Bool {
    if lhs._storage !== rhs._storage {
      let storagesAreEqual: Bool = withExtendedLifetime((lhs._storage, rhs._storage)) { (_args: (_StorageClass, _StorageClass)) in
        let _storage = _args.0
        let rhs_storage = _args.1
        if _storage._clientConfig != rhs_storage._clientConfig {return false}
        if _storage._databasePacking != rhs_storage._databasePacking {return false}
        return true
      }
      if !storagesAreEqual {return false}
    }
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}
