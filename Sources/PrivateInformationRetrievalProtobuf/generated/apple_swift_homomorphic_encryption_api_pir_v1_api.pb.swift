// DO NOT EDIT.
// swift-format-ignore-file
// swiftlint:disable all
//
// Generated by the Swift generator plugin for the protocol buffer compiler.
// Source: apple/swift_homomorphic_encryption/api/pir/v1/api.proto
//
// For information on using the generated types, please see the documentation:
//   https://github.com/apple/swift-protobuf/

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

/// Request for server side configurations.
public struct Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigRequest: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// List of usecases to fetch configs for.
  /// When set to empty array, all configs will be returned.
  public var usecases: [String] = []

  /// For each usecase, the existing config id, if one exists.
  public var existingConfigIds: [Data] = []

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

/// Usecase configuration.
public struct Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Configuration.
  public var config: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config.OneOf_Config? = nil

  /// Configuration for a PIR usecase.
  public var pirConfig: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRConfig {
    get {
      if case .pirConfig(let v)? = config {return v}
      return Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRConfig()
    }
    set {config = .pirConfig(newValue)}
  }

  /// Unique identifier for the configuration.
  public var configID: Data = Data()

  /// Indicator that the config is the same config as in the ConfigRequest. If set, all other fields can be unset.
  public var reuseExistingConfig: Bool = false

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  /// Configuration.
  public enum OneOf_Config: Equatable, Sendable {
    /// Configuration for a PIR usecase.
    case pirConfig(Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRConfig)

  }

  public init() {}
}

/// Server side configurations.
public struct Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigResponse: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// usecases with associated configurations.
  public var configs: Dictionary<String,Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config> = [:]

  /// Configuration & status of evaluation keys.
  public var keyInfo: [Apple_SwiftHomomorphicEncryption_Api_Shared_V1_KeyStatus] = []

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

/// Container for multiple requests.
public struct Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Requests: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Requests.
  public var requests: [Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Request] = []

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

/// Container for multiple responses.
public struct Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Responses: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Responses.
  public var responses: [Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response] = []

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  public init() {}
}

/// Generic request.
public struct Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Request: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Usecase identifier.
  public var usecase: String = String()

  /// Generic request.
  public var request: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Request.OneOf_Request? = nil

  /// PIR request.
  public var pirRequest: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRRequest {
    get {
      if case .pirRequest(let v)? = request {return v}
      return Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRRequest()
    }
    set {request = .pirRequest(newValue)}
  }

  /// OPRF request.
  public var oprfRequest: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFRequest {
    get {
      if case .oprfRequest(let v)? = request {return v}
      return Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFRequest()
    }
    set {request = .oprfRequest(newValue)}
  }

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  /// Generic request.
  public enum OneOf_Request: Equatable, Sendable {
    /// PIR request.
    case pirRequest(Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRRequest)
    /// OPRF request.
    case oprfRequest(Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFRequest)

  }

  public init() {}
}

/// Generic response.
public struct Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  /// Generic response.
  public var response: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response.OneOf_Response? = nil

  /// Response to a `PIRRequest`.
  public var pirResponse: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRResponse {
    get {
      if case .pirResponse(let v)? = response {return v}
      return Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRResponse()
    }
    set {response = .pirResponse(newValue)}
  }

  /// Response to `OPRFRequest`.
  public var oprfResponse: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFResponse {
    get {
      if case .oprfResponse(let v)? = response {return v}
      return Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFResponse()
    }
    set {response = .oprfResponse(newValue)}
  }

  public var unknownFields = SwiftProtobuf.UnknownStorage()

  /// Generic response.
  public enum OneOf_Response: Equatable, Sendable {
    /// Response to a `PIRRequest`.
    case pirResponse(Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRResponse)
    /// Response to `OPRFRequest`.
    case oprfResponse(Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFResponse)

  }

  public init() {}
}

// MARK: - Code below here is support for the SwiftProtobuf runtime.

fileprivate let _protobuf_package = "apple.swift_homomorphic_encryption.api.pir.v1"

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigRequest: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".ConfigRequest"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "usecases"),
    2: .standard(proto: "existing_config_ids"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeRepeatedStringField(value: &self.usecases) }()
      case 2: try { try decoder.decodeRepeatedBytesField(value: &self.existingConfigIds) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.usecases.isEmpty {
      try visitor.visitRepeatedStringField(value: self.usecases, fieldNumber: 1)
    }
    if !self.existingConfigIds.isEmpty {
      try visitor.visitRepeatedBytesField(value: self.existingConfigIds, fieldNumber: 2)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigRequest, rhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigRequest) -> Bool {
    if lhs.usecases != rhs.usecases {return false}
    if lhs.existingConfigIds != rhs.existingConfigIds {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".Config"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "pir_config"),
    3: .standard(proto: "config_id"),
    4: .standard(proto: "reuse_existing_config"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try {
        var v: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRConfig?
        var hadOneofValue = false
        if let current = self.config {
          hadOneofValue = true
          if case .pirConfig(let m) = current {v = m}
        }
        try decoder.decodeSingularMessageField(value: &v)
        if let v = v {
          if hadOneofValue {try decoder.handleConflictingOneOf()}
          self.config = .pirConfig(v)
        }
      }()
      case 3: try { try decoder.decodeSingularBytesField(value: &self.configID) }()
      case 4: try { try decoder.decodeSingularBoolField(value: &self.reuseExistingConfig) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    try { if case .pirConfig(let v)? = self.config {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 1)
    } }()
    if !self.configID.isEmpty {
      try visitor.visitSingularBytesField(value: self.configID, fieldNumber: 3)
    }
    if self.reuseExistingConfig != false {
      try visitor.visitSingularBoolField(value: self.reuseExistingConfig, fieldNumber: 4)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config, rhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config) -> Bool {
    if lhs.config != rhs.config {return false}
    if lhs.configID != rhs.configID {return false}
    if lhs.reuseExistingConfig != rhs.reuseExistingConfig {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigResponse: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".ConfigResponse"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "configs"),
    2: .standard(proto: "key_info"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeMapField(fieldType: SwiftProtobuf._ProtobufMessageMap<SwiftProtobuf.ProtobufString,Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config>.self, value: &self.configs) }()
      case 2: try { try decoder.decodeRepeatedMessageField(value: &self.keyInfo) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.configs.isEmpty {
      try visitor.visitMapField(fieldType: SwiftProtobuf._ProtobufMessageMap<SwiftProtobuf.ProtobufString,Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config>.self, value: self.configs, fieldNumber: 1)
    }
    if !self.keyInfo.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.keyInfo, fieldNumber: 2)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigResponse, rhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigResponse) -> Bool {
    if lhs.configs != rhs.configs {return false}
    if lhs.keyInfo != rhs.keyInfo {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Requests: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".Requests"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "requests"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeRepeatedMessageField(value: &self.requests) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.requests.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.requests, fieldNumber: 1)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Requests, rhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Requests) -> Bool {
    if lhs.requests != rhs.requests {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Responses: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".Responses"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "responses"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeRepeatedMessageField(value: &self.responses) }()
      default: break
      }
    }
  }

  public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.responses.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.responses, fieldNumber: 1)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Responses, rhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Responses) -> Bool {
    if lhs.responses != rhs.responses {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Request: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".Request"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "usecase"),
    2: .standard(proto: "pir_request"),
    4: .standard(proto: "oprf_request"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularStringField(value: &self.usecase) }()
      case 2: try {
        var v: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRRequest?
        var hadOneofValue = false
        if let current = self.request {
          hadOneofValue = true
          if case .pirRequest(let m) = current {v = m}
        }
        try decoder.decodeSingularMessageField(value: &v)
        if let v = v {
          if hadOneofValue {try decoder.handleConflictingOneOf()}
          self.request = .pirRequest(v)
        }
      }()
      case 4: try {
        var v: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFRequest?
        var hadOneofValue = false
        if let current = self.request {
          hadOneofValue = true
          if case .oprfRequest(let m) = current {v = m}
        }
        try decoder.decodeSingularMessageField(value: &v)
        if let v = v {
          if hadOneofValue {try decoder.handleConflictingOneOf()}
          self.request = .oprfRequest(v)
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
    if !self.usecase.isEmpty {
      try visitor.visitSingularStringField(value: self.usecase, fieldNumber: 1)
    }
    switch self.request {
    case .pirRequest?: try {
      guard case .pirRequest(let v)? = self.request else { preconditionFailure() }
      try visitor.visitSingularMessageField(value: v, fieldNumber: 2)
    }()
    case .oprfRequest?: try {
      guard case .oprfRequest(let v)? = self.request else { preconditionFailure() }
      try visitor.visitSingularMessageField(value: v, fieldNumber: 4)
    }()
    case nil: break
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Request, rhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Request) -> Bool {
    if lhs.usecase != rhs.usecase {return false}
    if lhs.request != rhs.request {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  public static let protoMessageName: String = _protobuf_package + ".Response"
  public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "pir_response"),
    3: .standard(proto: "oprf_response"),
  ]

  public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try {
        var v: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_PIRResponse?
        var hadOneofValue = false
        if let current = self.response {
          hadOneofValue = true
          if case .pirResponse(let m) = current {v = m}
        }
        try decoder.decodeSingularMessageField(value: &v)
        if let v = v {
          if hadOneofValue {try decoder.handleConflictingOneOf()}
          self.response = .pirResponse(v)
        }
      }()
      case 3: try {
        var v: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFResponse?
        var hadOneofValue = false
        if let current = self.response {
          hadOneofValue = true
          if case .oprfResponse(let m) = current {v = m}
        }
        try decoder.decodeSingularMessageField(value: &v)
        if let v = v {
          if hadOneofValue {try decoder.handleConflictingOneOf()}
          self.response = .oprfResponse(v)
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
    switch self.response {
    case .pirResponse?: try {
      guard case .pirResponse(let v)? = self.response else { preconditionFailure() }
      try visitor.visitSingularMessageField(value: v, fieldNumber: 1)
    }()
    case .oprfResponse?: try {
      guard case .oprfResponse(let v)? = self.response else { preconditionFailure() }
      try visitor.visitSingularMessageField(value: v, fieldNumber: 3)
    }()
    case nil: break
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  public static func ==(lhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response, rhs: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response) -> Bool {
    if lhs.response != rhs.response {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}
