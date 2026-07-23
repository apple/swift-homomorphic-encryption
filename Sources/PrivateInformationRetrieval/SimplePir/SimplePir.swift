// Copyright 2025-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

public import Foundation
public import HomomorphicEncryption
import ModularArithmetic

/// Security parameters for SimplePIR.
public struct SimplePirEncryptionParams: Hashable, Codable, Sendable {
    /// Number of bits in plaintext modulus.
    public let plaintextModulusBits: Int
    /// Number of bits in ciphertext modulus.
    public let ciphertextModulusBits: Int
    /// The lattice dimension used for encryption.
    public let latticeDimension: Int
    /// The error distribution's standard deviation used for encryption.
    public let errorStdDev: ErrorStdDev

    /// Creates a new SimplePIR configuration with the specified security parameters.
    ///
    /// This initializer sets up the cryptographic parameters needed for SimplePIR operations,
    /// including plaintext and ciphertext bit sizes, lattice dimensions for the underlying
    /// encryption scheme, and error parameters that affect both security and correctness.
    ///
    /// - Parameters:
    ///   - plaintextModulusBits: The number of bits used to represent plaintext values. This determines
    ///     the range of values that can be encoded in a single plaintext element.
    ///   - ciphertextModulusBits: The number of bits used to represent ciphertext values. Must be larger
    ///     than `plaintextModulusBits` to accommodate encryption noise and ensure correctness.
    ///   - latticeDimension: The dimension of the lattice used for encryption. Must be a power of 2.
    ///   - errorStdDev: The standard deviation of the error distribution used during encryption.
    ///     This parameter affects both the security level and the noise growth in ciphertexts.
    ///   - securityLevel: Security level to enforce. Defaults to `.quantum128`.
    /// - Throws: `HeError` upon invalid or insecure encryption parameters.
    /// - Warning: If `securityLevel` is set to `.unchecked`, no guarantees are made about cryptographic security.
    public init(
        plaintextModulusBits: Int,
        ciphertextModulusBits: Int,
        latticeDimension: Int,
        errorStdDev: ErrorStdDev,
        securityLevel: SecurityLevel = .quantum128) throws
    {
        self.plaintextModulusBits = plaintextModulusBits
        self.ciphertextModulusBits = ciphertextModulusBits
        self.latticeDimension = latticeDimension
        self.errorStdDev = errorStdDev

        guard latticeDimension.isPowerOfTwo else {
            throw HeError.invalidEncryptionParameters(
                "SimplePir latticeDimension=\(latticeDimension) is not a power of 2")
        }
        guard ciphertextModulusBits > plaintextModulusBits else {
            throw HeError.invalidEncryptionParameters(
                "SimplePir ciphertextModulusBits=\(ciphertextModulusBits) must be > " +
                    "plaintextModulusBits=\(plaintextModulusBits)")
        }
        let allowedCiphertextBits = try EncryptionParameters<UInt64>.maxLog2CoefficientModulus(
            degree: latticeDimension,
            securityLevel: securityLevel,
            errorStdDev: errorStdDev)

        guard ciphertextModulusBits <= allowedCiphertextBits else {
            throw HeError.insecureEncryptionParameters(
                "SimplePir ciphertextModulusBits=\(ciphertextModulusBits) exceeds " +
                    "\(allowedCiphertextBits) for latticeDimension=\(latticeDimension), " +
                    "errorStdDev=\(errorStdDev)")
        }
    }

    @inlinable
    func getCiphertextMask<Scalar: ScalarType>() -> Scalar {
        (Scalar(1) << ciphertextModulusBits) - 1
    }

    @inlinable
    func getDelta<Scalar: ScalarType>() -> Scalar {
        Scalar(1) << (ciphertextModulusBits - plaintextModulusBits)
    }
}

/// Parameters for SimplePIR.
public struct SimplePirParameters: Hashable, Codable, Sendable {
    /// Security parameters.
    public let encryptionParams: SimplePirEncryptionParams
    /// The size of each database entry in bytes.
    public let entrySizeInBytes: Int
    /// Number of entries per column.
    public let entriesPerColumn: Int
    /// Number of chunks per entry.
    public let chunksPerEntry: Int
    /// Number of database columns.
    public let databaseColumns: Int
    /// Initial seed used to generate the random matrix `A`.
    public let seed: [UInt8]

    /// Entry size in scalars.
    public var entrySizeInScalar: Int {
        CoefficientPacking.bytesToCoefficientsCoeffCount(
            byteCount: entrySizeInBytes,
            bitsPerCoeff: plaintextModulusBits,
            decode: false)
    }

    /// Chunk size in scalars.
    public var chunkSize: Int {
        entrySizeInScalar.dividingCeil(chunksPerEntry, variableTime: true)
    }

    /// Column size in scalars.
    public var columnSize: Int {
        if chunksPerEntry == 1 {
            entriesPerColumn * entrySizeInScalar
        } else {
            chunkSize
        }
    }

    /// Number of bits in plaintext modulus.
    public var plaintextModulusBits: Int {
        encryptionParams.plaintextModulusBits
    }

    /// Number of bits in ciphertext modulus.
    public var ciphertextModulusBits: Int {
        encryptionParams.ciphertextModulusBits
    }

    /// The lattice dimension used for encryption.
    public var latticeDimension: Int {
        encryptionParams.latticeDimension
    }

    /// The error distribution's standard deviation used for encryption.
    public var errorStdDev: Double {
        encryptionParams.errorStdDev.toDouble
    }

    @inlinable
    public init(
        encryptionParams: SimplePirEncryptionParams,
        entrySizeInBytes: Int,
        entriesPerColumn: Int,
        chunksPerEntry: Int,
        databaseColumns: Int,
        seed: [UInt8])
    {
        precondition(entriesPerColumn == 1 || chunksPerEntry == 1)
        self.encryptionParams = encryptionParams
        self.entrySizeInBytes = entrySizeInBytes
        self.entriesPerColumn = entriesPerColumn
        self.chunksPerEntry = chunksPerEntry
        self.databaseColumns = databaseColumns
        self.seed = seed
    }
}

/// This Protocol will be inherited by both server and client so they agree on request/response format.
public protocol SimplePirProtocol: Sendable {
    /// The scalar type used for all operations.
    associatedtype Scalar: ScalarType
    /// The hint in SimplePIR.
    typealias Hint = Array2d<Scalar>
    /// The PIR queries.
    typealias Requests = Array2d<Scalar>
    /// The PIR query responses.
    typealias Responses = Array2d<Scalar>
}

/// Simple PIR server protocol.
public protocol SimplePirServerProtocol: SimplePirProtocol {
    typealias RawDatabase = Array2d<UInt8>
    typealias ProcessedDatabase = Array2d<Scalar>
    var hint: Hint { get }
    var params: SimplePirParameters { get }

    init(from serializedDatabase: Data, hint: Hint, params: SimplePirParameters) async throws
    init(processedDatabase: ProcessedDatabase, hint: Hint, params: SimplePirParameters) async throws

    /// Generate the responses to a batch of requests
    ///
    /// - Parameter requests: requests packed in an 2-dim array, one request per column
    /// - Returns: the corresponding responses for each request. One per column
    func computeResponse(to requests: Requests) async throws -> Responses
}

extension SimplePirServerProtocol {
    /// Creates a `SimplePirServerProtocol` instance from a serialized database.
    /// - Parameters:
    ///   - serializedDatabase: The serialized database.
    ///   - hint: The hint.
    ///   - params: The parameters.
    public init(from serializedDatabase: Data, hint: Array2d<Scalar>, params: SimplePirParameters) async throws {
        let data: [Scalar] = try CoefficientPacking.bytesToCoefficients(
            bytes: Array(serializedDatabase),
            bitsPerCoeff: params.plaintextModulusBits,
            decode: true)
        let entryCount = data.count.dividingCeil(params.entrySizeInScalar, variableTime: true)
        precondition(entryCount * params.entrySizeInScalar == data.count, "Corrupted database")
        try await self.init(
            processedDatabase: Array2d(data: data, rowCount: params.entrySizeInScalar, columnCount: entryCount),
            hint: hint,
            params: params)
    }
}
