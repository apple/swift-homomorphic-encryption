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

/// Which algorithm to use for PIR computation.
public enum PirAlgorithm: String, CaseIterable, Codable, CodingKeyRepresentable, Hashable, Sendable {
    /// PIR using ciphertext word decomposition.
    ///
    /// - seealso: <https://eprint.iacr.org/2017/1142.pdf>.
    case aclsPir

    /// PIR using ciphertext-ciphertext multiplication.
    ///
    /// - seealso: ``MulPir``, <https://eprint.iacr.org/2019/1483.pdf>.
    case mulPir
}

/// Which strategy to use for evaluation key compression.
public enum PirKeyCompressionStrategy: String, CaseIterable, Codable, CodingKeyRepresentable, Hashable, Sendable {
    /// A middle ground between no compression and ``PirKeyCompressionStrategy/maxCompression``.
    case hybridCompression

    /// Use as small an evaluation key as possible.
    case maxCompression

    /// No compression.
    case noCompression
}

/// Configuration for an Index PIR database.
public struct IndexPirConfig: Hashable, Codable, Sendable {
    /// Number of entries in the database.
    public let entryCount: Int
    /// Byte size of each entry in the database.
    public let entrySizeInBytes: Int
    /// Number of dimensions in the database.
    public let dimensionCount: Int
    /// Number of indices in a query to the database.
    public let batchSize: Int
    /// Whether or not to enable `uneven dimensions` optimization.
    public let unevenDimensions: Bool
    /// Evaluation key compression.
    public let keyCompression: PirKeyCompressionStrategy

    /// Initializes an ``IndexPirConfig``.
    /// - Parameters:
    ///   - entryCount: Number of entries in the database.
    ///   - entrySizeInBytes: Byte size of each entry in the database.
    ///   - dimensionCount: Number of dimensions in database.
    ///   - batchSize: Number of indices in a query to the database.
    ///   - unevenDimensions: Whether or not to enable `uneven dimensions` optimization.
    ///   - keyCompression: Evaluation key compression.
    /// - Throws: Error upon invalid configuration parameters.
    public init(
        entryCount: Int,
        entrySizeInBytes: Int,
        dimensionCount: Int,
        batchSize: Int,
        unevenDimensions: Bool,
        keyCompression: PirKeyCompressionStrategy) throws
    {
        let validDimensionsCount = [1, 2]
        guard validDimensionsCount.contains(dimensionCount) else {
            throw PirError.invalidDimensionCount(dimensionCount: dimensionCount, expected: validDimensionsCount)
        }
        self.entryCount = entryCount
        self.entrySizeInBytes = entrySizeInBytes
        self.dimensionCount = dimensionCount
        self.batchSize = batchSize
        self.unevenDimensions = unevenDimensions
        self.keyCompression = keyCompression
    }
}

/// Parameters for an index PIR lookup.
///
/// Must be the same between client and server for a correct database lookup.
public struct IndexPirParameter: Hashable, Codable, Sendable {
    /// Number of entries in the database.
    public let entryCount: Int
    /// Byte size of each entry in the database.
    public let entrySizeInBytes: Int
    /// Number of plaintexts in each dimension of the database.
    public let dimensions: [Int]
    /// Number of indices in a query to the database.
    public let batchSize: Int
    /// Evaluation key configuration.
    public let evaluationKeyConfig: EvaluationKeyConfiguration

    /// The number of dimensions in the database.
    @usableFromInline var dimensionCount: Int { dimensions.count }
    /// The number of ciphertexts in each query after server-side expansion.
    @usableFromInline var expandedQueryCount: Int { dimensions.sum() }

    /// Initializes an ``IndexPirParameter``.
    /// - Parameters:
    ///   - entryCount:  Number of entries in the database.
    ///   - entrySizeInBytes:  Byte size of each entry in the database.
    ///   - dimensions: Number of plaintexts in each dimension of the database.
    ///   - batchSize: Number of indices in a query to the database.
    ///   - evaluationKeyConfig: Evaluation key configuration.
    public init(
        entryCount: Int,
        entrySizeInBytes: Int,
        dimensions: [Int],
        batchSize: Int,
        evaluationKeyConfig: EvaluationKeyConfiguration)
    {
        self.entryCount = entryCount
        self.entrySizeInBytes = entrySizeInBytes
        self.dimensions = dimensions
        self.batchSize = batchSize
        self.evaluationKeyConfig = evaluationKeyConfig
    }
}

/// A database after processing to prepare to PIR queries.
public struct ProcessedDatabase<Scheme: HeScheme>: Equatable, Sendable {
    /// Type of the serialization version.
    @usableFromInline typealias SerializationVersionType = UInt8
    /// Serialization version.
    @usableFromInline static var serializationVersion: SerializationVersionType {
        1
    }

    /// Indicates a zero plaintext.
    @usableFromInline static var serializedZeroPlaintextTag: UInt8 {
        0
    }

    /// Indicates a non-zero plaintext.
    @usableFromInline static var serializedPlaintextTag: UInt8 {
        1
    }

    /// Plaintexts in the database, including nil plaintexts used for padding.
    public let plaintexts: [Plaintext<Scheme, Eval>?]

    /// Number of plaintexts in the database, including padding plaintexts.
    public var count: Int { plaintexts.count }

    /// Whether or not the database is empty.
    public var isEmpty: Bool { plaintexts.isEmpty }

    /// Initializes a ``ProcessedDatabase`` from plaintexts.
    /// - Parameter plaintexts: Plaintexts.
    public init(plaintexts: [Plaintext<Scheme, Eval>?]) {
        self.plaintexts = plaintexts
    }

    /// Initializes a ``ProcessedDatabase`` from a filepath.
    /// - Parameters:
    ///   - path: Filepath storing serialized plaintexts.
    ///   - context: Context for HE computation.
    /// - Throws: Error upon failure to load the database.
    public init(from path: String, context: Context<Scheme>) throws {
        let loadedFile = try [UInt8](Data(contentsOf: URL(fileURLWithPath: path)))
        try self.init(from: loadedFile, context: context)
    }

    /// Initializes  a ``ProcessedDatabase`` from buffer.
    /// - Parameters:
    ///   - buffer: Serialized plaintexts.
    ///   - context: Context for HE computation.
    /// - Throws: Error upon failure to deserialize.
    public init(from buffer: [UInt8], context: Context<Scheme>) throws {
        var offset = buffer.startIndex
        let versionNumber = buffer[offset]
        offset += MemoryLayout<SerializationVersionType>.size
        guard versionNumber == Self.serializationVersion else {
            throw PirError.invalidDatabaseSerializationVersion(
                serializationVersion: Int(versionNumber),
                expected: Int(Self.serializationVersion))
        }

        let plaintextCount = Int(UInt32(
            littleEndianBytes: buffer[offset..<offset + MemoryLayout<UInt32>.size]))
        offset += MemoryLayout<UInt32>.size

        let serializedPlaintextByteCount = context.ciphertextContext.serializationByteCount()
        let plaintexts: [Plaintext<Scheme, Eval>?] = try (0..<plaintextCount).map { _ in
            let tag = buffer[offset]
            offset += 1
            switch tag {
            case Self.serializedZeroPlaintextTag:
                return nil
            case Self.serializedPlaintextTag:
                let plaintextBytes: [UInt8] = Array(buffer[offset..<offset + serializedPlaintextByteCount])
                offset += serializedPlaintextByteCount
                let serializedPlaintext = SerializedPlaintext(poly: plaintextBytes)
                return try Scheme.EvalPlaintext(deserialize: serializedPlaintext, context: context)
            default:
                throw PirError.invalidDatabaseSerializationPlaintextTag(tag: tag)
            }
        }
        self.init(plaintexts: plaintexts)
    }

    /// Returns the serialization size in bytes of the database.
    @inlinable
    public func serializationByteCount() throws -> Int {
        let nonNilPlaintexts = plaintexts.compactMap { $0 }
        guard let polyContext = nonNilPlaintexts.first?.polyContext() else {
            throw PirError.emptyDatabase
        }
        var serializationSize = MemoryLayout<SerializationVersionType>.size
        serializationSize += MemoryLayout<UInt32>.size // plaintext count
        serializationSize += nonNilPlaintexts.count * polyContext.serializationByteCount() // non-nil plaintexts
        serializationSize += plaintexts.count * MemoryLayout<UInt8>.size // "nil" or "non-nil" indicator

        return serializationSize
    }

    /// Saves the database to a filepath.
    /// - Parameter path: Filepath to save the database to.
    /// - Throws: Error upon failure to save the database.
    @inlinable
    public func save(to path: String) throws {
        try Data(serialize()).write(to: URL(fileURLWithPath: path))
    }

    /// Serializes the database.
    /// - Returns: The serialized database.
    /// - Throws: Error upon failure to serialize the database.
    @inlinable
    public func serialize() throws -> [UInt8] {
        var buffer: [UInt8] = []
        try buffer.reserveCapacity(serializationByteCount())
        buffer.append(Self.serializationVersion)
        buffer += UInt32(plaintexts.count).littleEndianBytes

        for plaintext in plaintexts {
            if let plaintext {
                buffer.append(Self.serializedPlaintextTag)
                buffer += plaintext.poly.serialize()
            } else {
                buffer.append(Self.serializedZeroPlaintextTag)
            }
        }
        return buffer
    }
}

/// A processed database along with PIR parameters describing the database.
public struct ProcessedDatabaseWithParameters<Scheme: HeScheme>: Equatable, Sendable {
    /// Processed database.
    public let database: ProcessedDatabase<Scheme>
    /// The algorithm that this database was processed for.
    public let algorithm: PirAlgorithm
    /// Evaluation key configuration.
    public let evaluationKeyConfiguration: EvaluationKeyConfiguration
    /// Parameters for Index PIR queries.
    public let pirParameter: IndexPirParameter
    /// Parameters for keyword-value PIR queries.
    public let keywordPirParameter: KeywordPirParameter?

    /// Initializes a ``ProcessedDatabaseWithParameters``.
    /// - Parameters:
    ///   - database: Processed database.
    ///   - algorithm: The PIR algorithm used.
    ///   - evaluationKeyConfiguration: Evaluation key configuration.
    ///   - pirParameter: Index PIR parameters.
    ///   - keywordPirParameter: Optional keyword PIR parameters.
    public init(
        database: ProcessedDatabase<Scheme>,
        algorithm: PirAlgorithm,
        evaluationKeyConfiguration: EvaluationKeyConfiguration,
        pirParameter: IndexPirParameter,
        keywordPirParameter: KeywordPirParameter? = nil)
    {
        self.database = database
        self.algorithm = algorithm
        self.evaluationKeyConfiguration = evaluationKeyConfiguration
        self.pirParameter = pirParameter
        self.keywordPirParameter = keywordPirParameter
    }
}

/// An index PIR query.
public struct Query<Scheme: HeScheme>: Sendable {
    /// Ciphertexts in the query.
    public let ciphertexts: [Scheme.CanonicalCiphertext]
    /// Number of indices to query to an index PIR database.
    public let indicesCount: Int

    /// Initializes an index PIR ``Query``.
    /// - Parameters:
    ///   - ciphertexts: Ciphertexts in the query.
    ///   - indicesCount: Number of indices to query.
    @inlinable
    public init(ciphertexts: [Scheme.CanonicalCiphertext], indicesCount: Int) {
        self.ciphertexts = ciphertexts
        self.indicesCount = indicesCount
    }
}

/// An index PIR response.
public struct Response<Scheme: HeScheme>: Sendable {
    /// Ciphertexts in the response.
    public let ciphertexts: [[Scheme.CoeffCiphertext]]

    /// Initializes an index PIR ``Response``.
    /// - Parameter ciphertexts: Ciphertexts in the response.
    @inlinable
    public init(ciphertexts: [[Scheme.CoeffCiphertext]]) {
        self.ciphertexts = ciphertexts
    }
}

/// Protocol for queries to an integer-indexed database.
public protocol IndexPirProtocol {
    /// HE scheme used for PIR computation.
    associatedtype Scheme: HeScheme
    /// Encrypted query type.
    typealias Query = PrivateInformationRetrieval.Query<Scheme>
    /// Encrypted server response type.
    typealias Response = PrivateInformationRetrieval.Response<Scheme>

    /// The PIR algorithm.
    static var algorithm: PirAlgorithm { get }

    /// Generates the PIR parameters for a database.
    /// - Parameters:
    ///   - config: Database configuration.
    ///   - context: Context for HE computation.
    /// - Returns: The PIR parameters for the database.
    static func generateParameter(config: IndexPirConfig, with context: Context<Scheme>) -> IndexPirParameter
}

/// Protocol for a server hosting index PIR databases for lookup.
///
/// The server hosts multiple databases, which are all compatible with a single index PIR parameters.
public protocol IndexPirServer: Sendable {
    /// Index PIR type backing the keyword PIR computation.
    associatedtype IndexPir: IndexPirProtocol
    /// HE scheme used for PIR computation.
    typealias Scheme = IndexPir.Scheme
    /// Encrypted query type.
    typealias Query = IndexPir.Query
    /// Encrypted server response type.
    typealias Response = IndexPir.Response
    /// Processed keyword-value database.
    typealias Database = PrivateInformationRetrieval.ProcessedDatabase<Scheme>

    /// The processed databases.
    var databases: [Database] { get }
    /// The index PIR parameters, suitable for use with any of the databases.
    var parameter: IndexPirParameter { get }

    /// Evaluation key configuration.
    ///
    /// This tells the client what to include in the evaluation key. Must be the same between client and server.
    var evaluationKeyConfiguration: EvaluationKeyConfiguration { get }

    /// Initializes an ``IndexPirServer`` with a database.
    /// - Parameters:
    ///   - parameter: PIR parameters associated with the database.
    ///   - context: Context for HE computation.
    ///   - database: Integer-indexed database.
    /// - Throws: Error upon failure to initialize the server.
    init(parameter: IndexPirParameter, context: Context<Scheme>, database: Database) throws

    /// Initializes an ``IndexPirServer`` with databases.
    ///
    /// - Parameters:
    ///   - parameter: PIR parameters associated with the database.
    ///   - context: Context for HE computation.
    ///   - databases: Integer-indexed databases, each compatible with the given `parameter`.
    /// - Throws: Error upon failure to initialize the server.
    init(parameter: IndexPirParameter, context: Context<Scheme>, databases: [Database]) throws

    /// Processes the database to prepare for PIR queries.
    ///
    /// This processing must be performed whenever the database changes.
    /// - Parameters:
    ///   - database: Collection of database entries.
    ///   - context: Context for HE computation.
    ///   - parameter: PIR parameters.
    /// - Returns: A processed database.
    /// - Throws: Error upon failure to process the database.
    static func process(database: some Collection<[UInt8]>,
                        with context: Context<Scheme>,
                        using parameter: IndexPirParameter) throws -> Database

    /// Compute the encrypted response to a query lookup.
    /// - Parameters:
    ///   - query: Encrypted query with one or more indices.
    ///   - evaluationKey: Evaluation key to aid in the server computation.
    /// - Returns: The encrypted response.
    /// - Throws: Error upon failure to compute a response.
    func computeResponse(to query: Query,
                         using evaluationKey: EvaluationKey<Scheme>) throws -> Response
}

extension IndexPirServer {
    /// Initializes an ``IndexPirServer``.
    /// - Parameters:
    ///   - parameter: PIR parameters.
    ///   - context: Context for HE computation.
    ///   - database: Database.
    /// - Throws: Error upon failure to initialize the server.
    @inlinable
    public init(parameter: IndexPirParameter, context: Context<Scheme>, database: Database) throws {
        try self.init(parameter: parameter, context: context, databases: [database])
    }

    /// Generates the PIR parameters for a database.
    /// - Parameters:
    ///   - config: Database configuration.
    ///   - context: Context for HE computation.
    /// - Returns: The PIR parameters for the database.
    @inlinable
    public static func generateParameter(config: IndexPirConfig, with context: Context<Scheme>) -> IndexPirParameter {
        IndexPir.generateParameter(config: config, with: context)
    }
}

/// Client which can perform an Index PIR lookup.
public protocol IndexPirClient: Sendable {
    /// IndexPir protocol type.
    associatedtype IndexPir: IndexPirProtocol
    /// HE scheme for PIR computation.
    typealias Scheme = IndexPir.Scheme
    /// Encrypted query type.
    typealias Query = IndexPir.Query
    /// Encrypted response type.
    typealias Response = IndexPir.Response

    /// The PIR parameters for the database.
    var parameter: IndexPirParameter { get }

    /// Evaluation key configuration.
    ///
    /// Must be the same between client and server.
    var evaluationKeyConfiguration: EvaluationKeyConfiguration { get }

    /// Initializes an ``IndexPirClient``.
    /// - Parameters:
    ///   - parameter: Parameters for the database.
    ///   - context: Context for HE computation.
    init(parameter: IndexPirParameter, context: Context<Scheme>)

    /// Generates an encrypted query.
    /// - Parameters:
    ///   - queryIndices: Database indices at which to query.
    ///   - secretKey: Secret key used for the query.
    /// - Returns: An encrypted query.
    /// - Throws: Error upon failure to generate a query.
    func generateQuery(at queryIndices: [Int], using secretKey: SecretKey<Scheme>) throws -> Query

    /// Decrypts an encrypted response.
    /// - Parameters:
    ///   - response: Encrypted response from a PIR query.
    ///   - queryIndices: Indices which were queried.
    ///   - secretKey: Secret key used for decryption.
    /// - Returns: For each query index, the database entry at that index.
    /// - Throws: Error upon failure to decrypt.
    func decrypt(response: Response,
                 at queryIndices: [Int],
                 using secretKey: SecretKey<Scheme>) throws -> [[UInt8]]

    /// Generates an `EvaluationKey` that the server uses to evaluate PIR queries.
    /// - Parameter secretKey: Secret key used to generate the evaluation key.
    /// - Returns: An `EvaluationKey` for use in sever-side computation.
    /// - Throws: Error upon failure to generate an evaluation key.
    /// - Warning: The evaluation key is only valid for use with the given `secretKey`.
    func generateEvaluationKey(using secretKey: SecretKey<Scheme>) throws -> EvaluationKey<Scheme>
}

extension IndexPirClient {
    /// Generates an encrypted query.
    /// - Parameters:
    ///   - queryIndex: Database index at which to query.
    ///   - secretKey: Secret key used for the query.
    /// - Returns: An encrypted query.
    /// - Throws: Error upon failure to generate a query.
    @inlinable
    public func generateQuery(at queryIndex: Int, using secretKey: SecretKey<Scheme>) throws -> Query {
        try generateQuery(at: [queryIndex], using: secretKey)
    }

    /// Decrypts an encrypted response.
    /// - Parameters:
    ///   - response: Encrypted response from a PIR query.
    ///   - queryIndex: Database index which was queried.
    ///   - secretKey: Secret key used for decryption.
    /// - Returns: For each query index, the database entry at that index.
    /// - Throws: Error upon failure to decrypt.
    @inlinable
    public func decrypt(response: Response,
                        at queryIndex: Int,
                        using secretKey: SecretKey<Scheme>) throws -> [UInt8]
    {
        try decrypt(response: response, at: [queryIndex], using: secretKey)[0]
    }
}

extension Response {
    @inlinable
    package func noiseBudget(using secretKey: Scheme.SecretKey, variableTime: Bool) throws -> Double {
        try ciphertexts.flatMap { ciphertexts in
            try ciphertexts
                .map { ciphertext in try ciphertext.noiseBudget(using: secretKey, variableTime: variableTime) }
        }.min() ?? -Double.infinity
    }
}
