// Copyright 2024-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

public import AsyncAlgorithms
public import DequeModule
import Foundation
public import HomomorphicEncryption
public import ModularArithmetic
import Numerics

/// PIR using ciphertext-ciphertext multiplication.
/// - seealso: ``PirAlgorithm/mulPir``, <https://eprint.iacr.org/2019/1483.pdf>.
public enum MulPir<Scheme: HeScheme>: IndexPirProtocol {
    /// HE scheme used for PIR computation.
    public typealias Scheme = Scheme
    /// Encrypted query type.
    public typealias Query = PrivateInformationRetrieval.Query<Scheme>
    /// Encrypted server response type.
    public typealias Response = PrivateInformationRetrieval.Response<Scheme>
    @usableFromInline typealias CanonicalCiphertext = Scheme.CanonicalCiphertext

    public static var algorithm: PirAlgorithm { .mulPir }

    public static func generateParameter(config: IndexPirConfig,
                                         with context: Scheme.Context) -> IndexPirParameter
    {
        let encodedEntrySize = config.encodedEntrySize
        let perChunkPlaintextCount = if encodedEntrySize <= context.bytesPerPlaintext {
            config.entryCount.dividingCeil(context.bytesPerPlaintext / encodedEntrySize, variableTime: true)
        } else {
            config.entryCount
        }

        let dimensionSize = Int(floor(Double.root(Double(perChunkPlaintextCount), config.dimensionCount)))
        var dimensions = Array(repeating: dimensionSize, count: config.dimensionCount)
        for index in dimensions.indices {
            if dimensions.product() < perChunkPlaintextCount {
                dimensions[index] += 1
            } else {
                break
            }
        }
        if config.unevenDimensions, config.dimensionCount == 2, Scheme.cryptosystem == .bfv {
            // BFV ciphertext-ciphertext multiply is a runtime bottleneck.
            // To improve runtime, we reduce the second dimension and
            // increase the first dimension while keeping the total expansion length
            // within the next power of two, preventing the Galois key size from increasing.
            let unevenDimensionsLimit = UInt32(dimensions.sum() * config.batchSize).nextPowerOfTwo
            var newDimensions = dimensions
            while (newDimensions.sum() * config.batchSize).nextPowerOfTwo <= unevenDimensionsLimit {
                dimensions = newDimensions
                if newDimensions[1] == 1 {
                    break
                }
                newDimensions[1] -= 1
                newDimensions[0] = perChunkPlaintextCount.dividingCeil(newDimensions[1], variableTime: true)
            }
        }

        let evalKeyConfig = Self.evaluationKeyConfig(
            expandedQueryCount: dimensions.sum() * config.batchSize,
            degree: context.encryptionParameters.polyDegree,
            keyCompression: config.keyCompression)
        return IndexPirParameter(
            entryCount: config.entryCount,
            entrySizeInBytes: config.entrySizeInBytes,
            dimensions: dimensions, batchSize: config.batchSize,
            evaluationKeyConfig: evalKeyConfig,
            encodingEntrySize: config.encodingEntrySize)
    }

    @inlinable
    package static func evaluationKeyConfig(
        expandedQueryCount: Int,
        degree: Int,
        keyCompression: PirKeyCompressionStrategy) -> EvaluationKeyConfig
    {
        let maxExpansionDepth = min(expandedQueryCount, degree).ceilLog2
        let smallestPower = degree.log2 - maxExpansionDepth + 1
        let largestPower = switch keyCompression {
        case .noCompression: degree.log2
        case .hybridCompression, .maxCompression:
            max(smallestPower, (degree.log2 + 1).dividingCeil(2, variableTime: true))
        }
        var galoisElements = (smallestPower...largestPower).map { level in
            (1 << level) + 1
        }
        if keyCompression == .hybridCompression {
            let extraPower = max(largestPower, (degree.log2 + largestPower + 1) / 2)
            let extraGaloisElement = (1 << extraPower) + 1
            if !galoisElements.contains(extraGaloisElement) {
                galoisElements.append(extraGaloisElement)
            }
        }
        return .init(galoisElements: galoisElements, hasRelinearizationKey: true)
    }

    @inlinable
    static func computePerChunkPlaintextCount(for parameter: IndexPirParameter) -> Int {
        parameter.dimensions.product()
    }
}

/// Client which can compute queries and decrypt responses using the ``PirAlgorithm/mulPir`` algorithm.
public final class MulPirClient<PirUtil: PirUtilProtocol>: IndexPirClient {
    @usableFromInline typealias Scalar = Scheme.Scalar
    /// Underlying HE scheme
    public typealias Scheme = PirUtil.Scheme
    /// IndexPir protocol type.
    public typealias IndexPir = MulPir<Scheme>
    /// Encrypted query type.
    public typealias Query = IndexPir.Query
    /// Encrypted response type.
    public typealias Response = IndexPir.Response

    public let parameter: IndexPirParameter

    /// Context for HE computation.
    public let context: Scheme.Context

    public var evaluationKeyConfig: EvaluationKeyConfig {
        parameter.evaluationKeyConfig
    }

    @usableFromInline var entrySizeInBytes: Int { parameter.entrySizeInBytes }

    @usableFromInline var encodingEntrySize: Bool { parameter.encodingEntrySize }

    @usableFromInline var encodedEntrySize: Int { parameter.encodedEntrySize }

    @usableFromInline var entryChunksPerPlaintext: Int {
        if context.bytesPerPlaintext >= encodedEntrySize {
            return context.bytesPerPlaintext / encodedEntrySize
        }
        return 1
    }

    @usableFromInline var perChunkPlaintextCount: Int {
        IndexPir.computePerChunkPlaintextCount(for: parameter)
    }

    public init(parameter: IndexPirParameter, context: Scheme.Context) {
        self.parameter = parameter
        self.context = context
    }

    /// Generates an `EvaluationKey` that the server uses to evaluate PIR queries.
    /// - Parameter secretKey: Secret key used to generate the evaluation key.
    /// - Returns: An `EvaluationKey` for use in sever-side computation.
    /// - Throws: Error upon failure to generate an evaluation key.
    /// - Warning: The evaluation key is only valid for use with the given `secretKey`.
    public func generateEvaluationKey(using secretKey: SecretKey<Scheme>) throws -> EvaluationKey<Scheme> {
        try context.generateEvaluationKey(config: evaluationKeyConfig,
                                          using: secretKey)
    }
}

// MARK: query generation related function

extension MulPirClient {
    @inlinable
    package func computeCoordinates(at index: Int) throws -> [Int] {
        guard index >= 0, index < parameter.entryCount else {
            throw PirError.invalidIndex(index: index, numberOfEntries: parameter.entryCount)
        }
        var plaintextIndex = plaintextIndex(entryIndex: index)
        var product = parameter.dimensions.product() as Int
        return parameter.dimensions.map { dimensionSize in
            product /= dimensionSize
            let coordinate = plaintextIndex / product
            plaintextIndex -= coordinate * product
            return coordinate
        }
    }

    /// Generates an encrypted query.
    /// - Parameters:
    ///   - indices: Database indices at which to query.
    ///   - secretKey: Secret key used for the query.
    /// - Returns: An encrypted query.
    /// - Throws: Error upon failure to generate a query.
    public func generateQuery(at indices: [Int],
                              using secretKey: SecretKey<Scheme>) throws -> Query
    {
        var accumulatedCoordinate = 0
        let nonZeroPositions = try indices.flatMap { index in
            let coordinates = try computeCoordinates(at: index)
            return parameter.dimensions.enumerated().map { dimIndex, dimSize in
                let coordinate = accumulatedCoordinate + coordinates[dimIndex]
                accumulatedCoordinate += dimSize
                return coordinate
            }
        }
        return try Query(ciphertexts: PirUtil.compressBinaryInputs(
            totalInputCount: parameter.expandedQueryCount * indices.count,
            oneIndices: nonZeroPositions,
            context: context,
            using: secretKey), indicesCount: indices.count)
    }

    @inlinable
    package func plaintextIndex(entryIndex: Int) -> Int {
        entryIndex / entryChunksPerPlaintext
    }
}

// MARK: query decrypt function

extension MulPirClient {
    var expectedResponseCiphertextCount: Int {
        encodedEntrySize.dividingCeil(context.bytesPerPlaintext, variableTime: true)
    }

    private func computeResponseRangeInBytes(at index: Int) -> Range<Int> {
        let position = index % entryChunksPerPlaintext
        return position * encodedEntrySize..<(position + 1) * encodedEntrySize
    }

    /// Decrypts an encrypted response.
    /// - Parameters:
    ///   - response: Encrypted response from a PIR query.
    ///   - queryIndices: Indices which were queried.
    ///   - secretKey: Secret key used for decryption.
    /// - Returns: For each query index, the database entry at that index.
    /// - Throws: Error upon failure to decrypt.
    public func decrypt(response: Response,
                        at queryIndices: [Int],
                        using secretKey: SecretKey<Scheme>) throws -> [[UInt8]]
    {
        guard response.ciphertexts.count == queryIndices.count else {
            throw PirError.invalidResponse(replyCount: response.ciphertexts.count, expected: queryIndices.count)
        }
        return try zip(response.ciphertexts, queryIndices).map { reply, entryIndex in
            guard reply.count == expectedResponseCiphertextCount else {
                throw PirError.invalidReply(ciphertextCount: reply.count, expected: expectedResponseCiphertextCount)
            }
            let bytes: [UInt8] = try reply.flatMap { ciphertext in
                let plaintext = try ciphertext.decrypt(using: secretKey)
                let coefficients: [Scalar] = try plaintext.decode(format: .coefficient)
                return try CoefficientPacking.coefficientsToBytes(
                    coeffs: coefficients,
                    bitsPerCoeff: context.plaintextModulus.log2)
            }

            let responseBytes = bytes[computeResponseRangeInBytes(at: entryIndex)]
            if encodingEntrySize {
                let entrySizeBytes =
                    Data(responseBytes[responseBytes.startIndex..<responseBytes.startIndex + parameter
                            .entrySizeEncodingWidth])
                let entrySize = try parameter.readEntrySize(from: entrySizeBytes)
                return Array(responseBytes[(responseBytes.startIndex + parameter.entrySizeEncodingWidth)...]
                    .prefix(Int(entrySize)))
            }
            return Array(responseBytes)
        }
    }

    // swiftlint:disable:next missing_docs
    public func decryptFull(response: Response, using secretKey: SecretKey<Scheme>) throws -> [[UInt8]] {
        try response.ciphertexts.map { reply in
            try reply.flatMap { ciphertext in
                let plaintext = try ciphertext.decrypt(using: secretKey)
                let coefficients: [Scalar] = try plaintext.decode(format: .coefficient)
                return try CoefficientPacking.coefficientsToBytes(
                    coeffs: coefficients,
                    bitsPerCoeff: context.plaintextModulus.log2)
            }
        }
    }
}

/// Server which can compute responses using the ``PirAlgorithm/mulPir`` algorithm.
public final class MulPirServer<PirUtil: PirUtilProtocol>: IndexPirServer {
    /// Underlying HE scheme
    public typealias Scheme = PirUtil.Scheme
    /// Index PIR type backing the keyword PIR computation.
    public typealias IndexPir = MulPir<Scheme>
    /// Encrypted query type.
    public typealias Query = IndexPir.Query

    /// Encrypted response type.
    public typealias Response = IndexPir.Response

    @usableFromInline typealias CanonicalCiphertext = Scheme.CanonicalCiphertext
    @usableFromInline typealias Scalar = Scheme.Scalar

    /// Index PIR parameters.
    ///
    /// Valid for PIR lookup on any of the databases.
    /// Must be the same between server and client
    public let parameter: IndexPirParameter

    /// Context for HE computation.
    ///
    /// Must be the same between client and server.
    public let context: Scheme.Context
    /// Evaluation key configuration.
    public var evaluationKeyConfig: EvaluationKeyConfig {
        parameter.evaluationKeyConfig
    }

    /// Processed databases.
    public let databases: [Database]

    @usableFromInline var entrySizeInBytes: Int { parameter.entrySizeInBytes }

    @usableFromInline var chunkCount: Int {
        Self.chunkCount(parameter: parameter, context: context)
    }

    /// The number of plaintexts, including padding, within a chunk.
    @usableFromInline var perChunkPlaintextCount: Int {
        IndexPir.computePerChunkPlaintextCount(for: parameter)
    }

    /// The number of plaintexts, including padding, in a database.
    @usableFromInline var plaintextCount: Int {
        chunkCount * perChunkPlaintextCount
    }

    /// Initializes a ``MulPirServer`` with databases.
    /// - Parameters:
    ///   - parameter: PIR parameters associated with the databases.
    ///   - context: Context for HE computation.
    ///   - databases: Databases, each compatible with the given `parameter`.
    /// - Throws: Error upon failure to initialize the server.
    public init(parameter: IndexPirParameter, context: Scheme.Context, databases: [Database]) throws {
        self.parameter = parameter
        self.context = context
        self.databases = databases
        for database in databases {
            guard database.count == plaintextCount else {
                throw PirError.invalidDatabasePlaintextCount(
                    plaintextCount: database.count,
                    expected: plaintextCount)
            }
        }
    }

    @inlinable
    package static func chunkCount(parameter: IndexPirParameter, context: Scheme.Context) -> Int {
        parameter.encodedEntrySize.dividingCeil(context.bytesPerPlaintext, variableTime: true)
    }
}

extension MulPirServer {
    @inlinable
    func computeResponseForOneChunk<ExpandedQueries: Sendable, DataChunk: Sendable>(
        expandedDim0Query: [Ciphertext<Scheme, Eval>],
        expandedRemainingQuery: ExpandedQueries,
        dataChunk: DataChunk,
        using evaluationKey: EvaluationKey<Scheme>) async throws
        -> Ciphertext<Scheme, Coeff>
        where ExpandedQueries: Collection<CanonicalCiphertext>, DataChunk: Collection<Plaintext<Scheme, Eval>?>,
        ExpandedQueries.Index == Int, DataChunk.Index == Int
    {
        let databaseColumnsCount = perChunkPlaintextCount / parameter.dimensions[0]
        precondition(databaseColumnsCount == 1 || databaseColumnsCount == expandedRemainingQuery.count)

        var intermediateResults: [Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>] =
            try await .init((0..<databaseColumnsCount).async.map { columnIndex in
                let startIndex = dataChunk.startIndex + expandedDim0Query.count * columnIndex
                let endIndex = min(startIndex + expandedDim0Query.count, dataChunk.endIndex)
                let plaintexts = dataChunk[startIndex..<endIndex]
                return try await expandedDim0Query.innerProduct(plaintexts: plaintexts).convertToCanonicalFormat()
            })

        var queryStartingIndex = expandedRemainingQuery.startIndex
        for await dimensionSize in parameter.dimensions.dropFirst().async {
            let currentIndex = queryStartingIndex
            let currentResults = intermediateResults
            intermediateResults = try await .init(stride(from: 0, to: intermediateResults.count, by: dimensionSize)
                .async.map { startIndex in
                    let vector0 = expandedRemainingQuery[currentIndex..<currentIndex + dimensionSize]
                    let vector1 = currentResults[startIndex..<startIndex + dimensionSize]
                    var product = try await vector0.innerProduct(ciphertexts: vector1)
                    try await product.relinearize(using: evaluationKey)
                    return product
                })
            queryStartingIndex += dimensionSize
        }

        precondition(intermediateResults.count == 1,
                     "There should be only 1 ciphertext in the final result for each chunk")
        try await intermediateResults[0].modSwitchDownToSingle()
        return try await intermediateResults[0].convertToCoeffFormat()
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public func computeResponse(to query: Query,
                                using evaluationKey: EvaluationKey<Scheme>) async throws -> Response

    {
        guard databases.count == 1 || databases.count >= query.indicesCount else {
            throw PirError.invalidBatchSize(queryCount: query.indicesCount, databaseCount: databases.count)
        }
        let expandedQueries = try await PirUtil.expand(ciphertexts:
            query.ciphertexts,
            outputCount: parameter.expandedQueryCount * query.indicesCount,
            using: evaluationKey)
        // This is a deque where remove first is a constant time op.
        var ciphertextForEachQuery = expandedQueries.chunk(by: parameter.expandedQueryCount)
        var responseCiphertexts: [[Scheme.CoeffCiphertext]] = []

        for queryIndex in 0..<query.indicesCount {
            let database = databases[databases.count == 1 ? 0 : queryIndex]
            var queryCiphertexts = ciphertextForEachQuery.removeFirst()
            var firstDimensionQueries: [Scheme.EvalCiphertext] = []
            firstDimensionQueries.reserveCapacity(parameter.dimensions[0])
            for _ in 0..<parameter.dimensions[0] {
                try await firstDimensionQueries.append(queryCiphertexts.removeFirst().convertToEvalFormat())
            }
            let perChunkPlaintextCount = database.count / chunkCount

            try await responseCiphertexts
                .append(.init(stride(from: 0, to: database.count, by: perChunkPlaintextCount).async
                        .map { [queryCiphertexts, firstDimensionQueries] startIndex in
                            try await self.computeResponseForOneChunk(
                                expandedDim0Query: firstDimensionQueries,
                                expandedRemainingQuery: queryCiphertexts,
                                dataChunk: database
                                    .plaintexts[startIndex..<startIndex + perChunkPlaintextCount],
                                using: evaluationKey)
                        }))
        }
        return Response(ciphertexts: responseCiphertexts)
    }
}

// MARK: database process function

extension MulPirServer {
    @inlinable
    // swiftlint:disable:next attributes missing_docs
    public static func process(database: some Collection<[UInt8]>, with context: Scheme.Context,
                               using parameter: IndexPirParameter) async throws -> Database
    {
        guard database.count == parameter.entryCount else {
            throw PirError
                .invalidDatabaseEntryCount(entryCount: database.count, expected: parameter.entryCount)
        }
        let maxEntrySize = database.map(\.count).max() ?? 0
        guard maxEntrySize <= parameter.entrySizeInBytes else {
            throw PirError
                .invalidDatabaseEntrySize(maximumEntrySize: maxEntrySize, expected: parameter.entrySizeInBytes)
        }
        let chunkCount = parameter.encodedEntrySize.dividingCeil(context.bytesPerPlaintext, variableTime: true)
        if chunkCount > 1 {
            return try await processSplitLargeEntries(database: database, with: context, using: parameter)
        }
        return try await processPackEntries(database: database, with: context, using: parameter)
    }

    @inlinable
    static func processSplitLargeEntries(
        database: some Collection<[UInt8]>,
        with context: Scheme.Context,
        using parameter: IndexPirParameter) async throws -> Database
    {
        let chunkCount = Self.chunkCount(parameter: parameter, context: context)
        var plaintexts: [[Plaintext<Scheme, Eval>?]] = try await .init(database.async.map { entry in
            try await .init(stride(from: 0, to: parameter.encodedEntrySize, by: context.bytesPerPlaintext).async
                .map { startIndex in
                    let entryStartIndex = startIndex - parameter.entrySizeEncodingWidth
                    let endIndex = min(entryStartIndex + context.bytesPerPlaintext, entry.count)
                    // Avoid computing on padding plaintexts
                    guard entryStartIndex < endIndex else {
                        return nil
                    }
                    let bytes = if startIndex == 0, parameter.encodingEntrySize {
                        try IndexPirConfig
                            .encodeEntrySize(entry.count, encodingSize: parameter.entrySizeEncodingWidth) +
                            entry[0..<endIndex]
                    } else {
                        Array(entry[entryStartIndex..<endIndex])
                    }

                    let coefficients: [Scheme.Scalar] = try CoefficientPacking.bytesToCoefficients(
                        bytes: bytes,
                        bitsPerCoeff: context.plaintextModulus.log2,
                        decode: false)
                    if coefficients.allSatisfy({ $0 == 0 }) {
                        return nil
                    }
                    return try context.encode(values: coefficients, format: .coefficient)
                })
        })

        let perChunkPlaintextCount = IndexPir.computePerChunkPlaintextCount(for: parameter)
        let zeroChunk: [Plaintext<Scheme, Eval>?] = Array(repeatElement(nil, count: chunkCount))
        while plaintexts.count < perChunkPlaintextCount {
            plaintexts.append(zeroChunk)
        }
        var flatPlaintexts: [Plaintext<Scheme, Eval>?] = []
        flatPlaintexts.reserveCapacity(plaintexts.count * plaintexts[0].count)
        let remainingDimensions = perChunkPlaintextCount / parameter.dimensions[0]
        for chunk in 0..<chunkCount {
            for skip in 0..<remainingDimensions {
                for rowIndex in stride(from: skip, to: plaintexts.count, by: remainingDimensions) {
                    flatPlaintexts.append(plaintexts[rowIndex][chunk])
                }
            }
        }
        assert(flatPlaintexts.count == chunkCount * perChunkPlaintextCount)
        return Database(plaintexts: flatPlaintexts)
    }

    @inlinable
    static func processPackEntries(
        database: some Collection<[UInt8]>,
        with context: Scheme.Context,
        using parameter: IndexPirParameter) async throws -> Database
    {
        assert(database.count == parameter.entryCount)
        let flatDatabase: [UInt8] = try database.flatMap { entry in
            var entry = entry
            if parameter.encodingEntrySize {
                let encoded = try IndexPirConfig.encodeEntrySize(
                    entry.count,
                    encodingSize: parameter.entrySizeEncodingWidth)
                entry = encoded + entry
            }
            let pad = parameter.encodedEntrySize - entry.count
            entry.append(contentsOf: repeatElement(0, count: pad))
            return entry
        }
        let entriesPerPlaintext = context.bytesPerPlaintext / parameter.encodedEntrySize
        let bytesPerPlaintext = entriesPerPlaintext * parameter.encodedEntrySize
        let plaintextIndices = stride(from: 0, to: flatDatabase.count, by: bytesPerPlaintext)
        var plaintexts: [Plaintext<Scheme, Eval>?] = try await .init(plaintextIndices.async
            .map { startIndex in
                let endIndex = min(startIndex + bytesPerPlaintext, flatDatabase.count)
                let values = Array(flatDatabase[startIndex..<endIndex])
                let plaintextCoefficients: [Scalar] = try CoefficientPacking.bytesToCoefficients(
                    bytes: values,
                    bitsPerCoeff: context.plaintextModulus.log2,
                    decode: false)
                if plaintextCoefficients.allSatisfy({ $0 == 0 }) {
                    return nil
                }
                return try context.encode(values: plaintextCoefficients, format: .coefficient)
            })

        let perChunkPlaintextCount = IndexPir.computePerChunkPlaintextCount(for: parameter)
        while plaintexts.count < perChunkPlaintextCount {
            plaintexts.append(nil)
        }

        // Reorder for sequential access at query time
        var reorderedPlaintexts: [Plaintext<Scheme, Eval>?] = []
        let remainingDimensions = perChunkPlaintextCount / parameter.dimensions[0]
        for skip in 0..<remainingDimensions {
            for rowIndex in stride(from: skip, to: plaintexts.count, by: remainingDimensions) {
                reorderedPlaintexts.append(plaintexts[rowIndex])
            }
        }
        return Database(plaintexts: reorderedPlaintexts)
    }
}

extension Array {
    @inlinable
    consuming func chunk(by step: Int) -> Deque<Deque<Element>> {
        precondition(count.isMultiple(of: step))
        let shares = count / step
        return Deque((0..<shares).map { index in Deque(self[index * step..<(index + 1) * step]) })
    }
}
