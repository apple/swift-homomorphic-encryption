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

    public static func generateParameter(config: IndexPirConfig, with context: Context<Scheme>) -> IndexPirParameter {
        let entrySizeInBytes = config.entrySizeInBytes
        let perChunkPlaintextCount = if entrySizeInBytes <= context.bytesPerPlaintext {
            config.entryCount.dividingCeil(context.bytesPerPlaintext / entrySizeInBytes, variableTime: true)
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
        if config.unevenDimensions, config.dimensionCount == 2, Scheme.self == Bfv<Scheme.Scalar>.self {
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

        let evalKeyConfig = Self.evaluationKeyConfiguration(
            expandedQueryCount: dimensions.sum() * config.batchSize,
            degree: context.encryptionParameters.polyDegree,
            keyCompression: config.keyCompression)
        return IndexPirParameter(
            entryCount: config.entryCount,
            entrySizeInBytes: entrySizeInBytes,
            dimensions: dimensions, batchSize: config.batchSize,
            evaluationKeyConfig: evalKeyConfig)
    }

    static func evaluationKeyConfiguration(
        expandedQueryCount: Int,
        degree: Int,
        keyCompression: PirKeyCompressionStrategy) -> HomomorphicEncryption.EvaluationKeyConfiguration
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
public final class MulPirClient<Scheme: HeScheme>: IndexPirClient {
    /// IndexPir protocol type.
    public typealias IndexPir = MulPir<Scheme>
    /// Encrypted query type.
    public typealias Query = IndexPir.Query
    /// Encrypted response type.
    public typealias Response = IndexPir.Response

    public let parameter: IndexPirParameter

    /// Context for HE computation.
    public let context: HomomorphicEncryption.Context<Scheme>

    public var evaluationKeyConfiguration: HomomorphicEncryption.EvaluationKeyConfiguration {
        parameter.evaluationKeyConfig
    }

    @usableFromInline var entrySizeInBytes: Int { parameter.entrySizeInBytes }

    @usableFromInline var entryChunksPerPlaintext: Int {
        if context.bytesPerPlaintext >= entrySizeInBytes {
            return context.bytesPerPlaintext / entrySizeInBytes
        }
        return 1
    }

    @usableFromInline var perChunkPlaintextCount: Int {
        IndexPir.computePerChunkPlaintextCount(for: parameter)
    }

    public init(parameter: IndexPirParameter, context: Context<Scheme>) {
        self.parameter = parameter
        self.context = context
    }

    /// Generates an `EvaluationKey` that the server uses to evaluate PIR queries.
    /// - Parameter secretKey: Secret key used to generate the evaluation key.
    /// - Returns: An `EvaluationKey` for use in sever-side computation.
    /// - Throws: Error upon failure to generate an evaluation key.
    /// - Warning: The evaluation key is only valid for use with the given `secretKey`.
    public func generateEvaluationKey(using secretKey: SecretKey<Scheme>) throws -> EvaluationKey<Scheme> {
        try Scheme.generateEvaluationKey(
            context: context,
            configuration: evaluationKeyConfiguration,
            using: secretKey)
    }
}

// MARK: query generation related function

extension MulPirClient {
    func computeCoordinates(at index: Int) throws -> [Int] {
        guard index >= 0, index < parameter.entryCount else {
            throw PirError.invalidIndex(index: index, numberOfEntries: parameter.entryCount)
        }
        var plaintextIndex = plaintextIndex(parameter, entryIndex: index)
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
        return try Query(ciphertexts: PirUtil.compressInputs(
            totalInputCount: parameter.expandedQueryCount * indices.count,
            nonZeroInputs: nonZeroPositions,
            context: context,
            using: secretKey), indicesCount: indices.count)
    }

    private func plaintextIndex(_: IndexPirParameter,
                                entryIndex: Int) -> Int
    {
        let entryPerPlaintext = entryChunksPerPlaintext
        return entryIndex / entryPerPlaintext
    }
}

// MARK: query decrypt function

extension MulPirClient {
    var expectedResponseCiphertextCount: Int {
        entrySizeInBytes.dividingCeil(context.bytesPerPlaintext, variableTime: true)
    }

    private func computeResponseRangeInBytes(at index: Int) -> Range<Int> {
        let position = index % entryChunksPerPlaintext
        return position * entrySizeInBytes..<(position + 1) * entrySizeInBytes
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
                let coefficients: [Scheme.Scalar] = try plaintext.decode(format: .coefficient)
                return try CoefficientPacking.coefficientsToBytes(
                    coeffs: coefficients,
                    bitsPerCoeff: context.plaintextModulus.log2)
            }

            // this is a copy of the client side bug
            let accessRange = computeResponseRangeInBytes(at: entryIndex)
            guard accessRange.upperBound < bytes.count else {
                throw PirError.validationError("Client side bug hit!")
            }

            return Array(bytes[computeResponseRangeInBytes(at: entryIndex)])
        }
    }
}

/// Server which can compute responses using the ``PirAlgorithm/mulPir`` algorithm.
public final class MulPirServer<Scheme: HeScheme>: IndexPirServer {
    /// Index PIR type backing the keyword PIR computation.
    public typealias IndexPir = MulPir<Scheme>
    /// Encrypted query type.
    public typealias Query = IndexPir.Query

    /// Encrypted response type.
    public typealias Response = IndexPir.Response

    @usableFromInline typealias CanonicalCiphertext = Scheme.CanonicalCiphertext

    /// Index PIR parameters.
    ///
    /// Valid for PIR lookup on any of the databases.
    /// Must be the same between server and client
    public let parameter: IndexPirParameter

    /// Context for HE computation.
    ///
    /// Must be the same between client and server.
    public let context: HomomorphicEncryption.Context<Scheme>

    /// Evaluation key configuration.
    public var evaluationKeyConfiguration: EvaluationKeyConfiguration {
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
    public init(parameter: IndexPirParameter, context: Context<Scheme>, databases: [Database]) throws {
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
    package static func chunkCount(parameter: IndexPirParameter, context: Context<Scheme>) -> Int {
        parameter.entrySizeInBytes.dividingCeil(context.bytesPerPlaintext, variableTime: true)
    }
}

extension MulPirServer {
    @inlinable
    func computeResponseForOneChunk<ExpandedQueries, DataChunk>(expandedDim0Query: [Ciphertext<Scheme, Eval>],
                                                                expandedRemainingQuery: ExpandedQueries,
                                                                dataChunk: DataChunk,
                                                                using evaluationKey: EvaluationKey<Scheme>) throws
        -> Ciphertext<Scheme, Coeff>
        where ExpandedQueries: Collection<CanonicalCiphertext>, DataChunk: Collection<Plaintext<Scheme, Eval>?>,
        ExpandedQueries.Index == Int, DataChunk.Index == Int
    {
        let databaseColumnsCount = perChunkPlaintextCount / parameter.dimensions[0]
        precondition(databaseColumnsCount == 1 || databaseColumnsCount == expandedRemainingQuery.count)

        var startIndex = dataChunk.startIndex
        var intermediateResults: [CanonicalCiphertext] = try (0..<databaseColumnsCount).map { _ in
            let endIndex = min(startIndex + expandedDim0Query.count, dataChunk.endIndex)
            let plaintexts = dataChunk[startIndex..<endIndex]
            startIndex += expandedDim0Query.count
            return try expandedDim0Query.innerProduct(plaintexts: plaintexts)
                .convertToCanonicalFormat()
        }
        var queryStartingIndex = expandedRemainingQuery.startIndex
        for dimensionSize in parameter.dimensions.dropFirst() {
            intermediateResults = try stride(from: 0, to: intermediateResults.count, by: dimensionSize)
                .map { startIndex in
                    var product = try expandedRemainingQuery[queryStartingIndex..<queryStartingIndex + dimensionSize]
                        .innerProduct(ciphertexts: intermediateResults[startIndex..<startIndex + dimensionSize])
                    try product.relinearize(using: evaluationKey)
                    return product
                }
            queryStartingIndex += dimensionSize
        }
        precondition(
            intermediateResults.count == 1,
            "There should be only 1 ciphertext in the final result for each chunk")
        try intermediateResults[0].modSwitchDownToSingle()
        return try intermediateResults[0].convertToCoeffFormat()
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public func computeResponse(to query: Query,
                                using evaluationKey: EvaluationKey<Scheme>) throws -> Response

    {
        guard databases.count == 1 || databases.count >= query.indicesCount else {
            throw PirError.invalidBatchSize(queryCount: query.indicesCount, databaseCount: databases.count)
        }
        let expandedQueries = try PirUtil.expandCiphertexts(
            query.ciphertexts,
            outputCount: parameter.expandedQueryCount * query.indicesCount,
            using: evaluationKey)

        // Note that `parameter.expandedQueryCount` is the sum of all dimension sizes. We process the expanded
        // queries in chunks of `parameter.expandedQueryCount`. In each chunk, we firstly convert the first
        // `parameter.dimensions[0]` ciphertexts into eval format as they will multiply with plaintexts. The rest are
        // queries for the remaining dimensions, multiplying with ciphertexts, thus can stay in canonical format. Then
        // we simply use these queries to process every chunk of the database. The first iteration is looping over each
        // PIR call. The second iteration is looping over chunks of entries.
        return try Response(ciphertexts: (0..<query.indicesCount).map { queryIndex in
            let database = databases[databases.count == 1 ? 0 : queryIndex]
            let startingQueryIndex = queryIndex * parameter.expandedQueryCount
            let firstDimensionQueries =
                try expandedQueries[startingQueryIndex..<startingQueryIndex + parameter.dimensions[0]]
                    .map { ciphertext in try ciphertext.convertToEvalFormat() }
            let remainingQueries =
                expandedQueries[startingQueryIndex + parameter.dimensions[0]..<startingQueryIndex + parameter
                    .expandedQueryCount]
            let perChunkPlaintextCount = database.count / chunkCount
            return try stride(from: 0, to: database.count, by: perChunkPlaintextCount)
                .map { startIndex in
                    try computeResponseForOneChunk(
                        expandedDim0Query: firstDimensionQueries,
                        expandedRemainingQuery: remainingQueries,
                        dataChunk: database
                            .plaintexts[startIndex..<startIndex + perChunkPlaintextCount],
                        using: evaluationKey)
                }
        })
    }
}

// MARK: database process function

extension MulPirServer {
    @inlinable
    // swiftlint:disable:next attributes missing_docs
    public static func process(database: some Collection<[UInt8]>, with context: Context<Scheme>,
                               using parameter: IndexPirParameter) throws -> Database
    {
        guard database.count == parameter.entryCount else {
            throw PirError
                .invalidDatabaseEntryCount(entryCount: database.count, expected: parameter.entryCount)
        }
        let maximumElementSize = database.map(\.count).max() ?? 0
        guard maximumElementSize <= parameter.entrySizeInBytes else {
            throw PirError
                .invalidDatabaseEntrySize(maximumEntrySize: maximumElementSize, expected: parameter.entrySizeInBytes)
        }
        let chunkCount = parameter.entrySizeInBytes.dividingCeil(context.bytesPerPlaintext, variableTime: true)
        if chunkCount > 1 {
            return try processSplitLargeEntries(database: database, with: context, using: parameter)
        }
        return try processPackEntries(database: database, with: context, using: parameter)
    }

    @inlinable
    static func processSplitLargeEntries(
        database: some Collection<[UInt8]>,
        with context: Context<Scheme>,
        using parameter: IndexPirParameter) throws -> Database
    {
        let chunkCount = Self.chunkCount(parameter: parameter, context: context)
        var plaintexts: [[Plaintext<Scheme, Eval>?]] = try database.map { entry in
            try stride(from: 0, to: parameter.entrySizeInBytes, by: context.bytesPerPlaintext).map { startIndex in
                let endIndex = min(startIndex + context.bytesPerPlaintext, entry.count)
                // Avoid computing on padding plaintexts
                guard startIndex < endIndex else {
                    return nil
                }
                let bytes = Array(entry[startIndex..<endIndex])
                let coefficients: [Scheme.Scalar] = CoefficientPacking.bytesToCoefficients(
                    bytes: bytes,
                    bitsPerCoeff: context.plaintextModulus.log2,
                    decode: false)
                if coefficients.allSatisfy({ $0 == 0 }) {
                    return nil
                }
                return try Scheme.encode(context: context, values: coefficients, format: .coefficient)
            }
        }

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
        with context: Context<Scheme>,
        using parameter: IndexPirParameter) throws -> Database
    {
        assert(database.count == parameter.entryCount)
        let flatDatabase: [UInt8] = database.flatMap { entry in
            var entry = entry
            let pad = parameter.entrySizeInBytes - entry.count
            entry.append(contentsOf: repeatElement(0, count: pad))
            return entry
        }
        let entriesPerPlaintext = context.bytesPerPlaintext / parameter.entrySizeInBytes
        let bytesPerPlaintext = entriesPerPlaintext * parameter.entrySizeInBytes
        var plaintexts: [Plaintext<Scheme, Eval>?] = try stride(from: 0, to: flatDatabase.count, by: bytesPerPlaintext)
            .map { startIndex in
                let endIndex = min(startIndex + bytesPerPlaintext, flatDatabase.count)
                let values = Array(flatDatabase[startIndex..<endIndex])
                let plaintextCoefficients: [Scheme.Scalar] = CoefficientPacking.bytesToCoefficients(
                    bytes: values,
                    bitsPerCoeff: context.plaintextModulus.log2,
                    decode: false)
                if plaintextCoefficients.allSatisfy({ $0 == 0 }) {
                    return nil
                }
                return try Scheme.encode(context: context, values: plaintextCoefficients, format: .coefficient)
            }
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
