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

public import Algorithms
public import AsyncAlgorithms
public import DequeModule
public import HomomorphicEncryption
public import ModularArithmetic

/// A protocol  outlining the auxiliary functionalities used in PIR.
public protocol PirUtilProtocol: Sendable {
    /// The underlying HE scheme.
    associatedtype Scheme: HeScheme
    /// The Scalar type used by the HE scheme.
    associatedtype Scalar where Scalar == Scheme.Scalar
    /// HE ciphertext in canonical format.
    typealias CanonicalCiphertext = Scheme.CanonicalCiphertext

    /// Expand a small number of ciphertexts to a large number of ciphertexts with as many threads as possible
    ///
    /// Each output will be the encryption of a constant poly, where the constant of i-th output is the i-th coefficient
    /// in the inputs.
    /// - Parameters:
    ///   - ciphertexts: ciphertexts to expand
    ///   - outputCount: how many outputs are expected
    ///   - evaluationKey: evaluation key used for rotation and apply galois
    /// - Returns: the expanded ciphertext
    static func expand(
        ciphertexts: consuming [CanonicalCiphertext],
        outputCount: Int,
        using evaluationKey: EvaluationKey<Scheme>) async throws -> [CanonicalCiphertext]

    /// Expand a small number of ciphertexts to a large number of ciphertexts with the option to turn off
    /// multi-threading.
    ///
    /// Each output will be the encryption of a constant poly, where the constant of i-th output is the i-th coefficient
    /// in the inputs.
    /// - Parameters:
    ///   - ciphertexts: ciphertexts to expand
    ///   - outputCount: how many outputs are expected
    ///   - evaluationKey: evaluation key used for rotation and apply galois
    ///   - callOptions: runtime configs (e.g. multi-threading).
    /// - Returns: the expanded ciphertext
    static func expand(
        ciphertexts: consuming [CanonicalCiphertext],
        outputCount: Int,
        using evaluationKey: EvaluationKey<Scheme>,
        callOptions: CallOptions) async throws -> [CanonicalCiphertext]

    /// Compress an binary array into ciphertexts such that the expanded ciphertexts is the original array.
    ///
    /// - Parameters:
    ///        - totalInputCount: the length of the binary array
    ///        - oneIndices: the position of 1s
    ///        - context: the context for HE
    ///        - secretKey: the secret key for encryption.
    static func compressBinaryInputs(
        totalInputCount: Int,
        oneIndices: [Int],
        context: Scheme.Context,
        using secretKey: SecretKey<Scheme>) throws -> [CanonicalCiphertext]

    /// Compute the PIR response for a query with as many possible threads as possible
    /// - Parameters:
    ///   - query: The encrypted query.
    ///   - evaluationKey: Evaluation key for homomorphic operations.
    ///   - databases: The processed databases.
    ///   - parameter: PIR parameters.
    ///   - context: The HE context.
    /// - Returns: The encrypted response.
    static func computeResponse(
        to query: Query<Scheme>,
        using evaluationKey: EvaluationKey<Scheme>,
        databases: [ProcessedDatabase<Scheme>],
        parameter: IndexPirParameter,
        context: Scheme.Context) async throws -> Response<Scheme>

    // swiftlint:disable function_parameter_count

    /// Compute the PIR response for a query with an option to turn-off multi-threading.
    /// - Parameters:
    ///   - query: The encrypted query.
    ///   - evaluationKey: Evaluation key for homomorphic operations.
    ///   - databases: The processed databases.
    ///   - parameter: PIR parameters.
    ///   - context: The HE context.
    ///   - callOptions: runtime configs (e.g. multi-threading)
    /// - Returns: The encrypted response.
    static func computeResponse(
        to query: Query<Scheme>,
        using evaluationKey: EvaluationKey<Scheme>,
        databases: [ProcessedDatabase<Scheme>],
        parameter: IndexPirParameter,
        context: Scheme.Context,
        callOptions: CallOptions) async throws -> Response<Scheme>

    /// Compute the response for one chunk of the database with as many threads as possible.
    /// - Parameters:
    ///   - expandedDim0Query: Expanded queries for the first dimension.
    ///   - expandedRemainingQuery: Expanded queries for remaining dimensions.
    ///   - dataChunk: Chunk of plaintexts from the database.
    ///   - evaluationKey: Evaluation key for homomorphic operations.
    ///   - parameter: PIR parameters.
    /// - Returns: The ciphertext response for this chunk.
    static func computeResponseForOneChunk<
        ExpandedQueries: Sendable & Collection<CanonicalCiphertext>,
        DataChunk: Sendable & Collection<Plaintext<Scheme, Eval>?>,
    >(
        expandedDim0Query: [Ciphertext<Scheme, Eval>],
        expandedRemainingQuery: ExpandedQueries,
        dataChunk: DataChunk,
        using evaluationKey: EvaluationKey<Scheme>,
        parameter: IndexPirParameter) async throws -> Ciphertext<Scheme, Coeff>
        where ExpandedQueries.Index == Int, DataChunk.Index == Int

    /// Compute the response for one chunk of the database with the option to disable multi-threading.
    /// - Parameters:
    ///   - expandedDim0Query: Expanded queries for the first dimension.
    ///   - expandedRemainingQuery: Expanded queries for remaining dimensions.
    ///   - dataChunk: Chunk of plaintexts from the database.
    ///   - evaluationKey: Evaluation key for homomorphic operations.
    ///   - parameter: PIR parameters.
    ///   - callOptions: runtime configs (e.g. multi-threading).
    /// - Returns: The ciphertext response for this chunk.
    static func computeResponseForOneChunk<
        ExpandedQueries: Sendable & Collection<CanonicalCiphertext>,
        DataChunk: Sendable & Collection<Plaintext<Scheme, Eval>?>,
    >(
        expandedDim0Query: [Ciphertext<Scheme, Eval>],
        expandedRemainingQuery: ExpandedQueries,
        dataChunk: DataChunk,
        using evaluationKey: EvaluationKey<Scheme>,
        parameter: IndexPirParameter,
        callOptions: CallOptions) async throws -> Ciphertext<Scheme, Coeff>
        where ExpandedQueries.Index == Int, DataChunk.Index == Int
}

extension PirUtilProtocol {
    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func computeResponseForOneChunk<
        ExpandedQueries: Sendable & Collection<CanonicalCiphertext>,
        DataChunk: Sendable & Collection<Plaintext<Scheme, Eval>?>,
    >(
        expandedDim0Query: [Ciphertext<Scheme, Eval>],
        expandedRemainingQuery: ExpandedQueries,
        dataChunk: DataChunk,
        using evaluationKey: EvaluationKey<Scheme>,
        parameter: IndexPirParameter) async throws -> Ciphertext<Scheme, Coeff>
        where ExpandedQueries.Index == Int, DataChunk.Index == Int
    {
        try await computeResponseForOneChunk(expandedDim0Query: expandedDim0Query,
                                             expandedRemainingQuery: expandedRemainingQuery,
                                             dataChunk: dataChunk,
                                             using: evaluationKey,
                                             parameter: parameter,
                                             callOptions: .default)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func computeResponse(
        to query: Query<Scheme>,
        using evaluationKey: EvaluationKey<Scheme>,
        databases: [ProcessedDatabase<Scheme>],
        parameter: IndexPirParameter,
        context: Scheme.Context) async throws -> Response<Scheme>
    {
        try await computeResponse(to: query,
                                  using: evaluationKey,
                                  databases: databases,
                                  parameter: parameter,
                                  context: context,
                                  callOptions: .default)
    }

    /// Convert one encrypted polynomial `c` to two encrypted polynomials, `p` and `q`.
    ///
    /// It is guaranteed that:
    /// (1) `p[k*t] = c[k*t]*2` for all `k` where `t = 2^logStep`.
    /// (2) `q[k*t] = c[k*t+offset]*2` for all `k` where `t = 2^logStep` and `offset = 2^{logStep-1}`.
    /// Other coefficients of `p` and `q` are all some linear combination of `c`'s coefficients whose indices are not
    /// multiples of `2^{logStep-1}`.
    /// Therefore, it is recommended to make sure `c` only has non-zero coefficients on positions that are multiples of
    /// `2^{logStep-1}` to avoid unintelligent results.
    /// The algorithm is to first apply a transformation to convert `f(x)` to `f(x^{degree/2^{logStep-1}})`, which flips
    /// the sign of the coefficients at `(2^{logStep}*i + 2^{logStep-1})`-th positions and keeps the coefficients at
    /// `2^{logStep}*i`-th positions. Other coefficients become permutation of original coefficients that are not at
    /// multiples-of-`2^{logStep-1}` positions. After that, sum/subtraction helps cancel coefficients at
    /// `2^{logStep}*i`-th  or `(2^{logStep}*i + 2^{logStep-1})`-th positions. As the last step, shifting by multiplying
    /// the polynomial with `x^-{2^{logStep-1}}` helps compensate for the offset of `2^{logStep-1})`.
    @inlinable
    package static func expandCiphertextForOneStep(
        _ ciphertext: CanonicalCiphertext,
        logStep: Int,
        using evaluationKey: EvaluationKey<Scheme>) async throws -> (CanonicalCiphertext, CanonicalCiphertext)
    {
        let degree = ciphertext.degree
        precondition(logStep <= degree.log2)
        let shiftingPower = 1 << (logStep - 1)

        let targetElement = 1 << (degree.log2 - logStep + 1) + 1
        var c1 = ciphertext

        guard let galoisElement = evaluationKey.config.galoisElements.filter({ element in
            element <= targetElement }).max()
        else {
            throw HeError.missingGaloisKey
        }
        let applyGaloisCount = 1 << ((targetElement - 1).log2 - (galoisElement - 1).log2)
        var currElement = 1
        for await _ in (0..<applyGaloisCount).async {
            try await c1.applyGalois(element: galoisElement, using: evaluationKey)
            currElement *= galoisElement
            currElement %= (2 * degree)
        }
        precondition(currElement == targetElement)

        let difference = try await ciphertext - c1
        var differenceCoeff = try await difference.convertToCoeffFormat()
        try await differenceCoeff.multiplyPowerOfX(power: -shiftingPower)
        let differenceCanonical = try await differenceCoeff.convertToCanonicalFormat()
        try await c1 += ciphertext
        return (c1, differenceCanonical)
    }

    /// Expand one ciphertext into given number of encrypted constant polynomials.
    ///
    /// The input ciphertext is expected to have zero-coefficient except at multiple-of-2^{logStep-1} positions
    /// Each time, the input ciphertext is expanded to two ciphertexts, containing the even/odd non-zero coefficients,
    /// respectively. These two ciphertexts are used to generate ceil(outputCount/2) and floor(outputCount/2)
    /// ciphertexts, respectively. When only 1 ciphertext is needed to be generated, no further expansion is needed.
    /// If outputCount is a power of two, then every resulting ciphertext will come from same number of expansion where
    /// each expansion will multiply the coefficients by 2.
    /// However when outputCount is not power of two, some of them may experience one less expansion. To make them have
    /// the same blow-up factor, we add the ciphertext to itself when returning.
    @inlinable
    package static func expandCiphertext(
        _ ciphertext: CanonicalCiphertext,
        outputCount: Int,
        logStep: Int,
        expectedHeight: Int,
        using evaluationKey: EvaluationKey<Scheme>,
        callOptions: CallOptions) async throws -> [CanonicalCiphertext]
    {
        precondition(outputCount >= 0 && outputCount <= ciphertext.degree)
        var output = ciphertext
        if outputCount == 1 {
            if logStep > expectedHeight {
                return [ciphertext]
            }
            try await output += ciphertext
            return [output]
        }
        let secondHalfCount = outputCount >> 1
        let firstHalfCount = outputCount - secondHalfCount

        let (p0, p1) = try await expandCiphertextForOneStep(
            ciphertext,
            logStep: logStep,
            using: evaluationKey)
        var firstHalf: [CanonicalCiphertext] = []
        var secondHalf: [CanonicalCiphertext] = []
        let taskLeft: @Sendable () async throws -> [CanonicalCiphertext] = {
            try await expandCiphertext(
                p0,
                outputCount: firstHalfCount,
                logStep: logStep + 1,
                expectedHeight: expectedHeight,
                using: evaluationKey,
                callOptions: callOptions.divided(among: 2))
        }
        let taskRight: @Sendable () async throws -> [CanonicalCiphertext] = {
            try await expandCiphertext(
                p1,
                outputCount: secondHalfCount,
                logStep: logStep + 1,
                expectedHeight: expectedHeight,
                using: evaluationKey,
                callOptions: callOptions.divided(among: 2))
        }
        if callOptions.multiThreading {
            async let asyncFirstHalf = taskLeft()
            async let asyncSecondHalf = taskRight()
            firstHalf = try await asyncFirstHalf
            secondHalf = try await asyncSecondHalf
        } else {
            firstHalf = try await taskLeft()
            secondHalf = try await taskRight()
        }
        return zip(firstHalf.prefix(secondHalfCount), secondHalf).flatMap { [$0, $1] } + firstHalf
            .suffix(firstHalfCount - secondHalfCount)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func expand(ciphertexts: consuming [CanonicalCiphertext],
                              outputCount: Int,
                              using evaluationKey: EvaluationKey<Scheme>) async throws -> [CanonicalCiphertext]
    {
        try await expand(
            ciphertexts: ciphertexts,
            outputCount: outputCount,
            using: evaluationKey,
            callOptions: .default)
    }

    /// Expand a ciphertext array into given number of encrypted constant polynomials.
    @inlinable
    public static func expand(ciphertexts: consuming [CanonicalCiphertext],
                              outputCount: Int,
                              using evaluationKey: EvaluationKey<Scheme>,
                              callOptions: CallOptions = .default) async throws -> [CanonicalCiphertext]
    {
        precondition((ciphertexts.count - 1) * ciphertexts[0].degree < outputCount)
        precondition(ciphertexts.count * ciphertexts[0].degree >= outputCount)
        var remainingOutputs = outputCount
        let lengths: [Int] = ciphertexts.compactMap { ciphertext in
            let outputToGenerate = min(remainingOutputs, ciphertext.degree)
            remainingOutputs -= outputToGenerate
            return outputToGenerate
        }
        let transform: @Sendable (Int) async throws -> [CanonicalCiphertext] = { [ciphertexts] ciphertextIndex in
            let outputToGenerate = lengths[ciphertextIndex]
            let childOptions = callOptions.divided(among: min(callOptions.maxConcurrentTasks, ciphertexts.count))
            return try await expandCiphertext(
                ciphertexts[ciphertextIndex],
                outputCount: outputToGenerate,
                logStep: 1,
                expectedHeight: outputToGenerate.ceilLog2,
                using: evaluationKey,
                callOptions: childOptions)
        }
        let groupCount = max(1, min(callOptions.maxConcurrentTasks, ciphertexts.count))
        let expanded: [[CanonicalCiphertext]] = if groupCount > 1 {
            try await .init(Array(0..<ciphertexts.count).evenlyChunked(in: groupCount)
                .concurrentMap { batch in
                    try await [[CanonicalCiphertext]](batch.async.map { try await transform($0) }).flatMap(\.self)
                })
        } else {
            try await .init((0..<ciphertexts.count).async.map(transform))
        }
        return expanded.flatMap(\.self)
    }

    /// Convert the MulPir indices into a plaintext.
    ///
    /// The MulPir indices are the indices of non-zero results after expansion
    @inlinable
    package static func compressInputsForOneCiphertext(totalInputCount: Int, oneIndices: [Int],
                                                       context: Scheme.Context) throws -> Plaintext<Scheme, Coeff>
    {
        precondition(totalInputCount <= context.degree)
        var rawData: [Scalar] = Array(repeating: 0, count: context.degree)

        let inputCountCeilLog = totalInputCount.ceilLog2
        let inverseInputCountCeilLog = try Scalar(2).powMod(
            exponent: Scalar(inputCountCeilLog),
            modulus: context.plaintextModulus,
            variableTime: true).inverseMod(modulus: context.plaintextModulus, variableTime: true)

        for index in oneIndices {
            rawData[index] = inverseInputCountCeilLog
        }
        return try context.encode(values: rawData, format: .coefficient)
    }

    /// Generate the ciphertext based on the given non-zero positions.
    @inlinable
    public static func compressBinaryInputs(
        totalInputCount: Int,
        oneIndices: [Int],
        context: Scheme.Context,
        using secretKey: SecretKey<Scheme>) throws -> [CanonicalCiphertext]
    {
        var remainingInputs = totalInputCount
        var processedInputCount = 0
        var plaintexts: [Plaintext<Scheme, Coeff>] = []

        while remainingInputs > 0 {
            let numberOfInputsToProcess = min(remainingInputs, context.degree)
            let inputs = oneIndices.filter { x in
                (processedInputCount..<(processedInputCount + numberOfInputsToProcess)).contains(x)
            }.map { $0 - processedInputCount }
            try plaintexts.append(compressInputsForOneCiphertext(
                totalInputCount: numberOfInputsToProcess,
                oneIndices: inputs,
                context: context))
            processedInputCount += numberOfInputsToProcess
            remainingInputs -= numberOfInputsToProcess
        }
        return try plaintexts.map { plaintext in try plaintext.encrypt(using: secretKey) }
    }

    /// Default implementation of computeResponseForOneChunk.
    @inlinable
    public static func computeResponseForOneChunk<
        ExpandedQueries: Sendable & Collection<CanonicalCiphertext>,
        DataChunk: Sendable & Collection<Plaintext<Scheme, Eval>?>,
    >(
        expandedDim0Query: [Ciphertext<Scheme, Eval>],
        expandedRemainingQuery: ExpandedQueries,
        dataChunk: DataChunk,
        using evaluationKey: EvaluationKey<Scheme>,
        parameter: IndexPirParameter,
        callOptions: CallOptions) async throws -> Ciphertext<Scheme, Coeff>
        where ExpandedQueries.Index == Int, DataChunk.Index == Int
    {
        let perChunkPlaintextCount: Int = parameter.dimensions.product()
        let databaseColumnsCount = perChunkPlaintextCount / parameter.dimensions[0]
        precondition(databaseColumnsCount == 1 || databaseColumnsCount == expandedRemainingQuery.count)

        let columnGroupCount = max(1, min(callOptions.maxConcurrentTasks, databaseColumnsCount))
        let columnChildOptions = callOptions.divided(among: columnGroupCount)

        let computePtCtInnerProduct: @Sendable (Int) async throws -> Scheme.CanonicalCiphertext = { columnIndex in
            let startIndex = dataChunk.startIndex + expandedDim0Query.count * columnIndex
            let endIndex = min(startIndex + expandedDim0Query.count, dataChunk.endIndex)
            let plaintexts = dataChunk[startIndex..<endIndex]
            return try await Scheme.innerProduct(ciphertexts: expandedDim0Query,
                                                 plaintexts: plaintexts,
                                                 maxConcurrentTasks: columnChildOptions.maxConcurrentTasks)
                .convertToCanonicalFormat()
        }

        var intermediateResults: [Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>] = if columnGroupCount > 1 {
            try await Array(0..<databaseColumnsCount).evenlyChunked(in: columnGroupCount)
                .concurrentMap { batch in
                    try await [Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>](batch.async
                        .map { try await computePtCtInnerProduct($0) })
                }.flatMap(\.self)
        } else {
            try await .init((0..<databaseColumnsCount).async.map(computePtCtInnerProduct))
        }

        let computeCtCtInnerProduct: @Sendable (Int, Int, Int, [Scheme.CanonicalCiphertext]) async throws -> Scheme
            .CanonicalCiphertext = { startIndex, currentIndex, dimensionSize, currentResults in
                let vector0 = expandedRemainingQuery[currentIndex..<currentIndex + dimensionSize]
                let vector1 = currentResults[startIndex..<startIndex + dimensionSize]
                var product = try await Scheme.innerProduct(vector0, vector1,
                                                            maxConcurrentTasks: columnChildOptions.maxConcurrentTasks)
                try await product.relinearize(using: evaluationKey)
                return product
            }
        var queryStartingIndex = expandedRemainingQuery.startIndex
        for await dimensionSize in parameter.dimensions.dropFirst().async {
            let currentIndex = queryStartingIndex
            let lastResult = intermediateResults
            let dimItemCount = intermediateResults.count / dimensionSize
            let dimGroupCount = max(1, min(callOptions.maxConcurrentTasks, dimItemCount))
            if dimGroupCount > 1 {
                intermediateResults = try await Array(stride(
                    from: 0,
                    to: intermediateResults.count,
                    by: dimensionSize)).evenlyChunked(in: dimGroupCount)
                    .concurrentMap { batch in
                        try await [Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>](batch.async.map { startIndex in
                            try await computeCtCtInnerProduct(startIndex, currentIndex, dimensionSize, lastResult)
                        })
                    }.flatMap(\.self)
            } else {
                intermediateResults = try await .init(stride(
                    from: 0,
                    to: intermediateResults.count,
                    by: dimensionSize)
                    .async.map { try await computeCtCtInnerProduct($0, currentIndex, dimensionSize, lastResult) })
            }
            queryStartingIndex += dimensionSize
        }

        precondition(intermediateResults.count == 1,
                     "There should be only 1 ciphertext in the final result for each chunk")
        try await intermediateResults[0].modSwitchDownToSingle()
        return try await intermediateResults[0].convertToCoeffFormat()
    }

    /// Default implementation of computeResponse.
    @inlinable
    public static func computeResponse(
        to query: Query<Scheme>,
        using evaluationKey: EvaluationKey<Scheme>,
        databases: [ProcessedDatabase<Scheme>],
        parameter: IndexPirParameter,
        context: Scheme.Context,
        callOptions: CallOptions) async throws -> Response<Scheme>
    {
        guard databases.count == 1 || databases.count >= query.indicesCount else {
            throw PirError.invalidBatchSize(queryCount: query.indicesCount, databaseCount: databases.count)
        }
        let expandedQueries = try await expand(ciphertexts:
            query.ciphertexts,
            outputCount: parameter.expandedQueryCount * query.indicesCount,
            using: evaluationKey,
            callOptions: callOptions)

        let chunkCount = parameter.encodedEntrySize.dividingCeil(context.bytesPerPlaintext, variableTime: true)

        func computeResponse(ciphertextForEachQuery: consuming Deque<Deque<CanonicalCiphertext>>) async throws
            -> [[Ciphertext<Scheme, Coeff>]]
        {
            var enumerated = ciphertextForEachQuery.enumerated()
            let queryCount = ciphertextForEachQuery.count
            let queryGroupCount = max(1, min(callOptions.maxConcurrentTasks, queryCount))
            let queryChildOptions = callOptions.divided(among: queryGroupCount)

            let computeResponseChunk: @Sendable ((Int, Deque<CanonicalCiphertext>)) async throws
                -> [Ciphertext<Scheme, Coeff>] = { enumerated in
                    var (queryIndex, queryCiphertexts) = enumerated
                    let database = databases[databases.count == 1 ? 0 : queryIndex]
                    let dim0Count = parameter.dimensions[0]
                    let dim0GroupCount = max(1, min(queryChildOptions.maxConcurrentTasks, dim0Count))
                    let firstDimensionQueries: [Ciphertext<Scheme, Eval>] = if dim0GroupCount > 1 {
                        try await Array(queryCiphertexts[0..<dim0Count])
                            .evenlyChunked(in: dim0GroupCount)
                            .concurrentMap { batch in
                                try batch.map { try $0.convertToEvalFormat() }
                            }.flatMap(\.self)
                    } else {
                        try await .init(queryCiphertexts[0..<dim0Count].async
                            .map { try $0.convertToEvalFormat() })
                    }
                    queryCiphertexts.removeFirst(parameter.dimensions[0])
                    let perChunkPlaintextCount = database.count / chunkCount
                    let chunkItemCount = database.count / perChunkPlaintextCount
                    let chunkGroupCount = max(1, min(queryChildOptions.maxConcurrentTasks, chunkItemCount))
                    let chunkChildOptions = queryChildOptions.divided(among: chunkGroupCount)
                    let computeRemainingDimensions: @Sendable (Int) async throws -> Ciphertext<Scheme, Coeff> =
                        { [queryCiphertexts, firstDimensionQueries] startIndex in
                            try await Self.computeResponseForOneChunk(
                                expandedDim0Query: firstDimensionQueries,
                                expandedRemainingQuery: queryCiphertexts,
                                dataChunk: database
                                    .plaintexts[startIndex..<startIndex + perChunkPlaintextCount],
                                using: evaluationKey,
                                parameter: parameter,
                                callOptions: chunkChildOptions)
                        }
                    if chunkGroupCount > 1 {
                        return try await Array(stride(from: 0, to: database.count, by: perChunkPlaintextCount))
                            .evenlyChunked(in: chunkGroupCount)
                            .concurrentMap { batch in
                                try await [Ciphertext<Scheme, Coeff>](batch.async
                                    .map { try await computeRemainingDimensions($0) })
                            }.flatMap(\.self)
                    }
                    return try await .init(stride(from: 0, to: database.count, by: perChunkPlaintextCount).async
                        .map(computeRemainingDimensions))
                }
            if queryGroupCount > 1 {
                return try await enumerated.concurrentConsumingMap(computeResponseChunk)
            }
            return try await .init(enumerated.async.map(computeResponseChunk))
        }
        let responseCiphertexts = try await computeResponse(ciphertextForEachQuery:
            expandedQueries.chunk(by: parameter.expandedQueryCount))
        return Response(ciphertexts: responseCiphertexts)
    }

    // swiftlint:enable function_parameter_count
}

public enum PirUtil<Scheme: HeScheme>: PirUtilProtocol {}
