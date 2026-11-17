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

public import Collections
public import DequeModule
public import HomomorphicEncryption
import Foundation
import ModularArithmetic

public protocol MatrixBufferProtocol: Sendable {
    associatedtype Element
    var shape: (rowCount: Int, columnCount: Int) { get }
    func withUnsafeBufferPointer<R>(_ body: (UnsafeBufferPointer<Element>) throws -> R) throws -> R
}

extension MatrixBufferProtocol {
    /// number of rows
    public var rowCount: Int {
        shape.rowCount
    }

    /// number of columns
    public var columnCount: Int {
        shape.columnCount
    }
}

extension Array2d: MatrixBufferProtocol {
    public typealias Element = T

    public func withUnsafeBufferPointer<R>(_ body: (UnsafeBufferPointer<T>) throws -> R) throws -> R {
        try data.withUnsafeBufferPointer(body)
    }
}

extension Array2d where T: ScalarType {
    /// Returns the elements of `buffer` as an array, avoiding a copy when `buffer` is already an ``Array2d``.
    @inlinable
    static func data<Other: MatrixBufferProtocol>(of buffer: Other) throws -> [T] where Other.Element == T {
        if let array = buffer as? Array2d<T> {
            return array.data
        }
        return try buffer.withUnsafeBufferPointer { Array($0) }
    }

    /// Perform matrix multiplication after trasponsing the rhs.
    ///
    /// A mask will be applied to results after an optional offset is applied.
    /// - Parameters:
    ///   - other: Matrix to multiply with, before transposing.
    ///   - mask: Mask applied to each result entry.
    ///   - offset: Optional offset added to the result before masking.
    ///   - maxConcurrentTasks: Maximum number of concurrent tasks to use. When `<= 1`, computes serially.
    /// - Returns: `(self * other^T + offset) & mask`.
    public func multiply<Other: MatrixBufferProtocol>(
        transposing other: Other,
        mask: T,
        offset: Array2d<T>? = nil,
        maxConcurrentTasks: Int = CallOptions.multiThreaded.maxConcurrentTasks) async throws -> Array2d<T>
        where Other.Element == T
    {
        // We are transposing `other` before matmul. Thus we are checking columnCount = other.columnCount, instead of
        // rowCount.
        precondition(
            columnCount == other.columnCount,
            "Matrix multiplication shapes: \(shape) x (\(other.columnCount), \(other.rowCount)")
        let hasOffset = offset != nil
        let offset = offset ?? Array2d()
        if hasOffset {
            precondition(rowCount == offset.rowCount)
            precondition(other.rowCount == offset.columnCount)
        }
        let columnCount = columnCount
        let otherRowCount = other.rowCount
        let selfData = data
        let otherData = try Self.data(of: other)
        let offsetData = offset.data

        return await Array2d.computeInParallel(
            rowCount: rowCount,
            columnCount: otherRowCount,
            maxConcurrentTasks: maxConcurrentTasks)
        { rows, otherRows in
            var result = [T](repeating: .zero, count: rows.count &* otherRows.count)
            var resultIndex = 0
            for row in rows {
                let selfRowOffset = row &* columnCount
                for otherRow in otherRows {
                    let otherRowOffset = otherRow &* columnCount
                    var sum: T = 0
                    for index in 0..<columnCount {
                        sum &+= selfData[selfRowOffset &+ index] &* otherData[otherRowOffset &+ index]
                    }
                    if hasOffset {
                        sum &+= offsetData[row &* otherRowCount &+ otherRow]
                    }
                    result[resultIndex] = sum & mask
                    resultIndex &+= 1
                }
            }
            return result
        }
    }

    /// Perform a modular matrix multiplication after trasponsing the rhs.
    /// - Parameters:
    ///   - other: other matrix to multiply with.
    ///   - modulus: The modulus to use.
    ///   - offset: Optional offset that gets added to the result.
    ///   - maxConcurrentTasks: Maximum number of concurrent tasks to use. When `<= 1`, computes serially.
    /// - Returns: `self * other^T + offset`.
    public func multiply<Other: MatrixBufferProtocol>(
        transposing other: Other,
        modulus: T,
        offset: Array2d<T>? = nil,
        maxConcurrentTasks: Int = CallOptions.multiThreaded.maxConcurrentTasks) async throws -> Array2d<T>
        where Other.Element == T
    {
        // We are transposing `other` before matmul. Thus we are checking columnCount = other.columnCount, instead of
        // rowCount.
        precondition(
            columnCount == other.columnCount,
            "Matrix multiplication shapes: \(shape) x (\(other.columnCount), \(other.rowCount)")
        let hasOffset = offset != nil
        let offset = offset ?? Array2d()
        if hasOffset {
            precondition(rowCount == offset.rowCount)
            precondition(other.rowCount == offset.columnCount)
        }
        let reductionModulus = ReduceModulus(modulus: modulus, bound: .DoubleWord, variableTime: true)
        let maxProductCount = Self.maxLazyProductAccumulationCount(modulus: modulus)
        let columnCount = columnCount
        let otherRowCount = other.rowCount
        let selfData = data
        let otherData = try Self.data(of: other)
        let offsetData = offset.data
        assert(selfData.allSatisfy { $0 < modulus })
        assert(otherData.allSatisfy { $0 < modulus })

        return await Array2d.computeInParallel(
            rowCount: rowCount,
            columnCount: otherRowCount,
            maxConcurrentTasks: maxConcurrentTasks)
        { rows, otherRows in
            var result = [T](repeating: .zero, count: rows.count &* otherRows.count)
            selfData.withUnsafeBufferPointer { selfBuf in
                otherData.withUnsafeBufferPointer { otherBuf in
                    // swiftlint:disable force_unwrapping
                    let selfPtr = selfBuf.baseAddress!
                    let otherPtr = otherBuf.baseAddress!
                    // swiftlint:enable force_unwrapping
                    var resultIndex = 0
                    for row in rows {
                        let selfRowOffset = row &* columnCount
                        for otherRow in otherRows {
                            result[resultIndex] = Self.innerProduct(
                                selfPtr + selfRowOffset,
                                otherPtr + otherRow &* columnCount,
                                count: columnCount,
                                maxProductCount: maxProductCount,
                                modulus: reductionModulus,
                                initialValue: hasOffset ? offsetData[row &* otherRowCount &+ otherRow] : 0)
                            resultIndex &+= 1
                        }
                    }
                }
            }
            return result
        }
    }
}

public enum PrecomputedQueries<Scalar: ScalarType>: SimplePirProtocol {
    public struct WithoutIndices: Sendable {
        @usableFromInline let context: SimplePirContext<Scalar>
        /// The precomputed queries without adding the indice-dependent deltas.
        @usableFromInline let queriesWithoutIndices: Requests
        /// The precomputed decryption results before integrating the response.
        @usableFromInline let resultsWithoutResponse: Responses

        public init<MatrixBuffer: MatrixBufferProtocol>(
            context: SimplePirContext<Scalar>,
            hint: MatrixBuffer,
            aPolynomials: [PolyRq<Scalar, Eval>],
            using rng: inout some PseudoRandomNumberGenerator) async throws where MatrixBuffer.Element == Scalar
        {
            var secretPolys = context.generateSecretPolys()
            var secretMatrix = secretPolys.collect()
            defer {
                // important: secret keys must be zeroized
                for i in secretPolys.indices {
                    secretPolys[i].data.zeroize()
                }
                secretMatrix.zeroize()
            }

            let halfBakedQuery = try await context.encryptZero(
                aPolynomials: aPolynomials,
                secretKeys: secretPolys,
                using: &rng)
            let resultsWithoutResponse = try await secretMatrix.multiply(
                transposing: hint,
                modulus: context.nttFriendlyMod)

            self.init(
                context: context,
                queriesWithoutIndices: halfBakedQuery,
                resultsWithoutResponse: resultsWithoutResponse)
        }

        @inlinable
        init(
            context: SimplePirContext<Scalar>,
            queriesWithoutIndices: Array2d<Scalar>,
            resultsWithoutResponse: Array2d<Scalar>)
        {
            self.context = context
            self.queriesWithoutIndices = queriesWithoutIndices
            self.resultsWithoutResponse = resultsWithoutResponse
        }

        @inlinable
        consuming func add(index: Int) -> WithQueryIndices {
            let subIndices = (0..<context.chunksPerEntry).map { $0 + index * context.chunksPerEntry }
            var queries = queriesWithoutIndices
            let delta = context.delta
            let mask = context.mask
            for (queryIndex, entryIndex) in subIndices.enumerated() {
                let columnIndex = entryIndex / context.entriesPerColumn
                queries[queryIndex, columnIndex] += delta
                queries[queryIndex, columnIndex] &= mask
            }
            return WithQueryIndices(
                context: context,
                queries: queries,
                resultsWithoutResponse: resultsWithoutResponse,
                index: index)
        }
    }

    public struct WithQueryIndices: Sendable {
        @usableFromInline let context: SimplePirContext<Scalar>
        /// The precomputed queries after adding the indice-dependent deltas.
        public let queries: Requests
        /// The precomputed decryption results before integrating the response.
        @usableFromInline let resultsWithoutResponse: Responses
        @usableFromInline let index: Int

        @inlinable
        init(
            context: SimplePirContext<Scalar>,
            queries: Requests,
            resultsWithoutResponse: Responses,
            index: Int)
        {
            self.context = context
            self.queries = queries
            self.resultsWithoutResponse = resultsWithoutResponse
            self.index = index
        }

        @inlinable
        public func prepareResponse() -> WithPreparedResponse {
            WithPreparedResponse(
                context: context,
                resultsWithoutResponse: context.extractEntries(from: resultsWithoutResponse, for: index))
        }
    }

    public struct WithPreparedResponse: Sendable {
        @usableFromInline let context: SimplePirContext<Scalar>
        /// The precomputed decryption results before integrating the response.
        @usableFromInline let resultsWithoutResponse: Responses

        @inlinable
        init(context: SimplePirContext<Scalar>, resultsWithoutResponse: Responses) {
            self.context = context
            self.resultsWithoutResponse = resultsWithoutResponse
        }

        @inlinable
        consuming func integrate(responses: Responses, at index: Int) -> [Scalar] {
            var extractedResponse = context.extractEntries(from: responses, for: index)
            let delta = context.delta
            let mask = context.mask
            for index in extractedResponse.data.indices {
                extractedResponse.data[index] &-= resultsWithoutResponse.data[index]
                extractedResponse.data[index] &+= delta >> 1
                extractedResponse.data[index] &= mask
                extractedResponse.data[index] &>>= context.ciphertextModulusBits - context.plaintextModulusBits
            }
            return extractedResponse.data
        }
    }
}

public protocol QueryGenerator: SimplePirProtocol {
    var context: SimplePirContext<Scalar> { get }
    /// Fetch the next unused Precomputed queries.
    func nextPrecomputedQueries() async throws -> PrecomputedQueries<Scalar>.WithoutIndices
}

public actor DefaultQueryGenerator<Scalar: ScalarType>: QueryGenerator {
    @usableFromInline var unusedRequests: Deque<PrecomputedQueries<Scalar>.WithoutIndices>

    public let context: SimplePirContext<Scalar>
    @usableFromInline let hint: Hint
    @usableFromInline let aPolynomials: [PolyRq<Scalar, Eval>]

    public init(params: SimplePirParameters, hint: Hint) async throws {
        self.context = try .init(params: params)
        self.hint = hint
        self.aPolynomials = try context.generateAPolynomials().map { try $0.convertToEvalFormat() }
        self.unusedRequests = []
        try await addPrecomputedQueries()
    }

    public func addPrecomputedQueries() async throws {
        try await unusedRequests.append(precomputeQueries())
    }

    @inlinable
    func precomputeQueries() async throws -> PrecomputedQueries<Scalar>.WithoutIndices {
        var rng = SystemRandomNumberGenerator()
        return try await PrecomputedQueries<Scalar>.WithoutIndices(
            context: context,
            hint: hint,
            aPolynomials: aPolynomials,
            using: &rng)
    }

    public func nextPrecomputedQueries() async throws -> PrecomputedQueries<Scalar>.WithoutIndices {
        if let precomputed = unusedRequests.popFirst() {
            return precomputed
        }
        return try await precomputeQueries()
    }
}
