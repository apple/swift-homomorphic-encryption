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
    /// Perform matrix multiplication after trasponsing the rhs.
    ///
    /// A mask will be applied to results after an optional offset is applied.
    public func multiply<Other: MatrixBufferProtocol>(
        transposing other: Other,
        mask: T,
        offset: Array2d<T>? = nil) async throws -> Array2d<T> where Other.Element == T
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
        var result: Array2d = .zero(rowCount: rowCount, columnCount: other.rowCount)
        let cpuCount = ProcessInfo.processInfo.processorCount
        let perThreadRowCount = other.rowCount.dividingCeil(cpuCount, variableTime: true)

        try await withThrowingTaskGroup(of: Void.self) { group in
            try result.data.withUnsafeMutableBufferPointer { resultBuf in
                try self.data.withUnsafeBufferPointer { selfBuf in
                    try other.withUnsafeBufferPointer { otherBuf in
                        // swiftlint:disable force_unwrapping
                        let resultPtr = resultBuf.baseAddress!
                        let selfPtr = selfBuf.baseAddress!
                        let otherPtr = otherBuf.baseAddress!
                        // swiftlint:enable force_unwrapping
                        let columnCount = columnCount
                        let otherRowCount = other.rowCount
                        for cpuIndex in 0..<cpuCount {
                            group.addTask { @Sendable in
                                let startRowIndex = cpuIndex &* perThreadRowCount
                                let endRowIndex = min(startRowIndex &+ perThreadRowCount, other.rowCount)
                                if startRowIndex >= endRowIndex {
                                    return
                                }
                                for otherRowIndex in startRowIndex..<endRowIndex {
                                    let offset3 = otherRowIndex &* columnCount
                                    var offset1 = otherRowIndex
                                    var offset2 = 0
                                    for _ in 0..<rowCount {
                                        for index in 0..<columnCount {
                                            let a = selfPtr[offset2 &+ index]
                                            let b = otherPtr[offset3 &+ index]
                                            resultPtr[offset1] &+= a &* b
                                        }
                                        if hasOffset {
                                            resultPtr[offset1] &+= offset.data[offset1]
                                        }
                                        resultPtr[offset1] &= mask
                                        offset1 &+= otherRowCount
                                        offset2 &+= columnCount
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return result
    }

    /// Perform a modular matrix multiplication after trasponsing the rhs.
    /// - Parameters:
    ///   - other: other matrix to multiply with.
    ///   - modulus: The modulus to use.
    ///   - offset: Optional offset that gets added to the result.
    /// - Returns: `self * other^T + offset`.
    public func multiply<Other: MatrixBufferProtocol>(
        transposing other: Other,
        modulus: T,
        offset: Array2d<T>? = nil) async throws -> Array2d<T> where Other.Element == T
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
        var result: Array2d = .zero(rowCount: rowCount, columnCount: other.rowCount)
        let cpuCount = ProcessInfo.processInfo.processorCount
        let perThreadRowCount = other.rowCount.dividingCeil(cpuCount, variableTime: true)

        try await withThrowingTaskGroup(of: Void.self) { group in
            try result.data.withUnsafeMutableBufferPointer { resultBuf in
                // swiftlint:disable:next force_unwrapping
                let resultPtr = resultBuf.baseAddress!
                try self.data.withUnsafeBufferPointer { selfBuf in
                    // swiftlint:disable:next force_unwrapping
                    let selfPtr = selfBuf.baseAddress!
                    try other.withUnsafeBufferPointer { otherBuf in
                        // swiftlint:disable:next force_unwrapping
                        let otherPtr = otherBuf.baseAddress!
                        let columnCount = columnCount
                        let otherRowCount = other.rowCount
                        for cpuIndex in 0..<cpuCount {
                            group.addTask { @Sendable in
                                let startRowIndex = cpuIndex &* perThreadRowCount
                                let endRowIndex = min(startRowIndex &+ perThreadRowCount, other.rowCount)
                                if startRowIndex >= endRowIndex {
                                    return
                                }
                                for otherRowIndex in startRowIndex..<endRowIndex {
                                    let offset3 = otherRowIndex &* columnCount
                                    var offset1 = otherRowIndex
                                    var offset2 = 0
                                    for _ in 0..<rowCount {
                                        var sum: T.DoubleWidth = 0
                                        for index in 0..<columnCount {
                                            let a = selfPtr[offset2 &+ index]
                                            let b = otherPtr[offset3 &+ index]
                                            sum &+= T.DoubleWidth(a.multipliedFullWidth(by: b))
                                        }
                                        if hasOffset {
                                            sum &+= T.DoubleWidth(offset.data[offset1])
                                        }
                                        resultPtr[offset1] = reductionModulus.reduce(sum)
                                        offset1 &+= otherRowCount
                                        offset2 &+= columnCount
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return result
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
