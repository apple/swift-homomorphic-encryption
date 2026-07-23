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

public import ModularArithmetic
import Foundation

/// Stores values in a 2 dimensional array.
public struct Array2d<T: Equatable & AdditiveArithmetic & Sendable>: Equatable, Sendable {
    /// Values stored in row-major order.
    @usableFromInline package var data: [T]
    @usableFromInline package var rowCount: Int
    @usableFromInline package var columnCount: Int

    /// The row and column counts.
    public var shape: (rowCount: Int, columnCount: Int) {
        (rowCount: rowCount, columnCount: columnCount)
    }

    /// The number of entries in the array.
    public var count: Int {
        rowCount * columnCount
    }

    /// Creates a new ``Array2d``.
    /// - Parameter data: Row-major entries of the array. Each row must have the same number of entries.
    @inlinable
    public init(data: [[T]] = []) {
        if data.isEmpty {
            self.init(data: [], rowCount: 0, columnCount: 0)
        } else {
            let flatData = data.flatMap(\.self)
            if flatData.isEmpty {
                self.init(data: [], rowCount: 0, columnCount: 0)
            } else {
                self.init(data: flatData, rowCount: data.count, columnCount: data[0].count)
            }
        }
    }

    /// Creates a new ``Array2d``.
    /// - Parameters:
    ///   - data: Row-major entries of the array. Must have `rowCount * columnCount` entries.
    ///   - rowCount: Number of rows. Must be non-negative.
    ///   - columnCount: Number of columns. Must be non-negative.
    @inlinable
    public init(data: [T], rowCount: Int, columnCount: Int) {
        precondition(data.count == rowCount * columnCount, "Wrong data count \(data.count)")
        precondition(rowCount >= 0 && columnCount >= 0)
        self.data = data
        self.rowCount = rowCount
        self.columnCount = columnCount
    }

    /// Creates a new ``Array2d`` from an existing array.
    /// - Parameter array: Existing array; must have entry type representable by `T`.
    @inlinable
    public init(array: Array2d<some FixedWidthInteger>) where T: FixedWidthInteger {
        self.columnCount = array.columnCount
        self.rowCount = array.rowCount
        self.data = array.data.map { T($0) }
    }

    /// Creates a new array of zeros.
    /// - Parameters:
    ///   - rowCount: Number of rows.
    ///   - columnCount: Number of columns.
    /// - Returns: The array of zeros.
    @inlinable
    public static func zero(rowCount: Int, columnCount: Int) -> Self {
        self.init(
            data: [T](Array(repeating: T.zero, count: rowCount * columnCount)),
            rowCount: rowCount,
            columnCount: columnCount)
    }

    /// Provides scoped access to the underlying buffer storing the array's data using a Span.
    ///
    /// Use this method when you need temporary read-only access to the array's contiguous storage.
    ///
    /// - Parameter body: A closure that takes a `Span<T>` to the array's data.
    /// - Returns: The return value of the `body` closure.
    /// - Throws: Rethrows any error thrown by the `body` closure.
    @inlinable
    public func withDataSpan<Return>(_ body: (Span<T>) throws -> Return) rethrows -> Return {
        try body(data.span)
    }

    /// Provides scoped access to the underlying buffer storing the array's data for mutation.
    ///
    /// Use this method when you need temporary read-write access to the array's contiguous storage.
    ///
    /// - Parameter body: A closure that takes a `MutableSpan<T>` to the array's data.
    /// - Returns: The return value of the `body` closure.
    /// - Throws: Rethrows any error thrown by the `body` closure.
    @inlinable
    public mutating func withMutableDataSpan<Return>(_ body: (inout MutableSpan<T>) throws -> Return) rethrows
        -> Return
    {
        var span = data.mutableSpan
        return try body(&span)
    }
}

extension Array2d {
    @inlinable
    func index(row: Int, column: Int) -> Int {
        row &* columnCount &+ column
    }

    @inlinable
    func rowIndices(row: Int) -> Range<Int> {
        index(row: row, column: 0)..<index(row: row, column: columnCount)
    }

    @inlinable
    func columnIndices(column: Int) -> StrideTo<Int> {
        stride(from: index(row: 0, column: column), to: index(row: rowCount, column: column), by: columnCount)
    }

    /// Returns the entries in the row.
    /// - Parameter row: Index of the row. Must be in `[0, rowCount)`.
    /// - Returns: The entries in the row.
    @inlinable
    public func row(_ row: Int) -> [T] {
        Array(data[rowIndices(row: row)])
    }

    /// Gathers array values into an array.
    /// - Parameter indices: Indices whose values to gather.
    /// - Returns: The values of the array in order of the given indices.
    @inlinable
    func collectValues(indices: any Sequence<Int>) -> [T] {
        indices.map { data[$0] }
    }

    /// Transposes the values.
    /// - Returns: The transposed values.
    @inlinable
    public func transposed() -> Self {
        var transposed = Self(
            data: Array(repeating: T.zero, count: count),
            rowCount: columnCount,
            columnCount: rowCount)
        for row in 0..<rowCount {
            for column in 0..<columnCount {
                transposed[column, row] = self[row, column]
            }
        }
        return transposed
    }

    @inlinable
    subscript(_ index: Int) -> T {
        get {
            data[index]
        }
        set {
            data[index] = newValue
        }
    }

    /// Access for the `(row, column)` entry.
    /// - Parameters:
    ///     - `row`: Must be in `[0, rowCount)`
    ///     - `column`: Must be in `[0, columnCount)`
    @inlinable
    public subscript(_ row: Int, _ column: Int) -> T {
        get {
            data[index(row: row, column: column)]
        }
        set {
            data[index(row: row, column: column)] = newValue
        }
    }
}

extension Array2d {
    /// Rotate columns.
    /// - Parameter step: Negative step indicates a left rotation. Positive step indicates a right rotation.
    /// - Warning: L:eaks `step` through timing.
    @inlinable
    mutating func rotateColumns(by step: Int) throws {
        let effectiveStep = step.toRemainder(columnCount, variableTime: true)
        if effectiveStep == 0 {
            return
        }
        if effectiveStep < 0 {
            for index in stride(from: 0, to: data.count, by: columnCount) {
                let replacement = data[index - effectiveStep..<index + columnCount] +
                    data[index..<index - effectiveStep]
                data.replaceSubrange(index..<index + columnCount, with: replacement)
            }
        } else {
            for index in stride(from: 0, to: data.count, by: columnCount) {
                let cutoff = index + columnCount - effectiveStep
                let replacement = data[cutoff..<index + columnCount] + data[index..<cutoff]
                data.replaceSubrange(index..<index + columnCount, with: replacement)
            }
        }
    }

    @inlinable
    mutating func resizeColumn(newColumnCount: Int) where T: AdditiveArithmetic {
        resizeColumn(newColumnCount: newColumnCount, defaultValue: T.zero)
    }

    @inlinable
    mutating func resizeColumn(newColumnCount: Int, defaultValue: T) {
        var newData = [T]()
        let newSize = rowCount * newColumnCount
        newData.reserveCapacity(newSize)
        for i in stride(from: 0, to: rowCount * columnCount, by: columnCount) {
            newData.append(contentsOf: data[i..<i + min(columnCount, newColumnCount)])
            if newColumnCount > columnCount {
                newData.append(contentsOf: Array(repeating: defaultValue, count: newColumnCount - columnCount))
            }
        }
        data = newData
        columnCount = newColumnCount
    }

    /// Drops the last `k` rows of the array.
    /// - Parameter k: The number of rows to remove. `k` Must be greater than or equal to zero and must not exceed
    /// `rowCount`.
    @inlinable
    package mutating func removeLastRows(_ k: Int) {
        precondition(k >= 0 && k <= rowCount)
        rowCount -= k
        data.removeLast(columnCount * k)
    }

    /// Appends extra rows to the array.
    /// - Parameter rows: The row-major elements to append. Must have count dividing `columnCount`.
    @inlinable
    package mutating func append(rows: [T]) {
        let (newRowCount, leftover) = rows.count.quotientAndRemainder(dividingBy: columnCount)
        precondition(leftover == 0)
        data.append(contentsOf: rows)
        rowCount += newRowCount
    }

    /// Sets all the data to zero. This is useful for clearing sensitive data.
    @inlinable
    package mutating func zeroize() {
        let zeroizeSize = data.count * MemoryLayout<T>.size
        data.withUnsafeMutableBytes { dataPointer in
            // swiftlint:disable:next force_unwrapping
            HomomorphicEncryption.zeroize(dataPointer.baseAddress!, zeroizeSize)
        }
    }

    /// Returns the matrix after transforming each entry with a function.
    /// - Parameter transform: A mapping closure. `transform` accepts an element of the array as its parameter and
    /// returns a transformed value of the same or of a different type.
    /// - Returns: The transformed matrix.
    @inlinable
    public func map<V: Equatable & AdditiveArithmetic & Sendable>(_ transform: (T) -> (V)) -> Array2d<V> {
        Array2d<V>(
            data: data.map { value in transform(value) },
            rowCount: rowCount,
            columnCount: columnCount)
    }
}

extension UnsafePointer: @unchecked @retroactive Sendable {}
extension UnsafeMutablePointer: @unchecked @retroactive Sendable {}

extension Array2d where T: FixedWidthInteger {
    @inlinable
    static func >>= (lhs: inout Array2d<T>, _ shiftingBits: Int) {
        lhs.data.indices.forEach { lhs.data[$0] >>= shiftingBits }
    }

    @inlinable
    package static func += (_ lhs: inout Array2d<T>, _ rhs: Array2d<T>) {
        lhs.data.indices.forEach { lhs.data[$0] &+= rhs.data[$0] }
    }

    @inlinable
    package static func &= (_ lhs: inout Self, _ rhs: T) {
        lhs.data.indices.forEach { lhs.data[$0] &= rhs }
    }

    @inlinable
    package func transposed() async -> Array2d<T> {
        var transposed: Array2d<T> = .zero(rowCount: columnCount, columnCount: rowCount)
        await withTaskGroup(of: Void.self) { group in
            transposed.data.withUnsafeMutableBufferPointer { buffer in
                // swiftlint:disable:next force_unwrapping
                let bufferPointer = buffer.baseAddress!
                let sourceData = self.data
                let sourceColumnCount = self.columnCount
                let sourceRowCount = self.rowCount
                for rowIndex in 0..<rowCount {
                    group.addTask { @Sendable in
                        let offset = rowIndex &* sourceColumnCount
                        for columnIndex in 0..<sourceColumnCount {
                            bufferPointer[columnIndex &* sourceRowCount &+ rowIndex] = sourceData[offset &+ columnIndex]
                        }
                    }
                }
            }
        }
        return transposed
    }

    @inlinable
    func multiply(_ other: Array2d<T>) -> Array2d<T> {
        precondition(columnCount == other.rowCount, "Matrix multiplication shapes: \(shape) x \(other.shape)")

        var result: Array2d = .zero(rowCount: rowCount, columnCount: other.columnCount)

        for i in 0..<rowCount {
            for j in 0..<other.columnCount {
                for k in 0..<columnCount {
                    result[i, j] &+= self[i, k] &* other[k, j]
                }
            }
        }
        return result
    }

    @inlinable
    package func multiply(_ other: Array2d<T>) async -> Array2d<T> {
        precondition(columnCount == other.rowCount, "Matrix multiplication shapes: \(shape) x \(other.shape)")

        var result: Array2d = .zero(rowCount: rowCount, columnCount: other.columnCount)

        // Transposing first will greatly improve memory access pattern
        let transposedOther = await other.transposed()

        await withTaskGroup(of: Void.self) { group in
            result.data.withUnsafeMutableBufferPointer { resultBuf in
                // swiftlint:disable:next force_unwrapping
                let resultPtr = resultBuf.baseAddress!
                self.data.withUnsafeBufferPointer { selfBuf in
                    // swiftlint:disable:next force_unwrapping
                    let selfPtr = selfBuf.baseAddress!
                    transposedOther.data.withUnsafeBufferPointer { otherBuf in
                        // swiftlint:disable:next force_unwrapping
                        let otherPtr = otherBuf.baseAddress!
                        let selfColumnCount = self.columnCount
                        let otherColumnCount = other.columnCount
                        let otherRowCount = other.rowCount
                        for rowIndex in 0..<rowCount {
                            group.addTask { @Sendable in
                                let aRowOffset = rowIndex &* selfColumnCount
                                let cRowOffset = rowIndex &* otherColumnCount
                                for j in 0..<otherColumnCount {
                                    var sum: T = 0
                                    let bRowOffset = j &* otherRowCount
                                    for k in 0..<otherRowCount {
                                        let aVal = selfPtr[aRowOffset &+ k]
                                        let bVal = otherPtr[bRowOffset &+ k]
                                        sum &+= aVal &* bVal
                                    }
                                    resultPtr[cRowOffset &+ j] = sum
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

extension Array2d where T: ScalarType {
    @inlinable
    package mutating func randomCenteredBinomialDistribution(
        standardDeviation: Double,
        mod moduli: [T],
        using rng: inout some PseudoRandomNumberGenerator)
    {
        precondition(moduli.count == rowCount)
        // figure out n based on the noise std dev.
        // variance = npq, p = q = 0.5
        // n = variance / pq
        // n = 4 * variance
        // let k = n / 2
        // k = 2 * variance
        let variance = standardDeviation * standardDeviation
        let k = Int((2 * variance).rounded(.up))
        let numberOfUint64sPerTrial = 2 * k.dividingCeil(UInt64.bitWidth, variableTime: true)
        var trialBits = [UInt64](repeating: 0, count: numberOfUint64sPerTrial)

        let half = numberOfUint64sPerTrial >> 1
        let mask = if !k.isMultiple(of: UInt64.bitWidth) {
            (UInt64(1) << (k % UInt64.bitWidth)) - 1
        } else {
            // do not mask any bits, if 64 divides k
            UInt64.max
        }
        for columnIndex in 0..<columnCount {
            // fill trial bits
            trialBits.indices.forEach { trialBits[$0] = rng.next() }
            // mask off unneeded bits
            trialBits[half - 1] &= mask
            trialBits[numberOfUint64sPerTrial - 1] &= mask

            // count positive bits
            let positiveCount = trialBits[..<half].reduce(0) { partialResult, trial in
                partialResult + trial.nonzeroBitCount
            }

            // count negative bits
            let negativeCount = trialBits[half...].reduce(0) { partialResult, trial in
                partialResult + trial.nonzeroBitCount
            }

            let pos = T(positiveCount)
            let neg = T(negativeCount)
            for (index, modulus) in zip(columnIndices(column: columnIndex), moduli) {
                data[index] = pos.subtractMod(neg, modulus: modulus)
            }
        }
    }
}

extension Array2d where T: ScalarType {
    @inlinable
    package func multiply(_ other: Array2d<T>, modulus: T) async -> Array2d<T> {
        precondition(columnCount == other.rowCount, "Matrix multiplication shapes: \(shape) x \(other.shape)")

        let reductionModulus = ReduceModulus(modulus: modulus, bound: .DoubleWord, variableTime: true)
        var result: Array2d = .zero(rowCount: rowCount, columnCount: other.columnCount)

        // Transposing first will greatly improve memory access pattern
        let transposedOther = await other.transposed()

        await withTaskGroup(of: Void.self) { group in
            result.data.withUnsafeMutableBufferPointer { resultBuf in
                self.data.withUnsafeBufferPointer { selfBuf in
                    transposedOther.data.withUnsafeBufferPointer { otherBuf in
                        // swiftlint:disable force_unwrapping
                        let resultPtr = resultBuf.baseAddress!
                        let selfPtr = selfBuf.baseAddress!
                        let otherPtr = otherBuf.baseAddress!
                        // swiftlint:enable force_unwrapping
                        let selfColumnCount = self.columnCount
                        let otherColumnCount = other.columnCount
                        let otherRowCount = other.rowCount
                        for rowIndex in 0..<rowCount {
                            group.addTask { @Sendable in
                                let aRowOffset = rowIndex &* selfColumnCount
                                let cRowOffset = rowIndex &* otherColumnCount
                                for j in 0..<otherColumnCount {
                                    var sum: T.DoubleWidth = 0
                                    let bRowOffset = j &* otherRowCount
                                    for k in 0..<otherRowCount {
                                        let aVal = selfPtr[aRowOffset &+ k]
                                        let bVal = otherPtr[bRowOffset &+ k]
                                        sum &+= T.DoubleWidth(aVal.multipliedFullWidth(by: bVal))
                                    }
                                    resultPtr[cRowOffset &+ j] = reductionModulus.reduce(sum)
                                }
                            }
                        }
                    }
                }
            }
        }
        return result
    }

    /// Performs modulus switching with rounding from `initialMod` to `newMod`.
    ///
    /// For each element `x`, computes: `floor((x * newMod + initialMod/2) / initialMod) mod newMod`
    ///
    /// This implementation uses constant-time division to avoid timing side-channels.
    ///
    /// - Parameters:
    ///   - initialMod: The current modulus. Must be greater than 0.
    ///   - newMod: The new modulus. Must be greater than 0.
    /// - Throws: Error if modulus parameters are invalid.
    /// - Warning: The moduli themselves may be leaked through timing, but the data values are protected.
    public mutating func divideAndRound(initialMod: T, newMod: T) throws {
        // Use DoubleWidth arithmetic to avoid overflow during multiplication
        let initialModDiv2 = T.DoubleWidth(initialMod >> 1)
        let newModDW = T.DoubleWidth(newMod)

        // Use ReduceModulus for efficient constant-time reduction modulo newMod
        let reduceMod = ReduceModulus(modulus: newMod, bound: .DoubleWord, variableTime: true)

        // Create a DivisionModulus for constant-time division by initialMod
        let divisionMod = DivisionModulus(modulus: initialMod)

        for i in data.indices {
            // Convert value to DoubleWidth to prevent overflow
            let value = T.DoubleWidth(data[i])

            // Compute: (value * newMod + initialMod/2)
            let product = value * newModDW
            let sum = product + initialModDiv2

            // Perform constant-time division by initialMod
            let divided = divisionMod.dividingFloor(dividend: sum)

            // Reduce the result modulo newMod
            data[i] = reduceMod.reduce(divided)
        }
    }
}

extension Array2d {
    /// The size in bytes of the serialized representation of this array.
    ///
    /// Matches the format used by the `save(to:)` and `init(from:)` methods.
    public var serializationSize: Int {
        MemoryLayout<UInt32>.size + // rowCount
            MemoryLayout<UInt32>.size + // columnCount
            data.count * MemoryLayout<T>.size // data
    }
}

extension Sequence {
    /// Collects elements from a sequence of polynomials into an Array2d.
    ///
    /// Each polynomial contributes a row to the resulting Array2d. The polynomials must all have the same context
    /// and degree.
    /// - Returns: An Array2d where each row contains the polynomial data from one element in the sequence.
    @inlinable
    public func collect<Scalar: ScalarType>() -> Array2d<Scalar> where Element == PolyRq<Scalar, Coeff> {
        let polys = Array(self)
        guard let first = polys.first else {
            return Array2d<Scalar>(data: [], rowCount: 0, columnCount: 0)
        }

        // Each polynomial has data in Array2d format with shape (rnsCount, degree)
        // We want to collect all polynomial data row by row
        let totalRows = polys.count * first.data.rowCount
        let columnCount = first.data.columnCount

        var allData: [Scalar] = []
        allData.reserveCapacity(totalRows * columnCount)

        for poly in polys {
            allData.append(contentsOf: poly.data.data)
        }

        return Array2d<Scalar>(data: allData, rowCount: totalRows, columnCount: columnCount)
    }
}
