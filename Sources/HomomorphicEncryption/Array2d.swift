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

/// Stores values in a 2 dimensional array.
public struct Array2d<T: Equatable & AdditiveArithmetic & Sendable>: Equatable, Sendable {
    /// Values stored in row-major order.
    @usableFromInline package var data: [T]
    @usableFromInline package var rowCount: Int
    @usableFromInline package var columnCount: Int

    /// The row and column counts.
    public var shape: (rowCount: Int, columnCount: Int) { (rowCount: rowCount, columnCount: columnCount) }
    /// The number of entries in the array.
    public var count: Int { rowCount * columnCount }

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

    /// Provides scoped access to the underlying buffer storing the array's data.
    ///
    /// Use this method when you need temporary read-only access to the array's contiguous storage.
    /// The buffer pointer is only valid for the duration of the closure's execution.
    ///
    /// - Parameter body: A closure that takes an `UnsafeBufferPointer` to the array's data.
    ///   The buffer pointer argument is valid only for the duration of the closure's execution.
    /// - Returns: The return value of the `body` closure.
    /// - Throws: Rethrows any error thrown by the `body` closure.
    public func withUnsafeData<Return>(_ body: (UnsafeBufferPointer<T>) throws -> Return) rethrows -> Return {
        try data.withUnsafeBufferPointer { pointer in
            try body(pointer)
        }
    }

    /// Provides scoped access to the underlying buffer storing the array's data for mutation.
    ///
    /// Use this method when you need temporary read-write access to the array's contiguous storage.
    /// The buffer pointer is only valid for the duration of the closure's execution.
    ///
    /// - Parameter body: A closure that takes an `UnsafeMutableBufferPointer` to the array's data.
    ///   The buffer pointer argument is valid only for the duration of the closure's execution.
    /// - Returns: The return value of the `body` closure.
    /// - Throws: Rethrows any error thrown by the `body` closure.
    public mutating func withUnsafeMutableData<Return>(_ body: (UnsafeMutableBufferPointer<T>) throws
        -> Return) rethrows -> Return
    {
        try data.withUnsafeMutableBufferPointer { pointer in
            try body(pointer)
        }
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

    // Sets all the data to zero. This is useful for clearing sensitive data.
    @inlinable
    mutating func zeroize() {
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
