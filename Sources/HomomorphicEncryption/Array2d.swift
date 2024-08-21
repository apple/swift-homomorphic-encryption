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

/// Stores values in a 2 dimensional array.
public struct Array2d<T: Equatable & AdditiveArithmetic & Sendable>: Equatable, Sendable {
    @usableFromInline package var data: [T]
    @usableFromInline package var rowCount: Int
    @usableFromInline package var columnCount: Int

    @usableFromInline package var shape: (Int, Int) { (rowCount, columnCount) }
    @usableFromInline package var count: Int { rowCount * columnCount }

    @inlinable
    package init(data: [T], rowCount: Int, columnCount: Int) {
        precondition(data.count == rowCount * columnCount)
        self.data = data
        self.rowCount = rowCount
        self.columnCount = columnCount
    }

    @inlinable
    init(array: Array2d<some FixedWidthInteger>) where T: FixedWidthInteger {
        self.columnCount = array.columnCount
        self.rowCount = array.rowCount
        self.data = array.data.map { T($0) }
    }

    @inlinable
    package static func zero(rowCount: Int, columnCount: Int) -> Self {
        self.init(
            data: [T](Array(repeating: T.zero, count: rowCount * columnCount)),
            rowCount: rowCount,
            columnCount: columnCount)
    }
}

extension Array2d {
    @inlinable
    package func index(row: Int, column: Int) -> Int {
        row &* columnCount &+ column
    }

    @inlinable
    package func rowIndices(row: Int) -> Range<Int> {
        index(row: row, column: 0)..<index(row: row, column: columnCount)
    }

    @inlinable
    package func columnIndices(column: Int) -> StrideTo<Int> {
        stride(from: index(row: 0, column: column), to: index(row: rowCount, column: column), by: columnCount)
    }

    @inlinable
    package func row(row: Int) -> [T] {
        Array(data[rowIndices(row: row)])
    }

    /// Gathers array values into an array.
    /// - Parameter indices: Indices whose values to gather.
    /// - Returns: The values of the array in order of the given indices.
    @inlinable
    public func collectValues(indices: any Sequence<Int>) -> [T] {
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
    package subscript(_ index: Int) -> T {
        get {
            data[index]
        }
        set {
            data[index] = newValue
        }
    }

    @inlinable
    package subscript(_ row: Int, _ column: Int) -> T {
        get {
            data[index(row: row, column: column)]
        }
        set {
            data[index(row: row, column: column)] = newValue
        }
    }
}

extension Array2d {
    // rotate every `range` elements left by `step` elements
    @inlinable
    mutating func rotate(range: Int, step: Int) throws {
        guard columnCount.isMultiple(of: range) else {
            throw HeError.invalidRotationParameter(range: range, columnCount: data.count)
        }

        let effectiveStep = step.toRemainder(range)
        for index in stride(from: 0, to: data.count, by: range) {
            let replacement = data[index + effectiveStep..<index + range] + data[index..<index + effectiveStep]
            data.replaceSubrange(index..<index + range, with: replacement)
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
    mutating func removeLastRows(_ k: Int) {
        precondition(k >= 0 && k <= rowCount)
        rowCount -= k
        data.removeLast(columnCount * k)
    }

    /// Appends extra rows to the array.
    /// - Parameter rows: The row-major elements to append. Must have count dividing `columnCount`.
    @inlinable
    mutating func append(rows: [T]) {
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
}
