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

@testable import HomomorphicEncryption
import Testing

@Suite
struct Array2dTests {
    @Test
    func testInit() {
        func runTest<T: FixedWidthInteger & Sendable>(_: T.Type) {
            let data = [T](1...6)
            let array = Array2d(data: data, rowCount: 3, columnCount: 2)

            let data2d: [[T]] = [[1, 2], [3, 4], [5, 6]]
            #expect(array == Array2d(data: data2d))

            #expect(Array2d<T>(data: []).shape == (rowCount: 0, columnCount: 0))
            #expect(Array2d<T>(data: [[]]).shape == (rowCount: 0, columnCount: 0))
        }

        runTest(Int.self)
        runTest(Int32.self)
        runTest(Int32.self)
        runTest(Int64.self)
        runTest(UInt64.self)
        runTest(UInt128.self)
    }

    @Test
    func zeroAndZeroize() {
        func runTest<T: FixedWidthInteger & Sendable>(_: T.Type) {
            let data = [T](1...16)
            var array = Array2d(data: data, rowCount: 2, columnCount: 8)
            array.zeroize()

            let zero = Array2d(
                data: [T](repeating: 0, count: 16),
                rowCount: 2,
                columnCount: 8)
            #expect(array == zero)
            #expect(array == Array2d.zero(rowCount: 2, columnCount: 8))
        }
        runTest(Int.self)
        runTest(Int32.self)
        runTest(Int32.self)
        runTest(Int64.self)
        runTest(UInt64.self)
        runTest(UInt128.self)
    }

    @Test
    func shape() {
        let data = [Int](0..<16)
        let array = Array2d(data: data, rowCount: 2, columnCount: 8)
        #expect(array.shape == (rowCount: 2, columnCount: 8))
    }

    @Test
    func indices4x4() {
        let data = [Int](0..<16)
        let array = Array2d(data: data, rowCount: 4, columnCount: 4)

        #expect(array.collectValues(indices: array.rowIndices(row: 0)) == [0, 1, 2, 3])
        #expect(array.collectValues(indices: array.columnIndices(column: 0)) == [0, 4, 8, 12])
    }

    @Test
    func indices2x8() {
        let data = [Int](0..<16)
        let array = Array2d(data: data, rowCount: 2, columnCount: 8)

        #expect(array.collectValues(indices: array.rowIndices(row: 0)) == [0, 1, 2, 3, 4, 5, 6, 7])
        #expect(array.collectValues(indices: array.columnIndices(column: 0)) == [0, 8])
        #expect(array.collectValues(indices: array.columnIndices(column: 7)) == [7, 15])
    }

    @Test
    func transposed() {
        let data = [Int](0..<16)
        let array = Array2d(data: data, rowCount: 2, columnCount: 8)
        let transposed = array.transposed()

        #expect(array.shape == (2, 8))
        #expect(transposed.shape == (8, 2))

        #expect(transposed.collectValues(indices: transposed.rowIndices(row: 0)) == [0, 8])
        #expect(transposed.collectValues(indices: transposed.rowIndices(row: 7)) == [7, 15])
        #expect(transposed.collectValues(indices: transposed.columnIndices(column: 0)) == [0, 1, 2, 3, 4, 5, 6, 7])
        #expect(
            transposed.collectValues(indices: transposed.columnIndices(column: 1)) ==
                [8, 9, 10, 11, 12, 13, 14, 15])
    }

    @Test
    func resizeColumn() {
        var array = Array2d(data: [Int](0..<6), rowCount: 2, columnCount: 3)

        array.resizeColumn(newColumnCount: 5, defaultValue: 99)
        let newData: [Int] = [0, 1, 2, 99, 99, 3, 4, 5, 99, 99]
        #expect(array == Array2d(data: newData, rowCount: 2, columnCount: 5))

        array.resizeColumn(newColumnCount: 3)
        #expect(array == Array2d(data: [Int](0..<6), rowCount: 2, columnCount: 3))
    }

    @Test
    func removeLastRows() {
        let data = [Int](0..<32)
        var array = Array2d(data: data, rowCount: 4, columnCount: 8)

        array.removeLastRows(2)
        #expect(array == Array2d(data: [Int](0..<16), rowCount: 2, columnCount: 8))

        array.removeLastRows(1)
        #expect(array == Array2d(data: [Int](0..<8), rowCount: 1, columnCount: 8))

        array.removeLastRows(1)
        #expect(array == Array2d(data: [], rowCount: 0, columnCount: 8))
    }

    @Test
    func appendRows() {
        let data = [Int](0..<32)
        var array = Array2d(data: data, rowCount: 4, columnCount: 8)
        array.append(rows: [])
        #expect(array == Array2d(data: data, rowCount: 4, columnCount: 8))

        array.append(rows: [32, 33, 34, 35, 36, 37, 38, 39])
        #expect(array == Array2d(data: [Int](0..<40), rowCount: 5, columnCount: 8))

        array.append(rows: Array(40..<56))
        #expect(array == Array2d(data: [Int](0..<56), rowCount: 7, columnCount: 8))
    }

    @Test
    func map() {
        let data = [Int](0..<32)
        let array = Array2d(data: data, rowCount: 4, columnCount: 8)

        let arrayPlus1 = array.map { UInt($0) + 1 }
        let expected = Array2d(data: [UInt](1..<33), rowCount: 4, columnCount: 8)
        #expect(arrayPlus1 == expected)

        let roundtripArray = arrayPlus1.map { Int($0 - 1) }
        #expect(roundtripArray == array)
    }

    @Test
    func withUnsafeData() {
        let data = [Int](0..<32)
        let array = Array2d(data: data, rowCount: 4, columnCount: 8)
        array.withUnsafeData { dataPointer in
            array.data.withUnsafeBufferPointer { expectedDataPointer in
                #expect(dataPointer.baseAddress == expectedDataPointer.baseAddress)
            }
        }
    }

    @Test
    func withUnsafeMutableData() throws {
        let data = [Int](0..<32)
        var array = Array2d(data: data, rowCount: 4, columnCount: 8)
        // For the comparison we need 'mutable' pointers of the same type.
        // But, `withUnsafe*` methods need exclusive ownership of the pointer.
        let expectedBaseAddress = try #require(
            array.data.withUnsafeMutableBufferPointer { buffer in
                buffer.baseAddress
            },
            "Expected a valid base address")
        array.withUnsafeMutableData { dataPointer in
            #expect(dataPointer.baseAddress == expectedBaseAddress)
        }
    }
}
