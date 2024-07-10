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

/// Protocol for a pseudo random number genearator (PRNG).
public protocol PseudoRandomNumberGenerator {
    /// Fills a buffer with random values.
    /// - Parameter bufferPointer: Buffer to fill.
    @inlinable
    mutating func fill(_ bufferPointer: UnsafeMutableRawBufferPointer)
}

extension PseudoRandomNumberGenerator {
    /// Fills a buffer with random values.
    /// - Parameter buffer: Buffer to fill.
    @inlinable
    public mutating func fill(_ buffer: inout [UInt8]) {
        buffer.withUnsafeMutableBytes { bufferPointer in
            self.fill(bufferPointer)
        }
    }

    /// Computes the next generated random number.
    /// - Returns: The next generated random number.
    @inlinable
    @inline(__always)
    public mutating func next<T: FixedWidthInteger>() -> T {
        var r = T.zero
        withUnsafeMutableBytes(of: &r) { bufferPointer in
            self.fill(bufferPointer)
        }
        return r
    }

    /// Fills an array with random values.
    /// - Parameter array: Array to fill.
    @inlinable
    public mutating func fill(_ array: inout [some FixedWidthInteger]) {
        array.withUnsafeMutableBytes { bufferPointer in
            self.fill(bufferPointer)
        }
    }

    /// Fills an `ArraySlice` with random values.
    /// - Parameter slice: Slice to fill
    @inlinable
    public mutating func fill(_ slice: inout ArraySlice<some FixedWidthInteger>) {
        slice.withUnsafeMutableBytes { bufferPointer in
            self.fill(bufferPointer)
        }
    }
}

extension RandomNumberGenerator {
    /// Fills a buffer with random values.
    /// - Parameter bufferPointer: Buffer to fill.
    @inlinable
    public mutating func fill(_ bufferPointer: UnsafeMutableRawBufferPointer) {
        let size = MemoryLayout<UInt64>.size
        for i in stride(from: bufferPointer.startIndex, through: bufferPointer.endIndex &- size, by: size) {
            var random = next()
            withUnsafeBytes(of: &random) { randomBufferPointer in
                let rebased = UnsafeMutableRawBufferPointer(rebasing: bufferPointer[i..<(i &+ size)])
                rebased.copyMemory(from: randomBufferPointer)
            }
        }

        var remainingSlice = bufferPointer.suffix(from: (bufferPointer.count / size) * size)
        if !remainingSlice.isEmpty {
            var random = next()
            withUnsafeBytes(of: &random) { randomBufferPointer in
                for (sliceIndex, randomIndex) in zip(remainingSlice.indices, randomBufferPointer.indices) {
                    remainingSlice[sliceIndex] = randomBufferPointer[randomIndex]
                }
            }
        }
    }
}

extension SystemRandomNumberGenerator: PseudoRandomNumberGenerator {}
