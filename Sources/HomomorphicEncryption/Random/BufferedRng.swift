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

/// Wrapper for random number generator that adds a buffer.
public final class BufferedRng<R: PseudoRandomNumberGenerator> {
    /// Random number generator.
    @usableFromInline var rng: R
    /// Offset into ``buffer``, pointing to the next unused random byte.
    @usableFromInline var offset: Int
    /// Buffer of random bytes.
    @usableFromInline let buffer: UnsafeMutableRawBufferPointer
    /// Number of random bytes that have been generated but not used.
    @usableFromInline var remaining: Int {
        buffer.count &- offset
    }

    /// Initializes a ``BufferedRng``.
    /// - Parameters:
    ///   - rng: Random number generator.
    ///   - bufferCount: Number of bytes in the buffer.
    public init(rng: R, bufferCount: Int) {
        self.rng = rng
        self.offset = bufferCount
        self.buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: bufferCount, alignment: 16)
    }

    deinit {
        buffer.deallocate()
    }
}

extension BufferedRng: PseudoRandomNumberGenerator {
    /// Fills a buffer with random values.
    /// - Parameter bufferPointer: Buffer to fill.
    @inlinable
    public func fill(_ bufferPointer: UnsafeMutableRawBufferPointer) {
        var filled = 0
        while filled < bufferPointer.count {
            if remaining == 0 {
                rng.fill(buffer)
                offset = 0
            }

            let sliceEnd = min(filled &+ remaining, bufferPointer.endIndex)
            let sliceToBeFilled = UnsafeMutableRawBufferPointer(rebasing: bufferPointer[filled..<sliceEnd])

            let bufferSliceEnd = offset &+ sliceToBeFilled.count
            let bufferSlice = UnsafeRawBufferPointer(rebasing: buffer[offset..<bufferSliceEnd])
            sliceToBeFilled.copyMemory(from: bufferSlice)
            offset &+= sliceToBeFilled.count
            filled &+= sliceToBeFilled.count
        }
    }
}
