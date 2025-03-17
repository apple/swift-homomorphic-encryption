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
struct BufferedRngTests {
    private struct TestRng: PseudoRandomNumberGenerator {
        var counter: UInt8 = 0

        mutating func fill(_ bufferPointer: UnsafeMutableRawBufferPointer) {
            for i in bufferPointer.indices {
                bufferPointer[i] = counter
                counter += 1
            }
        }
    }

    @Test
    func fill() {
        var bufferedRng = BufferedRng(rng: TestRng(), bufferCount: 2)

        var data = [UInt8](repeating: 0, count: 7)
        bufferedRng.fill(&data[0..<3])

        #expect(data == [0, 1, 2, 0, 0, 0, 0])
        #expect(bufferedRng.offset == 1)
        #expect(bufferedRng.remaining == 1)
        #expect(bufferedRng.array == [2, 3])

        bufferedRng.fill(&data[...])
        #expect(data == [3, 4, 5, 6, 7, 8, 9])
        #expect(bufferedRng.offset == 2)
        #expect(bufferedRng.remaining == 0)
        #expect(bufferedRng.array == [8, 9])
    }

    @Test
    func nextFixedWidthInteger() {
        var bufferedRng = BufferedRng(rng: TestRng(), bufferCount: 32)

        #expect(bufferedRng.next() == UInt8(0))
        #expect(bufferedRng.next() == UInt16(2 << 8 | 1))
        #expect(bufferedRng.next() == UInt32(6 << 24 | 5 << 16 | 4 << 8 | 3))
        let _: UInt64 = bufferedRng.next()
        #expect(bufferedRng.next() == UInt8(15))
    }

    @Test
    func fixedWidthFill() {
        var bufferedRng = BufferedRng(rng: TestRng(), bufferCount: 32)
        var buffer = [UInt16](repeating: 0, count: 3)
        bufferedRng.fill(&buffer[...])
        #expect(buffer == [256, 770, 1284])
    }
}

extension BufferedRng {
    var array: [UInt8] {
        [UInt8](buffer)
    }
}
