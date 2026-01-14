// Copyright 2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

import Foundation
@testable import PrivateInformationRetrieval
import Testing

@Suite
struct VarIntTests {
    // Basic roundtrip test with parameterized input
    @Test(arguments: [0, 1, 127, 128, 150, 16383, 16384, UInt64.max])
    func roundtrip(value: UInt64) throws {
        let encoded = VarInt.encode(value)
        #expect(encoded.count == VarInt.encodedSize(value))
        let (decoded, bytesConsumed): (UInt64, Int) = try VarInt.decode(encoded)
        #expect(decoded == value)
        #expect(bytesConsumed == encoded.count)
    }

    // Test known encodings for specific values
    @Test
    func knownEncodings() {
        // Single-byte values
        #expect(VarInt.encode(UInt8(0)) == [0x00])
        #expect(VarInt.encode(UInt8(1)) == [0x01])
        #expect(VarInt.encode(UInt8(127)) == [0x7F])

        // Multi-byte values
        #expect(VarInt.encode(UInt8(128)) == [0x80, 0x01])
        #expect(VarInt.encode(UInt16(150)) == [0x96, 0x01]) // 0x96 = 150 | 0x80
        #expect(VarInt.encode(UInt32(16383)) == [0xFF, 0x7F])
        #expect(VarInt.encode(UInt64(16384)) == [0x80, 0x80, 0x01])
    }

    // Test decoding known encodings
    @Test
    func decodeKnownEncodings() throws {
        // Single-byte values
        var (value, consumed): (UInt64, Int) = try VarInt.decode([0x00])
        #expect(value == 0)
        #expect(consumed == 1)

        (value, consumed) = try VarInt.decode([0x01])
        #expect(value == 1)
        #expect(consumed == 1)

        (value, consumed) = try VarInt.decode([0x7F])
        #expect(value == 127)
        #expect(consumed == 1)

        // Multi-byte values
        (value, consumed) = try VarInt.decode([0x80, 0x01])
        #expect(value == 128)
        #expect(consumed == 2)

        (value, consumed) = try VarInt.decode([0x96, 0x01])
        #expect(value == 150)
        #expect(consumed == 2)

        (value, consumed) = try VarInt.decode([0xFF, 0x7F])
        #expect(value == 16383)
        #expect(consumed == 2)

        (value, consumed) = try VarInt.decode([0x80, 0x80, 0x01])
        #expect(value == 16384)
        #expect(consumed == 3)
    }

    // Test error cases
    @Test
    func truncatedInput() throws {
        // Truncated input (continuation bit set but no more bytes)
        #expect(throws: VarIntError.truncated) {
            let _: (UInt64, Int) = try VarInt.decode([0x80])
        }

        #expect(throws: VarIntError.truncated) {
            let _: (UInt64, Int) = try VarInt.decode([0x80, 0x80])
        }
    }

    @Test
    func testOverflow() throws {
        // Create a varint that would overflow UInt64
        // 10 bytes with continuation bit set + 1 more byte
        var bytes: [UInt8] = Array(repeating: 0xFF, count: 9) // 9 bytes with all bits set
        bytes.append(0xFF) // 10th byte with all bits set
        bytes.append(0x01) // 11th byte that would cause overflow

        #expect(throws: VarIntError.overflow) {
            let _: (UInt64, Int) = try VarInt.decode(bytes)
        }
    }

    // Test decoding to different integer types
    @Test
    func decodeToVariousTypes() throws {
        // Test UInt8
        let encoded128 = VarInt.encode(UInt8(128))
        let (valueUInt8, consumedUInt8): (UInt8, Int) = try VarInt.decode(encoded128)
        #expect(valueUInt8 == 128)
        #expect(consumedUInt8 == 2)

        // Test UInt16
        let encoded1000 = VarInt.encode(UInt16(1000))
        let (valueUInt16, consumedUInt16): (UInt16, Int) = try VarInt.decode(encoded1000)
        #expect(valueUInt16 == 1000)
        #expect(consumedUInt16 == 2)

        // Test UInt32
        let encoded100000 = VarInt.encode(UInt32(100_000))
        let (valueUInt32, consumedUInt32): (UInt32, Int) = try VarInt.decode(encoded100000)
        #expect(valueUInt32 == 100_000)
        #expect(consumedUInt32 == 3)

        // Test UInt
        let encoded50000 = VarInt.encode(UInt32(50000))
        let (valueUInt, consumedUInt): (UInt, Int) = try VarInt.decode(encoded50000)
        #expect(valueUInt == 50000)
        #expect(consumedUInt == 3)
    }

    // Test overflow when decoding to smaller integer types
    @Test
    func typeSpecificOverflow() throws {
        // Create a varint for a value that fits in UInt16 but not UInt8
        let encoded300 = VarInt.encode(UInt16(300))

        // Should work for UInt16
        let (valueUInt16, _): (UInt16, Int) = try VarInt.decode(encoded300)
        #expect(valueUInt16 == 300)

        // Should throw overflow for UInt8
        #expect(throws: VarIntError.overflow) {
            let _: (UInt8, Int) = try VarInt.decode(encoded300)
        }
    }
}
