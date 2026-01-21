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

@usableFromInline
enum VarIntError: Error {
    case overflow
    case truncated
}

/// Variable-width integer
/// https://protobuf.dev/programming-guides/encoding/#varints
@usableFromInline
enum VarInt {
    /// Encode an unsigned integer as a varint
    @inlinable
    static func encode(_ value: some FixedWidthInteger & UnsignedInteger) -> [UInt8] {
        var result: [UInt8] = []
        var value = value
        while value >= 0x80 {
            result.append(UInt8(truncatingIfNeeded: value & 0x7F) | 0x80)
            value >>= 7
        }
        result.append(UInt8(truncatingIfNeeded: value & 0x7F))

        return result
    }

    /// Calculate the number of bytes needed to encode a value as a varint
    /// - Parameter value: The value to calculate encoding size for
    /// - Returns: The number of bytes needed to encode the value
    static func encodedSize(_ value: some FixedWidthInteger & UnsignedInteger) -> Int {
        if value == 0 {
            return 1 // Zero is encoded as a single byte
        }

        // Find how many 7-bit groups are needed
        // Each byte can store 7 bits of data (the 8th bit is the continuation flag)
        let bitsNeeded = value.bitWidth - value.leadingZeroBitCount
        return bitsNeeded.dividingCeil(7, variableTime: true)
    }

    /// Decode a varint from a byte array
    /// Returns (decoded value, number of bytes consumed)
    @inlinable
    static func decode<T: FixedWidthInteger & UnsignedInteger>(_ bytes: some Collection<UInt8>) throws
        -> (decoded: T, bytesConsumed: Int)
    {
        precondition(T.bitWidth <= 64)
        var result: UInt64 = 0
        var shift = 0
        var index = 0

        while index < bytes.count {
            let byte = bytes[bytes.index(bytes.startIndex, offsetBy: index)]
            index += 1

            // Check for overflow (varint can be at most 10 bytes for 64-bit)
            if shift >= 64 {
                throw VarIntError.overflow
            }

            // Add the 7 data bits
            result |= UInt64(byte & 0x7F) << shift

            // If continuation bit is not set, we're done
            if (byte & 0x80) == 0 {
                // Check if the result fits in the target type
                guard let value = T(exactly: result) else {
                    throw VarIntError.overflow
                }
                return (value, index)
            }

            shift += 7
        }

        // Ran out of bytes while continuation bit was set
        throw VarIntError.truncated
    }
}
