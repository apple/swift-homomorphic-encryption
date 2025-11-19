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

public import Foundation

@usableFromInline
enum Serialize {}

extension Serialize {
    @inlinable
    static func serializePolysBufferSize(polyCount: Int, context: PolyContext<some ScalarType>,
                                         skipLSBs: [Int] = []) -> Int
    {
        let skipLSBs = skipLSBs.isEmpty ? .init(repeating: 0, count: polyCount) : skipLSBs
        return skipLSBs.map { context.serializationByteCount(skipLSBs: $0) }
            .sum() + MemoryLayout<UInt16>.size
    }

    @inlinable
    static func serializePolys<C, T>(
        _ polys: some Collection<PolyRq<T, some Any>>,
        to buffer: inout C,
        context: PolyContext<T>,
        skipLSBs: [Int] = []) throws
        where C: MutableCollection,
        C.Element == UInt8,
        C.Index == Int
    {
        let skipLSBs = skipLSBs.isEmpty ? .init(repeating: 0, count: polys.count) : skipLSBs
        guard buffer.count >= MemoryLayout<UInt16>.size else {
            let expectedBufferSize = serializePolysBufferSize(
                polyCount: polys.count,
                context: context,
                skipLSBs: skipLSBs)
            throw HeError.serializationBufferSizeMismatch(
                polyContext: context,
                actual: buffer.count,
                expected: expectedBufferSize)
        }
        var offset = buffer.startIndex
        let polyCount = UInt16(polys.count)
        buffer[offset] = UInt8(truncatingIfNeeded: polyCount)
        buffer.formIndex(after: &offset)
        buffer[offset] = UInt8(truncatingIfNeeded: polyCount >> UInt8.bitWidth)
        buffer.formIndex(after: &offset)

        let serialized = zip(polys, skipLSBs).flatMap { poly, skipLSBs in
            poly.serialize(skipLSBs: skipLSBs)
        }
        _ = serialized.withUnsafeBytes { srcBuffer in
            buffer[offset...].withContiguousMutableStorageIfAvailable { dstBuffer in
                // safe because we know the addresses are not nil
                // swiftlint:disable:next force_unwrapping
                memcpy(dstBuffer.baseAddress!, srcBuffer.baseAddress!, serialized.count)
            }
        }
    }

    @inlinable
    static func deserializePolys<C, T, F>(from buffer: C,
                                          context: PolyContext<T>,
                                          skipLSBs: [Int] = []) throws -> [PolyRq<T, F>]
        where C: Collection, C.Element == UInt8, C.Index == Int
    {
        guard buffer.count >= MemoryLayout<UInt16>.size else {
            throw HeError.serializationBufferSizeMismatch(polyContext: context, actual: buffer.count, expected: 2)
        }
        var offset = buffer.startIndex
        var polyCountU16: UInt16 = 0

        polyCountU16 |= UInt16(buffer[offset])
        buffer.formIndex(after: &offset)
        polyCountU16 |= (UInt16(buffer[offset]) << UInt8.bitWidth)
        buffer.formIndex(after: &offset)

        let polyCount = Int(polyCountU16)
        let skipLSBs = skipLSBs.isEmpty ? .init(repeating: 0, count: polyCount) : skipLSBs
        var polys: [PolyRq<T, F>] = .init(repeating: PolyRq<T, F>.zero(context: context), count: polyCount)
        for index in polys.indices {
            try polys[index].load(from: buffer[offset...], skipLSBs: skipLSBs[index])
            offset += context.serializationByteCount(skipLSBs: skipLSBs[index])
        }
        return polys
    }
}
