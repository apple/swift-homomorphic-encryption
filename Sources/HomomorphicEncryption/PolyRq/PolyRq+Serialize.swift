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

import Foundation
import ModularArithmetic

extension PolyRq {
    @inlinable
    init<C>(deserialize buffer: C, context: PolyContext<T>, skipLSBs: Int = 0) throws
        where C: Collection,
        C.Element == UInt8,
        C.Index == Int
    {
        self = Self.zero(context: context)
        try load(from: buffer, skipLSBs: skipLSBs)
    }

    @inlinable
    mutating func load<C>(from buffer: C, skipLSBs: Int = 0) throws
        where C: Collection, C.Element == UInt8, C.Index == Int
    {
        var offset = buffer.startIndex
        for (rnsIndex, modulus) in moduli.enumerated() {
            let bitsPerCoeff = modulus.ceilLog2
            let byteCount = CoefficientPacking.coefficientsToBytesByteCount(
                coeffCount: degree,
                bitsPerCoeff: bitsPerCoeff,
                skipLSBs: skipLSBs)

            guard offset &+ byteCount <= buffer.endIndex else {
                let expected = moduli.reduce(0) { total, mod in
                    total &+ CoefficientPacking.coefficientsToBytesByteCount(
                        coeffCount: degree,
                        bitsPerCoeff: mod.ceilLog2,
                        skipLSBs: skipLSBs)
                }
                throw HeError.serializedBufferSizeMismatch(
                    polyContext: context,
                    actual: buffer.count,
                    expected: expected)
            }

            let bytes = buffer[offset..<(offset &+ byteCount)]
            try CoefficientPacking.bytesToCoefficientsInplace(
                bytes: bytes,
                coeffs: &data.data[polyIndices(rnsIndex: rnsIndex)],
                bitsPerCoeff: bitsPerCoeff,
                skipLSBs: skipLSBs)
            offset &+= byteCount
        }
    }

    @inlinable
    func serializationByteCount(skipLSBs: Int = 0) -> Int {
        context.serializationByteCount(skipLSBs: skipLSBs)
    }

    @inlinable
    package func serialize(skipLSBs: Int = 0) -> [UInt8] {
        // safe because we initialize the buffer with correct count
        // swiftlint:disable:next force_try
        try! moduli.enumerated().flatMap { rnsIndex, modulus in
            let bitsPerCoeff = modulus.ceilLog2
            let bytesCount = CoefficientPacking.coefficientsToBytesByteCount(
                coeffCount: degree,
                bitsPerCoeff: bitsPerCoeff,
                skipLSBs: skipLSBs)
            var buffer: [UInt8] = .init(repeating: 0, count: bytesCount)
            try CoefficientPacking.coefficientsToBytesInplace(
                coeffs: data.data[polyIndices(rnsIndex: rnsIndex)],
                bytes: &buffer,
                bitsPerCoeff: bitsPerCoeff,
                skipLSBs: skipLSBs)
            return buffer
        }
    }
}

extension PolyContext {
    @inlinable
    package func serializationByteCount(skipLSBs: Int = 0) -> Int {
        moduli.map { modulus in
            CoefficientPacking.coefficientsToBytesByteCount(
                coeffCount: degree,
                bitsPerCoeff: modulus.ceilLog2,
                skipLSBs: skipLSBs)
        }.sum()
    }
}
