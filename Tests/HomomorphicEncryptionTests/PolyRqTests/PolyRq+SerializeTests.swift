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

import _TestUtilities
@testable import HomomorphicEncryption
import Testing

@Suite
struct PolyRqSerializeTests {
    @Test
    func serializationErrOnWrongBuffer() throws {
        let primes = try UInt32.generatePrimes(significantBitCounts: [5, 5, 5], preferringSmall: false)
        let context = try PolyContext(degree: 32, moduli: primes)
        let poly: PolyRq<UInt32, Coeff> = PolyRq.random(context: context)
        let bytes = poly.serialize()

        let wrongPrimes = try UInt32.generatePrimes(significantBitCounts: [5, 5, 16], preferringSmall: false)
        let wrongContext = try PolyContext(degree: 32, moduli: wrongPrimes)

        #expect(throws: HeError.serializedBufferSizeMismatch(
            polyContext: wrongContext,
            actual: bytes.count,
            expected: 104))
        {
            try PolyRq<UInt32, Coeff>(deserialize: bytes, context: wrongContext)
        }
    }

    @Test
    func roundtrip() throws {
        func runTest<T: ScalarType>(_: T.Type) throws {
            func runTestWithFormat<F: PolyFormat>(context: PolyContext<T>, _: F.Type) throws {
                let poly: PolyRq<_, F> = PolyRq.random(context: context)
                let bytes = poly.serialize()
                let deserialized: PolyRq<_, F> = try PolyRq(deserialize: bytes, context: context)
                #expect(deserialized == poly)
            }

            let primes = try T.generatePrimes(significantBitCounts: [14, 16, 21, 22, 27], preferringSmall: false)
            let context = try PolyContext(degree: 32, moduli: primes)

            try runTestWithFormat(context: context, Coeff.self)
            try runTestWithFormat(context: context, Eval.self)
        }

        try runTest(UInt32.self)
        try runTest(UInt64.self)
    }

    @Test
    func roundtripKAT() throws {
        struct SerializePolyKAT {
            let poly: [UInt64]
            let moduli: [UInt64]
            let skipLSBs: Int
            let expectedPoly: [UInt64]
        }

        let kats = [
            SerializePolyKAT(
                poly: [1, 2, 3, 4, 6, 7, 8, 9],
                moduli: [521, 541],
                skipLSBs: 0,
                expectedPoly: [1, 2, 3, 4, 6, 7, 8, 9]),
            SerializePolyKAT(
                poly: [1, 2, 3, 4],
                moduli: [521],
                skipLSBs: 1,
                expectedPoly: [0, 2, 2, 4]),
            SerializePolyKAT(
                poly: [1, 21, 302, 417],
                moduli: [521],
                skipLSBs: 2,
                expectedPoly: [0, 20, 300, 416]),
        ]

        for kat in kats {
            let degree = kat.poly.count / kat.moduli.count
            let context = try PolyContext(degree: degree, moduli: kat.moduli)
            let poly: PolyRq<_, Coeff> = PolyRq(
                context: context,
                data: Array2d(data: kat.poly, rowCount: kat.moduli.count, columnCount: degree))
            let expectedPoly: PolyRq<_, Coeff> = PolyRq(
                context: context,
                data: Array2d(data: kat.expectedPoly, rowCount: kat.moduli.count, columnCount: degree))

            let bytes = poly.serialize(skipLSBs: kat.skipLSBs)
            let deserialized: PolyRq<_, Coeff> = try PolyRq(
                deserialize: bytes,
                context: context,
                skipLSBs: kat.skipLSBs)
            #expect(deserialized == expectedPoly)
        }
    }

    @Test
    func roundtripInplace() throws {
        func runTest<T: ScalarType>(_: T.Type) throws {
            func runTestWithFormat<F: PolyFormat>(context: PolyContext<T>, _: F.Type) throws {
                let poly1: PolyRq<_, F> = PolyRq.random(context: context)
                let poly2: PolyRq<_, F> = PolyRq.random(context: context)
                let byteCount = context.serializationByteCount()
                let byteBuffer = poly2.serialize() + poly1.serialize()
                #expect(byteBuffer.count == 2 * byteCount)
                let deserialized1: PolyRq<_, F> = try PolyRq(deserialize: byteBuffer[byteCount...], context: context)
                let deserialized2: PolyRq<_, F> = try PolyRq(deserialize: byteBuffer, context: context)
                #expect(deserialized1 == poly1)
                #expect(deserialized2 == poly2)
                var loadPoly1: PolyRq<_, F> = PolyRq.zero(context: context)
                var loadPoly2: PolyRq<_, F> = PolyRq.zero(context: context)
                try loadPoly1.load(from: byteBuffer[byteCount...])
                try loadPoly2.load(from: byteBuffer)
                #expect(loadPoly1 == poly1)
                #expect(loadPoly2 == poly2)
            }

            let primes = try T.generatePrimes(significantBitCounts: [14, 16, 21, 22, 27], preferringSmall: false)
            let context = try PolyContext(degree: 32, moduli: primes)

            try runTestWithFormat(context: context, Coeff.self)
            try runTestWithFormat(context: context, Eval.self)
        }

        try runTest(UInt32.self)
        try runTest(UInt64.self)
    }
}
