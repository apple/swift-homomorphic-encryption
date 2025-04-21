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
import ModularArithmetic
import Testing

@Suite
struct PolyContextTests {
    @Test
    func error() throws {
        #expect(throws: HeError.emptyModulus) { try PolyContext<UInt32>(degree: 2, moduli: []) }
        #expect(throws: HeError.invalidDegree(3)) { try PolyContext<UInt32>(degree: 3, moduli: [2, 3, 5]) }
        #expect(throws: HeError.invalidModulus(9)) { try PolyContext<UInt32>(degree: 4, moduli: [2, 5, 9]) }
        #expect(throws: HeError.coprimeModuli(moduli: [2, 2])) {
            try PolyContext<UInt32>(degree: 4, moduli: [2, 2, 5])
        }
        #expect(throws: HeError.coprimeModuli(moduli: [2, 4])) {
            try PolyContext<UInt32>(degree: 4, moduli: [2, 4, 5])
        }

        let largeModulus = UInt32((1 << 31) - 1)
        #expect(throws: HeError.invalidModulus(Int64(largeModulus))) {
            try PolyContext<UInt32>(degree: 4, moduli: [largeModulus])
        }
    }

    @Test
    func equatable() throws {
        let context: PolyContext<UInt32> = try PolyContext(degree: 4, moduli: [2, 3, 5])
        let context2: PolyContext<UInt32> = try PolyContext(degree: 4, moduli: [2, 3, 5])
        #expect(context == context2)
        #expect(try context != PolyContext(degree: 8, moduli: [2, 3, 5]))
        #expect(try context != PolyContext(degree: 4, moduli: [2, 3, 7]))
    }

    @Test
    func testInit() throws {
        let context3 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5])
        let context2 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3])
        let context1 = try PolyContext<UInt32>(degree: 4, moduli: [2])

        #expect(context3.moduli == [2, 3, 5])
        #expect(context3.modulus == Width32<UInt32>(30))
        #expect(context3.degree == 4)
        #expect(context3.next == context2)
        if let context3Next = context3.next {
            #expect(context3Next.next == context1)
            if let context3NextNext = context3Next.next {
                #expect(context3NextNext.next == nil)
            }
        }
    }

    @Test
    func testInitChild() throws {
        let context1 = try PolyContext<UInt32>(degree: 4, moduli: [2])
        let context2 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3])
        let context3 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5], child: context1)

        #expect(context3.moduli == [2, 3, 5])
        #expect(context3.modulus == Width32<UInt32>(30))
        #expect(context3.degree == 4)
        #expect(context3.next == context2)
        if let context3Next = context3.next {
            #expect(context3Next.next == context1)
            if let context3NextNext = context3Next.next {
                #expect(context3NextNext.next == nil)
            }
        }
    }

    @Test
    func initLarge() throws {
        let moduli = try UInt32.generatePrimes(
            significantBitCounts: Array(repeating: 28, count: 40),
            preferringSmall: false)
        var context = try PolyContext<UInt32>(degree: 4, moduli: moduli)
        for moduliCount in (2...moduli.count).reversed() {
            #expect(context.moduli == Array(moduli.prefix(moduliCount)))
            #expect(context.degree == 4)
            if moduliCount * 28 < Width32<UInt32>.bitWidth {
                #expect(context.modulus == context.moduli.product())
            } else {
                #expect(context.modulus == nil)
            }
            if let next = context.next {
                context = next
            } else {
                Issue.record("Missing next")
            }
        }
    }

    @Test
    func qRemainder() throws {
        let contextSmall: PolyContext<UInt32> = try PolyContext(degree: 4, moduli: [2, 3, 5])
        #expect(contextSmall.qRemainder(dividingBy: Modulus(modulus: 11, variableTime: true)) == 8)

        let moduli: [UInt32] = [268_435_399, 268_435_367, 268_435_361]
        let contextLarge: PolyContext<UInt32> = try PolyContext(degree: 4, moduli: moduli)
        #expect(contextLarge.qRemainder(dividingBy: Modulus(modulus: 11, variableTime: true)) == 3)
        #expect(contextLarge.qRemainder(dividingBy: Modulus(modulus: 268_435_461, variableTime: true)) == 267_852_661)
    }

    @Test
    func isParent() throws {
        let context3 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5])
        let context3DifferentDegree = try PolyContext<UInt32>(degree: 8, moduli: [2, 3, 5])
        let context3DifferentModuli = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 7])
        let context3Same = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5])
        let context2 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3])
        let context1 = try PolyContext<UInt32>(degree: 4, moduli: [2])

        #expect(!context3.isParent(of: context3))
        #expect(!context3.isParent(of: context3Same))
        #expect(!context3.isParent(of: context3DifferentDegree))
        #expect(!context3.isParent(of: context3DifferentModuli))

        #expect(!context3.isParent(of: context3))
        #expect(try context3.isParent(of: #require(context3.next)))
        #expect(context3.isParent(of: context2))
        #expect(try context3.isParent(of: #require(context2.next)))
        #expect(context3.isParent(of: context1))

        #expect(!context2.isParent(of: context3))
        #expect(!context2.isParent(of: context2))
        #expect(context2.isParent(of: context1))

        #expect(!context1.isParent(of: context3))
        #expect(!context1.isParent(of: context2))
        #expect(!context1.isParent(of: context1))
    }

    @Test
    func isParentOfOrEqual() throws {
        let context3 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5])
        let context3DifferentDegree = try PolyContext<UInt32>(degree: 8, moduli: [2, 3, 5])
        let context3DifferentModuli = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 7])
        let context3Same = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5])
        let context2 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3])
        let context1 = try PolyContext<UInt32>(degree: 4, moduli: [2])

        #expect(context3.isParentOfOrEqual(to: context3))
        #expect(context3.isParentOfOrEqual(to: context3Same))
        #expect(!context3.isParentOfOrEqual(to: context3DifferentDegree))
        #expect(!context3.isParentOfOrEqual(to: context3DifferentModuli))

        #expect(context3.isParentOfOrEqual(to: context3))
        #expect(try context3.isParentOfOrEqual(to: #require(context3.next)))
        #expect(context3.isParentOfOrEqual(to: context2))
        #expect(try context3.isParentOfOrEqual(to: #require(context2.next)))
        #expect(context3.isParentOfOrEqual(to: context1))

        #expect(!context2.isParentOfOrEqual(to: context3))
        #expect(context2.isParentOfOrEqual(to: context2))
        #expect(context2.isParentOfOrEqual(to: context1))

        #expect(!context1.isParentOfOrEqual(to: context3))
        #expect(!context1.isParentOfOrEqual(to: context2))
        #expect(context1.isParentOfOrEqual(to: context1))
    }

    @Test
    func maxLazyProductAccumulationCount() throws {
        do {
            let context = try PolyContext<UInt32>(degree: 4, moduli: [(1 << 27) - 40959, // 134176769
                                                                      (1 << 28) - 65535, // 268369921
                                                                      (1 << 28) - 73727, // 268361729
                ])
            #expect(context.maxLazyProductAccumulationCount() == 256)
        }

        do {
            let context = try PolyContext<UInt64>(degree: 4, moduli: [(1 << 59) + 13313, // 576460752303436801
                                                                      (1 << 59) + 16385, // 576460752303439873
                ])
            #expect(context.maxLazyProductAccumulationCount() == 1023)
        }
    }
}
