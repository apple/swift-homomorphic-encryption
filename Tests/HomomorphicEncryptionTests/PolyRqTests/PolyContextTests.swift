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

@testable import HomomorphicEncryption
import TestUtilities
import XCTest

final class PolyContextTests: XCTestCase {
    func testError() throws {
        XCTAssertThrowsError(try PolyContext<UInt32>(degree: 2, moduli: []), error: HeError.emptyModulus)
        XCTAssertThrowsError(try PolyContext<UInt32>(degree: 3, moduli: [2, 3, 5]), error: HeError.invalidDegree(3))
        XCTAssertThrowsError(try PolyContext<UInt32>(degree: 4, moduli: [2, 5, 9]), error: HeError.invalidModulus(9))
        XCTAssertThrowsError(
            try PolyContext<UInt32>(degree: 4, moduli: [2, 2, 5]),
            error: HeError.coprimeModuli(moduli: [2, 2]))
        XCTAssertThrowsError(
            try PolyContext<UInt32>(degree: 4, moduli: [2, 4, 5]),
            error: HeError.coprimeModuli(moduli: [2, 4]))

        let largeModulus = UInt32((1 << 31) - 1)
        XCTAssertThrowsError(
            try PolyContext<UInt32>(degree: 4, moduli: [largeModulus]),
            error: HeError.invalidModulus(Int64(largeModulus)))
    }

    func testEquatable() throws {
        let context: PolyContext<UInt32> = try PolyContext(degree: 4, moduli: [2, 3, 5])
        let context2: PolyContext<UInt32> = try PolyContext(degree: 4, moduli: [2, 3, 5])
        XCTAssertEqual(context, context2)
        XCTAssertNotEqual(context, try PolyContext(degree: 8, moduli: [2, 3, 5]))
        XCTAssertNotEqual(context, try PolyContext(degree: 4, moduli: [2, 3, 7]))
    }

    func testInit() throws {
        let context3 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5])
        let context2 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3])
        let context1 = try PolyContext<UInt32>(degree: 4, moduli: [2])

        XCTAssertEqual(context3.moduli, [2, 3, 5])
        XCTAssertEqual(context3.degree, 4)
        XCTAssertEqual(context3.next, context2)
        if let context3Next = context3.next {
            XCTAssertEqual(context3Next.next, context1)
            if let context3NextNext = context3Next.next {
                XCTAssertNil(context3NextNext.next)
            }
        }
    }

    func testQRemainder() throws {
        let contextSmall: PolyContext<UInt32> = try PolyContext(degree: 4, moduli: [2, 3, 5])
        XCTAssertEqual(contextSmall.qRemainder(dividingBy: Modulus(modulus: 11, variableTime: true)), 8)

        let moduli: [UInt32] = [268_435_399, 268_435_367, 268_435_361]
        let contextLarge: PolyContext<UInt32> = try PolyContext(degree: 4, moduli: moduli)
        XCTAssertEqual(contextLarge.qRemainder(dividingBy: Modulus(modulus: 11, variableTime: true)), 3)
        XCTAssertEqual(
            contextLarge.qRemainder(dividingBy: Modulus(modulus: 268_435_461, variableTime: true)),
            267_852_661)
    }

    func testIsParent() throws {
        let context3 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5])
        let context3DifferentDegree = try PolyContext<UInt32>(degree: 8, moduli: [2, 3, 5])
        let context3DifferentModuli = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 7])
        let context3Same = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5])
        let context2 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3])
        let context1 = try PolyContext<UInt32>(degree: 4, moduli: [2])

        XCTAssertFalse(context3.isParent(of: context3))
        XCTAssertFalse(context3.isParent(of: context3Same))
        XCTAssertFalse(context3.isParent(of: context3DifferentDegree))
        XCTAssertFalse(context3.isParent(of: context3DifferentModuli))

        XCTAssertFalse(context3.isParent(of: context3))
        XCTAssertTrue(try context3.isParent(of: XCTUnwrap(context3.next)))
        XCTAssertTrue(context3.isParent(of: context2))
        XCTAssertTrue(try context3.isParent(of: XCTUnwrap(context2.next)))
        XCTAssertTrue(context3.isParent(of: context1))

        XCTAssertFalse(context2.isParent(of: context3))
        XCTAssertFalse(context2.isParent(of: context2))
        XCTAssertTrue(context2.isParent(of: context1))

        XCTAssertFalse(context1.isParent(of: context3))
        XCTAssertFalse(context1.isParent(of: context2))
        XCTAssertFalse(context1.isParent(of: context1))
    }

    func testIsParentOfOrEqual() throws {
        let context3 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5])
        let context3DifferentDegree = try PolyContext<UInt32>(degree: 8, moduli: [2, 3, 5])
        let context3DifferentModuli = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 7])
        let context3Same = try PolyContext<UInt32>(degree: 4, moduli: [2, 3, 5])
        let context2 = try PolyContext<UInt32>(degree: 4, moduli: [2, 3])
        let context1 = try PolyContext<UInt32>(degree: 4, moduli: [2])

        XCTAssertTrue(context3.isParentOfOrEqual(to: context3))
        XCTAssertTrue(context3.isParentOfOrEqual(to: context3Same))
        XCTAssertFalse(context3.isParentOfOrEqual(to: context3DifferentDegree))
        XCTAssertFalse(context3.isParentOfOrEqual(to: context3DifferentModuli))

        XCTAssertTrue(context3.isParentOfOrEqual(to: context3))
        XCTAssertTrue(try context3.isParentOfOrEqual(to: XCTUnwrap(context3.next)))
        XCTAssertTrue(context3.isParentOfOrEqual(to: context2))
        XCTAssertTrue(try context3.isParentOfOrEqual(to: XCTUnwrap(context2.next)))
        XCTAssertTrue(context3.isParentOfOrEqual(to: context1))

        XCTAssertFalse(context2.isParentOfOrEqual(to: context3))
        XCTAssertTrue(context2.isParentOfOrEqual(to: context2))
        XCTAssertTrue(context2.isParentOfOrEqual(to: context1))

        XCTAssertFalse(context1.isParentOfOrEqual(to: context3))
        XCTAssertFalse(context1.isParentOfOrEqual(to: context2))
        XCTAssertTrue(context1.isParentOfOrEqual(to: context1))
    }

    func testMaxLazyProductAccumulationCount() throws {
        do {
            let context = try PolyContext<UInt32>(degree: 4, moduli: [(1 << 27) - 40959, // 134176769
                                                                      (1 << 28) - 65535, // 268369921
                                                                      (1 << 28) - 73727, // 268361729
                ])
            XCTAssertEqual(context.maxLazyProductAccumulationCount(), 256)
        }

        do {
            let context = try PolyContext<UInt64>(degree: 4, moduli: [(1 << 59) + 13313, // 576460752303436801
                                                                      (1 << 59) + 16385, // 576460752303439873
                ])
            XCTAssertEqual(context.maxLazyProductAccumulationCount(), 1023)
        }
    }
}
