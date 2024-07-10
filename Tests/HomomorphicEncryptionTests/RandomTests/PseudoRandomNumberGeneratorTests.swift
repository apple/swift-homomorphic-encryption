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

final class PseudoRandomNumberGeneratorTests: XCTestCase {
    func testRandomNumberGeneratorFill() {
        var rng = TestUtilities.TestRng(counter: 0x8899_AABB_CCDD_EEFF)
        var buffer = [UInt8](repeating: 0, count: 10)
        rng.fill(&buffer)
        XCTAssertEqual(buffer, [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x00, 0xEF])
        XCTAssertEqual(rng.next(), UInt32(0xCCDD_EF01))

        var exactBuffer = [UInt8](repeating: 0, count: 8)
        rng.fill(&exactBuffer)
        XCTAssertEqual(exactBuffer, [0x02, 0xEF, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88])

        exactBuffer = [UInt8](repeating: 0, count: 7)
        rng.fill(&exactBuffer)
        XCTAssertEqual(exactBuffer, [0x03, 0xEF, 0xDD, 0xCC, 0xBB, 0xAA, 0x99])
    }
}
