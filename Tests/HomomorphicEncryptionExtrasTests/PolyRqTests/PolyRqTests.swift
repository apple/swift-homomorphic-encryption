// Copyright 2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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

import _HomomorphicEncryptionExtras
import HomomorphicEncryption
import Testing

@Suite
struct PolyRqTests {
    @Test
    func removeLastModuli() async throws {
        let context: PolyContext<UInt32> = try PolyContext(degree: 4, moduli: [2, 3, 5])
        let data: [UInt32] = [0, 1, 0, 1,
                              0, 1, 2, 0,
                              0, 1, 2, 3]
        var poly = PolyRq<_, Coeff>(
            context: context,
            data: Array2d(data: data, rowCount: 3, columnCount: 4))
        #expect(poly.moduli == [2, 3, 5])
        try poly.removeLastModuli(1)
        #expect(poly.moduli == [2, 3])
        try poly.removeLastModuli(1)
        #expect(poly.moduli == [2])
    }
}
