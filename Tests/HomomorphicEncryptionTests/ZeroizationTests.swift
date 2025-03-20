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
struct ZeroizationTests {
    @Test
    func zeroize() {
        var buffer = [UInt32](1...10)
        let size = 5 * MemoryLayout<UInt32>.size
        buffer.withUnsafeMutableBytes { dataPointer in
            // swiftlint:disable:next force_unwrapping
            HomomorphicEncryption.zeroize(dataPointer.baseAddress!, size)
        }
        #expect(buffer == [0, 0, 0, 0, 0, 6, 7, 8, 9, 10])
    }
}
