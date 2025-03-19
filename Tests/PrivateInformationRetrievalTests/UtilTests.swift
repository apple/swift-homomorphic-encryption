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

import Foundation
@testable import PrivateInformationRetrieval
import Testing

@Suite
struct UtilTests {
    @Test
    func utf8OrBase64() throws {
        let utf8 = Array(Data("abc123".utf8))
        #expect(utf8.utf8OrBase64() == "abc123 (utf8)")

        let nonUtf8: [UInt8] = [128]
        #expect(nonUtf8.utf8OrBase64() == Data(nonUtf8).base64EncodedString() + " (base64)")
    }
}
