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

@testable import PIRGenerateDatabase
import Testing

@Suite
struct PIRGenerateDatabaseTests {
    @Test
    func valueSizeArguments() throws {
        #expect(try #require(ValueSizeArguments(argument: "1")?.range) == 1..<2)
        #expect(try #require(ValueSizeArguments(argument: "1..<10")?.range) == 1..<10)
        #expect(try #require(ValueSizeArguments(argument: "1...10")?.range) == 1..<11)
    }
}
