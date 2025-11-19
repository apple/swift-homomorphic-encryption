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
import HomomorphicEncryption
import Testing

@Suite
struct ClientTests {
    @Test
    func clientConfig() throws {
        try PrivateNearestNeighborSearchUtil.ClientTests.clientConfig(for: NoOpScheme.self)
        try PrivateNearestNeighborSearchUtil.ClientTests.clientConfig(for: Bfv<UInt32>.self)
        try PrivateNearestNeighborSearchUtil.ClientTests.clientConfig(for: Bfv<UInt64>.self)
    }

    @Test
    func normalizeRowsAndScale() throws {
        try PrivateNearestNeighborSearchUtil.ClientTests.normalizeRowsAndScale()
    }

    @Test
    func queryAsResponse() throws {
        try PrivateNearestNeighborSearchUtil.ClientTests.queryAsResponse(for: NoOpScheme.self)
        try PrivateNearestNeighborSearchUtil.ClientTests.queryAsResponse(for: Bfv<UInt32>.self)
        try PrivateNearestNeighborSearchUtil.ClientTests.queryAsResponse(for: Bfv<UInt64>.self)
    }

    @Test
    func clientServer() async throws {
        try await PrivateNearestNeighborSearchUtil.ClientTests.clientServer(for: Bfv<UInt32>.self)
        try await PrivateNearestNeighborSearchUtil.ClientTests.clientServer(for: Bfv<UInt64>.self)
    }
}
