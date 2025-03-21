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
struct PlaintextMatrixTests {
    @Test
    func matrixDimensions() throws {
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.matrixDimensions()
    }

    @Test
    func plaintextMatrixError() throws {
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixError(for: Bfv<UInt32>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixError(for: Bfv<UInt64>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixError(for: NoOpScheme.self)
    }

    @Test
    func plaintextMatrixDenseRowError() throws {
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDenseRowError(for: Bfv<UInt32>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDenseRowError(for: Bfv<UInt64>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDenseRowError(for: NoOpScheme.self)
    }

    @Test
    func plaintextMatrixDenseColumn() throws {
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDenseColumn(for: Bfv<UInt32>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDenseColumn(for: Bfv<UInt64>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDenseColumn(for: NoOpScheme.self)
    }

    @Test
    func plaintextMatrixDenseRow() throws {
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDenseRow(for: Bfv<UInt32>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDenseRow(for: Bfv<UInt64>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDenseRow(for: NoOpScheme.self)
    }

    @Test
    func plaintextMatrixDiagonal() throws {
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDiagonal(for: Bfv<UInt32>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDiagonal(for: Bfv<UInt64>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixDiagonal(for: NoOpScheme.self)
    }

    @Test
    func diagonalRotation() throws {
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.diagonalRotation(for: Bfv<UInt32>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.diagonalRotation(for: Bfv<UInt64>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.diagonalRotation(for: NoOpScheme.self)
    }

    @Test
    func plaintextMatrixConversion() throws {
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixConversion(for: Bfv<UInt32>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixConversion(for: Bfv<UInt64>.self)
        try PrivateNearestNeighborSearchUtil.PlaintextMatrixTests.plaintextMatrixConversion(for: NoOpScheme.self)
    }
}
