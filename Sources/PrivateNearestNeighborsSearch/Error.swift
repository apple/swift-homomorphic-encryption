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

import Foundation
import HomomorphicEncryption

/// Error type for ``PrivateNearestNeighborsSearch``.
enum PNNSError: Error, Equatable {
    case emptyPlaintextArray
    case invalidMatrixDimensions(_ dimensions: MatrixDimensions)
    case simdEncodingNotSupported(_ description: String)
    case wrongContext(gotDescription: String, expectedDescription: String)
    case wrongEncodingValuesCount(got: Int, expected: Int)
    case wrongPlaintextCount(got: Int, expected: Int)
    case wrongPlaintextMatrixPacking(
        got: PlaintextMatrixPacking,
        expected: PlaintextMatrixPacking)
}

extension PNNSError {
    @inlinable
    static func simdEncodingNotSupported(for encryptionParameters: EncryptionParameters<some HeScheme>) -> Self {
        .simdEncodingNotSupported(encryptionParameters.description)
    }

    @inlinable
    static func wrongContext(got: Context<some HeScheme>, expected: Context<some HeScheme>) -> Self {
        PNNSError.wrongContext(gotDescription: got.description, expectedDescription: expected.description)
    }
}

extension PNNSError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .emptyPlaintextArray:
            "Empty plaintext array"
        case let .invalidMatrixDimensions(dimensions):
            "Invalid matrix dimensions: rowCount \(dimensions.rowCount), columnCount \(dimensions.columnCount)"
        case let .simdEncodingNotSupported(encryptionParameters):
            "SIMD encoding is not supported for encryption parameters \(encryptionParameters)"
        case let .wrongContext(gotDescription, expectedDescription):
            "Wrong context: got \(gotDescription), expected \(expectedDescription)"
        case let .wrongEncodingValuesCount(got, expected):
            "Wrong encoding values count \(got), expected \(expected)"
        case let .wrongPlaintextCount(got, expected):
            "Wrong plaintext count \(got), expected \(expected)"
        case let .wrongPlaintextMatrixPacking(got: got, expected: expected):
            "Wrong plaintext matrix packing \(got), expected \(expected)"
        }
    }
}
