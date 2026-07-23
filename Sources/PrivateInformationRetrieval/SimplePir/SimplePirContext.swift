// Copyright 2025-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

public import HomomorphicEncryption
import ModularArithmetic

/// This is like `SimplePirParameters`, but with scalar type fixed.
public struct SimplePirContext<Scalar: ScalarType>: Sendable {
    public let params: SimplePirParameters
    @usableFromInline let nttFriendlyMod: Scalar
    @usableFromInline let regularMod: Scalar
    @usableFromInline let extraContext: PolyContext<Scalar>
    @usableFromInline let plainContext: PolyContext<Scalar>
    @usableFromInline let mask: Scalar
    @usableFromInline let delta: Scalar

    @usableFromInline var latticeDimension: Int {
        params.latticeDimension
    }

    @usableFromInline var databaseColumns: Int {
        params.databaseColumns
    }

    @usableFromInline var chunksPerEntry: Int {
        params.chunksPerEntry
    }

    @usableFromInline var chunkSize: Int {
        params.chunkSize
    }

    @usableFromInline var columnSize: Int {
        params.columnSize
    }

    @usableFromInline var entriesPerColumn: Int {
        params.entriesPerColumn
    }

    @usableFromInline var entrySizeInBytes: Int {
        params.entrySizeInBytes
    }

    @usableFromInline var ciphertextModulusBits: Int {
        params.ciphertextModulusBits
    }

    @usableFromInline var plaintextModulusBits: Int {
        params.plaintextModulusBits
    }

    @usableFromInline var errorStdDev: Double {
        params.errorStdDev
    }

    @usableFromInline var seed: [UInt8] {
        params.seed
    }

    @usableFromInline var aPolyCount: Int {
        params.aPolyCount
    }

    public init(params: SimplePirParameters) throws {
        self.params = params
        self.nttFriendlyMod = try Scalar.generatePrimes(
            significantBitCounts: [params.ciphertextModulusBits + 1],
            preferringSmall: true,
            nttDegree: params.latticeDimension)[0]
        self.regularMod = 1 << params.ciphertextModulusBits
        self.extraContext = try PolyContext(degree: params.latticeDimension, moduli: [nttFriendlyMod])
        self.plainContext = try PolyContext(degree: params.latticeDimension, moduli: [regularMod])
        self.mask = params.encryptionParams.getCiphertextMask()
        self.delta = params.encryptionParams.getDelta()
    }

    @inlinable
    func modSwitch(_ matrix: inout Array2d<Scalar>) throws {
        try matrix.divideAndRound(initialMod: nttFriendlyMod, newMod: regularMod)
    }
}
