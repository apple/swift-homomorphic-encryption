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

import _TestUtilities
import HomomorphicEncryption
@testable import PrivateInformationRetrieval
import Testing

struct SimplePirTests {
    @Test
    func encryptDecryptRoundTripSmallEntry() async throws {
        try await SimplePirTestsUtils.runEncryptDecryptRoundTripTest(plaintextBits: 7,
                                                                     ciphertextBits: 28,
                                                                     entryCount: 600,
                                                                     entrySize: 20,
                                                                     SimplePirServer<UInt32>.self)
        try await SimplePirTestsUtils.runEncryptDecryptRoundTripTest(plaintextBits: 14,
                                                                     ciphertextBits: 42,
                                                                     entryCount: 600,
                                                                     entrySize: 20,
                                                                     SimplePirServer<UInt64>.self)
    }

    @Test
    func encryptDecryptRoundTripLargeEntry() async throws {
        try await SimplePirTestsUtils.runEncryptDecryptRoundTripTest(plaintextBits: 7,
                                                                     ciphertextBits: 28,
                                                                     entryCount: 20,
                                                                     entrySize: 600,
                                                                     SimplePirServer<UInt32>.self)
        try await SimplePirTestsUtils.runEncryptDecryptRoundTripTest(plaintextBits: 14,
                                                                     ciphertextBits: 42,
                                                                     entryCount: 20,
                                                                     entrySize: 600,
                                                                     SimplePirServer<UInt64>.self)
    }

    @Test
    func databaseSerialization() throws {
        try SimplePirTestsUtils.testSimplePirDatabaseSerialization(rowCount: 10, columnCount: 20, UInt32.self)
        try SimplePirTestsUtils.testSimplePirDatabaseSerialization(rowCount: 8000, columnCount: 8000, UInt32.self)
        try SimplePirTestsUtils.testSimplePirDatabaseSerialization(rowCount: 10, columnCount: 20, UInt64.self)
    }

    @Test
    func databaseCorruptedData() throws {
        try SimplePirTestsUtils.testSimplePirDatabaseCorruptedData(rowCount: 10, columnCount: 20, UInt32.self)
        try SimplePirTestsUtils.testSimplePirDatabaseCorruptedData(rowCount: 10, columnCount: 20, UInt64.self)
    }

    @Test
    func simplePirFlow() async throws {
        try await SimplePirTestsUtils.testSimplePirFlowWithSharding(rowCount: 1000,
                                                                    entrySize: 50,
                                                                    chunkSize: 15,
                                                                    shardCount: 2)
    }

    @Test
    func simplePirFlowWithShardingOutOfBounds() async throws {
        try await SimplePirTestsUtils.testSimplePirFlowWithShardingOutOfBounds(rowCount: 1000,
                                                                               entrySize: 50,
                                                                               chunkSize: 15,
                                                                               shardCount: 2)
    }

    @Test(.disabled("Run manually to verify constant time behavior"))
    func simplePirFlowWithShardingTimingSideChannel() async throws {
        try await SimplePirTestsUtils.testSimplePirFlowWithShardingTimingSideChannel(rowCount: 1000,
                                                                                     entrySize: 90,
                                                                                     chunkSize: 15,
                                                                                     shardCount: 6)
    }

    @Test
    func shardMapTest() {
        let entryCount = 1000
        let entrySizeRange = 100..<1000

        var rng = SystemRandomNumberGenerator()

        let entries = (0..<entryCount).map { _ in
            let size = Int.random(in: entrySizeRange)
            var entry = [UInt8](repeating: 0, count: size)
            rng.fill(&entry)
            return entry
        }

        let entriesWithIndices = entries.lazy.enumerated().map { offset, entry in
            (originalIndex: offset, value: entry)
        }

        let shardCount = 5
        let chunkSize = 256

        let (databaseMap, _) = DatabaseMap.shardDatabase(
            entries: entriesWithIndices,
            shardCount: shardCount,
            chunkSize: chunkSize)
        let mapping = ShardMap(databaseMap: databaseMap)
        #expect(mapping.shardCount == shardCount)
        #expect(mapping.chunkSize == chunkSize)
        #expect(mapping.maximumChunkCount == entrySizeRange.upperBound.dividingCeil(chunkSize, variableTime: true))
        #expect(mapping.mapping.count == entryCount)
    }

    @Test
    func ternarySecretKeyMapsCorrectlyAfterModSwitch() throws {
        let seed = [UInt8](repeating: 0, count: 32)
        let context = try SimplePirContext<UInt64>(
            params: .init(
                encryptionParams: .init(
                    plaintextModulusBits: 5,
                    ciphertextModulusBits: 42,
                    latticeDimension: 2048,
                    errorStdDev: .stdDev64),
                entrySizeInBytes: 1,
                entriesPerColumn: 1,
                chunksPerEntry: 1,
                databaseColumns: 5,
                seed: seed))
        var secretKeys = context.generateSecretPolys().collect()
        try context.modSwitch(&secretKeys)
        let uniqueCoeffs = Set(secretKeys.data)
        #expect(uniqueCoeffs.count == 3)
        #expect(uniqueCoeffs.contains(0))
        #expect(uniqueCoeffs.contains(1))
        #expect(uniqueCoeffs.contains(context.regularMod - 1))
    }

    func noiselessSampleHelper<Scalar: ScalarType>(params: SimplePirParameters, _: Scalar.Type) async throws {
        let context: SimplePirContext<Scalar> = try .init(params: params)

        let secretPolys = context.generateSecretPolys()
        let secretMatrix = secretPolys.collect()

        let aPolynomials = try context.generateAPolynomials()
        let evalAPolynomials = try aPolynomials.map { try $0.convertToEvalFormat() }
        let negacyclicA = try context.materializeAMatrix(aPolynomials: aPolynomials)

        #expect(secretPolys.count == params.chunksPerEntry)
        #expect(aPolynomials.count == params.databaseColumns.dividingCeil(params.latticeDimension, variableTime: true))

        let matrixCompute = try await secretMatrix.multiply(transposing: negacyclicA, modulus: context.nttFriendlyMod)
        let polynomialCompute = try await context.noiselessSample(
            aPolynomials: evalAPolynomials,
            secretKeys: secretPolys)
        #expect(polynomialCompute == matrixCompute)
    }

    @Test
    func noiselessSample() async throws {
        let singleBoth = try SimplePirServer<UInt32>.computingParams(
            encryptionParams: .init(
                plaintextModulusBits: 8,
                ciphertextModulusBits: 9,
                latticeDimension: 16,
                errorStdDev: .stdDev64,
                securityLevel: .unchecked),
            entryCount: 1,
            entrySizeInBytes: 1,
            seed: .init(repeating: 0, count: 32))
        #expect(singleBoth.chunksPerEntry == 1)
        #expect(singleBoth.aPolyCount == 1)
        try await noiselessSampleHelper(params: singleBoth, UInt32.self)
        try await noiselessSampleHelper(params: singleBoth, UInt64.self)

        let multipleAPolynomials = try SimplePirServer<UInt32>.computingParams(
            encryptionParams: .init(
                plaintextModulusBits: 8,
                ciphertextModulusBits: 9,
                latticeDimension: 8,
                errorStdDev: .stdDev64,
                securityLevel: .unchecked),
            entryCount: 10,
            entrySizeInBytes: 1,
            seed: .init(repeating: 0, count: 32))
        #expect(multipleAPolynomials.chunksPerEntry == 1)
        #expect(multipleAPolynomials.aPolyCount > 1)
        try await noiselessSampleHelper(params: multipleAPolynomials, UInt32.self)
        try await noiselessSampleHelper(params: multipleAPolynomials, UInt64.self)

        let multipleSecretKeys = try SimplePirServer<UInt32>.computingParams(
            encryptionParams: .init(
                plaintextModulusBits: 4,
                ciphertextModulusBits: 8,
                latticeDimension: 8,
                errorStdDev: .stdDev64,
                securityLevel: .unchecked),
            entryCount: 1,
            entrySizeInBytes: 1,
            seed: .init(repeating: 0, count: 32))
        #expect(multipleSecretKeys.chunksPerEntry > 1)
        #expect(multipleSecretKeys.aPolyCount == 1)
        try await noiselessSampleHelper(params: multipleSecretKeys, UInt32.self)
        try await noiselessSampleHelper(params: multipleSecretKeys, UInt64.self)

        let multipleBoth = try SimplePirServer<UInt32>.computingParams(
            encryptionParams: .init(
                plaintextModulusBits: 4,
                ciphertextModulusBits: 8,
                latticeDimension: 8,
                errorStdDev: .stdDev64,
                securityLevel: .unchecked),
            entryCount: 10,
            entrySizeInBytes: 62,
            seed: .init(repeating: 0, count: 32))
        #expect(multipleBoth.chunksPerEntry > 1)
        #expect(multipleBoth.aPolyCount > 1)
        try await noiselessSampleHelper(params: multipleBoth, UInt32.self)
        try await noiselessSampleHelper(params: multipleBoth, UInt64.self)
    }
}
