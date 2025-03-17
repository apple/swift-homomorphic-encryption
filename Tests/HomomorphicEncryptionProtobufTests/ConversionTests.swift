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
@testable import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import Testing

extension SerializedCiphertext {
    /// Returns the number of non-zero bytes in the serialized data.
    func nonZeroBytes() throws -> Int {
        let data = try proto().serializedData()
        return data.count { byte in byte != 0 }
    }
}

@Suite
struct ConversionTests {
    @Test
    func heScheme() throws {
        let bfvUInt32 = try Bfv<UInt32>.proto()
        #expect(bfvUInt32 == .bfv)
        #expect(try bfvUInt32.native() is Bfv<UInt64>.Type)

        let bfvUInt64 = try Bfv<UInt64>.proto()
        #expect(bfvUInt64 == .bfv)
        #expect(try bfvUInt64.native() is Bfv<UInt64>.Type)

        #expect(throws: (any Error).self) { try Apple_SwiftHomomorphicEncryption_V1_HeScheme.bgv.native() }
        #expect(throws: (any Error).self) { try NoOpScheme.proto() }
    }

    @Test
    func encryptionParameters() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let parametersProto = try context.encryptionParameters.proto()

            let _: EncryptionParameters<Scheme> = try parametersProto.native()
        }

        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    // MARK: - Largely copied from SerializationTests and then edited

    @Test
    func ciphertextSerialization() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let values = TestUtils.getRandomPlaintextData(count: context.degree, in: 0..<context.plaintextModulus)
            let plaintext: Scheme.CoeffPlaintext = try context.encode(
                values: values,
                format: .coefficient)
            let secretKey = try context.generateSecretKey()
            let ciphertext = try plaintext.encrypt(using: secretKey)

            // serialize seeded
            do {
                let serialized = ciphertext.serialize().proto()
                if case .seeded = serialized.serializedCiphertextType {
                } else {
                    Issue.record("Must be seeded serialization")
                }

                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized.native(),
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                #expect(decrypted == plaintext)
            }
            // serialize full
            do {
                var ciphertext = ciphertext
                ciphertext.clearSeed()
                let serialized = ciphertext.serialize().proto()
                if case .full = serialized.serializedCiphertextType {} else {
                    Issue.record("Must be full serialization")
                }

                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized.native(),
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                #expect(decrypted == plaintext)
            }
            // serialize for decryption
            do {
                var ciphertext = ciphertext
                try ciphertext.modSwitchDownToSingle()
                let serialized = ciphertext.serialize(forDecryption: true).proto()
                if case let .some(.full(full)) = serialized.serializedCiphertextType {
                    #expect(full.skipLsbs.contains { $0 > 0 })
                } else {
                    Issue.record("Must be full serialization")
                }
                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized.native(),
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                #expect(decrypted == plaintext)
            }
            // serialize indices for decryption
            do {
                var ciphertext = ciphertext
                try ciphertext.modSwitchDownToSingle()
                let indices = [1, 3, 5]
                let serializedAllIndices = ciphertext.serialize(forDecryption: true)
                let serialized = try ciphertext.serialize(indices: indices, forDecryption: true)
                if case let .full(_, skipLSBs, _) = serialized {
                    #expect(skipLSBs.contains { $0 > 0 })
                } else {
                    Issue.record("Must be full serialization")
                }
                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized,
                    context: context,
                    moduliCount: 1)
                let decrypted = try deserialized.decrypt(using: secretKey)
                let decoded: [Scheme.Scalar] = try decrypted.decode(format: .coefficient)
                for index in indices {
                    #expect(decoded[index] == values[index])
                }

                // Check non-zero byte count.
                let allIndicesSize = try serializedAllIndices.nonZeroBytes()
                let indicesSize = try serialized.nonZeroBytes()
                #expect(indicesSize < allIndicesSize)
            }
        }

        // TODO: NoOpScheme is broken: ciphertext.polyContext != context.ciphertextContext
        // ciphertext.polyContext == context.plaintextContext

        // try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    @Test(arguments: EncodeFormat.allCases)
    func plaintextSerialization(format: EncodeFormat) throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type, format: EncodeFormat) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let values = TestUtils.getRandomPlaintextData(count: context.degree, in: 0..<context.plaintextModulus)
            do { // CoeffPlaintext
                let plaintext: Scheme.CoeffPlaintext = try context.encode(values: values, format: format)
                let proto = plaintext.serialize().proto()
                let deserialized: Scheme.CoeffPlaintext = try Plaintext(deserialize: proto.native(), context: context)
                #expect(deserialized == plaintext)
            }
            do { // EvalPlaintext
                let plaintext: Scheme.EvalPlaintext = try context.encode(values: values, format: format)
                let proto = plaintext.serialize().proto()
                let deserialized: Scheme.EvalPlaintext = try Plaintext(deserialize: proto.native(), context: context)
                #expect(deserialized == plaintext)
            }
        }

        // TODO: NoOpScheme is broken again: NoOpScheme.EvalPlaintext.polyContext != context.ciphertextContext
        // try runTest(NoOpScheme.self, format: format)
        try runTest(Bfv<UInt32>.self, format: format)
        try runTest(Bfv<UInt64>.self, format: format)
    }

    @Test(arguments: EncodeFormat.allCases)
    func evalPlaintextSerializationWithVariableModuliCount(format: EncodeFormat) throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type, format: EncodeFormat) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let values = TestUtils.getRandomPlaintextData(count: context.degree, in: 0..<context.plaintextModulus)
            for moduliCount in 1...context.ciphertextContext.moduli.count {
                let plaintext: Scheme.EvalPlaintext = try context.encode(
                    values: values,
                    format: format,
                    moduliCount: moduliCount)
                let proto = plaintext.serialize().proto()
                let deserialized: Scheme.EvalPlaintext = try Plaintext(
                    deserialize: proto.native(),
                    context: context,
                    moduliCount: moduliCount)
                #expect(deserialized == plaintext)
            }
        }

        // TODO: NoOpScheme is broken again: NoOpScheme.EvalPlaintext.polyContext != context.ciphertextContext
        // try runTest(NoOpScheme.self, format: format)
        try runTest(Bfv<UInt32>.self, format: format)
        try runTest(Bfv<UInt64>.self, format: format)
    }

    @Test
    func secretKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let proto = secretKey.serialize().proto()
            let deserialized = try SecretKey(deserialize: proto.native(), context: context)
            #expect(deserialized == secretKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    @Test
    func galoisKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let evaluationKey = try context.generateEvaluationKey(
                config: EvaluationKeyConfig(galoisElements: [3, 5, 7]), using: secretKey)
            let galoisKey = try #require(evaluationKey.galoisKey)
            let proto = galoisKey.serialize().proto()
            let deserialized = try GaloisKey(deserialize: proto.native(), context: context)
            #expect(deserialized == galoisKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    @Test
    func relinearizationKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let evaluationKey = try context.generateEvaluationKey(
                config: EvaluationKeyConfig(
                    hasRelinearizationKey: true), using: secretKey)
            let relinearizationKey = try #require(evaluationKey.relinearizationKey)
            let proto = relinearizationKey.serialize().proto()
            let deserialized = try RelinearizationKey(deserialize: proto.native(), context: context)
            #expect(deserialized == relinearizationKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    @Test
    func evaluationKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let evaluationKey = try context.generateEvaluationKey(
                config: EvaluationKeyConfig(
                    galoisElements: [3, 5, 7],
                    hasRelinearizationKey: true), using: secretKey)
            let proto = evaluationKey.serialize().proto()
            let deserialized = try EvaluationKey(deserialize: proto.native(), context: context)
            #expect(deserialized == evaluationKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }
}
