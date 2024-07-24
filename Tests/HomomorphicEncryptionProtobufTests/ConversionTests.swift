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

@testable import HomomorphicEncryption
import HomomorphicEncryptionProtobuf
import TestUtilities
import XCTest

class ConversionTests: XCTestCase {
    func testHeScheme() throws {
        let bfvUInt32 = try Bfv<UInt32>.proto()
        XCTAssertEqual(bfvUInt32, .bfv)
        XCTAssert(try bfvUInt32.native() is Bfv<UInt64>.Type)

        let bfvUInt64 = try Bfv<UInt64>.proto()
        XCTAssertEqual(bfvUInt64, .bfv)
        XCTAssert(try bfvUInt64.native() is Bfv<UInt64>.Type)

        XCTAssertThrowsError(try Apple_SwiftHomomorphicEncryption_V1_HeScheme.bgv.native())
        XCTAssertThrowsError(try NoOpScheme.proto())
    }

    func testEncryptionParameters() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let parametersProto = try context.encryptionParameters.proto()

            let _: EncryptionParameters<Scheme> = try parametersProto.native()
        }

        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    // MARK: - Largely copied from SerializationTests and then edited

    func testCiphertextSerialization() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let values = TestUtils.getRandomPlaintextData(count: context.degree, in: 0..<context.plaintextModulus)
            let plaintext: Scheme.CoeffPlaintext = try Scheme.encode(context: context,
                                                                     values: values,
                                                                     format: .coefficient)
            let secretKey = try context.generateSecretKey()
            let ciphertext = try plaintext.encrypt(using: secretKey)

            // serialize seeded
            do {
                let serialized = ciphertext.serialize().proto()
                if case .seeded = serialized.serializedCiphertextType {
                } else {
                    XCTFail("Must be seeded serialization")
                }

                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized.native(),
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                XCTAssertEqual(decrypted, plaintext)
            }
            // serialize full
            do {
                var ciphertext = ciphertext
                ciphertext.clearSeed()
                let serialized = ciphertext.serialize().proto()
                if case .full = serialized.serializedCiphertextType {} else {
                    XCTFail("Must be full serialization")
                }

                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized.native(),
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                XCTAssertEqual(decrypted, plaintext)
            }
            // serialize for decryption
            do {
                var ciphertext = ciphertext
                try ciphertext.modSwitchDownToSingle()
                let serialized = ciphertext.serialize(forDecryption: true).proto()
                if case let .some(.full(full)) = serialized.serializedCiphertextType {
                    XCTAssertTrue(full.skipLsbs.contains { $0 > 0 })
                } else {
                    XCTFail("Must be full serialization")
                }
                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized.native(),
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                XCTAssertEqual(decrypted, plaintext)
            }
        }

        // TODO: NoOpScheme is broken: ciphertext.polyContext != context.ciphertextContext
        // ciphertext.polyContext == context.plaintextContext

        // try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    func testPlaintextSerialization() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type, format: EncodeFormat) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let values = TestUtils.getRandomPlaintextData(count: context.degree, in: 0..<context.plaintextModulus)
            do { // CoeffPlaintext
                let plaintext: Scheme.CoeffPlaintext = try Scheme.encode(context: context,
                                                                         values: values,
                                                                         format: format)
                let proto = plaintext.serialize().proto()
                let deserialized: Scheme.CoeffPlaintext = try Plaintext(deserialize: proto.native(), context: context)
                XCTAssertEqual(deserialized, plaintext)
            }
            do { // EvalPlaintext
                let plaintext: Scheme.EvalPlaintext = try Scheme.encode(context: context,
                                                                        values: values,
                                                                        format: format)
                let proto = plaintext.serialize().proto()
                let deserialized: Scheme.EvalPlaintext = try Plaintext(deserialize: proto.native(), context: context)
                XCTAssertEqual(deserialized, plaintext)
            }
        }

        for format in EncodeFormat.allCases {
            // TODO: NoOpScheme is broken again: NoOpScheme.EvalPlaintext.polyContext != context.ciphertextContext
            // try runTest(NoOpScheme.self, format: format)
            try runTest(Bfv<UInt32>.self, format: format)
            try runTest(Bfv<UInt64>.self, format: format)
        }
    }

    func testEvalPlaintextSerializationWithVariableModuliCount() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type, format: EncodeFormat) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let values = TestUtils.getRandomPlaintextData(count: context.degree, in: 0..<context.plaintextModulus)
            for moduliCount in 1...context.ciphertextContext.moduli.count {
                let plaintext: Scheme.EvalPlaintext = try Scheme.encode(context: context,
                                                                        values: values,
                                                                        format: format,
                                                                        moduliCount: moduliCount)
                let proto = plaintext.serialize().proto()
                let deserialized: Scheme.EvalPlaintext = try Plaintext(
                    deserialize: proto.native(),
                    context: context,
                    moduliCount: moduliCount)
                XCTAssertEqual(deserialized, plaintext)
            }
        }

        for format in EncodeFormat.allCases {
            // TODO: NoOpScheme is broken again: NoOpScheme.EvalPlaintext.polyContext != context.ciphertextContext
            // try runTest(NoOpScheme.self, format: format)
            try runTest(Bfv<UInt32>.self, format: format)
            try runTest(Bfv<UInt64>.self, format: format)
        }
    }

    func testSecretKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let proto = secretKey.serialize().proto()
            let deserialized = try SecretKey(deserialize: proto.native(), context: context)
            XCTAssertEqual(deserialized, secretKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    func testGaloisKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let evaluationKey = try context.generateEvaluationKey(
                configuration: EvaluationKeyConfiguration(galoisElements: [3, 5, 7]), using: secretKey)
            let galoisKey = try XCTUnwrap(evaluationKey.galoisKey)
            let proto = galoisKey.serialize().proto()
            let deserialized = try GaloisKey(deserialize: proto.native(), context: context)
            XCTAssertEqual(deserialized, galoisKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    func testRelinearizationKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let evaluationKey = try context.generateEvaluationKey(
                configuration: EvaluationKeyConfiguration(
                    hasRelinearizationKey: true), using: secretKey)
            let relinearizationKey = try XCTUnwrap(evaluationKey.relinearizationKey)
            let proto = relinearizationKey.serialize().proto()
            let deserialized = try RelinearizationKey(deserialize: proto.native(), context: context)
            XCTAssertEqual(deserialized, relinearizationKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    func testEvaluationKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let evaluationKey = try context.generateEvaluationKey(
                configuration: EvaluationKeyConfiguration(
                    galoisElements: [3, 5, 7],
                    hasRelinearizationKey: true), using: secretKey)
            let proto = evaluationKey.serialize().proto()
            let deserialized = try EvaluationKey(deserialize: proto.native(), context: context)
            XCTAssertEqual(deserialized, evaluationKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }
}
