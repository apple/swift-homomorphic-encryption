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
import TestUtilities
import XCTest

class SerializationTests: XCTestCase {
    func testCiphertextSerialization() throws {
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
                let serialized = ciphertext.serialize()
                if case .seeded = serialized {
                } else {
                    XCTFail("Must be seeded serialization")
                }

                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized,
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                XCTAssertEqual(decrypted, plaintext)
            }
            // serialize full
            do {
                var ciphertext = ciphertext
                ciphertext.clearSeed()
                let serialized = ciphertext.serialize()
                if case .full = serialized {} else {
                    XCTFail("Must be full serialization")
                }

                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized,
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                XCTAssertEqual(decrypted, plaintext)
            }
            // serialize for decryption
            do {
                var ciphertext = ciphertext
                try ciphertext.modSwitchDownToSingle()
                let serialized = ciphertext.serialize(forDecryption: true)
                if case let .full(_, skipLSBs, _) = serialized {
                    XCTAssertTrue(skipLSBs.contains { $0 > 0 })
                } else {
                    XCTFail("Must be full serialization")
                }
                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized,
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                XCTAssertEqual(decrypted, plaintext)
            }
            // serialize indices for decryption
            do {
                var ciphertext = ciphertext
                try ciphertext.modSwitchDownToSingle()
                let indices = [1, 2, 5]
                let serialized = try ciphertext.serialize(indices: indices, forDecryption: true)
                if case let .full(_, skipLSBs, _) = serialized {
                    XCTAssertTrue(skipLSBs.contains { $0 > 0 })
                } else {
                    XCTFail("Must be full serialization")
                }
                let deserialized: Scheme.CanonicalCiphertext = try Ciphertext(
                    deserialize: serialized,
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                let decoded: [Scheme.Scalar] = try decrypted.decode(format: .coefficient)
                for index in indices {
                    XCTAssertEqual(decoded[index], values[index])
                }
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
                let plaintext: Scheme.CoeffPlaintext = try context.encode(values: values, format: format)
                let serialized = plaintext.serialize()
                let deserialized: Scheme.CoeffPlaintext = try Plaintext(deserialize: serialized, context: context)
                XCTAssertEqual(deserialized, plaintext)
            }
            do { // EvalPlaintext
                let plaintext: Scheme.EvalPlaintext = try context.encode(values: values, format: format)
                let serialized = plaintext.serialize()
                let deserialized: Scheme.EvalPlaintext = try Plaintext(deserialize: serialized, context: context)
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
                let plaintext: Scheme.EvalPlaintext = try context.encode(values: values,
                                                                         format: format,
                                                                         moduliCount: moduliCount)
                let serialized = plaintext.serialize()
                let deserialized: Scheme.EvalPlaintext = try Plaintext(
                    deserialize: serialized,
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
            let serialized = secretKey.serialize()
            let deserialized = try SecretKey(deserialize: serialized, context: context)
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
            let evaluationKeyConfig = EvaluationKeyConfiguration(galoisElements: [3, 5, 7])
            let evaluationKey = try context.generateEvaluationKey(configuration: evaluationKeyConfig, using: secretKey)
            let galoisKey = try XCTUnwrap(evaluationKey.galoisKey)
            let serialized = galoisKey.serialize()
            let deserialized = try GaloisKey(deserialize: serialized, context: context)
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
            let evaluationKeyConfig = EvaluationKeyConfiguration(hasRelinearizationKey: true)
            let evaluationKey = try context.generateEvaluationKey(configuration: evaluationKeyConfig, using: secretKey)
            let relinearizationKey = try XCTUnwrap(evaluationKey.relinearizationKey)
            let serialized = relinearizationKey.serialize()
            let deserialized = try RelinearizationKey(deserialize: serialized, context: context)
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
            let evaluationKeyConfig = EvaluationKeyConfiguration(
                galoisElements: [3, 5, 7],
                hasRelinearizationKey: true)
            let evaluationKey = try context.generateEvaluationKey(configuration: evaluationKeyConfig, using: secretKey)
            let serialized = evaluationKey.serialize()
            let deserialized = try EvaluationKey(deserialize: serialized, context: context)
            XCTAssertEqual(deserialized, evaluationKey)

            func checkSeededCiphertext(_ ciphertexts: [SerializedCiphertext<Scheme.Scalar>]) {
                for ciphertext in ciphertexts {
                    if case .full = ciphertext {
                        XCTFail("Must be seeded serialization inside serialized evaluation key")
                    }
                }
            }

            let galoisKey = try XCTUnwrap(serialized.galoisKey)
            for keySwitchKey in galoisKey.galoisKey.values {
                checkSeededCiphertext(keySwitchKey)
            }
            let relinearizationKey = try XCTUnwrap(serialized.relinearizationKey)
            checkSeededCiphertext(relinearizationKey.relinKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }
}
