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

    @Test(arguments: CiphertextSerializationConfig.allCases)
    func ciphertextSerialization(config: CiphertextSerializationConfig) throws {
        let indices: [Int]? = if config.indices { [1, 2, 3] } else { nil }
        if indices != nil, config.polyFormat == .eval {
            return
        }

        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Context<Scheme> = try TestUtils.getTestContext()
            let values = TestUtils.getRandomPlaintextData(count: context.degree, in: 0..<context.plaintextModulus)
            let plaintext: Scheme.CoeffPlaintext = try context.encode(values: values, format: .coefficient)
            let secretKey = try context.generateSecretKey()
            var ciphertext = try plaintext.encrypt(using: secretKey)

            func checkDeserialization<Format: PolyFormat>(
                serialized: SerializedCiphertext<Scheme.Scalar>,
                isSmallerThan upperBound: Int?,
                _: Format.Type) throws
            {
                if let upperBound {
                    try #expect(serialized.nonZeroBytes() < upperBound)
                }

                let shouldBeSeeded = Scheme.self != NoOpScheme.self && !config.modSwitchDownToSingle
                let proto = serialized.proto()
                switch (proto.serializedCiphertextType, shouldBeSeeded) {
                case (.full, true):
                    Issue.record("Must be full serialization")
                case (.seeded, false):
                    Issue.record("Must be seeded serialization")
                default:
                    break
                }
                let deserialized: Ciphertext<Scheme, Format> = try Ciphertext(
                    deserialize: proto.native(),
                    context: context,
                    moduliCount: ciphertext.moduli.count)
                let decrypted = try deserialized.decrypt(using: secretKey)
                if let indices {
                    let decoded: [Scheme.Scalar] = try decrypted.decode(format: .coefficient)
                    for index in indices {
                        #expect(decoded[index] == values[index])
                    }
                } else {
                    #expect(decrypted == plaintext)
                }
            }

            if config.modSwitchDownToSingle {
                try ciphertext.modSwitchDownToSingle()
            }
            switch config.polyFormat {
            case .coeff:
                let coeffCiphertext = try ciphertext.convertToCoeffFormat()
                let serialized = if let indices {
                    try coeffCiphertext.serialize(indices: indices, forDecryption: config.forDecryption)
                } else {
                    coeffCiphertext.serialize(forDecryption: config.forDecryption)
                }
                let baseline: Int? = if config.modSwitchDownToSingle, config.forDecryption || config.indices {
                    try coeffCiphertext.serialize().nonZeroBytes()
                } else {
                    nil
                }
                try checkDeserialization(serialized: serialized, isSmallerThan: baseline, Coeff.self)

            case .eval:
                let evalCiphertext = try ciphertext.convertToEvalFormat()
                let serialized = if let indices {
                    try evalCiphertext.serialize(indices: indices, forDecryption: config.forDecryption)
                } else {
                    evalCiphertext.serialize(forDecryption: config.forDecryption)
                }
                try checkDeserialization(serialized: serialized, isSmallerThan: nil, Eval.self)
            }
        }

        // TODO: NoOpScheme is broken: ciphertext.polyContext != context.ciphertextContext
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

extension SerializedCiphertext {
    /// Returns the number of non-zero bytes in the serialized data.
    func nonZeroBytes() throws -> Int {
        let data = try proto().serializedData()
        return data.count { byte in byte != 0 }
    }
}

enum PolyFormatEnum: CaseIterable {
    case coeff
    case eval
}

struct CiphertextSerializationConfig: CaseIterable {
    static var allCases: [Self] {
        [false, true].flatMap { modSwitchDownToSingle in
            [false, true].flatMap { forDecryption in
                [false, true].flatMap { indices in
                    PolyFormatEnum.allCases.map { polyFormat in
                        CiphertextSerializationConfig(
                            modSwitchDownToSingle: modSwitchDownToSingle,
                            forDecryption: forDecryption,
                            indices: indices,
                            polyFormat: polyFormat)
                    }
                }
            }
        }
    }

    let modSwitchDownToSingle: Bool
    let forDecryption: Bool
    let indices: Bool
    let polyFormat: PolyFormatEnum
}
