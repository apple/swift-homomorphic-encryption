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
import Testing

@Suite
struct SerializationTests {
    @Test(arguments: CiphertextSerializationConfig.allCases)
    func ciphertextSerialization(config: CiphertextSerializationConfig) throws {
        let indices: [Int]? = if config.indices { [1, 2, 3] } else { nil }
        if indices != nil, config.polyFormat == .eval {
            return
        }

        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Scheme.Context = try TestUtils.getTestContext()
            let values = TestUtils.getRandomPlaintextData(count: context.degree, in: 0..<context.plaintextModulus)
            let plaintext: Scheme.CoeffPlaintext = try context.encode(values: values, format: .coefficient)
            let secretKey = try context.generateSecretKey()
            var ciphertext = try plaintext.encrypt(using: secretKey)

            func checkDeserialization<Format: PolyFormat>(
                serialized: SerializedCiphertext<Scheme.Scalar>, forDecryption: Bool,
                _: Format.Type) throws
            {
                let shouldBeSeeded = Scheme.self != NoOpScheme.self && !config.modSwitchDownToSingle
                switch (serialized, shouldBeSeeded) {
                case (.full, true):
                    Issue.record("Must be full serialization")
                case (.seeded, false):
                    Issue.record("Must be seeded serialization")
                case (.full(_, let skipLSBs, _), false):
                    if Format.self == Coeff.self, forDecryption {
                        #expect(try skipLSBs == Scheme.skipLSBsForDecryption(for: ciphertext.convertToCoeffFormat()))
                    }
                default:
                    break
                }

                let deserialized: Ciphertext<Scheme, Format> = try Ciphertext(
                    deserialize: serialized,
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
                try checkDeserialization(serialized: serialized, forDecryption: config.forDecryption, Coeff.self)

            case .eval:
                let evalCiphertext = try ciphertext.convertToEvalFormat()
                let serialized = if let indices {
                    try evalCiphertext.serialize(indices: indices, forDecryption: config.forDecryption)
                } else {
                    evalCiphertext.serialize(forDecryption: config.forDecryption)
                }
                try checkDeserialization(serialized: serialized, forDecryption: config.forDecryption, Eval.self)
            }
        }

        // TODO: NoOpScheme is broken: ciphertext.polyContext != context.ciphertextContext
        // try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    @Test
    func plaintextSerialization() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type, format: EncodeFormat) throws {
            let context: Scheme.Context = try TestUtils.getTestContext()
            let values = TestUtils.getRandomPlaintextData(count: context.degree, in: 0..<context.plaintextModulus)
            do { // CoeffPlaintext
                let plaintext: Scheme.CoeffPlaintext = try context.encode(values: values, format: format)
                let serialized = plaintext.serialize()
                let deserialized: Scheme.CoeffPlaintext = try Plaintext(deserialize: serialized, context: context)
                #expect(deserialized == plaintext)
            }
            do { // EvalPlaintext
                let plaintext: Scheme.EvalPlaintext = try context.encode(values: values, format: format)
                let serialized = plaintext.serialize()
                let deserialized: Scheme.EvalPlaintext = try Plaintext(deserialize: serialized, context: context)
                #expect(deserialized == plaintext)
            }
        }

        for format in EncodeFormat.allCases {
            // TODO: NoOpScheme is broken again: NoOpScheme.EvalPlaintext.polyContext != context.ciphertextContext
            // try runTest(NoOpScheme.self, format: format)
            try runTest(Bfv<UInt32>.self, format: format)
            try runTest(Bfv<UInt64>.self, format: format)
        }
    }

    @Test
    func evalPlaintextSerializationWithVariableModuliCount() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type, format: EncodeFormat) throws {
            let context: Scheme.Context = try TestUtils.getTestContext()
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
                #expect(deserialized == plaintext)
            }
        }

        for format in EncodeFormat.allCases {
            // TODO: NoOpScheme is broken again: NoOpScheme.EvalPlaintext.polyContext != context.ciphertextContext
            // try runTest(NoOpScheme.self, format: format)
            try runTest(Bfv<UInt32>.self, format: format)
            try runTest(Bfv<UInt64>.self, format: format)
        }
    }

    @Test
    func secretKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Scheme.Context = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let serialized = secretKey.serialize()
            let deserialized = try SecretKey<Scheme>(deserialize: serialized, context: context)
            #expect(deserialized == secretKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    @Test
    func galoisKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Scheme.Context = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let evaluationKeyConfig = EvaluationKeyConfig(galoisElements: [3, 5, 7])
            let evaluationKey = try context.generateEvaluationKey(config: evaluationKeyConfig, using: secretKey)
            let galoisKey = try #require(evaluationKey.galoisKey)
            let serialized = galoisKey.serialize()
            let deserialized = try _GaloisKey<Scheme>(deserialize: serialized, context: context)
            #expect(deserialized == galoisKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    @Test
    func relinearizationKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Scheme.Context = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let evaluationKeyConfig = EvaluationKeyConfig(hasRelinearizationKey: true)
            let evaluationKey = try context.generateEvaluationKey(config: evaluationKeyConfig,
                                                                  using: secretKey)
            let relinearizationKey = try #require(evaluationKey.relinearizationKey)
            let serialized = relinearizationKey.serialize()
            let deserialized = try _RelinearizationKey<Scheme>(deserialize: serialized, context: context)
            #expect(deserialized == relinearizationKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
    }

    @Test
    func evaluationKey() throws {
        func runTest<Scheme: HeScheme>(_: Scheme.Type) throws {
            let context: Scheme.Context = try TestUtils.getTestContext()
            let secretKey = try context.generateSecretKey()
            let evaluationKeyConfig = EvaluationKeyConfig(
                galoisElements: [3, 5, 7],
                hasRelinearizationKey: true)
            let evaluationKey = try context.generateEvaluationKey(config: evaluationKeyConfig,
                                                                  using: secretKey)
            let serialized = evaluationKey.serialize()
            let deserialized = try EvaluationKey<Scheme>(deserialize: serialized, context: context)
            #expect(deserialized == evaluationKey)

            func checkSeededCiphertext(_ ciphertexts: [SerializedCiphertext<Scheme.Scalar>]) {
                for ciphertext in ciphertexts {
                    if case .full = ciphertext {
                        Issue.record("Must be seeded serialization inside serialized evaluation key")
                    }
                }
            }

            let galoisKey = try #require(serialized.galoisKey)
            for keySwitchKey in galoisKey.galoisKey.values {
                checkSeededCiphertext(keySwitchKey)
            }
            let relinearizationKey = try #require(serialized.relinearizationKey)
            checkSeededCiphertext(relinearizationKey.relinKey)
        }

        try runTest(NoOpScheme.self)
        try runTest(Bfv<UInt32>.self)
        try runTest(Bfv<UInt64>.self)
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
