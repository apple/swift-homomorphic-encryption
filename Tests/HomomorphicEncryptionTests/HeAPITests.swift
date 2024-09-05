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
struct HeAPITests {
    private struct TestEnv<Scheme: HeScheme> {
        let context: Context<Scheme>
        let data1: [Scheme.Scalar]
        let data2: [Scheme.Scalar]
        let coeffPlaintext1: Plaintext<Scheme, Coeff>
        let coeffPlaintext2: Plaintext<Scheme, Coeff>
        let evalPlaintext1: Plaintext<Scheme, Eval>
        let evalPlaintext2: Plaintext<Scheme, Eval>
        let ciphertext1: Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>
        let ciphertext2: Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>
        let evalCiphertext1: Ciphertext<Scheme, Eval>
        let secretKey: SecretKey<Scheme>
        let evaluationKey: EvaluationKey<Scheme>?

        init(
            context: Context<Scheme>,
            format: EncodeFormat,
            galoisElements: [Int] = [],
            relinearizationKey: Bool = false) throws
        {
            self.context = context
            let polyDegree = context.degree
            let plaintextModulus = context.plaintextModulus
            self.data1 = TestUtils.getRandomPlaintextData(count: polyDegree, in: 0..<plaintextModulus)
            self.data2 = TestUtils.getRandomPlaintextData(count: polyDegree, in: 0..<plaintextModulus)
            self.coeffPlaintext1 = try context.encode(values: data1, format: format)
            self.coeffPlaintext2 = try context.encode(values: data2, format: format)
            self.evalPlaintext1 = try context.encode(values: data1, format: format)
            self.evalPlaintext2 = try context.encode(values: data2, format: format)
            self.secretKey = try context.generateSecretKey()
            self.ciphertext1 = try coeffPlaintext1.encrypt(using: secretKey)
            self.ciphertext2 = try coeffPlaintext2.encrypt(using: secretKey)
            self.evalCiphertext1 = try ciphertext1.convertToEvalFormat()
            let evaluationkeyConfig = EvaluationKeyConfig(
                galoisElements: galoisElements,
                hasRelinearizationKey: true)
            self.evaluationKey = if context.supportsEvaluationKey, !galoisElements.isEmpty || relinearizationKey {
                try context.generateEvaluationKey(config: evaluationkeyConfig, using: secretKey)
            } else {
                nil
            }
        }

        func checkDecryptsDecodes(
            ciphertext: Ciphertext<Scheme, some PolyFormat>,
            format: EncodeFormat,
            expected: [Scheme.Scalar],
            _ comment: Comment? = nil,
            sourceLocation: SourceLocation = #_sourceLocation) throws
        {
            if let coeffCiphertext = ciphertext as? Scheme.CoeffCiphertext {
                let decryptedData: [Scheme.Scalar] = try coeffCiphertext.decrypt(using: secretKey)
                    .decode(format: format)
                #expect(decryptedData == expected, comment, sourceLocation: sourceLocation)
            } else if let evalCiphertext = ciphertext as? Scheme.EvalCiphertext {
                let decryptedData: [Scheme.Scalar] = try evalCiphertext.decrypt(using: secretKey).decode(format: format)
                #expect(decryptedData == expected, comment, sourceLocation: sourceLocation)
            } else {
                let commentString = comment.map { $0.rawValue + ". " } ?? ""
                Issue.record(
                    "\(commentString)Invalid ciphertext \(ciphertext.description)",
                    sourceLocation: sourceLocation)
            }
        }
    }

    @Test
    func noOpScheme() async throws {
        let context: Context<NoOpScheme> = try TestUtils.getTestContext()
        try HeAPITestHelpers.schemeEncodeDecodeTest(context: context)
        try HeAPITestHelpers.schemeEncryptDecryptTest(context: context)
        try HeAPITestHelpers.schemeEncryptZeroDecryptTest(context: context)
        try HeAPITestHelpers.schemeEncryptZeroAddDecryptTest(context: context)
        try HeAPITestHelpers.schemeEncryptZeroMultiplyDecryptTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextAddTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextSubtractTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextCiphertextMultiplyTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextPlaintextAddTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextPlaintextSubtractTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextPlaintextMultiplyTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextMultiplyAddTest(context: context)
        try HeAPITestHelpers.schemeCiphertextMultiplyAddPlainTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextMultiplySubtractTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextMultiplySubtractPlainTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextNegateTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextPlaintextInnerProductTest(context: context)
        try await HeAPITestHelpers.schemeCiphertextCiphertextInnerProductTest(context: context)
        try HeAPITestHelpers.schemeEvaluationKeyTest(context: context)
        try await HeAPITestHelpers.schemeRotationTest(context: context)
        try await HeAPITestHelpers.schemeApplyGaloisTest(context: context)
    }

    private func bfvTestKeySwitching<T>(context: Context<Bfv<T>>) throws {
        guard context.supportsEvaluationKey else {
            return
        }

        let testEnv = try TestEnv(context: context, format: .coefficient)
        let newSecretKey = try context.generateSecretKey()

        let keySwitchKey = try Bfv<T>.generateKeySwitchKey(context: context,
                                                           currentKey: testEnv.secretKey.poly,
                                                           targetKey: newSecretKey)
        var switchedPolys = try Bfv<T>.computeKeySwitchingUpdate(
            context: context,
            target: testEnv.ciphertext1.polys[1],
            keySwitchingKey: keySwitchKey)
        switchedPolys[0] += testEnv.ciphertext1.polys[0]
        let switchedCiphertext = Ciphertext(context: context, polys: switchedPolys, correctionFactor: 1)
        let plaintext = try switchedCiphertext.decrypt(using: newSecretKey)
        let decrypted: [T] = try plaintext.decode(format: .coefficient)

        #expect(decrypted == testEnv.data1)
    }

    private func runBfvTests<T: ScalarType>(_: T.Type) async throws {
        let predefined: [EncryptionParameters<Bfv<T>>] = try PredefinedRlweParameters.allCases
            .filter { rlweParams in rlweParams.supportsScalar(T.self) }
            .filter { rlweParams in rlweParams.polyDegree <= 512 } // large degrees are slow
            .map { rlweParams in
                try EncryptionParameters<Bfv<T>>(from: rlweParams)
            }
        let custom = try EncryptionParameters<Bfv<T>>(
            polyDegree: TestUtils.testPolyDegree,
            plaintextModulus: T.generatePrimes(
                significantBitCounts: [12],
                preferringSmall: true,
                nttDegree: TestUtils.testPolyDegree)[0],
            coefficientModuli: HeAPITestHelpers.testCoefficientModuli(),
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.unchecked)
        let manyModuli = try EncryptionParameters<Bfv<T>>(
            polyDegree: TestUtils.testPolyDegree,
            plaintextModulus: T.generatePrimes(
                significantBitCounts: [12],
                preferringSmall: true,
                nttDegree: TestUtils.testPolyDegree)[0],
            coefficientModuli: T.generatePrimes(
                significantBitCounts: Array(repeating: T.bitWidth - 4, count: 32),
                preferringSmall: false,
                nttDegree: TestUtils.testPolyDegree),
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.unchecked)

        for encryptionParameters in predefined + [custom, manyModuli] {
            let context = try Context<Bfv<T>>(encryptionParameters: encryptionParameters)
            try HeAPITestHelpers.schemeEncodeDecodeTest(context: context)
            try HeAPITestHelpers.schemeEncryptDecryptTest(context: context)
            try HeAPITestHelpers.schemeEncryptZeroDecryptTest(context: context)
            try HeAPITestHelpers.schemeEncryptZeroAddDecryptTest(context: context)
            try HeAPITestHelpers.schemeEncryptZeroMultiplyDecryptTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextAddTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextSubtractTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextCiphertextMultiplyTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextPlaintextAddTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextPlaintextSubtractTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextPlaintextMultiplyTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextMultiplyAddTest(context: context)
            try HeAPITestHelpers.schemeCiphertextMultiplyAddPlainTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextMultiplySubtractTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextMultiplySubtractPlainTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextNegateTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextPlaintextInnerProductTest(context: context)
            try await HeAPITestHelpers.schemeCiphertextCiphertextInnerProductTest(context: context)
            try HeAPITestHelpers.schemeEvaluationKeyTest(context: context)
            try await HeAPITestHelpers.schemeRotationTest(context: context)
            try await HeAPITestHelpers.schemeApplyGaloisTest(context: context)
            try bfvTestKeySwitching(context: context)
            try HeAPITestHelpers.noiseBudgetTest(context: context)
            try await HeAPITestHelpers.repeatedAdditionTest(context: context)
            try await HeAPITestHelpers.multiplyInverseTest(context: context)
        }
    }

    @Test
    func bfvUInt32() async throws {
        try await runBfvTests(UInt32.self)
    }

    @Test
    func bfvUInt64() async throws {
        try await runBfvTests(UInt64.self)
    }
}

/// This will compile if `Plaintext/decode` is generic across PolyFormat.
extension Plaintext {
    private func checkDecodeIsGeneric() throws {
        let _: [Scheme.Scalar] = try decode(format: .coefficient)
        let _: [Scheme.SignedScalar] = try decode(format: .coefficient)
    }
}
