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

class HeAPITests: XCTestCase {
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
            self.data1 = TestUtils.getRandomPlaintextData(
                count: polyDegree,
                in: 0..<Scheme.Scalar(plaintextModulus))
            self.data2 = TestUtils.getRandomPlaintextData(
                count: polyDegree,
                in: 0..<Scheme.Scalar(plaintextModulus))
            self.coeffPlaintext1 = try Scheme.encode(context: context, values: data1, format: format)
            self.coeffPlaintext2 = try Scheme.encode(context: context, values: data2, format: format)
            self.evalPlaintext1 = try Scheme.encode(context: context, values: data1, format: format)
            self.evalPlaintext2 = try Scheme.encode(context: context, values: data2, format: format)
            self.secretKey = try Scheme.generateSecretKey(context: context)
            self.ciphertext1 = try Scheme.encrypt(coeffPlaintext1, using: secretKey)
            self.ciphertext2 = try Scheme.encrypt(coeffPlaintext2, using: secretKey)
            self.evalCiphertext1 = try ciphertext1.convertToEvalFormat()
            let evaluationkeyConfig = EvaluationKeyConfiguration(
                galoisElements: galoisElements,
                hasRelinearizationKey: true)
            self.evaluationKey = if context.supportsEvaluationKey, !galoisElements.isEmpty || relinearizationKey {
                try Scheme.generateEvaluationKey(
                    context: context,
                    configuration: evaluationkeyConfig,
                    using: secretKey)
            } else {
                nil
            }
        }

        func checkDecryptsDecodes(
            ciphertext: Ciphertext<Scheme, some PolyFormat>,
            format: EncodeFormat,
            expected: [Scheme.Scalar],
            _ message: @autoclosure () -> String = "",
            _ file: StaticString = #filePath,
            _ line: UInt = #line) throws
        {
            if let coeffCiphertext = ciphertext as? Scheme.CoeffCiphertext {
                let decryptedData: [Scheme.Scalar] = try context.decode(
                    plaintext: coeffCiphertext.decrypt(using: secretKey),
                    format: format)
                XCTAssertEqual(decryptedData, expected, message(), file: file, line: line)
            } else if let evalCiphertext = ciphertext as? Scheme.EvalCiphertext {
                let decryptedData: [Scheme.Scalar] = try context.decode(
                    plaintext: evalCiphertext.decrypt(using: secretKey),
                    format: format)
                XCTAssertEqual(decryptedData, expected, message(), file: file, line: line)
            } else {
                XCTFail("\(message()) Invalid ciphertext \(ciphertext.description)", file: file, line: line)
            }
        }
    }

    private func testCoefficientModuli<T: ScalarType>() throws -> [T] {
        // Avoid assumptions on ordering of moduli
        // Also test `T.bitWidth  - 2
        if T.self == UInt32.self {
            return try T.generatePrimes(
                significantBitCounts: [28, 27, 29, 30],
                preferringSmall: false,
                nttDegree: TestUtils.testPolyDegree)
        }
        if T.self == UInt64.self {
            return try T.generatePrimes(
                significantBitCounts: [55, 52, 62, 58],
                preferringSmall: false,
                nttDegree: TestUtils.testPolyDegree)
        }
        preconditionFailure("Unsupported scalar type \(T.self)")
    }

    private func getTestContext<Scheme: HeScheme>() throws -> Context<Scheme> {
        try Context<Scheme>(encryptionParameters: EncryptionParameters(
            polyDegree: TestUtils.testPolyDegree,
            plaintextModulus: Scheme.Scalar(TestUtils.testPlaintextModulus),
            coefficientModuli: testCoefficientModuli(),
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.unchecked))
    }

    private func schemeEvaluationKeyTest(context _: Context<some HeScheme>) throws {
        do {
            let config = EvaluationKeyConfiguration()
            XCTAssertFalse(config.hasRelinearizationKey)
            XCTAssertEqual(config.galoisElements, [])
            XCTAssertEqual(config.keyCount, 0)
        }
        do {
            let config = EvaluationKeyConfiguration(hasRelinearizationKey: true)
            XCTAssertTrue(config.hasRelinearizationKey)
            XCTAssertEqual(config.galoisElements, [])
            XCTAssertEqual(config.keyCount, 1)
        }
        do {
            let config = EvaluationKeyConfiguration(galoisElements: [1, 3], hasRelinearizationKey: true)
            XCTAssertTrue(config.hasRelinearizationKey)
            XCTAssertEqual(config.galoisElements, [1, 3])
            XCTAssertEqual(config.keyCount, 3)
        }
    }

    private func encodingTest<Scheme: HeScheme>(
        context: Context<Scheme>,
        encodeFormat: EncodeFormat,
        polyFormat: (some PolyFormat).Type) throws
    {
        guard context.supportsSimdEncoding || encodeFormat != .simd else {
            return
        }
        let data = TestUtils.getRandomPlaintextData(
            count: context.degree,
            in: 0..<Scheme.Scalar(context.plaintextModulus))
        switch polyFormat {
        case is Coeff.Type:
            let plaintextCoeff: Plaintext<Scheme, Coeff> = try context.encode(values: data, format: encodeFormat)
            let decoded = try context.decode(plaintext: plaintextCoeff, format: encodeFormat) as [Scheme.Scalar]
            XCTAssertEqual(data, decoded)
        case is Eval.Type:
            let plaintextEval: Plaintext<Scheme, Eval> = try context.encode(values: data, format: encodeFormat)
            let decoded = try context.decode(plaintext: plaintextEval, format: encodeFormat) as [Scheme.Scalar]
            XCTAssertEqual(data, decoded)
        default:
            XCTFail("Invalid PolyFormat \(polyFormat)")
        }
    }

    private func schemeEncodeDecodeTest(context: Context<some HeScheme>) throws {
        for encodeFormat in EncodeFormat.allCases {
            for polyFormat: PolyFormat.Type in [Coeff.self, Eval.self] {
                try encodingTest(context: context, encodeFormat: encodeFormat, polyFormat: polyFormat)
            }
        }
    }

    private func schemeEncryptDecryptTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        var ciphertext1 = testEnv.ciphertext1

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertext1.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()
        try ciphertext1.modSwitchDownToSingle()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: testEnv.data1)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .coefficient, expected: testEnv.data1)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertext1, format: .coefficient, expected: testEnv.data1)
        var ciphertext2 = testEnv.ciphertext2
        try ciphertext2.modSwitchDownToSingle()
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertext2, format: .coefficient, expected: testEnv.data2)
    }

    private func schemeEncryptZeroDecryptTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let zeros = [Scheme.Scalar](repeating: 0, count: context.degree)

        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try Scheme.zeroCiphertext(
            context: context,
            moduliCount: context.ciphertextContext.moduli.count)
        let evalCiphertext: Ciphertext<Scheme, Eval> = try Scheme.zeroCiphertext(
            context: context,
            moduliCount: context.ciphertextContext.moduli.count)
        var canonicalCiphertext = try coeffCiphertext.convertToCanonicalFormat()
        try canonicalCiphertext.modSwitchDownToSingle()

        XCTAssert(coeffCiphertext.isTransparent())
        XCTAssert(evalCiphertext.isTransparent())
        XCTAssert(canonicalCiphertext.isTransparent())

        let zeroPlaintext: Scheme.CoeffPlaintext = try Scheme.encode(
            context: context,
            values: zeros,
            format: .coefficient)
        let nonTransparentZero = try Scheme.encrypt(zeroPlaintext, using: testEnv.secretKey)
        if Scheme.self != NoOpScheme.self {
            XCTAssertFalse(nonTransparentZero.isTransparent())
        }

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: zeros)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .coefficient, expected: zeros)
        try testEnv.checkDecryptsDecodes(ciphertext: canonicalCiphertext, format: .coefficient, expected: zeros)
    }

    private func schemeEncryptZeroAddDecryptTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let expected = [Scheme.Scalar](repeating: 0, count: context.degree)

        let zeroCoeffCiphertext: Ciphertext<Scheme, Coeff> = try Scheme.zeroCiphertext(
            context: context,
            moduliCount: context.ciphertextContext.moduli.count)
        let zeroCiphertext = try zeroCoeffCiphertext.convertToCanonicalFormat()

        let sum1 = try zeroCiphertext + zeroCiphertext
        let sum2 = try zeroCiphertext + testEnv.ciphertext1
        let sum3 = try zeroCiphertext + testEnv.coeffPlaintext1

        XCTAssert(sum1.isTransparent())
        if Scheme.self != NoOpScheme.self {
            XCTAssertFalse(sum2.isTransparent())
        }
        XCTAssert(sum3.isTransparent())

        try testEnv.checkDecryptsDecodes(ciphertext: sum1, format: .coefficient, expected: expected)
        try testEnv.checkDecryptsDecodes(ciphertext: sum2, format: .coefficient, expected: testEnv.data1)
        XCTAssertEqual(try sum3.decrypt(using: testEnv.secretKey), testEnv.coeffPlaintext1)
    }

    private func schemeEncryptZeroMultiplyDecryptTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let expected = [Scheme.Scalar](repeating: 0, count: context.degree)

        let zeroCiphertext: Ciphertext<Scheme, Eval> = try Scheme.zeroCiphertext(
            context: context,
            moduliCount: context.ciphertextContext.moduli.count)
        let product = try zeroCiphertext * testEnv.evalPlaintext1
        XCTAssert(product.isTransparent())

        try testEnv.checkDecryptsDecodes(ciphertext: product, format: .coefficient, expected: expected)
    }

    private func schemeSameTypeAdditionTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let sumData = zip(data1, data2).map { x, y in x.addMod(y, modulus: context.plaintextModulus) }

        let coeffPlaintext1 = testEnv.coeffPlaintext1
        let coeffPlaintext2 = testEnv.coeffPlaintext2
        let plaintextSum = try coeffPlaintext1 + coeffPlaintext2
        var ciphertext1 = testEnv.ciphertext1
        var ciphertext2 = testEnv.ciphertext2
        let ciphertextSum1 = try ciphertext1 + ciphertext2
        try ciphertext1.modSwitchDownToSingle()
        try ciphertext2.modSwitchDownToSingle()
        let ciphertextSum2 = try ciphertext1 + ciphertext2

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextSum1.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        let decodedData: [Scheme.Scalar] = try context.decode(plaintext: plaintextSum, format: .coefficient)
        XCTAssertEqual(decodedData, sumData)

        let ciphertextSum3 = try [testEnv.ciphertext1, testEnv.ciphertext2].sum()
        let ciphertextSum4 = try [testEnv.ciphertext1.convertToEvalFormat(), testEnv.ciphertext2.convertToEvalFormat()]
            .sum()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: sumData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .coefficient, expected: sumData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextSum2, format: .coefficient, expected: sumData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextSum3, format: .coefficient, expected: sumData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextSum4, format: .coefficient, expected: sumData)
    }

    private func schemeSameTypeSubtractionTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let diffData = zip(data1, data2).map { x, y in x.subtractMod(y, modulus: context.plaintextModulus) }

        var ciphertext1 = testEnv.ciphertext1
        var ciphertext2 = testEnv.ciphertext2
        let ciphertextDiff1 = try ciphertext1 - ciphertext2
        try ciphertext1.modSwitchDownToSingle()
        try ciphertext2.modSwitchDownToSingle()
        let ciphertextDiff2 = try ciphertext1 - ciphertext2

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextDiff1.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: diffData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .coefficient, expected: diffData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextDiff2, format: .coefficient, expected: diffData)
    }

    private func schemeCiphertextCiphertextMultiplicationTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        guard context.supportsSimdEncoding, context.supportsEvaluationKey else {
            return
        }
        let testEnv = try TestEnv(context: context, format: .simd, relinearizationKey: true)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let productData = zip(data1, data2)
            .map { x, y in x.multiplyMod(y, modulus: context.plaintextModulus, variableTime: true) }

        let ciphertext1 = testEnv.ciphertext1
        let ciphertext2 = testEnv.ciphertext2
        let ciphertextProduct = try ciphertext1 * ciphertext2
        var relinearizedProd = ciphertextProduct
        try relinearizedProd.relinearize(using: XCTUnwrap(testEnv.evaluationKey))
        XCTAssertEqual(relinearizedProd.polys.count, Scheme.freshCiphertextPolyCount)

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextProduct.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()
        let evalRelinearizedCiphertext: Ciphertext<Scheme, Eval> = try relinearizedProd.convertToEvalFormat()
        let coeffRelinearizedCiphertext: Ciphertext<Scheme, Coeff> = try evalRelinearizedCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: productData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: productData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextProduct, format: .simd, expected: productData)
        try testEnv.checkDecryptsDecodes(ciphertext: coeffRelinearizedCiphertext, format: .simd, expected: productData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalRelinearizedCiphertext, format: .simd, expected: productData)
    }

    private func schemeCiphertextPlaintextInnerProductTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        for count in [4, 1257] {
            let innerProductData = zip(data1, data2)
                .map { x, y in
                    let t = context.plaintextModulus
                    let xTimesY = x.multiplyMod(y, modulus: t, variableTime: true)
                    return xTimesY.multiplyMod(Scheme.Scalar(count), modulus: t, variableTime: true)
                }
            // no nil type
            do {
                let ciphertexts = Array(repeating: testEnv.evalCiphertext1, count: count)
                let plaintexts = Array(repeating: testEnv.evalPlaintext2, count: count)
                let innerProduct = try ciphertexts.innerProduct(plaintexts: plaintexts)
                try testEnv.checkDecryptsDecodes(ciphertext: innerProduct, format: .simd, expected: innerProductData)
            }
            // no nil values
            do {
                let ciphertexts: [Scheme.EvalCiphertext] = Array(
                    repeating: testEnv.evalCiphertext1,
                    count: count)
                let plaintexts: [Scheme.EvalPlaintext?] = Array(
                    repeating: testEnv.evalPlaintext2,
                    count: count)
                let innerProduct = try XCTUnwrap(ciphertexts.innerProduct(plaintexts: plaintexts))
                try testEnv.checkDecryptsDecodes(ciphertext: innerProduct, format: .simd, expected: innerProductData)
            }
            // some nil values
            do {
                let ciphertexts: [Scheme.EvalCiphertext] = Array(
                    repeating: testEnv.evalCiphertext1,
                    count: count + 1)
                let plaintexts: [Scheme.EvalPlaintext?] = Array(
                    repeating: testEnv.evalPlaintext2,
                    count: count) + [nil]
                let innerProduct = try XCTUnwrap(ciphertexts.innerProduct(plaintexts: plaintexts))
                try testEnv.checkDecryptsDecodes(ciphertext: innerProduct, format: .simd, expected: innerProductData)
            }
        }
    }

    private func schemeCiphertextCiphertextInnerProductTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        for count in [4, 257] {
            let innerProductData = zip(data1, data2)
                .map { x, y in
                    let t = context.plaintextModulus
                    let xTimesY = x.multiplyMod(y, modulus: t, variableTime: true)
                    return xTimesY.multiplyMod(Scheme.Scalar(count), modulus: t, variableTime: true)
                }
            let ciphers1 = Array(repeating: testEnv.ciphertext1, count: count)
            let ciphers2 = Array(repeating: testEnv.ciphertext2, count: count)
            let innerProduct = try ciphers1.innerProduct(ciphertexts: ciphers2)
            try testEnv.checkDecryptsDecodes(ciphertext: innerProduct, format: .simd, expected: innerProductData)
        }
    }

    private func schemeCiphertextCiphertextNilInnerProductTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        for count in [4, 257] {
            let innerProductData = zip(data1, data2)
                .map { x, y in
                    let t = context.plaintextModulus
                    let xTimesY = x.multiplyMod(y, modulus: t, variableTime: true)
                    return xTimesY.multiplyMod(Scheme.Scalar(count), modulus: t, variableTime: true)
                }
            let innerProduct = try Array(repeating: testEnv.ciphertext1, count: count).innerProduct(ciphertexts: Array(
                repeating: testEnv.ciphertext2,
                count: count))

            try testEnv.checkDecryptsDecodes(ciphertext: innerProduct, format: .simd, expected: innerProductData)
        }
    }

    private func schemeCiphertextMultiplyAddTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let multiplyAddData = zip(data1, data2).map { data1, data2 in
            let t = context.plaintextModulus
            return data1.multiplyMod(data2, modulus: t, variableTime: true).addMod(data1, modulus: t)
        }

        let ciphertext1 = testEnv.ciphertext1
        let ciphertext2 = testEnv.ciphertext2
        let ciphertextResult = try ciphertext1 * ciphertext2 + ciphertext1

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplyAddData)
    }

    private func schemeCiphertextMultiplyAddPlainTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let multiplyAddData = zip(data1, data2).map { data1, data2 in
            let t = context.plaintextModulus
            return data1.multiplyMod(data2, modulus: t, variableTime: true).addMod(data1, modulus: t)
        }

        let ciphertext1 = testEnv.ciphertext1
        let ciphertext2 = testEnv.ciphertext2
        let ciphertextResult = try ciphertext1 * ciphertext2 + testEnv.coeffPlaintext1

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplyAddData)
    }

    private func schemeCiphertextMultiplySubTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let multiplySubtractData = zip(data1, data2).map { data1, data2 in
            let t = context.plaintextModulus
            return data1.multiplyMod(data2, modulus: t, variableTime: true).subtractMod(data1, modulus: t)
        }

        let ciphertext1 = testEnv.ciphertext1
        let ciphertext2 = testEnv.ciphertext2
        let ciphertextResult = try ciphertext1 * ciphertext2 - ciphertext1

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplySubtractData)
    }

    private func schemeCiphertextNegateTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let negatedData = testEnv.data1.map { data1 in
            data1.negateMod(modulus: context.plaintextModulus)
        }

        let ciphertextResult = -testEnv.ciphertext1
        let evalCiphertext = -testEnv.evalCiphertext1

        var coeffCiphertext: Ciphertext<Scheme, Coeff> = try testEnv.evalCiphertext1.inverseNtt()
        coeffCiphertext = -coeffCiphertext

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: negatedData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .coefficient, expected: negatedData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .coefficient, expected: negatedData)
    }

    private func schemeCiphertextPlaintextAdditionTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let sumData = zip(data1, data2).map { x, y in x.addMod(y, modulus: context.plaintextModulus) }
        let canonicalCiphertext = testEnv.ciphertext1
        let evalCiphertext: Ciphertext<Scheme, Eval> = try canonicalCiphertext.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()
        let coeffPlaintext = testEnv.coeffPlaintext2
        let evalPlaintext = try coeffPlaintext.forwardNtt()

        // canonicalCiphertext
        do {
            // coeffPlaintext + canonicalCiphertext
            try testEnv.checkDecryptsDecodes(
                ciphertext: coeffPlaintext + canonicalCiphertext,
                format: .simd,
                expected: sumData)

            // canonicalCiphertext + coeffPlaintext
            try testEnv.checkDecryptsDecodes(
                ciphertext: canonicalCiphertext + coeffPlaintext,
                format: .simd,
                expected: sumData)

            // canonicalCiphertext += coeffPlaintext
            do {
                var sum = canonicalCiphertext
                try sum += coeffPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .simd, expected: sumData)
            }

            // evalPlaintext + canonicalCiphertext
            do {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: evalPlaintext + canonicalCiphertext,
                    format: .simd,
                    expected: sumData)
            } catch HeError.unsupportedHeOperation(_) {}

            // canonicalCiphertext + evalPlaintext
            do {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: canonicalCiphertext + evalPlaintext,
                    format: .simd,
                    expected: sumData)
            } catch HeError.unsupportedHeOperation(_) {}

            // canonicalCiphertext += evalPlaintext
            do {
                var sum = canonicalCiphertext
                try sum += evalPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .simd, expected: sumData)
            } catch HeError.unsupportedHeOperation(_) {}
        }

        // coeffCiphertext
        do {
            // coeffPlaintext + coeffCiphertext
            try testEnv.checkDecryptsDecodes(
                ciphertext: coeffPlaintext + coeffCiphertext,
                format: .simd,
                expected: sumData)

            // coeffCiphertext + coeffPlaintext
            try testEnv.checkDecryptsDecodes(
                ciphertext: coeffCiphertext + coeffPlaintext,
                format: .simd,
                expected: sumData)

            // coeffCiphertext += coeffPlaintext
            do {
                var sum = coeffCiphertext
                try sum += coeffPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .simd, expected: sumData)
            }
        }

        // evalCiphertext
        do {
            // evalPlaintext + evalCiphertext
            do {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: evalPlaintext + evalCiphertext,
                    format: .simd,
                    expected: sumData)
            } catch HeError.unsupportedHeOperation(_) {}

            // evalCiphertext + evalPlaintext
            do {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: evalCiphertext + evalPlaintext,
                    format: .simd,
                    expected: sumData)
            } catch HeError.unsupportedHeOperation(_) {}

            // evalCiphertext += evalPlaintext
            do {
                var sum = evalCiphertext
                try sum += evalPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .simd, expected: sumData)
            } catch HeError.unsupportedHeOperation(_) {}
        }
    }

    private func schemeCiphertextPlaintextSubtractionTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let diffData = zip(data1, data2).map { x, y in x.subtractMod(y, modulus: context.plaintextModulus) }
        let canonicalCiphertext = testEnv.ciphertext1
        let evalCiphertext: Ciphertext<Scheme, Eval> = try canonicalCiphertext.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()
        let coeffPlaintext = testEnv.coeffPlaintext2
        let evalPlaintext = try coeffPlaintext.forwardNtt()

        // canonicalCiphertext
        do {
            // canonicalCiphertext - coeffPlaintext
            try testEnv.checkDecryptsDecodes(
                ciphertext: canonicalCiphertext - coeffPlaintext,
                format: .simd,
                expected: diffData)

            // canonicalCiphertext -= coeffPlaintext
            do {
                var diff = canonicalCiphertext
                try diff -= coeffPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .simd, expected: diffData)
            }

            // canonicalCiphertext - evalPlaintext
            do {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: canonicalCiphertext - evalPlaintext,
                    format: .simd,
                    expected: diffData)
            } catch HeError.unsupportedHeOperation(_) {}

            // canonicalCiphertext -= evalPlaintext
            do {
                var diff = canonicalCiphertext
                try diff -= evalPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .simd, expected: diffData)
            } catch HeError.unsupportedHeOperation(_) {}
        }

        // coeffCiphertext
        do {
            // coeffCiphertext - coeffPlaintext
            try testEnv.checkDecryptsDecodes(
                ciphertext: coeffCiphertext - coeffPlaintext,
                format: .simd,
                expected: diffData)

            // coeffCiphertext -= coeffPlaintext
            do {
                var diff = coeffCiphertext
                try diff -= coeffPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .simd, expected: diffData)
            }
        }

        // evalCiphertext
        do {
            // evalCiphertext - evalPlaintext
            do {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: evalCiphertext - evalPlaintext,
                    format: .simd,
                    expected: diffData)
            } catch HeError.unsupportedHeOperation(_) {}

            // evalCiphertext -= evalPlaintext
            do {
                var diff = evalCiphertext
                try diff -= evalPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .simd, expected: diffData)
            } catch HeError.unsupportedHeOperation(_) {}
        }
    }

    private func schemeCiphertextPlaintextMultiplicationTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        var productData = [Scheme.Scalar](repeating: 0, count: context.degree)
        for index in productData.indices {
            productData[index] = data1[index].multiplyMod(
                data2[index],
                modulus: context.plaintextModulus,
                variableTime: true)
        }

        let ciphertext = testEnv.evalCiphertext1
        let evalPlaintext = testEnv.evalPlaintext2

        // cipher * plain
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertext * evalPlaintext, format: .simd, expected: productData)
        // with mod-switch down
        if context.coefficientModuli.count > 2 {
            var ciphertext = testEnv.ciphertext1
            try ciphertext.modSwitchDown()
            let evalCiphertext = try ciphertext.convertToEvalFormat()
            let evalPlaintext = try Scheme.encode(context: testEnv.context,
                                                  values: testEnv.data2,
                                                  format: .simd,
                                                  moduliCount: evalCiphertext.moduli.count)
            try testEnv.checkDecryptsDecodes(
                ciphertext: evalCiphertext * evalPlaintext,
                format: .simd,
                expected: productData)
        }
        // plain * cipher
        try testEnv.checkDecryptsDecodes(
            ciphertext: testEnv.evalCiphertext1 * testEnv.evalPlaintext2,
            format: .simd,
            expected: productData)
    }

    private func schemeRotationTest(context: Context<some HeScheme>) throws {
        guard context.supportsSimdEncoding, context.supportsEvaluationKey else {
            return
        }
        let degree = context.degree
        let galoisElements = try (1..<(context.degree >> 1)).flatMap { step in
            try [
                GaloisElement.rotatingColumns(by: step, degree: degree),
                GaloisElement.rotatingColumns(by: -step, degree: degree),
            ]
        } + [GaloisElement.swappingRows(degree: degree)]
        let testEnv = try TestEnv(context: context, format: .simd, galoisElements: galoisElements)
        let evaluationKey = try XCTUnwrap(testEnv.evaluationKey)
        for step in 1..<min(8, degree / 2) {
            let expectedData = Array(testEnv.data1[degree / 2 - step..<degree / 2] + testEnv
                .data1[0..<degree / 2 - step] + testEnv
                .data1[degree - step..<degree] + testEnv.data1[degree / 2..<degree - step])
            var rotatedCiphertext = testEnv.ciphertext1
            try rotatedCiphertext.rotateColumns(by: step, using: evaluationKey)
            try testEnv.checkDecryptsDecodes(ciphertext: rotatedCiphertext, format: .simd, expected: expectedData)

            try rotatedCiphertext.rotateColumns(by: -step, using: evaluationKey)
            try testEnv.checkDecryptsDecodes(ciphertext: rotatedCiphertext, format: .simd, expected: testEnv.data1)
        }
        let expectedData = Array(testEnv.data1[degree / 2..<degree] + testEnv.data1[0..<degree / 2])
        var ciphertext = testEnv.ciphertext1
        try ciphertext.swapRows(using: evaluationKey)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertext, format: .simd, expected: expectedData)

        try ciphertext.swapRows(using: evaluationKey)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertext, format: .simd, expected: testEnv.data1)
    }

    private func schemeApplyGaloisTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        guard context.supportsSimdEncoding, context.supportsEvaluationKey else {
            return
        }
        let elements = try (1..<min(8, context.degree >> 1)).map { step in
            try GaloisElement.rotatingColumns(by: -step, degree: context.degree)
        }
        let testEnv = try TestEnv(context: context, format: .simd, galoisElements: elements)
        let evaluationKey = try XCTUnwrap(testEnv.evaluationKey)

        let dataCount = testEnv.data1.count
        let halfDataCount = dataCount / 2
        let rotate = { (original: [Scheme.Scalar], step: Int) -> [Scheme.Scalar] in
            Array(original[step..<halfDataCount]) + Array(original[0..<step]) +
                Array(original[step + halfDataCount..<dataCount]) +
                Array(original[halfDataCount..<halfDataCount + step])
        }
        for (step, element) in elements.enumerated() {
            for modSwitchCount in 0...max(0, context.coefficientModuli.count - 2) {
                var rotatedCiphertext = testEnv.ciphertext1
                for _ in 0..<modSwitchCount {
                    try rotatedCiphertext.modSwitchDown()
                }
                try rotatedCiphertext.applyGalois(element: element, using: evaluationKey)
                let expected = rotate(testEnv.data1, step + 1)
                try testEnv.checkDecryptsDecodes(ciphertext: rotatedCiphertext, format: .simd, expected: expected)
            }
        }
    }

    func testNoOpScheme() throws {
        let context: Context<NoOpScheme> = try TestUtils.getTestContext()
        try schemeEncodeDecodeTest(context: context)
        try schemeEncryptDecryptTest(context: context)
        try schemeEncryptZeroDecryptTest(context: context)
        try schemeEncryptZeroAddDecryptTest(context: context)
        try schemeEncryptZeroMultiplyDecryptTest(context: context)
        try schemeSameTypeAdditionTest(context: context)
        try schemeSameTypeSubtractionTest(context: context)
        try schemeCiphertextCiphertextMultiplicationTest(context: context)
        try schemeCiphertextPlaintextAdditionTest(context: context)
        try schemeCiphertextPlaintextSubtractionTest(context: context)
        try schemeCiphertextPlaintextMultiplicationTest(context: context)
        try schemeCiphertextMultiplyAddTest(context: context)
        try schemeCiphertextMultiplyAddPlainTest(context: context)
        try schemeCiphertextMultiplySubTest(context: context)
        try schemeCiphertextNegateTest(context: context)
        try schemeEvaluationKeyTest(context: context)
        try schemeRotationTest(context: context)
        try schemeApplyGaloisTest(context: context)
    }

    private func bfvTestKeySwitching<T>(context: Context<Bfv<T>>) throws {
        guard context.supportsEvaluationKey else {
            return
        }

        let testEnv = try TestEnv(context: context, format: .coefficient)
        let newSecretKey = try Bfv<T>.generateSecretKey(context: context)

        let keySwitchKey = try Bfv<T>.generateKeySwitchKey(context: context,
                                                           currentKey: testEnv.secretKey.poly,
                                                           targetKey: newSecretKey)
        var switchedPolys = try Bfv<T>.computeKeySwitchingUpdate(
            context: context,
            target: testEnv.ciphertext1.polys[1],
            keySwitchingKey: keySwitchKey)
        switchedPolys[0] += testEnv.ciphertext1.polys[0]
        let switchedCiphertext = Ciphertext(context: context, polys: switchedPolys, correctionFactor: 1)
        let plaintext = try Bfv<T>.decrypt(switchedCiphertext, using: newSecretKey)
        let decrypted: [T] = try Bfv<T>.decode(plaintext: plaintext, format: .coefficient)

        XCTAssertEqual(testEnv.data1, decrypted)
    }

    private func bfvNoiseBudgetTest<T>(context: Context<Bfv<T>>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)

        let zeroCoeffCiphertext: Bfv<T>.CoeffCiphertext = try Bfv<T>.zeroCiphertext(
            context: context,
            moduliCount: 1)
        XCTAssertEqual(
            try Bfv<T>.noiseBudget(of: zeroCoeffCiphertext, using: testEnv.secretKey, variableTime: true),
            Double.infinity)
        let zeroEvalCiphertext: Bfv<T>.CoeffCiphertext = try Bfv<T>.zeroCiphertext(
            context: context,
            moduliCount: 1)
        XCTAssertEqual(
            try Bfv<T>.noiseBudget(of: zeroEvalCiphertext, using: testEnv.secretKey, variableTime: true),
            Double.infinity)

        var coeffCiphertext = testEnv.ciphertext1
        var expected = testEnv.coeffPlaintext1
        try coeffCiphertext.modSwitchDownToSingle()
        var ciphertext = try coeffCiphertext.convertToEvalFormat()

        var noiseBudget = try Bfv<T>.noiseBudget(of: ciphertext, using: testEnv.secretKey, variableTime: true)
        XCTAssert(noiseBudget > 0)
        while noiseBudget > Bfv<T>.minNoiseBudget + 1 {
            ciphertext = try ciphertext + ciphertext
            try expected += expected
            let newNoiseBudget = try Bfv<T>.noiseBudget(of: ciphertext, using: testEnv.secretKey, variableTime: true)
            XCTAssertIsClose(newNoiseBudget, noiseBudget - 1)
            noiseBudget = newNoiseBudget

            let decrypted = try Bfv<T>.decrypt(ciphertext, using: testEnv.secretKey)
            XCTAssertEqual(decrypted, expected)
        }
        // Two more decryptions yields incorrect results
        ciphertext = try ciphertext + ciphertext
        ciphertext = try ciphertext + ciphertext
        try expected += expected
        try expected += expected
        let decrypted = try Bfv<T>.decrypt(ciphertext, using: testEnv.secretKey)
        XCTAssertNotEqual(decrypted, expected)
    }

    private func runBfvTests<T: ScalarType>(_: T.Type) throws {
        let predefined: [EncryptionParameters<Bfv<T>>] = try PredefinedRlweParameters.allCases
            .filter { rlweParams in rlweParams.supportsScalar(T.self) }
            .map { rlweParams in
                try EncryptionParameters<Bfv<T>>(from: rlweParams)
            }.filter { encryptParams in
                encryptParams.polyDegree <= 512 // large degrees are slow
            }

        let custom = try EncryptionParameters<Bfv<T>>(
            polyDegree: TestUtils.testPolyDegree,
            plaintextModulus: T
                .generatePrimes(
                    significantBitCounts: [12],
                    preferringSmall: true,
                    nttDegree: TestUtils.testPolyDegree)[0],
            coefficientModuli: testCoefficientModuli(),
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.unchecked)

        for encryptionParams in predefined + [custom] {
            let context = try Context<Bfv<T>>(encryptionParameters: encryptionParams)
            try schemeEncodeDecodeTest(context: context)
            try schemeEncryptDecryptTest(context: context)
            try schemeEncryptZeroDecryptTest(context: context)
            try schemeEncryptZeroAddDecryptTest(context: context)
            try schemeEncryptZeroMultiplyDecryptTest(context: context)
            try schemeSameTypeAdditionTest(context: context)
            try schemeSameTypeSubtractionTest(context: context)
            try schemeCiphertextPlaintextAdditionTest(context: context)
            try schemeCiphertextPlaintextSubtractionTest(context: context)
            try schemeCiphertextPlaintextMultiplicationTest(context: context)
            try schemeCiphertextMultiplyAddPlainTest(context: context)
            try schemeCiphertextCiphertextMultiplicationTest(context: context)
            try schemeCiphertextPlaintextInnerProductTest(context: context)
            try schemeCiphertextCiphertextInnerProductTest(context: context)
            try schemeCiphertextMultiplyAddTest(context: context)
            try schemeCiphertextNegateTest(context: context)
            try schemeEvaluationKeyTest(context: context)
            try schemeApplyGaloisTest(context: context)
            try schemeRotationTest(context: context)
            try bfvTestKeySwitching(context: context)
            try bfvNoiseBudgetTest(context: context)
        }
    }

    func testBfvUInt32() throws {
        try runBfvTests(UInt32.self)
    }

    func testBfvUInt64() throws {
        try runBfvTests(UInt64.self)
    }
}
