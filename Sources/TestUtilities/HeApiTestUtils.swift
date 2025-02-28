// Copyright 2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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

import HomomorphicEncryption
import XCTest

/// A collection of helpers for HeScheme level API tests.
public enum HeAPITestHelpers {
    /// Test environment with plaintexts and ciphertexts ready for use
    public struct TestEnv<Scheme: HeScheme> {
        /// Context for testing.
        public let context: Context<Scheme>
        /// Raw data for first plaintext/ciphertext
        public let data1: [Scheme.Scalar]
        /// Raw data fro second plaintext/ciphertext
        public let data2: [Scheme.Scalar]
        /// First plaintext in coeff format.
        public let coeffPlaintext1: Plaintext<Scheme, Coeff>
        /// Second plaintext in coeff format.
        public let coeffPlaintext2: Plaintext<Scheme, Coeff>
        /// First plaintext in eval format.
        public let evalPlaintext1: Plaintext<Scheme, Eval>
        /// Second plaintext in eval format.
        public let evalPlaintext2: Plaintext<Scheme, Eval>
        /// First ciphertext in canonical format.
        public let ciphertext1: Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>
        /// Second ciphertext in canonical format.
        public let ciphertext2: Ciphertext<Scheme, Scheme.CanonicalCiphertextFormat>
        /// First ciphertext in eval format.
        public let evalCiphertext1: Ciphertext<Scheme, Eval>
        /// Secret key for testing.
        public let secretKey: SecretKey<Scheme>
        /// Evaluation key for testing.
        public let evaluationKey: EvaluationKey<Scheme>?

        /// Create the test environment.
        public init(
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
            let evaluationKeyConfig = EvaluationKeyConfig(
                galoisElements: galoisElements,
                hasRelinearizationKey: true)
            self.evaluationKey = if context.supportsEvaluationKey, !galoisElements.isEmpty || relinearizationKey {
                try context.generateEvaluationKey(config: evaluationKeyConfig, using: secretKey)
            } else {
                nil
            }
        }

        /// Check if the ciphertext decrypts to the expected result.
        public func checkDecryptsDecodes(
            ciphertext: Ciphertext<Scheme, some PolyFormat>,
            format: EncodeFormat,
            expected: [Scheme.Scalar],
            _ message: @autoclosure () -> String = "",
            _ file: StaticString = #filePath,
            _ line: UInt = #line) throws
        {
            if let coeffCiphertext = ciphertext as? Scheme.CoeffCiphertext {
                let decryptedData: [Scheme.Scalar] = try coeffCiphertext.decrypt(using: secretKey)
                    .decode(format: format)
                XCTAssertEqual(decryptedData, expected, message(), file: file, line: line)
            } else if let evalCiphertext = ciphertext as? Scheme.EvalCiphertext {
                let decryptedData: [Scheme.Scalar] = try evalCiphertext.decrypt(using: secretKey)
                    .decode(format: format)
                XCTAssertEqual(decryptedData, expected, message(), file: file, line: line)
            } else {
                XCTFail("\(message()) Invalid ciphertext \(ciphertext.description)", file: file, line: line)
            }
        }
    }

    /// generate the coefficient moduli for test
    public static func testCoefficientModuli<T: ScalarType>() throws -> [T] {
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

    /// generate the context for test
    public static func getTestContext<Scheme: HeScheme>() throws -> Context<Scheme> {
        try Context<Scheme>(encryptionParameters: EncryptionParameters(
            polyDegree: TestUtils.testPolyDegree,
            plaintextModulus: Scheme.Scalar(TestUtils.testPlaintextModulus),
            coefficientModuli: testCoefficientModuli(),
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.unchecked))
    }

    /// test the evaluation key configuration
    public static func schemeEvaluationKeyTest(context _: Context<some HeScheme>) throws {
        do {
            let config = EvaluationKeyConfig()
            XCTAssertFalse(config.hasRelinearizationKey)
            XCTAssertEqual(config.galoisElements, [])
            XCTAssertEqual(config.keyCount, 0)
        }
        do {
            let config = EvaluationKeyConfig(hasRelinearizationKey: true)
            XCTAssertTrue(config.hasRelinearizationKey)
            XCTAssertEqual(config.galoisElements, [])
            XCTAssertEqual(config.keyCount, 1)
        }
        do {
            let config = EvaluationKeyConfig(galoisElements: [1, 3], hasRelinearizationKey: true)
            XCTAssertTrue(config.hasRelinearizationKey)
            XCTAssertEqual(config.galoisElements, [1, 3])
            XCTAssertEqual(config.keyCount, 3)
        }
    }

    static func encodingTest<Scheme: HeScheme>(
        context: Context<Scheme>,
        encodeFormat: EncodeFormat,
        polyFormat: (some PolyFormat).Type,
        valueCount: Int) throws
    {
        guard context.supportsSimdEncoding || encodeFormat != .simd else {
            return
        }
        let data = TestUtils.getRandomPlaintextData(
            count: valueCount,
            in: 0..<Scheme.Scalar(context.plaintextModulus))
        var signedData = data.map { v in
            v.remainderToCentered(modulus: context.plaintextModulus)
        }
        let paddedData = data + repeatElement(0, count: context.degree - data.count)
        let paddedSignedData = signedData + repeatElement(0, count: context.degree - data.count)

        switch polyFormat {
        case is Coeff.Type:
            let plaintextCoeff: Plaintext<Scheme, Coeff> = try context.encode(values: data, format: encodeFormat)
            let decoded = try plaintextCoeff.decode(format: encodeFormat) as [Scheme.Scalar]
            XCTAssertEqual(decoded, paddedData)

            let decodedSigned: [Scheme.SignedScalar] = try plaintextCoeff.decode(format: encodeFormat)
            XCTAssertEqual(decodedSigned, paddedSignedData)

            let plaintextCoeffSigned: Plaintext<Scheme, Coeff> = try context.encode(
                signedValues: signedData,
                format: encodeFormat)
            let roundTrip: [Scheme.SignedScalar] = try plaintextCoeffSigned.decode(
                format: encodeFormat)
            XCTAssertEqual(roundTrip, paddedSignedData)
        case is Eval.Type:
            let plaintextEval: Plaintext<Scheme, Eval> = try context.encode(values: data, format: encodeFormat)
            let decoded = try plaintextEval.decode(format: encodeFormat) as [Scheme.Scalar]
            XCTAssertEqual(decoded, paddedData)

            let decodedSigned: [Scheme.SignedScalar] = try plaintextEval.decode(format: encodeFormat)
            XCTAssertEqual(decodedSigned, paddedSignedData)

            let plaintextEvalSigned: Plaintext<Scheme, Eval> = try context.encode(
                signedValues: signedData,
                format: encodeFormat)
            let roundTrip: [Scheme.SignedScalar] = try plaintextEvalSigned.decode(format: encodeFormat)
            XCTAssertEqual(roundTrip, paddedSignedData)
        default:
            XCTFail("Invalid PolyFormat \(polyFormat)")
        }
        signedData[0] = (Scheme.SignedScalar(context.plaintextModulus) - 1) / 2 + 1
        XCTAssertThrowsError(try context.encode(signedValues: signedData, format: encodeFormat))
        signedData[0] = -Scheme.SignedScalar(context.plaintextModulus) / 2 - 1
        XCTAssertThrowsError(try context.encode(signedValues: signedData, format: encodeFormat))
    }

    /// Testing the encoding/decoding functions of the scheme.
    public static func schemeEncodeDecodeTest(context: Context<some HeScheme>) throws {
        for encodeFormat in EncodeFormat.allCases {
            for polyFormat: PolyFormat.Type in [Coeff.self, Eval.self] {
                for valueCount in [context.degree / 2, context.degree] {
                    try encodingTest(
                        context: context,
                        encodeFormat: encodeFormat,
                        polyFormat: polyFormat,
                        valueCount: valueCount)
                }
            }
        }
    }

    /// Testing the encryption and decryption of the scheme.
    public static func schemeEncryptDecryptTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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

    /// Testing zero-ciphertext generation of the scheme.
    public static func schemeEncryptZeroDecryptTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let zeros = [Scheme.Scalar](repeating: 0, count: context.degree)

        let coeffCiphertext = try Ciphertext<Scheme, Coeff>.zero(context: context)
        let evalCiphertext = try Ciphertext<Scheme, Eval>.zero(context: context)
        var canonicalCiphertext = try coeffCiphertext.convertToCanonicalFormat()
        try canonicalCiphertext.modSwitchDownToSingle()

        XCTAssert(coeffCiphertext.isTransparent())
        XCTAssert(evalCiphertext.isTransparent())
        XCTAssert(canonicalCiphertext.isTransparent())

        let zeroPlaintext: Scheme.CoeffPlaintext = try context.encode(values: zeros, format: .coefficient)
        let nonTransparentZero = try zeroPlaintext.encrypt(using: testEnv.secretKey)
        if Scheme.self != NoOpScheme.self {
            XCTAssertFalse(nonTransparentZero.isTransparent())
        }

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: zeros)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .coefficient, expected: zeros)
        try testEnv.checkDecryptsDecodes(ciphertext: canonicalCiphertext, format: .coefficient, expected: zeros)
    }

    /// Testing addition with zero-ciphertext of the scheme.
    public static func schemeEncryptZeroAddDecryptTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let expected = [Scheme.Scalar](repeating: 0, count: context.degree)

        let zeroCoeffCiphertext = try Ciphertext<Scheme, Coeff>.zero(context: context)
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

    /// Testing multiplication with zero-ciphertext of the scheme.
    public static func schemeEncryptZeroMultiplyDecryptTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let expected = [Scheme.Scalar](repeating: 0, count: context.degree)

        let zeroCiphertext = try Ciphertext<Scheme, Eval>.zero(context: context)
        let product = try zeroCiphertext * testEnv.evalPlaintext1
        XCTAssert(product.isTransparent())

        try testEnv.checkDecryptsDecodes(ciphertext: product, format: .coefficient, expected: expected)
    }

    /// Testing ciphertext addition of the scheme.
    public static func schemeCiphertextAddTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let sumData = zip(data1, data2).map { x, y in x.addMod(y, modulus: context.plaintextModulus) }

        let canonicalCipher1 = testEnv.ciphertext1
        let canonicalCipher2 = testEnv.ciphertext2
        let evalCipher1 = try canonicalCipher1.convertToEvalFormat()
        let evalCipher2 = try canonicalCipher2.convertToEvalFormat()
        let coeffCipher1 = try canonicalCipher1.convertToCoeffFormat()
        let coeffCipher2 = try canonicalCipher2.convertToCoeffFormat()

        // canonicalCiphertext
        do {
            // canonicalCiphertext + canonicalCiphertext
            try testEnv.checkDecryptsDecodes(
                ciphertext: canonicalCipher1 + canonicalCipher2,
                format: .coefficient,
                expected: sumData)

            // canonicalCiphertext += canonicalCiphertext
            do {
                var sum = canonicalCipher1
                try sum += canonicalCipher2
                try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .coefficient, expected: sumData)
            }

            // canonicalCiphertext + coeffCiphertext
            if Scheme.CanonicalCiphertextFormat.self == Coeff.self {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: canonicalCipher1 + coeffCipher2,
                    format: .coefficient,
                    expected: sumData)

                // canonicalCiphertext += coeffCipherrtext
                do {
                    var sum = canonicalCipher1
                    try sum += coeffCipher2
                    try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .coefficient, expected: sumData)
                }
            }
            // canonicalCiphertext + evalCiphertext
            if Scheme.CanonicalCiphertextFormat.self == Eval.self {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: canonicalCipher1 + evalCipher2,
                    format: .coefficient,
                    expected: sumData)

                // canonicalCiphertext += evalCiphertext
                do {
                    var sum = canonicalCipher1
                    try sum += evalCipher2
                    try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .coefficient, expected: sumData)
                }
            }
        }

        // coeffCiphertext
        do {
            // coeffCiphertext + coeffCiphertext
            try testEnv.checkDecryptsDecodes(
                ciphertext: coeffCipher1 + coeffCipher2,
                format: .coefficient,
                expected: sumData)

            // coeffCiphertext + coeffCiphertext
            do {
                var sum = coeffCipher1
                try sum += coeffCipher2
                try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .coefficient, expected: sumData)
            }
        }

        // evalCiphertext
        do {
            // evalCiphertext + evalCiphertext
            try testEnv.checkDecryptsDecodes(
                ciphertext: evalCipher1 + evalCipher2,
                format: .coefficient,
                expected: sumData)

            // evalCiphertext += evalCiphertext
            do {
                var sum = evalCipher1
                try sum += evalCipher2
                try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .coefficient, expected: sumData)
            }
        }
    }

    /// Testing ciphertext subtraction of the scheme.
    public static func schemeCiphertextSubtractTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let diffData = zip(data1, data2).map { x, y in x.subtractMod(y, modulus: context.plaintextModulus) }

        let canonicalCipher1 = testEnv.ciphertext1
        let canonicalCipher2 = testEnv.ciphertext2
        let evalCipher1 = try canonicalCipher1.convertToEvalFormat()
        let evalCipher2 = try canonicalCipher2.convertToEvalFormat()
        let coeffCipher1 = try canonicalCipher1.convertToCoeffFormat()
        let coeffCipher2 = try canonicalCipher2.convertToCoeffFormat()

        // canonicalCiphertext
        do {
            // canonicalCiphertext - canonicalCiphertext
            try testEnv.checkDecryptsDecodes(
                ciphertext: canonicalCipher1 - canonicalCipher2,
                format: .coefficient,
                expected: diffData)

            // canonicalCiphertext -= canonicalCiphertext
            do {
                var diff = canonicalCipher1
                try diff -= canonicalCipher2
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .coefficient, expected: diffData)
            }

            // canonicalCiphertext - coeffCiphertext
            if Scheme.CanonicalCiphertextFormat.self == Coeff.self {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: canonicalCipher1 - coeffCipher2,
                    format: .coefficient,
                    expected: diffData)

                // canonicalCiphertext -= coeffCipherrtext
                do {
                    var diff = canonicalCipher1
                    try diff -= coeffCipher2
                    try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .coefficient, expected: diffData)
                }
            }
            // canonicalCiphertext - evalCiphertext
            if Scheme.CanonicalCiphertextFormat.self == Eval.self {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: canonicalCipher1 - evalCipher2,
                    format: .coefficient,
                    expected: diffData)

                // canonicalCiphertext -= evalCiphertext
                do {
                    var diff = canonicalCipher1
                    try diff -= evalCipher2
                    try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .coefficient, expected: diffData)
                }
            }
        }

        // coeffCiphertext
        do {
            // coeffCiphertext - coeffCiphertext
            try testEnv.checkDecryptsDecodes(
                ciphertext: coeffCipher1 - coeffCipher2,
                format: .coefficient,
                expected: diffData)

            // coeffCiphertext -= coeffCiphertext
            do {
                var diff = coeffCipher1
                try diff -= coeffCipher2
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .coefficient, expected: diffData)
            }
        }

        // evalCiphertext
        do {
            // evalCiphertext - evalCiphertext
            try testEnv.checkDecryptsDecodes(
                ciphertext: evalCipher1 - evalCipher2,
                format: .coefficient,
                expected: diffData)

            // evalCiphertext -= evalCiphertext
            do {
                var diff = evalCipher1
                try diff -= evalCipher2
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .coefficient, expected: diffData)
            }
        }
    }

    /// testing ciphertext multiplication of the scheme.
    public static func schemeCiphertextCiphertextMultiplyTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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

    /// Testing CT-PT inner product of the scheme.
    public static func schemeCiphertextPlaintextInnerProductTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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

    /// Testing CT-CT inner product of the scheme.
    public static func schemeCiphertextCiphertextInnerProductTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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

    /// Testing CT-CT inner product with nil of the scheme.
    public static func schemeCiphertextCiphertextNilInnerProductTest<Scheme: HeScheme>(
        context: Context<Scheme>) throws
    {
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

    /// Testing CT-CT multiplication followed by CT-CT addition of the scheme.
    public static func schemeCiphertextMultiplyAddTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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

    /// Testing CT-CT multiplication followed by CT-PT addition of the scheme.
    public static func schemeCiphertextMultiplyAddPlainTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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

    /// Testing CT-CT multiplication followed by CT-CT subtraction of the scheme.
    public static func schemeCiphertextMultiplySubtractTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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

    /// Testing CT-CT multiplication followed by CT-PT subtraction of the scheme.
    public static func schemeCiphertextMultiplySubtractPlainTest<Scheme: HeScheme>(
        context: Context<Scheme>) throws
    {
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
        let ciphertextResult = try ciphertext1 * ciphertext2 - testEnv.coeffPlaintext1

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplySubtractData)
    }

    /// Testing CT-PT multiplication followed by CT-PT addition of the scheme.
    public static func schemeCiphertextPlaintextMultiplyAddPlainTest<Scheme: HeScheme>(
        context: Context<Scheme>) throws
    {
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

        let ciphertext1 = testEnv.evalCiphertext1
        let ciphertextEvalResult = try ciphertext1 * testEnv.evalPlaintext2
        var ciphertextResult = try ciphertextEvalResult.inverseNtt()
        try ciphertextResult += testEnv.coeffPlaintext1

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplyAddData)
    }

    /// Testing CT-PT multiplication followed by CT-PT subtraction of the scheme.
    public static func schemeCiphertextPlaintextMultiplySubtractPlainTest<Scheme: HeScheme>(
        context: Context<Scheme>) throws
    {
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

        let ciphertext1 = testEnv.evalCiphertext1
        let ciphertextEvalResult = try ciphertext1 * testEnv.evalPlaintext2
        var ciphertextResult = try ciphertextEvalResult.inverseNtt()
        try ciphertextResult -= testEnv.coeffPlaintext1

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplySubtractData)
    }

    /// Testing ciphertext negation of the scheme.
    public static func schemeCiphertextNegateTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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

    /// Testing CT-PT addition of the scheme.
    public static func schemeCiphertextPlaintextAddTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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

    /// Testing CT-PT subtraction of the scheme.
    public static func schemeCiphertextPlaintextSubtractTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let diff1Minus2Data = zip(data1, data2).map { x, y in x.subtractMod(y, modulus: context.plaintextModulus) }
        let diff2Minus1Data = zip(data2, data1).map { x, y in x.subtractMod(y, modulus: context.plaintextModulus) }
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
                expected: diff1Minus2Data)

            // canonicalCiphertext -= coeffPlaintext
            do {
                var diff = canonicalCiphertext
                try diff -= coeffPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .simd, expected: diff1Minus2Data)
            }

            // canonicalCiphertext - evalPlaintext
            do {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: canonicalCiphertext - evalPlaintext,
                    format: .simd,
                    expected: diff1Minus2Data)
            } catch HeError.unsupportedHeOperation(_) {}

            // canonicalCiphertext -= evalPlaintext
            do {
                var diff = canonicalCiphertext
                try diff -= evalPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .simd, expected: diff1Minus2Data)
            } catch HeError.unsupportedHeOperation(_) {}

            // coeffPlaintext - canonicalCiphertext
            try testEnv.checkDecryptsDecodes(
                ciphertext: coeffPlaintext - canonicalCiphertext,
                format: .simd,
                expected: diff2Minus1Data)

            // evalPlaintext - canonicalCiphertext
            do {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: evalPlaintext - canonicalCiphertext,
                    format: .simd,
                    expected: diff2Minus1Data)
            } catch HeError.unsupportedHeOperation(_) {}
        }

        // coeffCiphertext
        do {
            // coeffCiphertext - coeffPlaintext
            try testEnv.checkDecryptsDecodes(
                ciphertext: coeffCiphertext - coeffPlaintext,
                format: .simd,
                expected: diff1Minus2Data)

            // coeffCiphertext -= coeffPlaintext
            do {
                var diff = coeffCiphertext
                try diff -= coeffPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .simd, expected: diff1Minus2Data)
            }
        }

        // evalCiphertext
        do {
            // evalCiphertext - evalPlaintext
            do {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: evalCiphertext - evalPlaintext,
                    format: .simd,
                    expected: diff1Minus2Data)
            } catch HeError.unsupportedHeOperation(_) {}

            // evalCiphertext -= evalPlaintext
            do {
                var diff = evalCiphertext
                try diff -= evalPlaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .simd, expected: diff1Minus2Data)
            } catch HeError.unsupportedHeOperation(_) {}

            // evalPlaintext - evalCiphertext
            do {
                try testEnv.checkDecryptsDecodes(
                    ciphertext: evalPlaintext - evalCiphertext,
                    format: .simd,
                    expected: diff2Minus1Data)
            } catch HeError.unsupportedHeOperation(_) {}
        }
    }

    /// Testing CT-PT multiplication of the scheme.
    public static func schemeCiphertextPlaintextMultiplyTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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
            let evalPlaintext = try testEnv.context.encode(
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

    /// Testign ciphertext rotation of the scheme.
    public static func schemeRotationTest(context: Context<some HeScheme>) throws {
        func runRotationTest(context: Context<some HeScheme>, galoisElements: [Int], multiStep: Bool) throws {
            let degree = context.degree
            let testEnv = try TestEnv(context: context, format: .simd, galoisElements: galoisElements)
            let evaluationKey = try XCTUnwrap(testEnv.evaluationKey)
            for step in 1..<min(8, degree / 2) {
                let expectedData = Array(testEnv.data1[degree / 2 - step..<degree / 2] + testEnv
                    .data1[0..<degree / 2 - step] + testEnv
                    .data1[degree - step..<degree] + testEnv.data1[degree / 2..<degree - step])
                var rotatedCiphertext = testEnv.ciphertext1
                if multiStep {
                    try rotatedCiphertext.rotateColumnsMultiStep(by: step, using: evaluationKey)
                } else {
                    try rotatedCiphertext.rotateColumns(by: step, using: evaluationKey)
                }
                try testEnv.checkDecryptsDecodes(ciphertext: rotatedCiphertext, format: .simd, expected: expectedData)

                if multiStep {
                    try rotatedCiphertext.rotateColumnsMultiStep(by: -step, using: evaluationKey)
                } else {
                    try rotatedCiphertext.rotateColumns(by: -step, using: evaluationKey)
                }
                try testEnv.checkDecryptsDecodes(ciphertext: rotatedCiphertext, format: .simd, expected: testEnv.data1)
            }
        }

        guard context.supportsSimdEncoding, context.supportsEvaluationKey else {
            return
        }

        let degree = context.degree
        let galoisElementsSwap = [GaloisElement.swappingRows(degree: degree)]
        let testEnv = try TestEnv(context: context, format: .simd, galoisElements: galoisElementsSwap)
        let evaluationKey = try XCTUnwrap(testEnv.evaluationKey)
        let expectedData = Array(testEnv.data1[degree / 2..<degree] + testEnv.data1[0..<degree / 2])
        var ciphertext = testEnv.ciphertext1
        try ciphertext.swapRows(using: evaluationKey)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertext, format: .simd, expected: expectedData)

        try ciphertext.swapRows(using: evaluationKey)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertext, format: .simd, expected: testEnv.data1)

        let galoisElementsRotate = try (1..<(degree >> 1)).flatMap { step in
            try [
                GaloisElement.rotatingColumns(by: step, degree: degree),
                GaloisElement.rotatingColumns(by: -step, degree: degree),
            ]
        }
        let galoisElementsMultiStep = try GaloisElement.rotatingColumnsMultiStep(degree: degree)

        try runRotationTest(context: context, galoisElements: galoisElementsRotate, multiStep: false)
        try runRotationTest(context: context, galoisElements: galoisElementsMultiStep, multiStep: true)
    }

    /// Testing apply Galois element of the scheme.
    public static func schemeApplyGaloisTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
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
}
