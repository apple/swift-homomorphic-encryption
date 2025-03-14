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

import HomomorphicEncryption
import Testing

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
            _ comment: Comment? = nil,
            sourceLocation: SourceLocation = #_sourceLocation) throws
        {
            if let coeffCiphertext = ciphertext as? Scheme.CoeffCiphertext {
                let decryptedData: [Scheme.Scalar] = try coeffCiphertext.decrypt(using: secretKey)
                    .decode(format: format)
                #expect(decryptedData == expected, comment, sourceLocation: sourceLocation)
            } else if let evalCiphertext = ciphertext as? Scheme.EvalCiphertext {
                let decryptedData: [Scheme.Scalar] = try evalCiphertext.decrypt(using: secretKey)
                    .decode(format: format)
                #expect(decryptedData == expected, comment, sourceLocation: sourceLocation)
            } else {
                let commentString = comment.map { "\($0.rawValue). " } ?? ""
                Issue.record("\(commentString)Invalid ciphertext \(ciphertext.description)",
                             sourceLocation: sourceLocation)
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
            #expect(!config.hasRelinearizationKey)
            #expect(config.galoisElements.isEmpty)
            #expect(config.keyCount == 0)
        }
        do {
            let config = EvaluationKeyConfig(hasRelinearizationKey: true)
            #expect(config.hasRelinearizationKey)
            #expect(config.galoisElements.isEmpty)
            #expect(config.keyCount == 1)
        }
        do {
            let config = EvaluationKeyConfig(galoisElements: [1, 3], hasRelinearizationKey: true)
            #expect(config.hasRelinearizationKey)
            #expect(config.galoisElements == [1, 3])
            #expect(config.keyCount == 3)
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
            #expect(decoded == paddedData)

            let decodedSigned: [Scheme.SignedScalar] = try plaintextCoeff.decode(format: encodeFormat)
            #expect(decodedSigned == paddedSignedData)

            let plaintextCoeffSigned: Plaintext<Scheme, Coeff> = try context.encode(
                signedValues: signedData,
                format: encodeFormat)
            let roundTrip: [Scheme.SignedScalar] = try plaintextCoeffSigned.decode(
                format: encodeFormat)
            #expect(roundTrip == paddedSignedData)
        case is Eval.Type:
            let plaintextEval: Plaintext<Scheme, Eval> = try context.encode(values: data, format: encodeFormat)
            let decoded = try plaintextEval.decode(format: encodeFormat) as [Scheme.Scalar]
            #expect(decoded == paddedData)

            let decodedSigned: [Scheme.SignedScalar] = try plaintextEval.decode(format: encodeFormat)
            #expect(decodedSigned == paddedSignedData)

            let plaintextEvalSigned: Plaintext<Scheme, Eval> = try context.encode(
                signedValues: signedData,
                format: encodeFormat)
            let roundTrip: [Scheme.SignedScalar] = try plaintextEvalSigned.decode(format: encodeFormat)
            #expect(roundTrip == paddedSignedData)
        default:
            Issue.record("Invalid PolyFormat \(polyFormat)")
        }

        let signedModulus = Int64(context.plaintextModulus)
        let bounds = -(signedModulus >> 1)...((signedModulus - 1) >> 1)
        signedData[0] = (Scheme.SignedScalar(context.plaintextModulus) - 1) / 2 + 1
        #expect(throws: HeError.encodingDataOutOfBounds(bounds).self) {
            try context.encode(signedValues: signedData, format: encodeFormat)
        }
        signedData[0] = -Scheme.SignedScalar(context.plaintextModulus) / 2 - 1
        #expect(throws: HeError.encodingDataOutOfBounds(bounds).self) {
            try context.encode(signedValues: signedData, format: encodeFormat)
        }
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

        #expect(coeffCiphertext.isTransparent())
        #expect(evalCiphertext.isTransparent())
        #expect(canonicalCiphertext.isTransparent())

        let zeroPlaintext: Scheme.CoeffPlaintext = try context.encode(values: zeros, format: .coefficient)
        let nonTransparentZero = try zeroPlaintext.encrypt(using: testEnv.secretKey)
        if Scheme.self != NoOpScheme.self {
            #expect(!nonTransparentZero.isTransparent())
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

        #expect(sum1.isTransparent())
        if Scheme.self != NoOpScheme.self {
            #expect(!sum2.isTransparent())
        }
        #expect(sum3.isTransparent())

        try testEnv.checkDecryptsDecodes(ciphertext: sum1, format: .coefficient, expected: expected)
        try testEnv.checkDecryptsDecodes(ciphertext: sum2, format: .coefficient, expected: testEnv.data1)
        #expect(try sum3.decrypt(using: testEnv.secretKey) == testEnv.coeffPlaintext1)
    }

    /// Testing multiplication with zero-ciphertext of the scheme.
    public static func schemeEncryptZeroMultiplyDecryptTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let expected = [Scheme.Scalar](repeating: 0, count: context.degree)

        let zeroCiphertext = try Ciphertext<Scheme, Eval>.zero(context: context)
        let product = try zeroCiphertext * testEnv.evalPlaintext1
        #expect(product.isTransparent())

        try testEnv.checkDecryptsDecodes(ciphertext: product, format: .coefficient, expected: expected)
    }

    /// Testing ciphertext addition of the scheme.
    public static func schemeCiphertextAddTest<Scheme: HeScheme>(context: Context<Scheme>) async throws {
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

        func syncTest() throws {
            func runTest(lhs: Ciphertext<Scheme, some PolyFormat>, rhs: Ciphertext<Scheme, some PolyFormat>) throws {
                let sum = try lhs + rhs
                var lhs = lhs
                try lhs += rhs

                try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .coefficient, expected: sumData)
                try testEnv.checkDecryptsDecodes(ciphertext: lhs, format: .coefficient, expected: sumData)
            }

            // canonicalCiphertext
            do {
                try runTest(lhs: canonicalCipher1, rhs: canonicalCipher2)
                if Scheme.CanonicalCiphertextFormat.self == Coeff.self {
                    try runTest(lhs: canonicalCipher1, rhs: coeffCipher2)
                }
                // canonicalCiphertext + evalCiphertext
                if Scheme.CanonicalCiphertextFormat.self == Eval.self {
                    try runTest(lhs: canonicalCipher1, rhs: evalCipher2)
                }
            }

            // coeffCiphertext
            try runTest(lhs: coeffCipher1, rhs: coeffCipher2)
            // evalCiphertext
            try runTest(lhs: evalCipher1, rhs: evalCipher2)
        }
        try syncTest()

        func asyncTest() async throws {
            func runTest(
                lhs: Ciphertext<Scheme, some PolyFormat>,
                rhs: Ciphertext<Scheme, some PolyFormat>) async throws
            {
                let sum = try await lhs + rhs
                var lhs = lhs
                try await lhs += rhs

                try testEnv.checkDecryptsDecodes(ciphertext: sum, format: .coefficient, expected: sumData)
                try testEnv.checkDecryptsDecodes(ciphertext: lhs, format: .coefficient, expected: sumData)
            }

            // canonicalCiphertext
            do {
                try await runTest(lhs: canonicalCipher1, rhs: canonicalCipher2)
                if Scheme.CanonicalCiphertextFormat.self == Coeff.self {
                    try await runTest(lhs: canonicalCipher1, rhs: coeffCipher2)
                }
                // canonicalCiphertext + evalCiphertext
                if Scheme.CanonicalCiphertextFormat.self == Eval.self {
                    try await runTest(lhs: canonicalCipher1, rhs: evalCipher2)
                }
            }

            // coeffCiphertext
            try await runTest(lhs: coeffCipher1, rhs: coeffCipher2)
            // evalCiphertext
            try await runTest(lhs: evalCipher1, rhs: evalCipher2)
        }
        try await asyncTest()
    }

    /// Testing ciphertext subtraction of the scheme.
    public static func schemeCiphertextSubtractTest<Scheme: HeScheme>(context: Context<Scheme>) async throws {
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

        func syncTest() throws {
            func runTest(lhs: Ciphertext<Scheme, some PolyFormat>, rhs: Ciphertext<Scheme, some PolyFormat>) throws {
                let diff = try lhs - rhs
                var lhs = lhs
                try lhs -= rhs

                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .coefficient, expected: diffData)
                try testEnv.checkDecryptsDecodes(ciphertext: lhs, format: .coefficient, expected: diffData)
            }

            // canonicalCiphertext
            do {
                try runTest(lhs: canonicalCipher1, rhs: canonicalCipher2)
                if Scheme.CanonicalCiphertextFormat.self == Coeff.self {
                    try runTest(lhs: canonicalCipher1, rhs: coeffCipher2)
                }
                // canonicalCiphertext + evalCiphertext
                if Scheme.CanonicalCiphertextFormat.self == Eval.self {
                    try runTest(lhs: canonicalCipher1, rhs: evalCipher2)
                }
            }

            // coeffCiphertext
            try runTest(lhs: coeffCipher1, rhs: coeffCipher2)
            // evalCiphertext
            try runTest(lhs: evalCipher1, rhs: evalCipher2)
        }
        try syncTest()

        func asyncTest() async throws {
            func runTest(
                lhs: Ciphertext<Scheme, some PolyFormat>,
                rhs: Ciphertext<Scheme, some PolyFormat>) async throws
            {
                let diff = try await lhs - rhs
                var lhs = lhs
                try await lhs -= rhs

                try testEnv.checkDecryptsDecodes(ciphertext: diff, format: .coefficient, expected: diffData)
                try testEnv.checkDecryptsDecodes(ciphertext: lhs, format: .coefficient, expected: diffData)
            }

            // canonicalCiphertext
            do {
                try await runTest(lhs: canonicalCipher1, rhs: canonicalCipher2)
                if Scheme.CanonicalCiphertextFormat.self == Coeff.self {
                    try await runTest(lhs: canonicalCipher1, rhs: coeffCipher2)
                }
                // canonicalCiphertext + evalCiphertext
                if Scheme.CanonicalCiphertextFormat.self == Eval.self {
                    try await runTest(lhs: canonicalCipher1, rhs: evalCipher2)
                }
            }

            // coeffCiphertext
            try await runTest(lhs: coeffCipher1, rhs: coeffCipher2)
            // evalCiphertext
            try await runTest(lhs: evalCipher1, rhs: evalCipher2)
        }
        try await asyncTest()
    }

    /// testing ciphertext multiplication of the scheme.
    public static func schemeCiphertextCiphertextMultiplyTest<Scheme: HeScheme>(
        context: Context<Scheme>) async throws
    {
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
        var ciphertextProductAsync = ciphertext1
        try await Scheme.mulAssignAsync(&ciphertextProductAsync, ciphertext2)
        var relinearizedProd = ciphertextProduct
        try relinearizedProd.relinearize(using: #require(testEnv.evaluationKey))
        var relinearizedProdAsync = ciphertextProductAsync
        try await Scheme.relinearizeAsync(&relinearizedProdAsync, using: #require(testEnv.evaluationKey))
        #expect(relinearizedProd.polys.count == Scheme.freshCiphertextPolyCount)
        #expect(relinearizedProdAsync.polys.count == Scheme.freshCiphertextPolyCount)

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextProduct.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()
        let evalRelinearizedCiphertext: Ciphertext<Scheme, Eval> = try relinearizedProd.convertToEvalFormat()
        let coeffRelinearizedCiphertext: Ciphertext<Scheme, Coeff> = try evalRelinearizedCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: productData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: productData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextProduct, format: .simd, expected: productData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextProductAsync, format: .simd, expected: productData)
        try testEnv.checkDecryptsDecodes(ciphertext: coeffRelinearizedCiphertext, format: .simd, expected: productData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalRelinearizedCiphertext, format: .simd, expected: productData)
    }

    /// Testing CT-PT inner product of the scheme.
    public static func schemeCiphertextPlaintextInnerProductTest<Scheme: HeScheme>(
        context: Context<Scheme>) async throws
    {
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

                let innerProductAsync = try await Scheme.innerProductAsync(
                    ciphertexts: ciphertexts,
                    plaintexts: plaintexts)
                try testEnv.checkDecryptsDecodes(
                    ciphertext: innerProductAsync,
                    format: .simd,
                    expected: innerProductData)
            }
            // no nil values
            do {
                let ciphertexts: [Scheme.EvalCiphertext] = Array(
                    repeating: testEnv.evalCiphertext1,
                    count: count)
                let plaintexts: [Scheme.EvalPlaintext?] = Array(
                    repeating: testEnv.evalPlaintext2,
                    count: count)
                let innerProduct = try ciphertexts.innerProduct(plaintexts: plaintexts)
                try testEnv.checkDecryptsDecodes(ciphertext: innerProduct, format: .simd, expected: innerProductData)

                let innerProductAsync = try await Scheme.innerProductAsync(
                    ciphertexts: ciphertexts,
                    plaintexts: plaintexts)
                try testEnv.checkDecryptsDecodes(
                    ciphertext: innerProductAsync,
                    format: .simd,
                    expected: innerProductData)
            }
            // some nil values
            do {
                let ciphertexts: [Scheme.EvalCiphertext] = Array(
                    repeating: testEnv.evalCiphertext1,
                    count: count + 1)
                let plaintexts: [Scheme.EvalPlaintext?] = Array(
                    repeating: testEnv.evalPlaintext2,
                    count: count) + [nil]
                let innerProduct = try ciphertexts.innerProduct(plaintexts: plaintexts)
                try testEnv.checkDecryptsDecodes(ciphertext: innerProduct, format: .simd, expected: innerProductData)

                let innerProductAsync = try await Scheme.innerProductAsync(
                    ciphertexts: ciphertexts,
                    plaintexts: plaintexts)
                try testEnv.checkDecryptsDecodes(
                    ciphertext: innerProductAsync,
                    format: .simd,
                    expected: innerProductData)
            }
        }
    }

    /// Testing CT-CT inner product of the scheme.
    public static func schemeCiphertextCiphertextInnerProductTest<Scheme: HeScheme>(
        context: Context<Scheme>) async throws
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
            let ciphers1 = Array(repeating: testEnv.ciphertext1, count: count)
            let ciphers2 = Array(repeating: testEnv.ciphertext2, count: count)
            let innerProduct = try ciphers1.innerProduct(ciphertexts: ciphers2)
            let innerProductAsync = try await Scheme.innerProductAsync(ciphers1, ciphers2)
            try testEnv.checkDecryptsDecodes(ciphertext: innerProduct, format: .simd, expected: innerProductData)
            try testEnv.checkDecryptsDecodes(ciphertext: innerProductAsync, format: .simd, expected: innerProductData)
        }
    }

    /// Testing CT-CT multiplication followed by CT-CT addition of the scheme.
    public static func schemeCiphertextMultiplyAddTest<Scheme: HeScheme>(context: Context<Scheme>) async throws {
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

        func syncTest() throws {
            let ciphertextResult = try ciphertext1 * ciphertext2 + ciphertext1

            let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
            let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplyAddData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplyAddData)
            try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplyAddData)
        }
        try syncTest()

        func asyncTest() async throws {
            var ciphertextResult = ciphertext1
            try await Scheme.mulAssignAsync(&ciphertextResult, ciphertext2)
            try await ciphertextResult += ciphertext1

            let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
            let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplyAddData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplyAddData)
            try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplyAddData)
        }
        try await asyncTest()
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

    /// Testing CT-CT multiplication followed by CT-PT subtraction of the scheme.
    public static func schemeCiphertextMultiplySubtractPlainTest<Scheme: HeScheme>(
        context: Context<Scheme>) async throws
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

        func syncTest() throws {
            let ciphertext1 = testEnv.ciphertext1
            let ciphertext2 = testEnv.ciphertext2
            let ciphertextResult = try ciphertext1 * ciphertext2 - testEnv.coeffPlaintext1

            let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
            let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(
                ciphertext: ciphertextResult,
                format: .simd,
                expected: multiplySubtractData)
        }
        try syncTest()

        func asyncTest() async throws {
            let ciphertext1 = testEnv.ciphertext1
            let ciphertext2 = testEnv.ciphertext2
            var ciphertextResult = ciphertext1
            try await Scheme.mulAssignAsync(&ciphertextResult, ciphertext2)
            try await ciphertextResult -= testEnv.coeffPlaintext1

            let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
            let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(
                ciphertext: ciphertextResult,
                format: .simd,
                expected: multiplySubtractData)
        }
        try await asyncTest()
    }

    /// Testing CT-PT multiplication followed by CT-PT addition of the scheme.
    public static func schemeCiphertextPlaintextMultiplyAddPlainTest<Scheme: HeScheme>(
        context: Context<Scheme>) async throws
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

        func syncTest() throws {
            let ciphertextEvalResult = try ciphertext1 * testEnv.evalPlaintext2
            var ciphertextResult = try ciphertextEvalResult.inverseNtt()
            try ciphertextResult += testEnv.coeffPlaintext1

            let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
            let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplyAddData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplyAddData)
            try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplyAddData)
        }
        try syncTest()

        func asyncTest() async throws {
            var ciphertextEvalResult = ciphertext1
            try await Scheme.mulAssignAsync(&ciphertextEvalResult, testEnv.evalPlaintext2)
            var ciphertextResult = try await Scheme.inverseNttAsync(ciphertextEvalResult)
            try await ciphertextResult += testEnv.coeffPlaintext1

            let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
            let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplyAddData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplyAddData)
            try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplyAddData)
        }
        try await asyncTest()
    }

    /// Testing CT-PT multiplication followed by CT-PT subtraction of the scheme.
    public static func schemeCiphertextPlaintextMultiplySubtractPlainTest<Scheme: HeScheme>(
        context: Context<Scheme>) async throws
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

        func syncTest() throws {
            let ciphertextEvalResult = try testEnv.evalCiphertext1 * testEnv.evalPlaintext2
            var ciphertextResult = try ciphertextEvalResult.inverseNtt()
            try ciphertextResult -= testEnv.coeffPlaintext1

            let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
            let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(
                ciphertext: ciphertextResult,
                format: .simd,
                expected: multiplySubtractData)
        }
        try syncTest()

        func asyncTest() async throws {
            var ciphertextEvalResult = testEnv.evalCiphertext1
            try await Scheme.mulAssignAsync(&ciphertextEvalResult, testEnv.evalPlaintext2)
            var ciphertextResult = try await Scheme.inverseNttAsync(ciphertextEvalResult)
            try await Scheme.subAssignCoeffAsync(&ciphertextResult, testEnv.coeffPlaintext1)

            let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
            let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(
                ciphertext: ciphertextResult,
                format: .simd,
                expected: multiplySubtractData)
        }
        try await asyncTest()
    }

    /// Testing CT-CT multiplication followed by CT-CT subtraction of the scheme.
    public static func schemeCiphertextMultiplySubtractTest<Scheme: HeScheme>(context: Context<Scheme>) async throws {
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

        func syncTest() throws {
            let ciphertext1 = testEnv.ciphertext1
            let ciphertext2 = testEnv.ciphertext2
            let ciphertextResult = try ciphertext1 * ciphertext2 - ciphertext1

            let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
            let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(
                ciphertext: ciphertextResult,
                format: .simd,
                expected: multiplySubtractData)
        }
        try syncTest()

        func asyncTest() async throws {
            let ciphertext1 = testEnv.ciphertext1
            let ciphertext2 = testEnv.ciphertext2
            var ciphertextResult = ciphertext1
            try await Scheme.mulAssignAsync(&ciphertextResult, ciphertext2)
            try await ciphertextResult -= ciphertext1

            let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
            let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
            try testEnv.checkDecryptsDecodes(
                ciphertext: ciphertextResult,
                format: .simd,
                expected: multiplySubtractData)
        }
        try await asyncTest()
    }

    /// Testing ciphertext negation of the scheme.
    public static func schemeCiphertextNegateTest<Scheme: HeScheme>(context: Context<Scheme>) async throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)
        let negatedData = testEnv.data1.map { data1 in
            data1.negateMod(modulus: context.plaintextModulus)
        }

        func syncTest() throws {
            let ciphertextResult = -testEnv.ciphertext1
            let evalCiphertext = -testEnv.evalCiphertext1

            var coeffCiphertext: Ciphertext<Scheme, Coeff> = try testEnv.evalCiphertext1.inverseNtt()
            coeffCiphertext = -coeffCiphertext

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: negatedData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .coefficient, expected: negatedData)
            try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .coefficient, expected: negatedData)
        }
        try syncTest()

        func asyncTest() async throws {
            let ciphertextResult = await -testEnv.ciphertext1
            let evalCiphertext = await -testEnv.evalCiphertext1

            var coeffCiphertext: Ciphertext<Scheme, Coeff> = try testEnv.evalCiphertext1.inverseNtt()
            coeffCiphertext = await -coeffCiphertext

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: negatedData)
            try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .coefficient, expected: negatedData)
            try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .coefficient, expected: negatedData)
        }
        try await asyncTest()
    }

    /// Testing cipherterxt-plaintext addition.
    public static func schemeCiphertextPlaintextAddTest<Scheme: HeScheme>(context: Context<Scheme>) async throws {
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

        func syncTest() throws {
            func runTest(
                ciphertext: Ciphertext<Scheme, some PolyFormat>,
                plaintext: Plaintext<Scheme, some PolyFormat>) throws
            {
                let sum1 = try ciphertext + plaintext
                let sum2 = try plaintext + ciphertext

                var sum3 = ciphertext
                try sum3 += plaintext

                try testEnv.checkDecryptsDecodes(ciphertext: sum1, format: .simd, expected: sumData)
                try testEnv.checkDecryptsDecodes(ciphertext: sum2, format: .simd, expected: sumData)
                try testEnv.checkDecryptsDecodes(ciphertext: sum3, format: .simd, expected: sumData)
            }
            try runTest(ciphertext: canonicalCiphertext, plaintext: coeffPlaintext)
            try runTest(ciphertext: coeffCiphertext, plaintext: coeffPlaintext)

            func checkUnsupported(
                ciphertext: Ciphertext<Scheme, some PolyFormat>,
                plaintext: Plaintext<Scheme, some PolyFormat>) throws
            {
                do { _ = try ciphertext + plaintext } catch HeError.unsupportedHeOperation(_) {}

                do { _ = try plaintext + ciphertext } catch HeError.unsupportedHeOperation(_) {}

                do {
                    var ciphertext = ciphertext
                    try ciphertext += plaintext
                } catch HeError.unsupportedHeOperation(_) {}
            }
            try checkUnsupported(ciphertext: canonicalCiphertext, plaintext: evalPlaintext)
            try checkUnsupported(ciphertext: evalCiphertext, plaintext: evalPlaintext)
        }
        try syncTest()

        func asyncTest() async throws {
            func runTest(
                ciphertext: Ciphertext<Scheme, some PolyFormat>,
                plaintext: Plaintext<Scheme, some PolyFormat>) async throws
            {
                let sum1 = try await ciphertext + plaintext
                let sum2 = try await plaintext + ciphertext

                var sum3 = ciphertext
                try await sum3 += plaintext

                try testEnv.checkDecryptsDecodes(ciphertext: sum1, format: .simd, expected: sumData)
                try testEnv.checkDecryptsDecodes(ciphertext: sum2, format: .simd, expected: sumData)
                try testEnv.checkDecryptsDecodes(ciphertext: sum3, format: .simd, expected: sumData)
            }
            try await runTest(ciphertext: canonicalCiphertext, plaintext: coeffPlaintext)
            try await runTest(ciphertext: coeffCiphertext, plaintext: coeffPlaintext)

            func checkUnsupported(
                ciphertext: Ciphertext<Scheme, some PolyFormat>,
                plaintext: Plaintext<Scheme, some PolyFormat>) async throws
            {
                do { _ = try await ciphertext + plaintext } catch HeError.unsupportedHeOperation(_) {}

                do { _ = try await plaintext + ciphertext } catch HeError.unsupportedHeOperation(_) {}

                do {
                    var ciphertext = ciphertext
                    try await ciphertext += plaintext
                } catch HeError.unsupportedHeOperation(_) {}
            }
            try await checkUnsupported(ciphertext: canonicalCiphertext, plaintext: evalPlaintext)
            try await checkUnsupported(ciphertext: evalCiphertext, plaintext: evalPlaintext)
        }
        try await asyncTest()
    }

    /// Testing CT-PT subtraction of the scheme.
    public static func schemeCiphertextPlaintextSubtractTest<Scheme: HeScheme>(
        context: Context<Scheme>) async throws
    {
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

        func syncTest() throws {
            func runTest(
                ciphertext: Ciphertext<Scheme, some PolyFormat>,
                plaintext: Plaintext<Scheme, some PolyFormat>) throws
            {
                let diff1 = try ciphertext - plaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff1, format: .simd, expected: diff1Minus2Data)

                var diff2 = ciphertext
                try diff2 -= plaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff2, format: .simd, expected: diff1Minus2Data)

                let diff3 = try plaintext - ciphertext
                try testEnv.checkDecryptsDecodes(ciphertext: diff3, format: .simd, expected: diff2Minus1Data)
            }
            try runTest(ciphertext: canonicalCiphertext, plaintext: coeffPlaintext)
            try runTest(ciphertext: coeffCiphertext, plaintext: coeffPlaintext)

            func checkUnsupported(
                ciphertext: Ciphertext<Scheme, some PolyFormat>,
                plaintext: Plaintext<Scheme, some PolyFormat>) throws
            {
                do { _ = try ciphertext - plaintext } catch HeError.unsupportedHeOperation(_) {}
                do {
                    var ciphertext = ciphertext
                    try ciphertext -= plaintext
                } catch HeError.unsupportedHeOperation(_) {}

                do { _ = try plaintext - ciphertext } catch HeError.unsupportedHeOperation(_) {}
            }
            try checkUnsupported(ciphertext: canonicalCiphertext, plaintext: evalPlaintext)
            try checkUnsupported(ciphertext: evalCiphertext, plaintext: evalPlaintext)
        }
        try syncTest()

        func asyncTest() async throws {
            func runTest(
                ciphertext: Ciphertext<Scheme, some PolyFormat>,
                plaintext: Plaintext<Scheme, some PolyFormat>) async throws
            {
                let diff1 = try await ciphertext - plaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff1, format: .simd, expected: diff1Minus2Data)

                var diff2 = ciphertext
                try await diff2 -= plaintext
                try testEnv.checkDecryptsDecodes(ciphertext: diff2, format: .simd, expected: diff1Minus2Data)

                let diff3 = try await plaintext - ciphertext
                try testEnv.checkDecryptsDecodes(ciphertext: diff3, format: .simd, expected: diff2Minus1Data)
            }
            try await runTest(ciphertext: canonicalCiphertext, plaintext: coeffPlaintext)
            try await runTest(ciphertext: coeffCiphertext, plaintext: coeffPlaintext)

            func checkUnsupported(
                ciphertext: Ciphertext<Scheme, some PolyFormat>,
                plaintext: Plaintext<Scheme, some PolyFormat>) async throws
            {
                do { _ = try await ciphertext - plaintext } catch HeError.unsupportedHeOperation(_) {}

                do {
                    var ciphertext = ciphertext
                    try await ciphertext -= plaintext
                } catch HeError.unsupportedHeOperation(_) {}

                do { _ = try await plaintext - ciphertext } catch HeError.unsupportedHeOperation(_) {}
            }
            try await checkUnsupported(ciphertext: canonicalCiphertext, plaintext: evalPlaintext)
            try await checkUnsupported(ciphertext: evalCiphertext, plaintext: evalPlaintext)
        }
        try await asyncTest()
    }

    /// Testing CT-PT multiplication of the scheme.
    public static func schemeCiphertextPlaintextMultiplyTest<Scheme: HeScheme>(
        context: Context<Scheme>) async throws
    {
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

        var productAsync = ciphertext
        try await Scheme.mulAssignAsync(&productAsync, evalPlaintext)
        // cipher * plain
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertext * evalPlaintext, format: .simd, expected: productData)

        try testEnv.checkDecryptsDecodes(ciphertext: productAsync, format: .simd, expected: productData)
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

            var ciphertextAsync = testEnv.ciphertext1
            try await Scheme.modSwitchDownAsync(&ciphertextAsync)
            var evalCiphertextAsync = try ciphertextAsync.convertToEvalFormat()
            try await Scheme.mulAssignAsync(&evalCiphertextAsync, evalPlaintext)
            try testEnv.checkDecryptsDecodes(
                ciphertext: evalCiphertextAsync,
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
    public static func schemeRotationTest<Scheme: HeScheme>(context: Context<Scheme>) async throws {
        func runRotationTest(context: Context<Scheme>, galoisElements: [Int], multiStep: Bool) async throws {
            let degree = context.degree
            let testEnv = try TestEnv(context: context, format: .simd, galoisElements: galoisElements)
            let evaluationKey = try #require(testEnv.evaluationKey)
            for step in 1..<min(8, degree / 2) {
                let expectedData = Array(testEnv.data1[degree / 2 - step..<degree / 2] + testEnv
                    .data1[0..<degree / 2 - step] + testEnv
                    .data1[degree - step..<degree] + testEnv.data1[degree / 2..<degree - step])
                var rotatedCiphertext = testEnv.ciphertext1
                var rotatedCiphertextAsync = testEnv.ciphertext1
                if multiStep {
                    try rotatedCiphertext.rotateColumnsMultiStep(by: step, using: evaluationKey)
                    try await Scheme.rotateColumnsMultiStepAsync(
                        of: &rotatedCiphertextAsync,
                        by: step,
                        using: evaluationKey)
                } else {
                    try rotatedCiphertext.rotateColumns(by: step, using: evaluationKey)
                    try await Scheme.rotateColumnsAsync(of: &rotatedCiphertextAsync, by: step, using: evaluationKey)
                }
                try testEnv.checkDecryptsDecodes(ciphertext: rotatedCiphertext, format: .simd, expected: expectedData)
                try testEnv.checkDecryptsDecodes(
                    ciphertext: rotatedCiphertextAsync,
                    format: .simd,
                    expected: expectedData)

                if multiStep {
                    try rotatedCiphertext.rotateColumnsMultiStep(by: -step, using: evaluationKey)
                    try await Scheme.rotateColumnsMultiStepAsync(
                        of: &rotatedCiphertextAsync,
                        by: -step,
                        using: evaluationKey)
                } else {
                    try rotatedCiphertext.rotateColumns(by: -step, using: evaluationKey)
                    try await Scheme.rotateColumnsAsync(of: &rotatedCiphertextAsync, by: -step, using: evaluationKey)
                }
                try testEnv.checkDecryptsDecodes(ciphertext: rotatedCiphertext, format: .simd, expected: testEnv.data1)
                try testEnv.checkDecryptsDecodes(
                    ciphertext: rotatedCiphertextAsync,
                    format: .simd,
                    expected: testEnv.data1)
            }
        }

        guard context.supportsSimdEncoding, context.supportsEvaluationKey else {
            return
        }

        let degree = context.degree
        let galoisElementsSwap = [GaloisElement.swappingRows(degree: degree)]
        let testEnv = try TestEnv(context: context, format: .simd, galoisElements: galoisElementsSwap)
        let evaluationKey = try #require(testEnv.evaluationKey)
        let expectedData = Array(testEnv.data1[degree / 2..<degree] + testEnv.data1[0..<degree / 2])
        var ciphertext = testEnv.ciphertext1
        var ciphertextAsync = ciphertext

        try ciphertext.swapRows(using: evaluationKey)
        try await Scheme.swapRowsAsync(of: &ciphertextAsync, using: evaluationKey)

        try testEnv.checkDecryptsDecodes(ciphertext: ciphertext, format: .simd, expected: expectedData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextAsync, format: .simd, expected: expectedData)

        try ciphertext.swapRows(using: evaluationKey)
        try await Scheme.swapRowsAsync(of: &ciphertextAsync, using: evaluationKey)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertext, format: .simd, expected: testEnv.data1)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextAsync, format: .simd, expected: testEnv.data1)

        let galoisElementsRotate = try (1..<(degree >> 1)).flatMap { step in
            try [
                GaloisElement.rotatingColumns(by: step, degree: degree),
                GaloisElement.rotatingColumns(by: -step, degree: degree),
            ]
        }
        let galoisElementsMultiStep = try GaloisElement.rotatingColumnsMultiStep(degree: degree)

        try await runRotationTest(context: context, galoisElements: galoisElementsRotate, multiStep: false)
        try await runRotationTest(context: context, galoisElements: galoisElementsMultiStep, multiStep: true)
    }

    /// Testing apply Galois element of the scheme.
    public static func schemeApplyGaloisTest<Scheme: HeScheme>(context: Context<Scheme>) async throws {
        guard context.supportsSimdEncoding, context.supportsEvaluationKey else {
            return
        }
        let elements = try (1..<min(8, context.degree >> 1)).map { step in
            try GaloisElement.rotatingColumns(by: -step, degree: context.degree)
        }
        let testEnv = try TestEnv(context: context, format: .simd, galoisElements: elements)
        let evaluationKey = try #require(testEnv.evaluationKey)

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
                var rotatedCiphertextAsync = testEnv.ciphertext1

                for _ in 0..<modSwitchCount {
                    try rotatedCiphertext.modSwitchDown()
                    try await Scheme.modSwitchDownAsync(&rotatedCiphertextAsync)
                }
                try rotatedCiphertext.applyGalois(element: element, using: evaluationKey)
                try await Scheme.applyGaloisAsync(
                    ciphertext: &rotatedCiphertextAsync,
                    element: element,
                    using: evaluationKey)
                let expected = rotate(testEnv.data1, step + 1)
                try testEnv.checkDecryptsDecodes(ciphertext: rotatedCiphertext, format: .simd, expected: expected)
                try testEnv.checkDecryptsDecodes(ciphertext: rotatedCiphertextAsync, format: .simd, expected: expected)
            }
        }
    }

    /// testing noise budget estimation.
    public static func noiseBudgetTest<Scheme: HeScheme>(context: Context<Scheme>) throws {
        let testEnv = try TestEnv(context: context, format: .coefficient)

        let zeroCoeffCiphertext = try Scheme.CoeffCiphertext.zero(context: context, moduliCount: 1)
        #expect(try zeroCoeffCiphertext.noiseBudget(using: testEnv.secretKey, variableTime: true) == Double.infinity)
        let zeroEvalCiphertext = try Scheme.EvalCiphertext.zero(context: context, moduliCount: 1)
        #expect(try zeroEvalCiphertext.noiseBudget(using: testEnv.secretKey, variableTime: true) == Double.infinity)

        var coeffCiphertext = testEnv.ciphertext1
        var expected = testEnv.coeffPlaintext1
        try coeffCiphertext.modSwitchDownToSingle()
        var ciphertext = try coeffCiphertext.convertToEvalFormat()

        var noiseBudget = try ciphertext.noiseBudget(using: testEnv.secretKey, variableTime: true)
        #expect(noiseBudget > 0)

        let coeffNoiseBudget = try ciphertext.convertToCoeffFormat().noiseBudget(
            using: testEnv.secretKey,
            variableTime: true)
        let canonicalNoiseBudget = try ciphertext.convertToCanonicalFormat().noiseBudget(
            using: testEnv.secretKey,
            variableTime: true)
        #expect(coeffNoiseBudget == noiseBudget)
        #expect(canonicalNoiseBudget == noiseBudget)

        while noiseBudget > Scheme.minNoiseBudget + 1 {
            ciphertext = try ciphertext + ciphertext
            try expected += expected
            let newNoiseBudget = try ciphertext.noiseBudget(using: testEnv.secretKey, variableTime: true)
            #expect(newNoiseBudget.isClose(to: noiseBudget - 1))
            noiseBudget = newNoiseBudget

            let decrypted = try ciphertext.decrypt(using: testEnv.secretKey)
            #expect(decrypted == expected)
        }
        // Two more additions yields incorrect results
        ciphertext = try ciphertext + ciphertext
        ciphertext = try ciphertext + ciphertext
        try expected += expected
        try expected += expected
        let decrypted = try ciphertext.decrypt(using: testEnv.secretKey)
        #expect(decrypted != expected)
    }

    /// testing repeated addition.
    public static func repeatedAdditionTest<Scheme: HeScheme>(context: Context<Scheme>) async throws {
        let testEnv = try HeAPITestHelpers.TestEnv<Scheme>(context: context, format: .coefficient)
        let expected = testEnv.data1.map { num in
            num.multiplyMod(Scheme.Scalar(5), modulus: testEnv.context.plaintextModulus, variableTime: true)
        }

        func syncTest() throws {
            var coeffCiphertext = try testEnv.ciphertext1.convertToCoeffFormat()
            try coeffCiphertext += testEnv.coeffPlaintext1
            try coeffCiphertext += testEnv.ciphertext1
            try coeffCiphertext += testEnv.coeffPlaintext1
            try coeffCiphertext += testEnv.ciphertext1

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: expected)
        }
        try syncTest()

        func asyncTest() async throws {
            var coeffCiphertext = try testEnv.ciphertext1.convertToCoeffFormat()
            try await coeffCiphertext += testEnv.coeffPlaintext1
            try await coeffCiphertext += testEnv.ciphertext1
            try await coeffCiphertext += testEnv.coeffPlaintext1
            try await coeffCiphertext += testEnv.ciphertext1

            try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: expected)
        }
        try await asyncTest()
    }

    /// testing multiply inverse power of x.
    public static func multiplyInverseTest<Scheme: HeScheme>(context: Context<Scheme>) async throws {
        let testEnv = try HeAPITestHelpers.TestEnv<Scheme>(context: context, format: .coefficient)

        var coeffCiphertext1 = try testEnv.ciphertext1.convertToCoeffFormat()
        var coeffCiphertext2 = coeffCiphertext1
        var coeffCiphertext3 = coeffCiphertext1
        var coeffCiphertext4 = coeffCiphertext1
        let degree = context.degree
        let plaintextModulus = context.plaintextModulus
        let power1 = Int.random(in: 0..<degree)
        let power2 = Int.random(in: degree..<(degree << 1))
        try Scheme.multiplyInversePowerOfX(&coeffCiphertext1, power: power1)
        try Scheme.multiplyInversePowerOfX(&coeffCiphertext2, power: power2)
        try await Scheme.multiplyInversePowerOfXAsync(&coeffCiphertext3, power: power1)
        try await Scheme.multiplyInversePowerOfXAsync(&coeffCiphertext4, power: power2)

        let expectedData1 = Array(testEnv.data1[power1..<degree] + testEnv.data1[0..<power1]
            .map { $0.negateMod(modulus: plaintextModulus) })
        let expectedData2 = Array(testEnv.data1[(power2 - degree)..<degree]
            .map { $0.negateMod(modulus: plaintextModulus) } + testEnv.data1[0..<(power2 - degree)])

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext1, format: .coefficient, expected: expectedData1)
        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext2, format: .coefficient, expected: expectedData2)
        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext3, format: .coefficient, expected: expectedData1)
        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext4, format: .coefficient, expected: expectedData2)
    }
}
