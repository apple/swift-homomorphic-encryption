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
import ModularArithmetic
import Testing

/// A collection of helpers for HeScheme level API tests.
public enum HeAPITestHelpers {
    /// Test environment with plaintexts and ciphertexts ready for use
    public struct TestEnv<Scheme: HeScheme> {
        /// Context for testing.
        public let context: Context<Scheme.Scalar>
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
            context: Context<Scheme.Scalar>,
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
    public static func getTestContext<Scalar: ScalarType>() throws -> Context<Scalar> {
        try Context<Scalar>(encryptionParameters: EncryptionParameters(
            polyDegree: TestUtils.testPolyDegree,
            plaintextModulus: Scalar(TestUtils.testPlaintextModulus),
            coefficientModuli: testCoefficientModuli(),
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.unchecked))
    }

    /// test the evaluation key configuration
    public static func schemeEvaluationKeyTest(context _: Context<some ScalarType>) throws {
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

    @inlinable
    static func encodingTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        encodeFormat: EncodeFormat,
        polyFormat: (some PolyFormat).Type,
        valueCount: Int,
        scheme _: Scheme.Type) throws
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
            let _: Plaintext<Scheme, Coeff> = try context.encode(signedValues: signedData, format: encodeFormat)
        }
        signedData[0] = -Scheme.SignedScalar(context.plaintextModulus) / 2 - 1
        #expect(throws: HeError.encodingDataOutOfBounds(bounds).self) {
            let _: Plaintext<Scheme, Coeff> = try context.encode(signedValues: signedData, format: encodeFormat)
        }
    }

    /// Testing the encoding/decoding functions of the scheme.
    @inlinable
    public static func schemeEncodeDecodeTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme: Scheme.Type) throws
    {
        for encodeFormat in EncodeFormat.allCases {
            for polyFormat: PolyFormat.Type in [Coeff.self, Eval.self] {
                for valueCount in [context.degree / 2, context.degree] {
                    try encodingTest(
                        context: context,
                        encodeFormat: encodeFormat,
                        polyFormat: polyFormat,
                        valueCount: valueCount, scheme: scheme)
                }
            }
        }
    }

    /// Testing the encryption and decryption of the scheme.
    @inlinable
    public static func schemeEncryptDecryptTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) throws
    {
        let testEnv = try TestEnv<Scheme>(context: context, format: .coefficient)
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
    @inlinable
    public static func schemeEncryptZeroDecryptTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) throws
    {
        let testEnv = try TestEnv<Scheme>(context: context, format: .coefficient)
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
    @inlinable
    public static func schemeEncryptZeroAddDecryptTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) throws
    {
        let testEnv = try TestEnv<Scheme>(context: context, format: .coefficient)
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
    @inlinable
    public static func schemeEncryptZeroMultiplyDecryptTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) throws
    {
        let testEnv = try TestEnv<Scheme>(context: context, format: .coefficient)
        let expected = [Scheme.Scalar](repeating: 0, count: context.degree)

        let zeroCiphertext = try Ciphertext<Scheme, Eval>.zero(context: context)
        let product = try zeroCiphertext * testEnv.evalPlaintext1
        #expect(product.isTransparent())

        try testEnv.checkDecryptsDecodes(ciphertext: product, format: .coefficient, expected: expected)
    }

    /// Testing ciphertext addition of the scheme.
    @inlinable
    public static func schemeCiphertextAddTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) async throws
    {
        let testEnv = try TestEnv<Scheme>(context: context, format: .coefficient)
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
                var sumAsync = canonicalCipher1
                try await Scheme.addAssignAsync(&sumAsync, canonicalCipher2)
                try testEnv.checkDecryptsDecodes(ciphertext: sumAsync, format: .coefficient, expected: sumData)
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

                var sumAsync = coeffCipher1
                try await Scheme.addAssignCoeffAsync(&sumAsync, coeffCipher2)
                try testEnv.checkDecryptsDecodes(ciphertext: sumAsync, format: .coefficient, expected: sumData)
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

                var sumAsync = evalCipher1
                try await Scheme.addAssignEvalAsync(&sumAsync, evalCipher2)
                try testEnv.checkDecryptsDecodes(ciphertext: sumAsync, format: .coefficient, expected: sumData)
            }
        }
    }

    /// Testing ciphertext subtraction of the scheme.
    @inlinable
    public static func schemeCiphertextSubtractTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) async throws
    {
        let testEnv = try TestEnv<Scheme>(context: context, format: .coefficient)
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

                var diffAsync = canonicalCipher1
                try await Scheme.subAssignAsync(&diffAsync, canonicalCipher2)
                try testEnv.checkDecryptsDecodes(ciphertext: diffAsync, format: .coefficient, expected: diffData)
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

                var diffAsync = coeffCipher1
                try await Scheme.subAssignCoeffAsync(&diffAsync, coeffCipher2)
                try testEnv.checkDecryptsDecodes(ciphertext: diffAsync, format: .coefficient, expected: diffData)
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

                var diffAsync = evalCipher1
                try await Scheme.subAssignEvalAsync(&diffAsync, evalCipher2)
                try testEnv.checkDecryptsDecodes(ciphertext: diffAsync, format: .coefficient, expected: diffData)
            }
        }
    }

    /// testing ciphertext multiplication of the scheme.
    @inlinable
    public static func schemeCiphertextCiphertextMultiplyTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>, scheme _: Scheme.Type) async throws
    {
        guard context.supportsSimdEncoding, context.supportsEvaluationKey else {
            return
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd, relinearizationKey: true)
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
    @inlinable
    public static func schemeCiphertextPlaintextInnerProductTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>, scheme _: Scheme.Type) async throws
    {
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
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
    @inlinable
    public static func schemeCiphertextCiphertextInnerProductTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>, scheme _: Scheme.Type) async throws
    {
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
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
    @inlinable
    public static func schemeCiphertextMultiplyAddTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) async throws
    {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let multiplyAddData = zip(data1, data2).map { data1, data2 in
            let t = context.plaintextModulus
            return data1.multiplyMod(data2, modulus: t, variableTime: true).addMod(data1, modulus: t)
        }

        let ciphertext1 = testEnv.ciphertext1
        let ciphertext2 = testEnv.ciphertext2
        let ciphertextResult = try ciphertext1 * ciphertext2 + ciphertext1

        var ciphertextResultAsync = ciphertext1
        try await Scheme.mulAssignAsync(&ciphertextResultAsync, ciphertext2)
        try await Scheme.addAssignAsync(&ciphertextResultAsync, ciphertext1)

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResultAsync, format: .simd, expected: multiplyAddData)
    }

    /// Testing CT-CT multiplication followed by CT-PT addition of the scheme.
    @inlinable
    public static func schemeCiphertextMultiplyAddPlainTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) throws
    {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
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
    @inlinable
    public static func schemeCiphertextMultiplySubtractPlainTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>, scheme _: Scheme.Type) async throws
    {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let multiplySubtractData = zip(data1, data2).map { data1, data2 in
            let t = context.plaintextModulus
            return data1.multiplyMod(data2, modulus: t, variableTime: true).subtractMod(data1, modulus: t)
        }

        let ciphertext1 = testEnv.ciphertext1
        let ciphertext2 = testEnv.ciphertext2
        let ciphertextResult = try ciphertext1 * ciphertext2 - testEnv.coeffPlaintext1

        var ciphertextResultAsync = ciphertext1
        try await Scheme.mulAssignAsync(&ciphertextResultAsync, ciphertext2)
        try await Scheme.subAssignAsync(&ciphertextResultAsync, testEnv.coeffPlaintext1)

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(
            ciphertext: ciphertextResultAsync,
            format: .simd,
            expected: multiplySubtractData)
    }

    /// Testing CT-PT multiplication followed by CT-PT addition of the scheme.
    @inlinable
    public static func schemeCiphertextPlaintextMultiplyAddPlainTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>, scheme _: Scheme.Type) async throws
    {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
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

        var ciphertextEvalResultAsync = ciphertext1
        try await Scheme.mulAssignAsync(&ciphertextEvalResultAsync, testEnv.evalPlaintext2)
        var ciphertextResultAsync = try await Scheme.inverseNttAsync(ciphertextEvalResultAsync)
        try await Scheme.addAssignCoeffAsync(&ciphertextResultAsync, testEnv.coeffPlaintext1)

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplyAddData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResultAsync, format: .simd, expected: multiplyAddData)
    }

    /// Testing CT-PT multiplication followed by CT-PT subtraction of the scheme.
    @inlinable
    public static func schemeCiphertextPlaintextMultiplySubtractPlainTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>, scheme _: Scheme.Type) async throws
    {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
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

        var ciphertextEvalResultAsync = ciphertext1
        try await Scheme.mulAssignAsync(&ciphertextEvalResultAsync, testEnv.evalPlaintext2)
        var ciphertextResultAsync = try await Scheme.inverseNttAsync(ciphertextEvalResultAsync)
        try await Scheme.subAssignCoeffAsync(&ciphertextResultAsync, testEnv.coeffPlaintext1)

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(
            ciphertext: ciphertextResultAsync,
            format: .simd,
            expected: multiplySubtractData)
    }

    /// Testing CT-CT multiplication followed by CT-CT subtraction of the scheme.
    @inlinable
    public static func schemeCiphertextMultiplySubtractTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) async throws
    {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
        let data1 = testEnv.data1
        let data2 = testEnv.data2
        let multiplySubtractData = zip(data1, data2).map { data1, data2 in
            let t = context.plaintextModulus
            return data1.multiplyMod(data2, modulus: t, variableTime: true).subtractMod(data1, modulus: t)
        }

        let ciphertext1 = testEnv.ciphertext1
        let ciphertext2 = testEnv.ciphertext2
        let ciphertextResult = try ciphertext1 * ciphertext2 - ciphertext1

        var ciphertextResultAsync = ciphertext1
        try await Scheme.mulAssignAsync(&ciphertextResultAsync, ciphertext2)
        try await Scheme.subAssignAsync(&ciphertextResultAsync, ciphertext1)

        let evalCiphertext: Ciphertext<Scheme, Eval> = try ciphertextResult.convertToEvalFormat()
        let coeffCiphertext: Ciphertext<Scheme, Coeff> = try evalCiphertext.inverseNtt()

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .simd, expected: multiplySubtractData)
        try testEnv.checkDecryptsDecodes(
            ciphertext: ciphertextResultAsync,
            format: .simd,
            expected: multiplySubtractData)
    }

    /// Testing ciphertext negation of the scheme.
    @inlinable
    public static func schemeCiphertextNegateTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) async throws
    {
        let testEnv = try TestEnv<Scheme>(context: context, format: .coefficient)
        let negatedData = testEnv.data1.map { data1 in
            data1.negateMod(modulus: context.plaintextModulus)
        }

        let ciphertextResult = -testEnv.ciphertext1
        let evalCiphertext = -testEnv.evalCiphertext1
        var evalCiphertextAsync = testEnv.evalCiphertext1
        await Scheme.negAssignEvalAsync(&evalCiphertextAsync)

        var coeffCiphertext: Ciphertext<Scheme, Coeff> = try testEnv.evalCiphertext1.inverseNtt()

        var coeffCiphertextAsync = coeffCiphertext
        await Scheme.negAssignCoeffAsync(&coeffCiphertextAsync)

        coeffCiphertext = -coeffCiphertext

        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: negatedData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertext, format: .coefficient, expected: negatedData)
        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertextAsync, format: .coefficient, expected: negatedData)
        try testEnv.checkDecryptsDecodes(ciphertext: evalCiphertextAsync, format: .coefficient, expected: negatedData)
        try testEnv.checkDecryptsDecodes(ciphertext: ciphertextResult, format: .coefficient, expected: negatedData)
    }

    /// Testing CT-PT addition of the scheme.
    @inlinable
    public static func schemeCiphertextPlaintextAddTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) async throws
    {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
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

                var sumAsync = coeffCiphertext
                try await Scheme.addAssignCoeffAsync(&sumAsync, coeffPlaintext)
                try testEnv.checkDecryptsDecodes(ciphertext: sumAsync, format: .simd, expected: sumData)
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

                var sumAsync = evalCiphertext
                try await Scheme.addAssignEvalAsync(&sumAsync, evalPlaintext)
                try testEnv.checkDecryptsDecodes(ciphertext: sumAsync, format: .simd, expected: sumData)
            } catch HeError.unsupportedHeOperation(_) {}
        }
    }

    /// Testing CT-PT subtraction of the scheme.
    @inlinable
    public static func schemeCiphertextPlaintextSubtractTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>, scheme _: Scheme.Type) async throws
    {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
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

                var diffAsync = coeffCiphertext
                try await Scheme.subAssignCoeffAsync(&diffAsync, coeffPlaintext)
                try testEnv.checkDecryptsDecodes(ciphertext: diffAsync, format: .simd, expected: diff1Minus2Data)
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

                var diffAsync = evalCiphertext
                try await Scheme.subAssignEvalAsync(&diffAsync, evalPlaintext)
                try testEnv.checkDecryptsDecodes(ciphertext: diffAsync, format: .simd, expected: diff1Minus2Data)
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
    @inlinable
    public static func schemeCiphertextPlaintextMultiplyTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>, scheme _: Scheme.Type) async throws
    {
        guard context.supportsSimdEncoding else {
            return
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd)
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
            let evalPlaintext: Plaintext<Scheme, Eval> = try testEnv.context.encode(
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

    /// Testing ciphertext rotation of the scheme.
    @inlinable
    public static func schemeRotationTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) async throws
    {
        func runRotationTest(context: Context<Scheme.Scalar>, galoisElements: [Int], multiStep: Bool) async throws {
            let degree = context.degree
            let testEnv = try TestEnv<Scheme>(context: context, format: .simd, galoisElements: galoisElements)
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
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd, galoisElements: galoisElementsSwap)
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
    @inlinable
    public static func schemeApplyGaloisTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) async throws
    {
        guard context.supportsSimdEncoding, context.supportsEvaluationKey else {
            return
        }
        let elements = try (1..<min(8, context.degree >> 1)).map { step in
            try GaloisElement.rotatingColumns(by: -step, degree: context.degree)
        }
        let testEnv = try TestEnv<Scheme>(context: context, format: .simd, galoisElements: elements)
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
    @inlinable
    public static func noiseBudgetTest<Scheme: HeScheme>(context: Context<Scheme.Scalar>,
                                                         scheme _: Scheme.Type) throws
    {
        let testEnv = try TestEnv<Scheme>(context: context, format: .coefficient)

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
    @inlinable
    public static func repeatedAdditionTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) async throws
    {
        let testEnv = try HeAPITestHelpers.TestEnv<Scheme>(context: context, format: .coefficient)

        var coeffCiphertext = testEnv.ciphertext1
        var coeffCiphertextAsync = try coeffCiphertext.convertToCoeffFormat()
        let coeffCifertextToAdd = try coeffCiphertext.convertToCoeffFormat()
        try coeffCiphertext += testEnv.coeffPlaintext1
        try coeffCiphertext += testEnv.ciphertext1
        try coeffCiphertext += testEnv.coeffPlaintext1
        try coeffCiphertext += testEnv.ciphertext1

        try await Scheme.addAssignCoeffAsync(&coeffCiphertextAsync, testEnv.coeffPlaintext1)
        try await Scheme.addAssignCoeffAsync(&coeffCiphertextAsync, coeffCifertextToAdd)
        try await Scheme.addAssignCoeffAsync(&coeffCiphertextAsync, testEnv.coeffPlaintext1)
        try await Scheme.addAssignCoeffAsync(&coeffCiphertextAsync, coeffCifertextToAdd)

        let expected = testEnv.data1.map { num in
            num.multiplyMod(Scheme.Scalar(5), modulus: testEnv.context.plaintextModulus, variableTime: true)
        }
        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertext, format: .coefficient, expected: expected)
        try testEnv.checkDecryptsDecodes(ciphertext: coeffCiphertextAsync, format: .coefficient, expected: expected)
    }

    /// testing multiply inverse power of x.
    @inlinable
    public static func multiplyInverseTest<Scheme: HeScheme>(
        context: Context<Scheme.Scalar>,
        scheme _: Scheme.Type) async throws
    {
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
