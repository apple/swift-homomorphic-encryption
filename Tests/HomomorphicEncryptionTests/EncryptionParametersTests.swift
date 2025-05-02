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
struct EncryptionParametersTests {
    @Test
    func invalid() throws {
        let plaintextModulus: UInt32 = (1 << 17) + 177
        let coefficientModuli: [UInt32] = [(1 << 17) + 225, (1 << 17) + 369, (1 << 17) + 417]
        let parameters = try EncryptionParameters<UInt32>(
            polyDegree: 8,
            plaintextModulus: plaintextModulus,
            coefficientModuli: coefficientModuli,
            errorStdDev: ErrorStdDev.stdDev32,
            securityLevel: SecurityLevel.unchecked)

        func expectedError(replacing target: String, with replacement: String) -> HeError {
            HeError
                .invalidEncryptionParameters(parameters.description.replacingOccurrences(of: target, with: replacement))
        }

        // degree not a power of two
        #expect(throws: expectedError(replacing: "degree=8", with: "degree=7")) {
            try EncryptionParameters<UInt32>(
                polyDegree: 7,
                plaintextModulus: plaintextModulus,
                coefficientModuli: coefficientModuli,
                errorStdDev: ErrorStdDev.stdDev32,
                securityLevel: SecurityLevel.unchecked)
        }

        // plaintext modulus not prime
        // BFV allows a non-prime plaintext modulus, but our implementation doesn't.
        #expect(throws: expectedError(
            replacing: "plaintextModulus=\(plaintextModulus)",
            with: "plaintextModulus=131248"))
        {
            try EncryptionParameters<UInt32>(
                polyDegree: 8,
                plaintextModulus: 131_248,
                coefficientModuli: coefficientModuli,
                errorStdDev: ErrorStdDev.stdDev32,
                securityLevel: SecurityLevel.unchecked)
        }

        // plaintext modulus matches ciphertext modulus
        #expect(throws: expectedError(
            replacing: "plaintextModulus=\(plaintextModulus)",
            with: "plaintextModulus=\(coefficientModuli[0])"))
        {
            try EncryptionParameters<UInt32>(
                polyDegree: 8,
                plaintextModulus: coefficientModuli[0],
                coefficientModuli: coefficientModuli,
                errorStdDev: ErrorStdDev.stdDev32,
                securityLevel: SecurityLevel.unchecked)
        }

        // plaintext modulus > ciphertext modulus
        do {
            let bigPrime = try UInt32.generatePrimes(
                significantBitCounts: [27],
                preferringSmall: true)[0]
            #expect(throws: expectedError(
                replacing: "plaintextModulus=\(plaintextModulus)",
                with: "plaintextModulus=\(bigPrime)"))
            {
                try EncryptionParameters<UInt32>(
                    polyDegree: 8,
                    plaintextModulus: bigPrime,
                    coefficientModuli: coefficientModuli,
                    errorStdDev: ErrorStdDev.stdDev32,
                    securityLevel: SecurityLevel.unchecked)
            }
        }

        // moduli too large
        do {
            let bigPrime = try UInt32.generatePrimes(
                significantBitCounts: [32],
                preferringSmall: true)[0]
            #expect(throws: expectedError(
                replacing: "plaintextModulus=\(plaintextModulus)",
                with: "plaintextModulus=\(bigPrime)"))
            {
                try EncryptionParameters<UInt32>(
                    polyDegree: 8,
                    plaintextModulus: bigPrime,
                    coefficientModuli: coefficientModuli,
                    errorStdDev: ErrorStdDev.stdDev32,
                    securityLevel: SecurityLevel.unchecked)
            }
        }
        // moduli too small
        #expect(throws: expectedError(
            replacing: "plaintextModulus=\(plaintextModulus)",
            with: "plaintextModulus=\(1)"))
        {
            try EncryptionParameters<UInt32>(
                polyDegree: 8,
                plaintextModulus: 1,
                coefficientModuli: coefficientModuli,
                errorStdDev: ErrorStdDev.stdDev32,
                securityLevel: SecurityLevel.unchecked)
        }

        // too many moduli
        do {
            let excessCoefficientModuli = try UInt32.generatePrimes(
                significantBitCounts: Array(repeating: 25, count: 10),
                preferringSmall: true)
            #expect(throws: expectedError(
                replacing: "coefficientModuli=\(coefficientModuli)",
                with: "coefficientModuli=\(excessCoefficientModuli)"))
            {
                try EncryptionParameters<UInt32>(
                    polyDegree: 8,
                    plaintextModulus: plaintextModulus,
                    coefficientModuli: excessCoefficientModuli,
                    errorStdDev: ErrorStdDev.stdDev32,
                    securityLevel: SecurityLevel.unchecked)
            }
        }
    }

    @Test
    func insecure() throws {
        do {
            #expect(throws: HeError.insecureEncryptionParameters(
                """
                EncryptionParameters<UInt64>(degree=1024, plaintextModulus=257, \
                coefficientModuli=[17179869209], errorStdDev=stdDev32, securityLevel=quantum128
                """))
            {
                try EncryptionParameters<NoOpScheme.Scalar>(
                    polyDegree: 1024,
                    plaintextModulus: 257,
                    coefficientModuli: [17_179_869_209], // 2**34 - 25
                    errorStdDev: ErrorStdDev.stdDev32,
                    securityLevel: SecurityLevel.quantum128)
            }
        }

        struct TestParameters {
            let degree: Int
            let secureBitCounts: [Int]
            let insecureBitCounts: [Int]
        }
        let testParams: [TestParameters] = [
            TestParameters(degree: 1024, secureBitCounts: [21], insecureBitCounts: [22]),
            TestParameters(degree: 2048, secureBitCounts: [41], insecureBitCounts: [42]),
            TestParameters(degree: 4096, secureBitCounts: [40, 43], insecureBitCounts: [40, 44]),
            TestParameters(degree: 8192, secureBitCounts: [40, 40, 40, 45], insecureBitCounts: [40, 46, 40, 40]),
            TestParameters(
                degree: 16384,
                secureBitCounts: [50, 50, 50, 50, 50, 50, 30],
                insecureBitCounts: [50, 50, 50, 50, 50, 50, 31]),
        ]

        for params in testParams {
            // secure moduli
            let secureCoefficientModuli = try UInt64.generatePrimes(
                significantBitCounts: params.secureBitCounts,
                preferringSmall: false,
                nttDegree: params.degree)
            #expect(throws: Never.self) {
                try EncryptionParameters<UInt64>(polyDegree: params.degree,
                                                 plaintextModulus: 1153,
                                                 coefficientModuli: secureCoefficientModuli,
                                                 errorStdDev: ErrorStdDev.stdDev32,
                                                 securityLevel: SecurityLevel.quantum128)
            }
            #expect(throws: Never.self) {
                try EncryptionParameters<UInt64>(polyDegree: params.degree,
                                                 plaintextModulus: 1153,
                                                 coefficientModuli: secureCoefficientModuli,
                                                 errorStdDev: ErrorStdDev.stdDev32,
                                                 securityLevel: SecurityLevel.unchecked)
            }

            // insecure moduli
            let insecureCoefficientModuli = try UInt64.generatePrimes(
                significantBitCounts: params.insecureBitCounts,
                preferringSmall: false,
                nttDegree: params.degree)
            #expect(throws: (any Error).self) {
                try EncryptionParameters<UInt64>(polyDegree: params.degree,
                                                 plaintextModulus: 1153,
                                                 coefficientModuli: insecureCoefficientModuli,
                                                 errorStdDev: ErrorStdDev.stdDev32,
                                                 securityLevel: SecurityLevel.quantum128)
            }
            #expect(throws: Never.self) {
                try EncryptionParameters<UInt64>(polyDegree: params.degree,
                                                 plaintextModulus: 1153,
                                                 coefficientModuli: insecureCoefficientModuli,
                                                 errorStdDev: ErrorStdDev.stdDev32,
                                                 securityLevel: SecurityLevel.unchecked)
            }
        }
    }

    @Test
    func predefined() throws {
        struct ParametersKAT {
            let predefined: PredefinedRlweParameters
            let polyDegree: Int
            let coefficientModuliBitCounts: [Int]
            let plaintextModulusBitCount: Int
            let supportsSimdEncoding: Bool
            let supportsEvaluationKey: Bool
            let skipLSBs: [Int]
        }

        func checkParameters(_ kat: ParametersKAT) throws {
            #expect(kat.predefined.polyDegree == kat.polyDegree)
            #expect(kat.predefined.coefficientModuli.map { qi in qi.ceilLog2 } == kat.coefficientModuliBitCounts)
            #expect(kat.predefined.plaintextModulus.ceilLog2 == kat.plaintextModulusBitCount)
            #expect(kat.predefined.supportsSimdEncoding == kat.supportsSimdEncoding)
            #expect(kat.predefined.supportsEvaluationKey == kat.supportsEvaluationKey)

            let params = try EncryptionParameters<UInt64>(from: kat.predefined)
            #expect(params.polyDegree == kat.polyDegree)
            #expect(params.coefficientModuli.map { qi in qi.ceilLog2 } == kat.coefficientModuliBitCounts)
            #expect(params.plaintextModulus.ceilLog2 == kat.plaintextModulusBitCount)
            #expect(params.supportsSimdEncoding == kat.supportsSimdEncoding)
            #expect(params.supportsEvaluationKey == kat.supportsEvaluationKey)

            // check skipLSBsForDecryption
            do {
                let context = try Context<Bfv<UInt64>>(encryptionParameters: params)
                let data = TestUtils.getRandomPlaintextData(count: params.polyDegree, in: 0..<params.plaintextModulus)
                let plaintext = try context.encode(values: data, format: .coefficient)
                let secretKey = try context.generateSecretKey()
                var ciphertext = try plaintext.encrypt(using: secretKey)
                try ciphertext.modSwitchDownToSingle()
                let skipLSBs = try ciphertext.convertToCoeffFormat().skipLSBs(forDecryption: true)
                #expect(skipLSBs == kat.skipLSBs)
            }

            if kat.predefined.supportsScalar(UInt32.self) {
                let params = try EncryptionParameters<UInt32>(from: kat.predefined)
                #expect(params.polyDegree == kat.polyDegree)
                #expect(params.coefficientModuli.map { qi in qi.ceilLog2 } == kat.coefficientModuliBitCounts)
                #expect(params.plaintextModulus.ceilLog2 == kat.plaintextModulusBitCount)
                #expect(params.supportsSimdEncoding == kat.supportsSimdEncoding)
                #expect(params.supportsEvaluationKey == kat.supportsEvaluationKey)
            }
        }

        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5,
            polyDegree: 8,
            coefficientModuliBitCounts: [18, 18, 18, 18, 18],
            plaintextModulusBitCount: 5,
            supportsSimdEncoding: true,
            supportsEvaluationKey: true,
            skipLSBs: [9, 5]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.insecure_n_512_logq_4x60_logt_20,
            polyDegree: 512,
            coefficientModuliBitCounts: [60, 60, 60, 60],
            plaintextModulusBitCount: 20,
            supportsSimdEncoding: true,
            supportsEvaluationKey: true,
            skipLSBs: [36, 29]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_4096_logq_27_28_28_logt_13,
            polyDegree: 4096,
            coefficientModuliBitCounts: [27, 28, 28],
            plaintextModulusBitCount: 13,
            supportsSimdEncoding: false,
            supportsEvaluationKey: true,
            skipLSBs: [11, 3]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_8192_logq_3x55_logt_42,
            polyDegree: 8192,
            coefficientModuliBitCounts: [55, 55, 55],
            plaintextModulusBitCount: 42,
            supportsSimdEncoding: true,
            supportsEvaluationKey: true,
            skipLSBs: [11, 0]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_8192_logq_3x55_logt_30,
            polyDegree: 8192,
            coefficientModuliBitCounts: [55, 55, 55],
            plaintextModulusBitCount: 30,
            supportsSimdEncoding: true,
            supportsEvaluationKey: true,
            skipLSBs: [22, 13]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_8192_logq_3x55_logt_29,
            polyDegree: 8192,
            coefficientModuliBitCounts: [55, 55, 55],
            plaintextModulusBitCount: 29,
            supportsSimdEncoding: true,
            supportsEvaluationKey: true,
            skipLSBs: [23, 14]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_4096_logq_27_28_28_logt_5,
            polyDegree: 4096,
            coefficientModuliBitCounts: [27, 28, 28],
            plaintextModulusBitCount: 5,
            supportsSimdEncoding: false,
            supportsEvaluationKey: true,
            skipLSBs: [19, 11]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_8192_logq_3x55_logt_24,
            polyDegree: 8192,
            coefficientModuliBitCounts: [55, 55, 55],
            plaintextModulusBitCount: 24,
            supportsSimdEncoding: true,
            supportsEvaluationKey: true,
            skipLSBs: [28, 19]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_8192_logq_29_60_60_logt_15,
            polyDegree: 8192,
            coefficientModuliBitCounts: [29, 60, 60],
            plaintextModulusBitCount: 15,
            supportsSimdEncoding: false,
            supportsEvaluationKey: true,
            skipLSBs: [11, 2]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_8192_logq_40_60_60_logt_26,
            polyDegree: 8192,
            coefficientModuliBitCounts: [40, 60, 60],
            plaintextModulusBitCount: 26,
            supportsSimdEncoding: true,
            supportsEvaluationKey: true,
            skipLSBs: [11, 2]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_8192_logq_28_60_60_logt_20,
            polyDegree: 8192,
            coefficientModuliBitCounts: [28, 60, 60],
            plaintextModulusBitCount: 20,
            supportsSimdEncoding: true,
            supportsEvaluationKey: true,
            skipLSBs: [6, 0]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_4096_logq_16_33_33_logt_4,
            polyDegree: 4096,
            coefficientModuliBitCounts: [16, 33, 33],
            plaintextModulusBitCount: 4,
            supportsSimdEncoding: false,
            supportsEvaluationKey: true,
            skipLSBs: [9, 0]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.insecure_n_16_logq_60_logt_15,
            polyDegree: 16,
            coefficientModuliBitCounts: [60],
            plaintextModulusBitCount: 15,
            supportsSimdEncoding: true,
            supportsEvaluationKey: false,
            skipLSBs: [42, 38]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_4096_logq_27_28_28_logt_6,
            polyDegree: 4096,
            coefficientModuliBitCounts: [27, 28, 28],
            plaintextModulusBitCount: 6,
            supportsSimdEncoding: false,
            supportsEvaluationKey: true,
            skipLSBs: [18, 10]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_4096_logq_27_28_28_logt_16,
            polyDegree: 4096,
            coefficientModuliBitCounts: [27, 28, 28],
            plaintextModulusBitCount: 16,
            supportsSimdEncoding: true,
            supportsEvaluationKey: true,
            skipLSBs: [9, 0]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_4096_logq_27_28_28_logt_17,
            polyDegree: 4096,
            coefficientModuliBitCounts: [27, 28, 28],
            plaintextModulusBitCount: 17,
            supportsSimdEncoding: true,
            supportsEvaluationKey: true,
            skipLSBs: [8, 0]))
        try checkParameters(ParametersKAT(
            predefined: PredefinedRlweParameters.n_4096_logq_27_28_28_logt_4,
            polyDegree: 4096,
            coefficientModuliBitCounts: [27, 28, 28],
            plaintextModulusBitCount: 4,
            supportsSimdEncoding: false,
            supportsEvaluationKey: true,
            skipLSBs: [20, 12]))
    }
}
