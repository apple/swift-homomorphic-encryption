// Copyright 2025-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

public import HomomorphicEncryption
public import ModularArithmetic
public import PrivateNearestNeighborSearch
public import Testing

@inlinable
func increasingData<T: ScalarType>(dimensions: MatrixDimensions, modulus: T) -> [[T]] {
    (0..<dimensions.rowCount).map { rowIndex in
        (0..<dimensions.columnCount).map { columnIndex in
            let value = 1 + T(rowIndex * dimensions.columnCount + columnIndex)
            return value % modulus
        }
    }
}

@inlinable
func randomData<T: ScalarType>(dimensions: MatrixDimensions, modulus: T) -> [[T]] {
    (0..<dimensions.rowCount).map { _ in
        (0..<dimensions.columnCount).map { _ in T.random(in: 0..<modulus) }
    }
}

extension PrivateNearestNeighborSearchUtil {
    /// Tests for `CiphertextMatrix`.
    public enum CiphertextMatrixTests {
        /// Testing encryption/decryption round-trip.
        @inlinable
        public static func encryptDecryptRoundTrip<Scheme: HeScheme>(for _: Scheme.Type) async throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: rlweParams)
            #expect(encryptionParameters.supportsSimdEncoding)
            let context = try Scheme.Context(encryptionParameters: encryptionParameters)
            let dimensions = try MatrixDimensions(rowCount: 10, columnCount: 4)
            let encodeValues: [[Scheme.Scalar]] = increasingData(
                dimensions: dimensions,
                modulus: context.plaintextModulus)
            let plaintextMatrix = try PlaintextMatrix<Scheme, Coeff>(
                context: context,
                dimensions: dimensions,
                packing: .denseRow,
                values: encodeValues.flatMap(\.self))
            let secretKey = try context.generateSecretKey()
            var ciphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)
            let plaintextMatrixRoundTrip = try ciphertextMatrix.decrypt(using: secretKey)
            #expect(plaintextMatrixRoundTrip == plaintextMatrix)

            // modSwitchDownToSingle
            do {
                try await ciphertextMatrix.modSwitchDownToSingle()
                let plaintextMatrixRoundTrip = try ciphertextMatrix.decrypt(using: secretKey)
                #expect(plaintextMatrixRoundTrip == plaintextMatrix)
            }
        }

        /// Testing convert to Coeff/Eval format roundtrip.
        @inlinable
        public static func convertFormatRoundTrip<Scheme: HeScheme>(for _: Scheme.Type) throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: rlweParams)
            #expect(encryptionParameters.supportsSimdEncoding)
            let context = try Scheme.Context(encryptionParameters: encryptionParameters)
            let dimensions = try MatrixDimensions(rowCount: 10, columnCount: 4)
            let encodeValues: [[Scheme.Scalar]] = increasingData(
                dimensions: dimensions,
                modulus: context.plaintextModulus)
            let plaintextMatrix = try PlaintextMatrix<Scheme, Coeff>(
                context: context,
                dimensions: dimensions,
                packing: .denseRow,
                values: encodeValues.flatMap(\.self))
            let secretKey = try context.generateSecretKey()
            let ciphertextCoeffMatrix: CiphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)
            let ciphertextEvalMatrix = try ciphertextCoeffMatrix.convertToEvalFormat()
            let ciphertextMatrixRoundTrip = try ciphertextEvalMatrix.convertToCoeffFormat()
            let decoded = try ciphertextMatrixRoundTrip.decrypt(using: secretKey)
            #expect(plaintextMatrix == decoded)
        }

        /// Testing ciphertext matrix addition.
        @inlinable
        public static func addition<Scheme: HeScheme>(for _: Scheme.Type) async throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: rlweParams)
            #expect(encryptionParameters.supportsSimdEncoding)
            let context = try Scheme.Context(encryptionParameters: encryptionParameters)
            let dimensions = try MatrixDimensions(rowCount: 10, columnCount: 4)
            let plaintextModulus = context.plaintextModulus

            let valuesA: [[Scheme.Scalar]] = increasingData(dimensions: dimensions, modulus: plaintextModulus)
            let valuesB: [[Scheme.Scalar]] = randomData(dimensions: dimensions, modulus: plaintextModulus)

            let plaintextMatrixA = try PlaintextMatrix<Scheme, Coeff>(
                context: context,
                dimensions: dimensions,
                packing: .denseRow,
                values: valuesA.flatMap(\.self))
            let plaintextMatrixB = try PlaintextMatrix<Scheme, Coeff>(
                context: context,
                dimensions: dimensions,
                packing: .denseRow,
                values: valuesB.flatMap(\.self))

            let secretKey = try context.generateSecretKey()
            let ciphertextMatrixA = try plaintextMatrixA.encrypt(using: secretKey)
            let ciphertextMatrixB = try plaintextMatrixB.encrypt(using: secretKey)

            let ciphertextMatrixSum = try ciphertextMatrixA + ciphertextMatrixB
            let decryptedSum = try ciphertextMatrixSum.decrypt(using: secretKey)
            let unpackedSum: [Scheme.Scalar] = try decryptedSum.unpack()

            let expectedSum = zip(valuesA.flatMap(\.self), valuesB.flatMap(\.self)).map { a, b in
                (a + b) % plaintextModulus
            }
            #expect(unpackedSum == expectedSum)

            // Test += variant
            var ciphertextMatrixC = ciphertextMatrixA
            try ciphertextMatrixC += ciphertextMatrixB
            let decryptedC = try ciphertextMatrixC.decrypt(using: secretKey)
            let unpackedC: [Scheme.Scalar] = try decryptedC.unpack()
            #expect(unpackedC == expectedSum)
        }

        /// Testing `extractDenseRow`.
        @inlinable
        public static func extractDenseRow<Scheme: HeScheme>(for _: Scheme.Type) async throws {
            let degree = 16
            let plaintextModulus = try Scheme.Scalar.generatePrimes(
                significantBitCounts: [9],
                preferringSmall: true,
                nttDegree: degree)[0]
            let coefficientModuli = try Scheme.Scalar.generatePrimes(
                significantBitCounts: Array(repeating: Scheme.Scalar.bitWidth - 4, count: 2),
                preferringSmall: false,
                nttDegree: degree)
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(
                polyDegree: degree,
                plaintextModulus: plaintextModulus,
                coefficientModuli: coefficientModuli,
                errorStdDev: .stdDev32,
                securityLevel: .unchecked)
            #expect(encryptionParameters.supportsSimdEncoding)
            let context = try Scheme.Context(encryptionParameters: encryptionParameters)

            for rowCount in 1..<(2 * degree) {
                for columnCount in 1..<degree / 2 {
                    let dimensions = try MatrixDimensions((rowCount, columnCount))
                    let encodeValues: [[Scheme.Scalar]] = increasingData(
                        dimensions: dimensions,
                        modulus: plaintextModulus)

                    let plaintextMatrix = try PlaintextMatrix<Scheme, Coeff>(
                        context: context,
                        dimensions: dimensions,
                        packing: .denseRow,
                        values: encodeValues.flatMap(\.self))
                    let secretKey = try context.generateSecretKey()
                    let ciphertextMatrix: CiphertextMatrix = try plaintextMatrix.encrypt(using: secretKey)

                    let evaluationKeyConfig = try CiphertextMatrix<Scheme, Coeff>.extractDenseRowConfig(
                        for: encryptionParameters,
                        dimensions: dimensions)
                    let evaluationKey = try context.generateEvaluationKey(
                        config: evaluationKeyConfig,
                        using: secretKey)

                    for rowIndex in 0..<rowCount {
                        let extractedRow = try await ciphertextMatrix.extractDenseRow(
                            rowIndex: rowIndex,
                            evaluationKey: evaluationKey)

                        let expectedDimensions = try MatrixDimensions(
                            rowCount: 1,
                            columnCount: columnCount)
                        #expect(extractedRow.dimensions == expectedDimensions)

                        // Check unpacking
                        let decrypted = try extractedRow.decrypt(using: secretKey)
                        let unpacked: [Scheme.Scalar] = try decrypted.unpack()
                        #expect(unpacked == encodeValues[rowIndex])

                        // Check encoded values
                        var row = encodeValues[rowIndex]
                        row += Array(repeating: 0, count: row.count.nextPowerOfTwo - row.count)
                        let expectedRow = Array(repeating: row, count: degree / row.count).flatMap(\.self)
                        let decoded: [Scheme.Scalar] = try decrypted.plaintexts[0].decode(format: .simd)
                        #expect(decoded == expectedRow)
                    }
                }
            }
        }

        /// Testing Response aggregation.
        @inlinable
        public static func responseAggregation<Scheme: HeScheme>(for _: Scheme.Type) async throws {
            let rlweParams = PredefinedRlweParameters.insecure_n_8_logq_5x18_logt_5
            let encryptionParameters = try EncryptionParameters<Scheme.Scalar>(from: rlweParams)
            let context = try Scheme.Context(encryptionParameters: encryptionParameters)
            let dimensions = try MatrixDimensions(rowCount: 10, columnCount: 4)
            let plaintextModulus = context.plaintextModulus

            let valuesA: [[Scheme.Scalar]] = randomData(dimensions: dimensions, modulus: plaintextModulus)
            let valuesB: [[Scheme.Scalar]] = randomData(dimensions: dimensions, modulus: plaintextModulus)
            let valuesC: [[Scheme.Scalar]] = randomData(dimensions: dimensions, modulus: plaintextModulus)

            let secretKey = try context.generateSecretKey()

            func encryptValues(_ values: [[Scheme.Scalar]]) throws -> CiphertextMatrix<Scheme, Coeff> {
                let plaintext = try PlaintextMatrix<Scheme, Coeff>(
                    context: context,
                    dimensions: dimensions,
                    packing: .denseRow,
                    values: values.flatMap(\.self))
                return try plaintext.encrypt(using: secretKey).convertToCoeffFormat()
            }

            let ctA = try encryptValues(valuesA)
            let ctB = try encryptValues(valuesB)
            let ctC = try encryptValues(valuesC)

            let entryIds: [UInt64] = (0..<10).map { UInt64($0) }

            let responseA = Response<Scheme>(ciphertextMatrices: [ctA], entryIds: entryIds, entryMetadatas: [])
            let responseB = Response<Scheme>(ciphertextMatrices: [ctB], entryIds: entryIds, entryMetadatas: [])
            let responseC = Response<Scheme>(ciphertextMatrices: [ctC], entryIds: entryIds, entryMetadatas: [])

            let aggregated = try Response.aggregate([responseA, responseB, responseC])

            #expect(aggregated.entryIds == entryIds)
            #expect(aggregated.ciphertextMatrices.count == 1)

            let decrypted = try aggregated.ciphertextMatrices[0].decrypt(using: secretKey)
            let unpacked: [Scheme.Scalar] = try decrypted.unpack()

            let flatA = valuesA.flatMap(\.self)
            let flatB = valuesB.flatMap(\.self)
            let flatC = valuesC.flatMap(\.self)
            let expectedSum = zip(zip(flatA, flatB), flatC).map { ab, c in
                (ab.0 + ab.1 + c) % plaintextModulus
            }
            #expect(unpacked == expectedSum)
        }
    }
}
