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

extension Bfv {
    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encodeSimdDimensions(for parameters: EncryptionParameters<T>) -> SimdEncodingDimensions? {
        guard parameters.supportsSimdEncoding else {
            return nil
        }
        return SimdEncodingDimensions(rowCount: 2, columnCount: parameters.polyDegree / 2)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(context: Context<Bfv<T>>, values: some Collection<Scalar>,
                              format: EncodeFormat) throws -> CoeffPlaintext
    {
        try context.encode(values: values, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(context: Context<Bfv<T>>, signedValues: some Collection<SignedScalar>,
                              format: EncodeFormat) throws -> CoeffPlaintext
    {
        try context.encode(signedValues: signedValues, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(context: Context<Bfv<T>>, values: some Collection<Scalar>, format: EncodeFormat,
                              moduliCount: Int?) throws -> EvalPlaintext
    {
        let coeffPlaintext = try Self.encode(context: context, values: values, format: format)
        return try coeffPlaintext.convertToEvalFormat(moduliCount: moduliCount)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(
        context: Context<Bfv<T>>,
        signedValues: some Collection<SignedScalar>,
        format: EncodeFormat,
        moduliCount: Int?) throws -> EvalPlaintext
    {
        let coeffPlaintext = try Self.encode(context: context, signedValues: signedValues, format: format)
        return try coeffPlaintext.convertToEvalFormat(moduliCount: moduliCount)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decodeCoeff(plaintext: CoeffPlaintext, format: EncodeFormat) throws -> [Scalar] {
        try plaintext.context.decode(plaintext: plaintext, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decodeCoeff(plaintext: CoeffPlaintext, format: EncodeFormat) throws -> [SignedScalar] {
        try plaintext.context.decode(plaintext: plaintext, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decodeEval(plaintext: EvalPlaintext, format: EncodeFormat) throws -> [Scalar] {
        try plaintext.convertToCoeffFormat().decode(format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decodeEval(plaintext: EvalPlaintext, format: EncodeFormat) throws -> [SignedScalar] {
        try plaintext.convertToCoeffFormat().decode(format: format)
    }
}
