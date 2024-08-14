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

extension Bfv {
    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encodeSimdDimensions(for parameters: EncryptionParameters<Bfv<T>>)
        -> (rowCount: Int, columnCount: Int)?
    {
        guard parameters.supportsSimdEncoding else {
            return nil
        }
        return (rowCount: 2, columnCount: parameters.polyDegree / 2)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(context: Context<Bfv<T>>, values: [some ScalarType],
                              format: EncodeFormat) throws -> CoeffPlaintext
    {
        try context.encode(values: values, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(context: Context<Bfv<T>>, values: [some ScalarType], format: EncodeFormat,
                              moduliCount: Int?) throws -> EvalPlaintext
    {
        let coeffPlaintext = try Self.encode(context: context, values: values, format: format)
        return try coeffPlaintext.convertToEvalFormat(moduliCount: moduliCount)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decode<V: ScalarType>(plaintext: CoeffPlaintext, format: EncodeFormat) throws -> [V] {
        try plaintext.context.decode(plaintext: plaintext, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decode<V: ScalarType>(plaintext: EvalPlaintext, format: EncodeFormat) throws -> [V] {
        let coeffPlaintext = try plaintext.convertToCoeffFormat()
        return try coeffPlaintext.decode(format: format)
    }
}
