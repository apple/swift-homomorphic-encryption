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
    public static func encode(context: Context<Bfv<T>>, values: [some ScalarType],
                              format: EncodeFormat) throws -> CoeffPlaintext
    {
        try context.encode(values: values, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(context: Context<Bfv<T>>, values: [some ScalarType], format: EncodeFormat,
                              moduliCount: Int) throws -> EvalPlaintext
    {
        try context.encode(values: values, format: format, moduliCount: moduliCount)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func encode(context: Context<Bfv<T>>, values: [some ScalarType],
                              format: EncodeFormat) throws -> EvalPlaintext
    {
        try context.encode(values: values, format: format, moduliCount: nil)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decode<V>(plaintext: CoeffPlaintext, format: EncodeFormat) throws -> [V] where V: ScalarType {
        try plaintext.context.decode(plaintext: plaintext, format: format)
    }

    @inlinable
    // swiftlint:disable:next missing_docs attributes
    public static func decode<V>(plaintext: EvalPlaintext, format: EncodeFormat) throws -> [V] where V: ScalarType {
        try plaintext.context.decode(plaintext: plaintext, format: format)
    }
}
