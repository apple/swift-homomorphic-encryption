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

/// This is a no-op scheme for development and testing.
///
/// The scheme simply takes the plaintext as a "ciphertext" and
/// ignores any ciphertext coefficient moduli.
public enum NoOpScheme: HeScheme {
    public typealias Scalar = UInt64
    public typealias CanonicalCiphertextFormat = Coeff

    public static var freshCiphertextPolyCount: Int {
        1
    }

    public static var minNoiseBudget: Double {
        0
    }

    public static func generateSecretKey(context: Context<NoOpScheme>) -> SecretKey<NoOpScheme> {
        let poly = PolyRq<Scalar, Eval>.zero(context: context.secretKeyContext)
        return SecretKey(poly: poly)
    }

    public static func generateEvaluationKey(
        context: Context<NoOpScheme>,
        configuration _: EvaluationKeyConfiguration, using _: SecretKey<NoOpScheme>) throws -> EvaluationKey<NoOpScheme>
    {
        EvaluationKey(
            galoisKey: GaloisKey(keys: [:]),
            relinearizationKey: RelinearizationKey(keySwitchKey: KeySwitchKey(context: context, ciphers: [])))
    }

    public static func encode(context: Context<NoOpScheme>, values: [some ScalarType],
                              format: EncodeFormat) throws -> CoeffPlaintext
    {
        try context.encode(values: values, format: format)
    }

    public static func encode(context: Context<NoOpScheme>, values: [some ScalarType],
                              format: EncodeFormat, moduliCount _: Int) throws -> EvalPlaintext
    {
        try encode(context: context, values: values, format: format).forwardNtt()
    }

    public static func encode(context: Context<NoOpScheme>, values: [some ScalarType],
                              format: EncodeFormat) throws -> EvalPlaintext
    {
        try encode(context: context, values: values, format: format, moduliCount: 1)
    }

    public static func decode<T>(plaintext: CoeffPlaintext, format: EncodeFormat) throws -> [T] where T: ScalarType {
        try plaintext.context.decode(plaintext: plaintext, format: format)
    }

    public static func decode<T>(plaintext: EvalPlaintext, format: EncodeFormat) throws -> [T] where T: ScalarType {
        try decode(plaintext: plaintext.inverseNtt(), format: format)
    }

    public static func zeroCiphertext(context: Context<Self>, moduliCount _: Int) throws -> CoeffCiphertext {
        NoOpScheme
            .CoeffCiphertext(
                context: context,
                polys: [PolyRq.zero(context: context.plaintextContext)],
                correctionFactor: 1)
    }

    public static func zeroCiphertext(context: Context<Self>, moduliCount _: Int) throws -> EvalCiphertext {
        NoOpScheme
            .EvalCiphertext(
                context: context,
                polys: [PolyRq.zero(context: context.plaintextContext)],
                correctionFactor: 1)
    }

    @inlinable
    public static func isTransparent(ciphertext _: CoeffCiphertext) -> Bool {
        true
    }

    @inlinable
    public static func isTransparent(ciphertext _: EvalCiphertext) -> Bool {
        true
    }

    public static func encrypt(_ plaintext: CoeffPlaintext,
                               using _: SecretKey<NoOpScheme>) throws -> CanonicalCiphertext
    {
        NoOpScheme.CanonicalCiphertext(
            context: plaintext.context,
            polys: [plaintext.poly], correctionFactor: 1)
    }

    public static func decryptCoeff(_ ciphertext: CoeffCiphertext,
                                    using _: SecretKey<NoOpScheme>) throws -> CoeffPlaintext
    {
        NoOpScheme.CoeffPlaintext(
            context: ciphertext.context,
            poly: ciphertext.polys[0])
    }

    public static func decryptEval(_ ciphertext: EvalCiphertext,
                                   using secretKey: SecretKey<NoOpScheme>) throws -> CoeffPlaintext
    {
        try decryptCoeff(ciphertext.inverseNtt(), using: secretKey)
    }

    public static func rotateColumns(
        of ciphertext: inout CanonicalCiphertext,
        by step: Int,
        using _: EvaluationKey<NoOpScheme>) throws
    {
        let element = try GaloisElement.rotatingColumns(by: step, degree: ciphertext.context.degree)
        ciphertext.polys[0] = ciphertext.polys[0].applyGalois(element: element)
    }

    public static func swapRows(
        of ciphertext: inout CanonicalCiphertext,
        using _: EvaluationKey<NoOpScheme>) throws
    {
        let element = GaloisElement.swappingRows(degree: ciphertext.context.degree)
        ciphertext.polys[0] = ciphertext.polys[0].applyGalois(element: element)
    }

    // MARK: plaintext += plaintext

    public static func addAssign(_ lhs: inout CoeffPlaintext, _ rhs: CoeffPlaintext) throws {
        try validateEquality(of: lhs.context, and: rhs.context)
        lhs.poly += rhs.poly
    }

    public static func addAssign(_ lhs: inout EvalPlaintext, _ rhs: EvalPlaintext) throws {
        try validateEquality(of: lhs.context, and: rhs.context)
        lhs.poly += rhs.poly
    }

    // MARK: ciphertext += plaintext

    public static func addAssignCoeff(_ ciphertext: inout CoeffCiphertext, _ plaintext: CoeffPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        ciphertext.polys[0] += plaintext.poly
    }

    public static func addAssignCoeffEval(_ ciphertext: inout CoeffCiphertext, _ plaintext: EvalPlaintext) throws {
        try addAssign(&ciphertext, plaintext.inverseNtt())
    }

    public static func addAssignEvalCoeff(_ ciphertext: inout EvalCiphertext, _ plaintext: CoeffPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        let evalPlaintext = try plaintext.forwardNtt()
        try addAssign(&ciphertext, evalPlaintext)
    }

    public static func addAssignEval(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        ciphertext.polys[0] += plaintext.poly
    }

    // MARK: ciphertext -= plaintext

    public static func subAssign(_ ciphertext: inout CoeffCiphertext, _ plaintext: CoeffPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        ciphertext.polys[0] -= plaintext.poly
    }

    public static func subAssign(_ ciphertext: inout CoeffCiphertext, _ plaintext: EvalPlaintext) throws {
        try subAssign(&ciphertext, plaintext.inverseNtt())
    }

    static func subAssign(_ ciphertext: inout EvalCiphertext, _ plaintext: CoeffPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        let evalPlaintext = try plaintext.forwardNtt()
        try subAssign(&ciphertext, evalPlaintext)
    }

    public static func subAssign(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        ciphertext.polys[0] -= plaintext.poly
    }

    // MARK: ciphertext += ciphertext

    public static func addAssign(_ lhs: inout CoeffCiphertext, _ rhs: CoeffCiphertext) throws {
        try validateEquality(of: lhs.context, and: rhs.context)
        lhs.polys[0] += rhs.polys[0]
    }

    public static func addAssign(_ lhs: inout EvalCiphertext, _ rhs: EvalCiphertext) throws {
        try validateEquality(of: lhs.context, and: rhs.context)
        lhs.polys[0] += rhs.polys[0]
    }

    // MARK: ciphertext -= ciphertext

    public static func subAssign(_ lhs: inout CoeffCiphertext, _ rhs: CoeffCiphertext) throws {
        try validateEquality(of: lhs.context, and: rhs.context)
        lhs.polys[0] -= rhs.polys[0]
    }

    public static func subAssign(_ lhs: inout EvalCiphertext, _ rhs: EvalCiphertext) throws {
        try validateEquality(of: lhs.context, and: rhs.context)
        lhs.polys[0] -= rhs.polys[0]
    }

    // MARK: ciphertext =- ciphertext

    public static func negAssign(_ ciphertext: inout EvalCiphertext) {
        ciphertext.polys[0] = -ciphertext.polys[0]
    }

    public static func negAssign(_ ciphertext: inout CoeffCiphertext) {
        ciphertext.polys[0] = -ciphertext.polys[0]
    }

    // MARK: ciphertext *= plaintext

    static func mulAssign(_ ciphertext: inout CoeffCiphertext, _ plaintext: CoeffPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        var evalCiphertext = try ciphertext.forwardNtt()
        let evalPlaintext = try plaintext.forwardNtt()
        try mulAssign(&evalCiphertext, evalPlaintext)
        ciphertext = try evalCiphertext.inverseNtt()
    }

    static func mulAssign(_ ciphertext: inout CoeffCiphertext, _ plaintext: EvalPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        var evalCiphertext = try ciphertext.forwardNtt()
        try mulAssign(&evalCiphertext, plaintext)
        ciphertext = try evalCiphertext.inverseNtt()
    }

    static func mulAssign(_ ciphertext: inout EvalCiphertext, _ plaintext: CoeffPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        let evalPlaintext = try plaintext.forwardNtt()
        try mulAssign(&ciphertext, evalPlaintext)
    }

    public static func mulAssign(_ ciphertext: inout EvalCiphertext, _ plaintext: EvalPlaintext) throws {
        try validateEquality(of: ciphertext.context, and: plaintext.context)
        ciphertext.polys[0] *= plaintext.poly
    }

    // MARK: ciphertext *= ciphertext

    public static func mulAssign(_ lhs: inout NoOpScheme.CanonicalCiphertext,
                                 _ rhs: NoOpScheme.CanonicalCiphertext) throws
    {
        try validateEquality(of: lhs.context, and: rhs.context)
        lhs.polys[0] = try (lhs.polys[0].forwardNtt() * rhs.polys[0].forwardNtt()).inverseNtt()
    }

    // MARK: ciphertext =-ciphertext

    public static func modSwitchDown(_: inout CanonicalCiphertext) throws {
        // mod switch down is no op in no-op scheme
    }

    public static func applyGalois(
        ciphertext: inout CanonicalCiphertext,
        element: Int,
        using _: EvaluationKey<Self>) throws
    {
        for index in ciphertext.polys.indices {
            ciphertext.polys[index] = ciphertext.polys[index].applyGalois(element: element)
        }
    }

    public static func relinearize(_: inout CanonicalCiphertext, using _: EvaluationKey<Self>) throws {}

    public static func noiseBudget(of _: CanonicalCiphertext, using _: SecretKey<Self>,
                                   variableTime _: Bool) throws -> Double
    {
        minNoiseBudget
    }

    public static func noiseBudget(of _: EvalCiphertext, using _: SecretKey<Self>,
                                   variableTime _: Bool) throws -> Double
    {
        minNoiseBudget
    }
}
