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
/// Plaintext type.
public struct Plaintext<Scheme: HeScheme, Format: PolyFormat>: Equatable, Sendable {
    public typealias SignedScalar = Scheme.SignedScalar

    /// Context for HE computation.
    public let context: Context<Scheme>

    @usableFromInline package var poly: PolyRq<Scalar, Format>

    @inlinable
    package init(context: Context<Scheme>, poly: PolyRq<Scalar, Format>) {
        self.context = context
        self.poly = poly
    }

    /// In-place plaintext addition: `lhs += rhs`.
    /// - Parameters:
    ///   - lhs: Plaintext to add to; will store the sum.
    ///   - rhs: Plaintext to add.
    /// - Throws: Error upon failure to add the plaintexts.
    /// - seealso: ``HeScheme/addAssign(_:_:)-3bv7g`` for an alternative API.
    @inlinable
    public static func += (lhs: inout Plaintext<Scheme, Format>, rhs: Plaintext<Scheme, Format>) throws
        where Format == Coeff
    {
        try Scheme.addAssign(&lhs, rhs)
    }

    /// In-place plaintext addition: `lhs += rhs`.
    /// - Parameters:
    ///   - lhs: Plaintext to add to; will store the sum.
    ///   - rhs: Plaintext to add.
    /// - Throws: Error upon failure to add the plaintexts.
    /// - seealso: ``HeScheme/addAssign(_:_:)-1osb9`` for an alternative API.
    @inlinable
    public static func += (lhs: inout Plaintext<Scheme, Format>, rhs: Plaintext<Scheme, Format>) throws
        where Format == Eval
    {
        try Scheme.addAssign(&lhs, rhs)
    }

    /// Computes the forward number-theoretic transform (NTT) on the plaintext.
    /// - Returns: The plaintext in ``Eval`` format.
    /// - Throws: Error upon failure to compute the forward NTT
    /// - seealso: ``PolyRq/forwardNtt()``
    @inlinable
    public func forwardNtt() throws -> Plaintext<Scheme, Eval> where Format == Coeff {
        let poly = try poly.forwardNtt()
        return Plaintext<Scheme, Eval>(context: context, poly: poly)
    }

    /// Computes the inverse number-theoretic transform (NTT) on the plaintext.
    /// - Returns: The plaintext in ``Coeff`` format.
    /// - Throws: Error upon failure to compute the inverse NTT
    /// - seealso: ``PolyRq/inverseNtt()``
    @inlinable
    public func inverseNtt() throws -> Plaintext<Scheme, Coeff> where Format == Eval {
        let poly = try poly.inverseNtt()
        return Plaintext<Scheme, Coeff>(context: context, poly: poly)
    }

    @inlinable
    subscript(_ index: Int) -> Scalar {
        get {
            poly.data[index]
        }
        set {
            poly.data[index] = newValue
        }
    }
}

extension Plaintext: PolyCollection {
    public typealias Scalar = Scheme.Scalar

    @inlinable
    public func polyContext() -> PolyContext<Scalar> {
        poly.context
    }
}

extension Plaintext {
    /// Plaintext addition: `lhs + rhs`.
    /// - Parameters:
    ///   - lhs: Plaintext to add.
    ///   - rhs: Plaintext add.
    /// - Returns: The sum `lhs + rhs`.
    /// - Throws: Error upon failure to add the plaintexts.
    /// - seealso: ``HeScheme/addAssign(_:_:)-3bv7g`` for an alternative API.
    @inlinable
    public static func + (lhs: Self, rhs: Self) throws -> Self where Format == Coeff {
        var result = lhs
        try result += rhs
        return result
    }

    /// Plaintext addition: `lhs + rhs`.
    /// - Parameters:
    ///   - lhs: Plaintext to add.
    ///   - rhs: Plaintext add.
    /// - Returns: The sum `lhs + rhs`.
    /// - Throws: Error upon failure to add the plaintexts.
    /// - seealso: ``HeScheme/addAssign(_:_:)-1osb9`` for an alternative API.
    @inlinable
    public static func + (lhs: Self, rhs: Self) throws -> Self where Format == Eval {
        var result = lhs
        try result += rhs
        return result
    }

    /// Converts the plaintext to ``Eval`` format.
    ///
    /// This makes the plaintext suitable for operations with ciphertexts in ``Eval`` format, with `moduliCount` moduli.
    /// - Parameter moduliCount: Number of coefficient moduli in the context.
    /// - Returns: The converted plaintext.
    /// - Throws: Error upon failure to convert the plaintext.
    @inlinable
    public func convertToEvalFormat(moduliCount: Int? = nil) throws -> Plaintext<Scheme, Eval> {
        if let plaintext = self as? Plaintext<Scheme, Eval> {
            return plaintext
        }
        let moduliCount = moduliCount ?? context.ciphertextContext.moduli.count
        let rnsTool = context.getRnsTool(moduliCount: moduliCount)
        let polyContext = try context.ciphertextContext.getContext(moduliCount: moduliCount)

        var poly: PolyRq<Scalar, Coeff> = PolyRq.zero(context: polyContext)
        let tThreshold = rnsTool.tThreshold
        let sourcePoly = self.poly.poly(rnsIndex: 0)
        for (rnsIndex, tIncrement) in rnsTool.tIncrement.enumerated() {
            for (valueIndex, index) in poly.polyIndices(rnsIndex: rnsIndex).enumerated() {
                let condition = sourcePoly[valueIndex].constantTimeLessThan(tThreshold)
                poly[index] = Scalar.constantTimeSelect(
                    if: condition,
                    then: sourcePoly[valueIndex],
                    else: sourcePoly[valueIndex] &+ tIncrement)
            }
        }
        return try Plaintext<Scheme, Eval>(context: context, poly: poly.forwardNtt())
    }

    /// Converts the plaintext to ``Coeff`` format.
    /// - Returns: The converted plaintext.
    /// - Throws: Error upon failure to convert the plaintext.
    @inlinable
    public func convertToCoeffFormat() throws -> Plaintext<Scheme, Coeff> {
        if let plaintext = self as? Plaintext<Scheme, Coeff> {
            return plaintext
        }
        let rnsTool = context.getRnsTool(moduliCount: moduli.count)
        var plaintextData = try poly.convertToCoeffFormat().data
        for index in plaintextData.rowIndices(row: 0) {
            let condition = plaintextData[index].constantTimeGreaterThanOrEqual(rnsTool.tThreshold)
            plaintextData[index] = Scalar.constantTimeSelect(
                if: condition,
                then: plaintextData[index] &- rnsTool.tIncrement[0],
                else: plaintextData[index])
        }
        plaintextData.removeLastRows(plaintextData.rowCount - 1)
        let coeffPoly: PolyRq<Scalar, Coeff> = PolyRq(
            context: context.plaintextContext,
            data: Array2d(array: plaintextData))
        return Plaintext<Scheme, Coeff>(context: context, poly: coeffPoly)
    }

    /// Decodes a plaintext.
    /// - Parameter format: Encoding format of the plaintext.
    /// - Returns: The decoded values.
    /// - Throws: Error upon failure to decode the plaintext.
    @inlinable
    public func decode(format: EncodeFormat) throws -> [Scalar] {
        try Scheme.decode(plaintext: self, format: format)
    }

    /// Decodes a plaintext to signed values.
    /// - Parameter format: Encoding format of the plaintext.
    /// - Returns: The decoded signed values.
    /// - Throws: Error upon failure to decode the plaintext.
    @inlinable
    public func decode(format: EncodeFormat) throws -> [SignedScalar] {
        try Scheme.decode(plaintext: self, format: format)
    }

    /// Symmetric secret key encryption of the plaintext.
    /// - Parameter secretKey: Secret key to encrypt with.
    /// - Returns: A ciphertext encrypting the plaintext.
    /// - Throws: Error upon failure to encrypt the plaintext.
    /// - seealso: ``HeScheme/encrypt(_:using:)`` for an alternative API.
    @inlinable
    public func encrypt(using secretKey: SecretKey<Scheme>) throws -> Scheme.CanonicalCiphertext where Format == Coeff {
        try Scheme.encrypt(self, using: secretKey)
    }
}

extension Plaintext: CustomStringConvertible {
    public var description: String {
        "Plaintext<\(Scheme.self), \(Format.self)>(\(context), \(poly)"
    }
}
