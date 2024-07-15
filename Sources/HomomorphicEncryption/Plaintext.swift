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
    @usableFromInline let context: Context<Scheme>
    @usableFromInline package var poly: PolyRq<Scheme.Scalar, Format>

    @inlinable
    package init(context: Context<Scheme>, poly: PolyRq<Scheme.Scalar, Format>) {
        self.context = context
        self.poly = poly
    }

    @inlinable
    static func += (lhs: inout Plaintext<Scheme, Format>, rhs: Plaintext<Scheme, Format>) throws where Format == Coeff {
        try Scheme.addAssign(&lhs, rhs)
    }

    @inlinable
    static func += (lhs: inout Plaintext<Scheme, Format>, rhs: Plaintext<Scheme, Format>) throws where Format == Eval {
        try Scheme.addAssign(&lhs, rhs)
    }

    @inlinable
    func forwardNtt() throws -> Plaintext<Scheme, Eval> where Format == Coeff {
        let poly = try poly.forwardNtt()
        return Plaintext<Scheme, Eval>(context: context, poly: poly)
    }

    @inlinable
    func inverseNtt() throws -> Plaintext<Scheme, Coeff> where Format == Eval {
        let poly = try poly.inverseNtt()
        return Plaintext<Scheme, Coeff>(context: context, poly: poly)
    }

    @inlinable subscript(_ index: Int) -> Scheme.Scalar {
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
    public func polyContext() -> PolyContext<Scheme.Scalar> {
        poly.context
    }
}

extension Plaintext {
    @inlinable
    static func + (lhs: Self, rhs: Self) throws -> Self where Format == Coeff {
        var result = lhs
        try result += rhs
        return result
    }

    @inlinable
    static func + (lhs: Self, rhs: Self) throws -> Self where Format == Eval {
        var result = lhs
        try result += rhs
        return result
    }

    @inlinable
    public func convertToEvalFormat(moduliCount: Int? = nil) throws -> Plaintext<Scheme, Eval>
        where Format == Coeff
    {
        let moduliCount = moduliCount ?? context.ciphertextContext.moduli.count
        let rnsTool = context.getRnsTool(moduliCount: moduliCount)
        let polyContext = try context.ciphertextContext.getContext(moduliCount: moduliCount)

        var poly: PolyRq<Scheme.Scalar, Coeff> = PolyRq.zero(context: polyContext)
        let tThreshold = rnsTool.tThreshold
        let sourcePoly = self.poly.poly(rnsIndex: 0)
        for (rnsIndex, tIncrement) in rnsTool.tIncrement.enumerated() {
            for (valueIndex, index) in poly.polyIndices(rnsIndex: rnsIndex).enumerated() {
                let condition = sourcePoly[valueIndex].constantTimeLessThan(tThreshold)
                poly[index] = Scheme.Scalar.constantTimeSelect(
                    if: condition,
                    then: sourcePoly[valueIndex],
                    else: sourcePoly[valueIndex] &+ tIncrement)
            }
        }
        return try Plaintext<Scheme, Eval>(context: context, poly: poly.forwardNtt())
    }

    @inlinable
    public func convertToCoeffFormat() throws -> Plaintext<Scheme, Coeff>
        where Format == Eval
    {
        let rnsTool = context.getRnsTool(moduliCount: moduli.count)
        var plaintextData = try poly.inverseNtt().data
        for index in plaintextData.rowIndices(row: 0) {
            let condition = plaintextData[index].constantTimeGreaterThanOrEqual(rnsTool.tThreshold)
            plaintextData[index] = Scheme.Scalar.constantTimeSelect(
                if: condition,
                then: plaintextData[index] &- rnsTool.tIncrement[0],
                else: plaintextData[index])
        }
        plaintextData.removeLastRows(plaintextData.rowCount - 1)
        let coeffPoly: PolyRq<Scheme.Scalar, Coeff> = PolyRq(
            context: context.plaintextContext,
            data: Array2d(array: plaintextData))
        return Plaintext<Scheme, Coeff>(context: context, poly: coeffPoly)
    }

    @inlinable
    public func decode(format: EncodeFormat) throws -> [Scheme.Scalar] where Format == Coeff {
        try context.decode(plaintext: self, format: format)
    }

    @inlinable
    public func decode(format: EncodeFormat) throws -> [Scheme.Scalar] where Format == Eval {
        try context.decode(plaintext: self, format: format)
    }

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
