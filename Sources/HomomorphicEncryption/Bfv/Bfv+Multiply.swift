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
    public static func mulAssign(_ lhs: inout CanonicalCiphertext, _ rhs: CanonicalCiphertext) throws {
        let evalCiphertext = try multiplyWithoutScaling(lhs, rhs)
        lhs = try dropExtendedBase(from: evalCiphertext)
    }

    /// Reduces a ciphertext from base `[Q, Bsk]` to base `Q`.
    ///
    /// The ciphertext may be an intermediate result from a call to ``Bfv/multiplyWithoutScaling(_:_:)``.
    ///
    /// - Parameter ciphertext: Ciphertext with base `[Q, Bsk]`.
    /// - Returns: The ciphertext with base `Q`.
    /// - Throws: Error upon failure to drop the base.
    @inlinable
    public static func dropExtendedBase(from ciphertext: EvalCiphertext) throws -> CoeffCiphertext {
        guard ciphertext.moduli.count % 2 == 1, ciphertext.moduli.count >= 3 else {
            throw HeError.invalidCiphertext(ciphertext, message: "Ciphertext must have modului count >= 3 and odd")
        }
        let scalingModuliCount = (ciphertext.moduli.count - 1) / 2
        let rnsTool = ciphertext.context.getRnsTool(moduliCount: scalingModuliCount)

        let tVec = Array(repeating: ciphertext.context.plaintextModulus, count: ciphertext.moduli.count)
        let polys = try ciphertext.polys.map { poly in
            let scaledPoly = poly * tVec
            let coeffPoly = try scaledPoly.inverseNtt()
            return try rnsTool.floorQBskToQ(poly: coeffPoly)
        }
        return try CoeffCiphertext(
            context: ciphertext.context,
            polys: polys,
            correctionFactor: ciphertext.correctionFactor)
    }

    @inlinable
    static func computeBehzPolys(ciphertext: CanonicalCiphertext) throws -> [PolyRq<Scalar, Eval>] {
        let rnsTool = ciphertext.context.getRnsTool(moduliCount: ciphertext.moduli.count)
        return try ciphertext.polys.map { poly in
            let polyQBsk = try rnsTool.liftQToQBsk(poly: poly)
            return try polyQBsk.forwardNtt()
        }
    }

    /// Computes `lhs * rhs` in an extended base.
    ///
    /// - seealso: Use ``Bfv/dropExtendedBase(from:)`` to remove the extended base.
    @inlinable
    public static func multiplyWithoutScaling(_ lhs: CanonicalCiphertext,
                                              _ rhs: CanonicalCiphertext) throws -> EvalCiphertext
    {
        try validateEquality(of: lhs.context, and: rhs.context)
        guard lhs.polys.count == freshCiphertextPolyCount, lhs.correctionFactor == 1 else {
            throw HeError.invalidCiphertext(lhs)
        }
        guard rhs.polys.count == freshCiphertextPolyCount, rhs.correctionFactor == 1 else {
            throw HeError.invalidCiphertext(rhs)
        }
        guard lhs.polyContext() == rhs.polyContext() else {
            throw HeError.incompatibleCiphertexts(lhs, rhs)
        }

        let lhsPolys = try computeBehzPolys(ciphertext: lhs)
        let rhsPolys = try computeBehzPolys(ciphertext: rhs)

        let poly0 = lhsPolys[0] * rhsPolys[0]
        let poly1 = lhsPolys[0] * rhsPolys[1] + lhsPolys[1] * rhsPolys[0]
        let poly2 = lhsPolys[1] * rhsPolys[1]

        return try EvalCiphertext(context: lhs.context, polys: [poly0, poly1, poly2], correctionFactor: 1)
    }
}
