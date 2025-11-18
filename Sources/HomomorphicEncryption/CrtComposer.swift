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

import ModularArithmetic

@usableFromInline
package typealias CrtComposer = _CrtComposer

/// Performs Chinese remainder theorem (CRT) composition of coefficients.
public struct _CrtComposer<T: ScalarType>: Sendable {
    /// Context for the CRT moduli `q_i`.
    public let polyContext: PolyContext<T>

    /// i'th entry stores `(q_i / q) % q_i`.
    public let inversePuncturedProducts: [MultiplyConstantModulus<T>]

    /// Creates a new ``CrtComposer``.
    /// - Parameter polyContext: Context for the CRT moduli.
    /// - Throws: Error upon failure to create a new ``CrtComposer``.
    @inlinable
    package init(polyContext: PolyContext<T>) throws {
        self.polyContext = polyContext
        self.inversePuncturedProducts = try polyContext.reduceModuli.map { qi in
            var puncturedProduct = T(1)
            for qj in polyContext.moduli where qj != qi.modulus {
                let prod = puncturedProduct.multipliedFullWidth(by: qj)
                puncturedProduct = qi.reduce(T.DoubleWidth(prod))
            }
            let inversePuncturedProduct = try puncturedProduct.inverseMod(
                modulus: qi.modulus,
                variableTime: true)
            return MultiplyConstantModulus(
                multiplicand: inversePuncturedProduct,
                modulus: qi.modulus,
                variableTime: true)
        }
    }

    /// Returns an upper bound on the maximum value during a `crtCompose` call.
    /// - Parameter moduli: Moduli in the polynomial context
    /// - Returns: The upper bound.
    @inlinable
    package static func composeMaxIntermediateValue(moduli: [T]) -> Double {
        let moduli = moduli.map { Double($0) }
        if moduli.count == 1 {
            return moduli[0]
        }
        let q = moduli.reduce(1.0, *)
        return 2.0 * q
    }

    /// Performs Chinese remainder theorem (CRT) composition on a list of
    /// coefficients.
    ///
    /// The composition yields a polynomial with coefficients in `[0, q - 1]`.
    /// - Parameter data:Data to compose. Each column must contain a
    /// coefficient's residues mod each modulus.
    /// - Returns: The composed coefficients. Each coefficient must be able to
    /// store values up to
    /// `crtComposeMaxIntermediateValue`.
    /// - Throws: `HeError` upon failure to compose the polynomial.
    /// - Warning: `V`'s operations must be constant time to prevent leaking
    /// `poly` through timing.
    @inlinable
    package func compose<V: FixedWidthInteger & UnsignedInteger>(data: Array2d<T>) throws -> [V] {
        precondition(data.rowCount == polyContext.moduli.count)
        precondition(Double(V.max) >= Self
            .composeMaxIntermediateValue(moduli: polyContext.moduli))
        let q: V = polyContext.moduli.product()
        let puncturedProducts = polyContext.moduli.map { qi in q / V(qi) }

        var products: [V] = Array(repeating: 0, count: data.columnCount)
        for row in 0..<data.rowCount {
            let puncturedProduct = puncturedProducts[row]
            let inversePuncturedProduct = inversePuncturedProducts[row]
            for column in 0..<data.columnCount {
                let tmp = V(inversePuncturedProduct.multiplyMod(data[
                    row,
                    column
                ]))
                let addend = tmp &* puncturedProduct
                products[column] = products[column].addMod(addend, modulus: q)
            }
        }
        return products
    }

    /// Performs Chinese remainder theorem (CRT) composition on a polynomial's
    /// coefficients.
    ///
    /// The composition yields a polynomial with coefficients in `[0, q)`.
    /// - Parameter poly: Polynomial whose coefficients to compose. Must have the
    /// same context as ``polyContext``.
    /// - Returns: The composed coefficients. Each coefficient must be able to
    /// store values up to
    /// `crtComposeMaxIntermediateValue`.
    /// - Throws: `HeError` upon failure to compose the polynomial.
    /// - Warning: `V`'s operations must be constant time to prevent leaking
    /// `poly` through timing.
    @inlinable
    package func compose<V: FixedWidthInteger & UnsignedInteger>(poly: PolyRq<T, Coeff>) throws -> [V] {
        try compose(data: poly.data)
    }
}
