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

/// Enables base conversion from an input RNS basis `q = q_0, ..., q_{L-1}` to an
/// output RNS basis `t = t_0, ..., t_{M-1}`.
@usableFromInline
struct RnsBaseConverter<T: ScalarType>: Sendable {
    /// `q_0, ..., q_{L-1}`.
    @usableFromInline let inputContext: PolyContext<T>
    /// `t_0, ..., t_{M-1}``.
    @usableFromInline let outputContext: PolyContext<T>
    /// (i, j)'th entry stores `(q / q_i) % t_j`.
    @usableFromInline let puncturedProducts: Array2d<T>

    /// Composes polynomials with `inputContext`.
    @usableFromInline let crtComposer: CrtComposer<T>

    /// i'th entry stores `(q_i / q) % q_i`.
    @usableFromInline var inversePuncturedProducts: [MultiplyConstantModulus<T>] {
        crtComposer.inversePuncturedProducts
    }

    @inlinable
    init(from inputContext: PolyContext<T>, to outputContext: PolyContext<T>) throws {
        precondition(inputContext.degree == outputContext.degree)
        self.inputContext = inputContext
        self.outputContext = outputContext

        let puncturedProducts: [T] = outputContext.reduceModuli.flatMap { tj in
            inputContext.moduli.map { qi in
                var puncturedProduct = T(1)
                for qj in inputContext.moduli where qj != qi {
                    let prod = puncturedProduct.multipliedFullWidth(by: qj)
                    puncturedProduct = tj.reduce(T.DoubleWidth(prod))
                }
                return puncturedProduct
            }
        }
        self.puncturedProducts = Array2d(
            data: puncturedProducts,
            rowCount: outputContext.moduli.count,
            columnCount: inputContext.moduli.count)

        self.crtComposer = try CrtComposer(polyContext: inputContext)
    }

    /// Performs approximate base conversion.
    ///
    /// Converts input polynomial with coefficients `x_i mod q` to `(x_i + a_x * q) % t` where `a_x \in [0, L - 1]`, for
    /// `L` the number of moduli in the input basis `q.
    /// - Parameter poly: Input polynomial with base `q`.
    /// - Returns: Converted polynomial with base `t`.
    /// - Throws: Error upon failure to perform approximate base conversion.
    /// - seealso: Equation 2 from <https://eprint.iacr.org/2016/510.pdf>.
    @inlinable
    func convertApproximate(poly: PolyRq<T, Coeff>) throws -> PolyRq<T, Coeff> {
        try poly.checkContext(inputContext)
        var poly = poly
        convertApproximateProducts(of: &poly)
        return convertApproximate(using: poly)
    }

    /// Performs Chinese remainder theorem (CRT) composition of each coefficient in `poly`.
    ///
    /// The composition yields a polynomial with coefficients in `[0, q - 1]`.
    /// - Parameter poly: Polynomial to compose.
    /// - Returns: The coefficients in the composed polynomial. Each coefficient must be able to store values up to
    /// `crtComposeMaxIntermediateValue`.
    /// - Throws: `HeError` upon failure to compose the polynomial.
    /// - Warning: `V`'s operations must be constant time to prevent leaking `poly` through timing.
    @inlinable
    func crtCompose<V: FixedWidthInteger & UnsignedInteger>(poly: PolyRq<T, Coeff>) throws -> [V] {
        try crtComposer.compose(poly: poly)
    }

    /// Computes approximate products.
    ///
    /// Specifically, given input polynomial with coefficients `x_i`, this returns a polynomail with coefficients `[x_0
    /// * q_0/q mod q_0, x_1 * q_1/q mod q_1, ..., x_{N-1} * q_k/q mod q_k]`.
    /// This calculation is the same for all elements of the basis `t`, and can be hoisted and shared between
    /// different bases.
    /// - Parameter poly: polynomial whose approximate products to compute.
    /// - seealso: `convertApproximate`.
    @inlinable
    func convertApproximateProducts(of poly: inout PolyRq<T, Coeff>) {
        assert(poly.context == inputContext)
        for (rnsIndex, puncturedProduct) in inversePuncturedProducts.enumerated() {
            let indices = poly.polyIndices(rnsIndex: rnsIndex)
            poly.data.data.withUnsafeMutableBufferPointer { dataPtr in
                for index in indices {
                    dataPtr[index] = puncturedProduct.multiplyMod(dataPtr[index])
                }
            }
        }
    }

    /// Performs approximate base conversion from a scaled input polynomial to base `t`.
    ///
    /// The input polynomial has coefficients `[x * q_0/q mod q_0, x * q_1/q mod q_1, ..., x * q_k/q mod q_k]`, as
    /// computed via `convertApproximateProducts`.
    /// The output polynnomial has coefficients `(x + a_x * q) % t` where `a_x \in [0, L-1]`, for `L` the number of
    /// moduli in the input basis `q.
    /// - Parameter products: Input polynomial scaled by `q_i / q mod q_i`.
    /// - Returns: Approximate conversion of the input polynomial to base `t`.
    @inlinable
    func convertApproximate(using products: PolyRq<T, Coeff>) -> PolyRq<T, Coeff> {
        var result = PolyRq<T, Coeff>.zero(context: outputContext)
        result.data.data.withUnsafeMutableBufferPointer { resultPtr in
            for (rnsOutIndex, tj) in outputContext.reduceModuli.enumerated() {
                let puncturedProductColumnIndices = puncturedProducts.rowIndices(row: rnsOutIndex)
                var sums = Array(repeating: T.DoubleWidth(0), count: outputContext.degree)
                var productsIndex = 0
                for (rnsInIndex, puncturedProdIdx) in puncturedProductColumnIndices.enumerated() {
                    let puncturedProd = puncturedProducts[puncturedProdIdx]
                    if rnsInIndex == inputContext.moduli.count &- 1 {
                        for (coeffIndex, outIndex) in products.polyIndices(rnsIndex: rnsOutIndex).enumerated() {
                            sums[coeffIndex] &+=
                                T.DoubleWidth(products.data[productsIndex].multipliedFullWidth(by: puncturedProd))
                            resultPtr[outIndex] = tj.reduce(sums[coeffIndex])
                            productsIndex &+= 1
                        }
                    } else {
                        for coeffIndex in 0..<outputContext.degree {
                            sums[coeffIndex] &+=
                                T.DoubleWidth(products.data[productsIndex].multipliedFullWidth(by: puncturedProd))
                            productsIndex &+= 1
                        }
                    }
                }
            }
        }
        return result
    }
}
