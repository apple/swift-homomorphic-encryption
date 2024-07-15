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

/// Polynomial context that holds all the pre-computed values for doing efficient calculations on ``PolyRq``
/// polynomials.
public final class PolyContext<T: ScalarType>: Sendable {
    /// Number `N` of coefficients in the polynomial, must be a power of two.
    @usableFromInline let degree: Int
    /// CRT-representation of the modulus `Q = q_0 * q_2 * ... * q_{L-1}`.
    @usableFromInline let moduli: [T]
    /// Next context, typically formed by dropping `q_{L-1}`.
    @usableFromInline let next: PolyContext<T>?
    /// Operations mod `q_0, ..., q_{L-1}`.`
    @usableFromInline let reduceModuli: [Modulus<T>]
    /// Operations mod `UInt64(q_0), ..., UInt64(q_{L-1})`.
    @usableFromInline let reduceModuliUInt64: [Modulus<UInt64>]
    /// Multiply by `q_{L-1}^{-1} mod q_i`, `mod q_i`.
    @usableFromInline let inverseQLast: [MultiplyConstantModulus<T>]
    /// Precomputation for the NTT, for modulus `q_{L-1}`.
    @usableFromInline let nttContext: NttContext<T>?

    /// Initializes a ``PolyContext``.
    /// - Parameters:
    ///   - degree: Polynomial degree.
    ///   - moduli: Decomposition of the modulus `Q` into co-prime factors `q_0, ..., q_{L-1}`.
    ///   - next: The next context in the modulus-switching chain.
    /// - Throws: Error upon failure to initialize the context.
    @inlinable
    required init(degree: Int, moduli: [T], next: PolyContext<T>?) throws {
        guard degree.isPowerOfTwo else {
            throw HeError.invalidDegree(degree)
        }
        // For CRT correctness, we require all moduli to be co-prime.
        // For convenience, we instead check a slightly stronger condition, that
        // additionally restricts an even modulus to be a power of two. This unnecessarily forbids,
        // 6, e.g., from being in the RNS base.
        for modulus in moduli {
            guard modulus.isPrime(variableTime: true) || modulus.isPowerOfTwo else {
                throw HeError.invalidModulus(Int64(modulus))
            }
            guard (1...Modulus<T>.max).contains(modulus) else {
                throw HeError.invalidModulus(Int64(modulus))
            }
        }
        let powerOfTwoModuli = moduli.filter { modulus in
            modulus.isPowerOfTwo
        }
        guard powerOfTwoModuli.count <= 1 else {
            throw HeError.coprimeModuli(moduli: moduli.map { Int64($0) })
        }
        guard moduli.allUnique() else {
            throw HeError.coprimeModuli(moduli: moduli.map { Int64($0) })
        }

        self.degree = degree
        self.moduli = moduli
        self.next = next

        self.reduceModuli = moduli.map { modulus in Modulus(
            modulus: modulus,
            variableTime: true)
        }
        self.reduceModuliUInt64 = moduli.map { modulus in Modulus(
            modulus: UInt64(modulus),
            variableTime: true)
        }

        guard let qLast = moduli.last else {
            throw HeError.emptyModulus
        }
        self.inverseQLast = try moduli.dropLast().map { modulus in
            let inverse = try qLast.inverseMod(modulus: modulus, variableTime: true)
            return MultiplyConstantModulus(multiplicand: inverse, modulus: modulus, variableTime: true)
        }
        if !qLast.isPowerOfTwo, qLast.isNttModulus(for: degree) {
            self.nttContext = try NttContext(degree: degree, modulus: qLast)
        } else {
            self.nttContext = nil
        }
    }

    /// Initializes a ``PolyContext``.
    /// - Parameters:
    ///   - degree: Polynomial degree.
    ///   - moduli: Decomposition of the modulus `Q` into co-prime factors `q_0, ..., q_{L-1}`.
    /// - Throws: Error upon failure to initialize the context.
    @inlinable
    public convenience init(degree: Int, moduli: [T]) throws {
        if moduli.count == 1 {
            try self.init(degree: degree, moduli: moduli, next: nil)
            return
        }
        var next = try PolyContext(degree: degree, moduli: Array(moduli.prefix(1)), next: nil)
        for moduliCount in 2..<moduli.count {
            next = try PolyContext(degree: degree, moduli: Array(moduli.prefix(moduliCount)), next: next)
        }
        try self.init(degree: degree, moduli: moduli, next: next)
    }

    @inlinable
    func validateNttModuli() throws {
        for modulus in moduli {
            guard modulus.isNttModulus(for: degree) else {
                throw HeError.invalidNttModulus(modulus: Int64(modulus), degree: degree)
            }
        }
    }

    /// Computes `Q mod modulus`.
    @inlinable
    func qRemainder(dividingBy modulus: Modulus<T>) -> T {
        var prod = T(1)
        for qi in moduli {
            prod = modulus.reduce(T.DoubleWidth(prod.multipliedFullWidth(by: qi)))
        }
        return prod
    }

    /// Returns whether or not this context is a strict parent of `context`.
    ///
    /// A context is a parent of a child context if the child context is a *next* context of the parent of one of its
    /// children. The next context typically drops the last modulus in the modulus chain.
    /// - Parameter context: Context to compare against.
    /// - Returns: Whether this context is a parent of or equal to `context`.
    @inlinable
    func isParent(of context: PolyContext<T>) -> Bool {
        var currentContext = self
        while let nextContext = currentContext.next {
            if nextContext == context {
                return true
            }
            currentContext = nextContext
        }
        return false
    }

    /// Returns whether or not this context is a parent of or equal to `context`.
    ///
    /// A context is a parent of a child context if the child context is a *next* context of the parent of one of its
    /// children. The next context typically drops the last modulus in the modulus chain.
    /// - Parameter context: Context to compare against.
    /// - Returns: Whether this context is a parent of or equal to `context`.
    @inlinable
    func isParentOfOrEqual(to context: PolyContext<T>) -> Bool {
        self == context || isParent(of: context)
    }

    @inlinable
    func getContext(moduliCount: Int) throws -> PolyContext<T> {
        precondition(moduliCount > 0 && moduliCount <= moduli.count, "Invalid number of moduli")
        var currentContext = self
        while currentContext.moduli.count > moduliCount, let nextContext = currentContext.next {
            currentContext = nextContext
        }
        if currentContext.moduli.count == moduliCount {
            return currentContext
        }
        throw HeError.invalidPolyContext(self)
    }

    /// Returns the maximum number of times a lazy product can be accumulated.
    ///
    /// Specifically, returns the maximum `L` such that `\sum_{i=0}^{L-1} x_i * y_i <= T.DoubleWidth.max - Q` for
    /// `x_i, y_i` in `[0, Q - 1]`.
    @inlinable
    func maxLazyProductAccumulationCount() -> Int {
        precondition(!moduli.isEmpty, "Empty moduli")
        // swiftlint:disable:next force_unwrapping
        let qMax = moduli.max()!
        let maxProduct = T.DoubleWidth((qMax - 1).multipliedFullWidth(by: qMax - 1))
        let maxProductCount = (T.DoubleWidth.max - T.DoubleWidth(qMax)) / maxProduct
        return maxProductCount > Int.max ? Int.max : Int(maxProductCount)
    }
}

extension PolyContext: Equatable {
    @inlinable
    public static func == (lhs: PolyContext, rhs: PolyContext) -> Bool {
        (lhs === rhs) || (lhs.degree == rhs.degree && lhs.moduli == rhs.moduli && lhs.next == rhs.next)
    }
}

extension PolyContext: CustomStringConvertible {
    public var description: String {
        "PolyContext<\(T.self)>(N=\(degree), moduli=\(moduli))"
    }
}
