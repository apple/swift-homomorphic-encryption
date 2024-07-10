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

/// Protocol for a collection of ``PolyRq`` polynomials.
public protocol PolyCollection {
    /// Coefficient type.
    associatedtype Scalar: ScalarType

    /// Returns the polynomial's context.
    @inlinable
    func polyContext() -> PolyContext<Scalar>
}

extension PolyCollection {
    /// The polynomial's degree.
    @inlinable public var degree: Int { polyContext().degree }

    /// The polynomial's scalar moduli.
    @inlinable public var moduli: [Scalar] { polyContext().moduli }

    /// The polynomial's moduli.
    @inlinable var reduceModuli: [Modulus<Scalar>] { polyContext().reduceModuli }
}
