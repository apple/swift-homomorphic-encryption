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

extension Sequence where Element: Hashable {
    @inlinable
    func allUnique() -> Bool {
        var seen = Set<Self.Element>()
        for element in self {
            guard seen.insert(element).inserted else {
                return false
            }
        }
        return true
    }
}

extension FixedWidthInteger {
    // not a constant time operation
    @inlinable
    func toRemainder(_ mod: Self, variableTime: Bool) -> Self {
        precondition(variableTime)
        precondition(mod > 0)
        var result = self % mod
        if result < 0 {
            result += mod
        }
        return result
    }
}

extension Array where Element: FixedWidthInteger {
    /// Computes the product of the elements in the array.
    ///
    /// The product is 1 for an empty array.
    /// - Returns: the product.
    @inlinable
    public func product<V: FixedWidthInteger>() -> V {
        reduce(V(1)) { V($0) * V($1) }
    }

    /// Computes the sum of the elements in the array.
    ///
    /// The sum is 0 for an empty array.
    /// - Returns: the sum.
    @inlinable
    public func sum<V: FixedWidthInteger>() -> V {
        reduce(V(0)) { V($0) + V($1) }
    }
}
