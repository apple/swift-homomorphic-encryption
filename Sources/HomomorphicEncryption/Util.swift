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

// https://github.com/swiftlang/swift-evolution/blob/main/proposals/0220-count-where.md
// introduced in swift 6
#if swift(<6.0)
extension Sequence {
    @inlinable
    package func count(where predicate: (Element) throws -> Bool) rethrows -> Int {
        var count = 0
        for element in self where try predicate(element) {
            count += 1
        }
        return count
    }
}
#endif

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

extension Array where Element: ScalarType {
    @inlinable
    func product() -> Width32<Self.Element> {
        func wideningProduct<Prod: FixedWidthInteger>(of elements: [some FixedWidthInteger]) -> [Prod] {
            stride(from: 0, to: elements.count, by: 2).map { index in
                var product = Prod(elements[index])
                if index < elements.count - 1 {
                    product &*= Prod(elements[index + 1])
                }
                return product
            }
        }

        let doubleWidth: [Self.Element.DoubleWidth] = wideningProduct(of: self)
        if doubleWidth.count == 1 {
            return Width32<Self.Element>(doubleWidth[0])
        }
        let quadWidth: [QuadWidth<Self.Element>] = wideningProduct(of: doubleWidth)
        if quadWidth.count == 1 {
            return Width32<Self.Element>(quadWidth[0])
        }
        let octoWidth: [OctoWidth<Self.Element>] = wideningProduct(of: quadWidth)
        if octoWidth.count == 1 {
            return Width32<Self.Element>(octoWidth[0])
        }
        let width16: [Width16<Self.Element>] = wideningProduct(of: octoWidth)
        if width16.count == 1 {
            return Width32<Self.Element>(width16[0])
        }
        let width32: [Width32<Self.Element>] = wideningProduct(of: width16)
        precondition(width32.count == 1)
        return width32[0]
    }
}
