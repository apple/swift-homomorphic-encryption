// Copyright 2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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

public import HomomorphicEncryption

extension PolyRq {
    /// Removes the last k rows of coefficients and drop the last k moduli from the context.
    ///
    ///  - Parameter k: The number of moduli to drop. It must be greater than or equal to zero and less than the number
    /// of moduli in the context.
    /// - Throws: Error upon failure to drop context.
    @inlinable
    public mutating func removeLastModuli(_ k: Int) throws {
        precondition(k >= 0 && k < moduli.count)
        var context = context
        for _ in 0..<k {
            guard let newContext = context.next else {
                throw HeError.invalidPolyContext(context)
            }
            context = newContext
        }
        self.context = context
        data.removeLastRows(k)
    }
}
