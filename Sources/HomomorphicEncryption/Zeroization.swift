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

#if !canImport(Darwin)
import CUtil

// swiftlint:disable:next implicitly_unwrapped_optional attributes
@inlinable func zeroize(_ s: UnsafeMutableRawPointer!, _ n: Int) {
    c_zeroize(s, n)
}
#else
import Darwin

// swiftlint:disable:next implicitly_unwrapped_optional attributes
@inlinable func zeroize(_ s: UnsafeMutableRawPointer!, _ n: Int) {
    let exitCode = memset_s(s, n, 0, n)
    precondition(exitCode == 0, "memset_s returned exit code \(exitCode)")
}
#endif
