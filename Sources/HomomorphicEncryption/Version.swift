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

package enum Version {
    case development(branch: String)
    case release(major: Int, minor: Int, patch: Int)

    package static let current = Version.development(branch: "main")

    package var description: String {
        switch self {
        case let .development(branch):
            "\(branch)-development"
        case let .release(major, minor, patch):
            "\(major).\(minor).\(patch)"
        }
    }
}
