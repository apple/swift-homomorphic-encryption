// Copyright 2024-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

import Foundation

extension [UInt8] {
    func utf8OrBase64() -> String {
        if let utf8 = String(validating: self, as: UTF8.self) {
            "\(utf8) (utf8)"
        } else {
            "\(Data(self).base64EncodedString()) (base64)"
        }
    }
}

/// Runtime options to specify configs. E.g. multi-threading preference.
public enum CallOptions: Equatable, Sendable {
    case multiThreaded(maxConcurrentTasks: Int)
    case singleThreaded
}

extension CallOptions {
    /// Default call options
    public static let `default` = CallOptions.singleThreaded

    /// Convenience: `.multiThreaded` without explicit `maxConcurrentTasks` uses all processors.
    public static var multiThreaded: CallOptions {
        .multiThreaded(maxConcurrentTasks: ProcessInfo.processInfo.activeProcessorCount)
    }

    @usableFromInline var multiThreading: Bool {
        if case .singleThreaded = self {
            return false
        }
        return true
    }

    /// The maximum number of concurrent tasks for this call option.
    @usableFromInline var maxConcurrentTasks: Int {
        switch self {
        case let .multiThreaded(maxConcurrentTasks): maxConcurrentTasks
        case .singleThreaded: 1
        }
    }

    /// Divide `maxConcurrentTasks` among `groupCount` child tasks.
    @usableFromInline
    func divided(among groupCount: Int) -> CallOptions {
        let childMaxConcurrentTasks = max(1, maxConcurrentTasks / max(1, groupCount))
        if childMaxConcurrentTasks <= 1 {
            return .singleThreaded
        }
        return .multiThreaded(maxConcurrentTasks: childMaxConcurrentTasks)
    }
}
