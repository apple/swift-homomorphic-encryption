// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Remember to update CI if changing

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

import Foundation
import PackageDescription

let featureSettings: [SwiftSetting] = [.enableUpcomingFeature("InternalImportsByDefault")]

let librarySettings: [SwiftSetting] = featureSettings

let executableSettings: [SwiftSetting] =
    librarySettings +
    [.unsafeFlags(["-cross-module-optimization"], .when(configuration: .release))]

let benchmarkSettings: [SwiftSetting] = featureSettings + [.unsafeFlags(
    ["-cross-module-optimization"],
    .when(configuration: .release))]

let enableFlags = "SWIFT_HOMOMORPHIC_ENCRYPTION_MODULAR_ARITHMETIC_EXTRA_SWIFT_FLAGS"
func shouldEnableFlags() -> Bool {
    if let flag = ProcessInfo.processInfo.environment[enableFlags], flag != "0", flag != "false" {
        return true
    }
    return false
}

var flags: [SwiftSetting] = []
let enableFlagsBool = shouldEnableFlags()
if enableFlagsBool {
    print("Building with additional flags. To disable, unset \(enableFlags) in your environment.")
    let flagsAsString = (ProcessInfo.processInfo.environment[enableFlags] ?? "") as String
    flags += [.unsafeFlags(flagsAsString.components(separatedBy: ","))]
}

let package = Package(
    name: "swift-homomorphic-encryption",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "ModularArithmetic",
            targets: ["ModularArithmetic"]),
        .library(
            name: "HomomorphicEncryption",
            targets: ["HomomorphicEncryption"]),
        .library(
            name: "HomomorphicEncryptionProtobuf",
            targets: ["HomomorphicEncryptionProtobuf"]),
        .library(
            name: "_HomomorphicEncryptionExtras",
            targets: ["_HomomorphicEncryptionExtras"]),
        .library(
            name: "PrivateInformationRetrieval",
            targets: ["PrivateInformationRetrieval"]),
        .library(
            name: "PrivateNearestNeighborSearch",
            targets: ["PrivateNearestNeighborSearch"]),
        .library(name: "ApplicationProtobuf", targets: ["ApplicationProtobuf"]),
        .library(name: "_TestUtilities", targets: ["_TestUtilities"]),
        .executable(name: "PIRGenerateDatabase", targets: ["PIRGenerateDatabase"]),
        .executable(name: "PIRProcessDatabase", targets: ["PIRProcessDatabase"]),
        .executable(name: "PIRShardDatabase", targets: ["PIRShardDatabase"]),
        .executable(name: "PNNSGenerateDatabase", targets: ["PNNSGenerateDatabase"]),
        .executable(name: "PNNSProcessDatabase", targets: ["PNNSProcessDatabase"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-algorithms", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-async-algorithms.git", from: "1.0.2"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.10.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-numerics", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-protobuf", from: "1.31.1"), // Keep version in sync with README
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "ModularArithmetic",
            dependencies: [],
            swiftSettings: librarySettings + flags),
        .target(
            name: "CUtil",
            dependencies: [],
            path: "Sources/CUtil",
            sources: ["zeroize.c"],
            publicHeadersPath: "."),
        .target(
            name: "HomomorphicEncryption",
            dependencies: [
                .product(name: "AsyncAlgorithms", package: "swift-async-algorithms"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                "CUtil",
                "ModularArithmetic",
            ],
            swiftSettings: librarySettings),
        .target(
            name: "HomomorphicEncryptionProtobuf",
            dependencies: ["HomomorphicEncryption",
                           .product(name: "SwiftProtobuf", package: "swift-protobuf")],
            exclude: ["generated/README.md"],
            swiftSettings: librarySettings),
        .target(
            name: "_HomomorphicEncryptionExtras",
            dependencies: ["HomomorphicEncryption"],
            swiftSettings: librarySettings),
        .target(
            name: "PrivateInformationRetrieval",
            dependencies: ["HomomorphicEncryption",
                           .product(name: "AsyncAlgorithms", package: "swift-async-algorithms"),
                           .product(name: "Numerics", package: "swift-numerics")],
            swiftSettings: librarySettings),
        .target(
            name: "PrivateNearestNeighborSearch",
            dependencies: [
                .product(name: "Algorithms", package: "swift-algorithms"),
                .product(name: "AsyncAlgorithms", package: "swift-async-algorithms"),
                "HomomorphicEncryption",
                "_HomomorphicEncryptionExtras",
            ],
            swiftSettings: librarySettings),
        .target(
            name: "ApplicationProtobuf",
            dependencies: ["HomomorphicEncryptionProtobuf",
                           "PrivateInformationRetrieval",
                           "PrivateNearestNeighborSearch",
                           .product(name: "SwiftProtobuf", package: "swift-protobuf")],
            exclude: ["generated/README.md", "protobuf_module_mappings.txtpb"],
            swiftSettings: librarySettings),
        .target(
            name: "_TestUtilities",
            dependencies: [
                "HomomorphicEncryption",
                "_HomomorphicEncryptionExtras",
                "PrivateInformationRetrieval",
                "PrivateNearestNeighborSearch",
                .product(name: "Numerics", package: "swift-numerics"),
            ],
            swiftSettings: librarySettings),
        .executableTarget(
            name: "PIRGenerateDatabase",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "HomomorphicEncryption",
                "ApplicationProtobuf",
            ],
            swiftSettings: executableSettings),
        .executableTarget(
            name: "PIRProcessDatabase",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "HomomorphicEncryptionProtobuf",
                "ApplicationProtobuf",
                "HomomorphicEncryption",
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: executableSettings),
        .executableTarget(
            name: "PIRShardDatabase",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "HomomorphicEncryption",
                "ApplicationProtobuf",
            ],
            swiftSettings: executableSettings),
        .executableTarget(
            name: "PNNSGenerateDatabase",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "HomomorphicEncryption",
                "ApplicationProtobuf",
            ],
            swiftSettings: executableSettings),
        .executableTarget(
            name: "PNNSProcessDatabase",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "HomomorphicEncryptionProtobuf",
                "ApplicationProtobuf",
                "HomomorphicEncryption",
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: executableSettings),
        .testTarget(
            name: "HomomorphicEncryptionTests",
            dependencies: [
                "HomomorphicEncryption", "_TestUtilities",
                .product(name: "Numerics", package: "swift-numerics"),
            ], swiftSettings: executableSettings),
        .testTarget(
            name: "HomomorphicEncryptionExtrasTests",
            dependencies: [
                "_HomomorphicEncryptionExtras",
            ], swiftSettings: executableSettings),
        .testTarget(
            name: "HomomorphicEncryptionProtobufTests",
            dependencies: [
                "HomomorphicEncryption",
                "HomomorphicEncryptionProtobuf",
                "_TestUtilities",
            ], swiftSettings: executableSettings),
        .testTarget(
            name: "PIRGenerateDatabaseTests",
            dependencies: ["PIRGenerateDatabase",
                           "_TestUtilities",
                           .product(name: "Numerics", package: "swift-numerics")], swiftSettings: executableSettings),
        .testTarget(
            name: "PIRProcessDatabaseTests",
            dependencies: ["PIRProcessDatabase",
                           "_TestUtilities",
                           .product(name: "Numerics", package: "swift-numerics")], swiftSettings: executableSettings),
        .testTarget(
            name: "PrivateInformationRetrievalTests",
            dependencies: [
                "PrivateInformationRetrieval", "_TestUtilities",
                .product(name: "Numerics", package: "swift-numerics"),
            ], swiftSettings: executableSettings),
        .testTarget(
            name: "PrivateNearestNeighborSearchTests",
            dependencies: [
                "PrivateNearestNeighborSearch", "HomomorphicEncryption", "_TestUtilities",
            ], swiftSettings: executableSettings),
        .testTarget(
            name: "ApplicationProtobufTests",
            dependencies: [
                "ApplicationProtobuf",
                "PrivateNearestNeighborSearch",
                "PrivateInformationRetrieval",
                "_TestUtilities",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ], swiftSettings: executableSettings),
    ])

// MARK: - Benchmarks

var enableBenchmarking: Bool {
    let benchmarkFlags = "SWIFT_HOMOMORPHIC_ENCRYPTION_ENABLE_BENCHMARKING"
    if let flag = ProcessInfo.processInfo.environment[benchmarkFlags], flag == "1" {
        return true
    }
    return false
}

if enableBenchmarking {
    print("Enabling benchmarking")
    package.dependencies += [
        .package(url: "https://github.com/ordo-one/package-benchmark", .upToNextMajor(from: "1.4.0")),
    ]
    package.products += [.library(name: "_BenchmarkUtilities", targets: ["_BenchmarkUtilities"])]
    package.targets += [
        .target(
            name: "_BenchmarkUtilities",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                "HomomorphicEncryption",
                "HomomorphicEncryptionProtobuf",
                "PrivateInformationRetrieval",
                "PrivateNearestNeighborSearch",
                "ApplicationProtobuf",
            ],
            swiftSettings: benchmarkSettings),
        .executableTarget(
            name: "PolyBenchmark",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                "HomomorphicEncryption",
            ],
            path: "Benchmarks/PolyBenchmark",
            swiftSettings: benchmarkSettings,
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark"),
            ]),
        .executableTarget(
            name: "RlweBenchmark",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                "HomomorphicEncryption",
            ],
            path: "Benchmarks/RlweBenchmark",
            swiftSettings: benchmarkSettings,
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark"),
            ]),
        .executableTarget(
            name: "PIRBenchmark",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                "HomomorphicEncryption",
                "_BenchmarkUtilities",
            ],
            path: "Benchmarks/PrivateInformationRetrievalBenchmark",
            swiftSettings: benchmarkSettings,
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark"),
            ]),
        .executableTarget(
            name: "PNNSBenchmark",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                "HomomorphicEncryption",
                "_BenchmarkUtilities",
            ],
            path: "Benchmarks/PrivateNearestNeighborSearchBenchmark",
            swiftSettings: benchmarkSettings,
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark"),
            ]),
    ]
}

// MARK: - DoCC plugin

var enableDocCPlugin: Bool {
    let benchmarkFlags = "SWIFT_HOMOMORPHIC_ENCRYPTION_ENABLE_DOCCPLUGIN"
    if let flag = ProcessInfo.processInfo.environment[benchmarkFlags], flag == "1" {
        return true
    }
    return false
}

if enableDocCPlugin {
    package.dependencies += [
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.1.0"),
    ]
}

// Set the minimum macOS version for the package
#if canImport(Darwin)
package.platforms = [
    .macOS(.v26), // Constrained by use of Span
]
#endif
