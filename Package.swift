// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Remember to update CI if changing

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
import PackageDescription

let librarySettings: [SwiftSetting] = [
    .enableExperimentalFeature("StrictConcurrency"),
]

let executableSettings: [SwiftSetting] =
    librarySettings +
    [.unsafeFlags(["-cross-module-optimization"], .when(configuration: .release))]

let benchmarkSettings: [SwiftSetting] = [.unsafeFlags(["-cross-module-optimization"], .when(configuration: .release))]

let package = Package(
    name: "swift-homomorphic-encryption",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "HomomorphicEncryption",
            targets: ["HomomorphicEncryption"]),
        .library(
            name: "HomomorphicEncryptionProtobuf",
            targets: ["HomomorphicEncryptionProtobuf"]),
        .library(
            name: "PrivateInformationRetrieval",
            targets: ["PrivateInformationRetrieval"]),
        .library(
            name: "PrivateInformationRetrievalProtobuf",
            targets: ["PrivateInformationRetrievalProtobuf"]),
        .library(
            name: "PrivateNearestNeighborsSearch",
            targets: ["PrivateNearestNeighborsSearch"]),
        .library(
            name: "PrivateNearestNeighborsSearchProtobuf",
            targets: ["PrivateNearestNeighborsSearchProtobuf"]),
        .executable(name: "PIRGenerateDatabase", targets: ["PIRGenerateDatabase"]),
        .executable(name: "PIRProcessDatabase", targets: ["PIRProcessDatabase"]),
        .executable(name: "PIRShardDatabase", targets: ["PIRShardDatabase"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-algorithms", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.4.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-numerics", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-protobuf", from: "1.27.0"), // Keep version in sync with README
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.1.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "CUtil",
            dependencies: [],
            path: "Sources/CUtil",
            sources: ["zeroize.c"],
            publicHeadersPath: "."),
        .target(
            name: "HomomorphicEncryption",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                "CUtil",
            ],
            swiftSettings: librarySettings),
        .target(
            name: "HomomorphicEncryptionProtobuf",
            dependencies: ["HomomorphicEncryption",
                           .product(name: "SwiftProtobuf", package: "swift-protobuf")],
            exclude: ["generated/README.md"],
            swiftSettings: librarySettings),
        .target(
            name: "PrivateInformationRetrieval",
            dependencies: ["HomomorphicEncryption",
                           .product(name: "Numerics", package: "swift-numerics")],
            swiftSettings: librarySettings),
        .target(
            name: "PrivateInformationRetrievalProtobuf",
            dependencies: ["PrivateInformationRetrieval",
                           "HomomorphicEncryption",
                           "HomomorphicEncryptionProtobuf",
                           .product(name: "SwiftProtobuf", package: "swift-protobuf")],
            exclude: ["generated/README.md", "protobuf_module_mappings.txtpb"],
            swiftSettings: librarySettings),
        .target(
            name: "PrivateNearestNeighborsSearch",
            dependencies: [
                .product(name: "Algorithms", package: "swift-algorithms"),
                "HomomorphicEncryption",
            ],
            swiftSettings: librarySettings),
        .target(
            name: "PrivateNearestNeighborsSearchProtobuf",
            dependencies: ["PrivateNearestNeighborsSearch",
                           "HomomorphicEncryption",
                           "HomomorphicEncryptionProtobuf",
                           .product(name: "SwiftProtobuf", package: "swift-protobuf")],
            exclude: ["generated/README.md", "protobuf_module_mappings.txtpb"],
            swiftSettings: librarySettings),
        .target(
            name: "TestUtilities",
            dependencies: [
                "HomomorphicEncryption",
                .product(name: "Numerics", package: "swift-numerics"),
            ],
            swiftSettings: librarySettings),
        .executableTarget(
            name: "PIRGenerateDatabase",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "HomomorphicEncryption",
                "PrivateInformationRetrievalProtobuf",
            ],
            swiftSettings: executableSettings),
        .executableTarget(
            name: "PIRProcessDatabase",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "HomomorphicEncryptionProtobuf",
                "PrivateInformationRetrievalProtobuf",
                "HomomorphicEncryption",
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: executableSettings),
        .executableTarget(
            name: "PIRShardDatabase",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "HomomorphicEncryption",
                "PrivateInformationRetrievalProtobuf",
            ],
            swiftSettings: executableSettings),
        .testTarget(
            name: "HomomorphicEncryptionTests",
            dependencies: [
                "HomomorphicEncryption", "TestUtilities",
                .product(name: "Numerics", package: "swift-numerics"),
            ], swiftSettings: executableSettings),
        .testTarget(
            name: "HomomorphicEncryptionProtobufTests",
            dependencies: [
                "HomomorphicEncryption",
                "HomomorphicEncryptionProtobuf",
                "TestUtilities",
            ], swiftSettings: executableSettings),
        .testTarget(
            name: "PIRGenerateDatabaseTests",
            dependencies: ["PIRGenerateDatabase",
                           "TestUtilities",
                           .product(name: "Numerics", package: "swift-numerics")], swiftSettings: executableSettings),
        .testTarget(
            name: "PIRProcessDatabaseTests",
            dependencies: ["PIRProcessDatabase",
                           "TestUtilities",
                           .product(name: "Numerics", package: "swift-numerics")], swiftSettings: executableSettings),
        .testTarget(
            name: "PrivateInformationRetrievalTests",
            dependencies: [
                "PrivateInformationRetrieval", "TestUtilities",
                .product(name: "Numerics", package: "swift-numerics"),
            ], swiftSettings: executableSettings),
        .testTarget(
            name: "PrivateInformationRetrievalProtobufTests",
            dependencies: [
                "PrivateInformationRetrieval",
                "PrivateInformationRetrievalProtobuf",
                "TestUtilities",
            ], swiftSettings: executableSettings),
        .testTarget(
            name: "PrivateNearestNeighborsSearchTests",
            dependencies: [
                "PrivateNearestNeighborsSearch", "HomomorphicEncryption", "TestUtilities",
            ], swiftSettings: executableSettings),
        .testTarget(
            name: "PrivateNearestNeighborsSearchProtobufTests",
            dependencies: [
                "PrivateNearestNeighborsSearch",
                "PrivateNearestNeighborsSearchProtobuf",
            ], swiftSettings: executableSettings),
    ])

// MARK: - Benchmarks

package.dependencies += [
    .package(url: "https://github.com/ordo-one/package-benchmark", .upToNextMajor(from: "1.4.0")),
]
package.targets += [
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
            "HomomorphicEncryptionProtobuf",
            "PrivateInformationRetrieval",
            "PrivateInformationRetrievalProtobuf",
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
            "HomomorphicEncryptionProtobuf",
            "PrivateNearestNeighborsSearch",
            "PrivateNearestNeighborsSearchProtobuf",
        ],
        path: "Benchmarks/PrivateNearestNeighborsSearchBenchmark",
        swiftSettings: benchmarkSettings,
        plugins: [
            .plugin(name: "BenchmarkPlugin", package: "package-benchmark"),
        ]),
]

// Set the minimum macOS version for the package
package.platforms = [
    .macOS(.v14), // Constrained by Swift 5.10 support for Xcode (https://developer.apple.com/support/xcode/)
]
