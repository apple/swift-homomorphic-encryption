# Using Swift Homomorphic Encryption

Get started using Swift Homomorphic Encryption.

## Overview
Swift Homomorphic Encryption is available as a Swift Package Manager package.
To use Swift Homomorphic Encryption, choose a [tag](https://github.com/apple/swift-homomorphic-encryption/tags).
Then, add the following dependency in your `Package.swift`
```swift
.package(
    url: "https://github.com/apple/swift-homomorphic-encryption",
    from: "tag"),
```
replacing `tag` with your chosen tag, e.g. `1.0.0`.

To use the `HomomorphicEncryption` library, add
```swift
.product(name: "HomomorphicEncryption", package: "swift-homomorphic-encryption"),
```
to your target's dependencies.

> Important:
> When linking your executable, make sure to set `-cross-module-optimization`.
> Without this flag, performance of Swift Homomorphic Encryption degrades dramatically,
> due to failure to specialize generics. For example,
> ```swift
> .executableTarget(
>    name: "YourTarget",
>    dependencies: [
>        .product(name: "HomomorphicEncryption", package: "swift-homomorphic-encryption"),
>    ],
>    swiftSettings: [.unsafeFlags(["-cross-module-optimization"],
>       .when(configuration: .release))]
> )

You can then add
```swift
 import HomomorphicEncryption
 ```
to your Swift code to access the functionality in the `HomomorphicEncryption` library.

> Note:
> If you are using Swift Homomorphic Encryption for research, please cite using the
> [CITATION.cff](https://github.com/apple/swift-homomorphic-encryption/blob/main/CITATION.cff) file.

### Supported Platforms
Swift Homomorphic Encryption aims to support all of the platforms where Swift is supported.

> Note: Swift Homomorphic Encryption relies on [SystemRandomNumberGenerator](https://developer.apple.com/documentation/swift/systemrandomnumbergenerator) as a cryptographically secure random number generator, which may have platform-dependent behavior.

### Swift / Xcode versions
The following table maps Swift Homomorphic Encryption packgae versions to required Swift and Xcode versions:

Package version | Swift version | Xcode version
----------------|---------------|-----------------------------------------
1.0.x           | >= Swift 5.10 | >= Xcode 15.3
main            | >= Swift 6.2  | >= Xcode 26

### Source Stability
Swift Homomorphic Encryption follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Source breaking changes to the public API can only land in a new major version, with the following exception:

* Adding a new `case` to a public `enum` type will require only a minor version bump. For instance, we may add a new `enum` to an [HeError](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/documentation/homomorphicencryption/heerror). To avoid breaking source code, add a  `default` case when adding a `switch` on the enum values.

Future minor versions of the package may introduce changes to these rules as needed.

We'd like this package to quickly embrace Swift language and toolchain improvements that are relevant to its mandate. Accordingly, from time to time, we expect that new versions of this package will require clients to upgrade to a more recent Swift toolchain release. Requiring a new Swift release will only require a minor version bump.

> Warning: Any symbol beginning with an underscore, and any product beginning with an underscore, is not subject to semantic versioning: these APIs may change without warning.
