# Using Swift Homomorphic Encryption

Get started using Swift Homomorphic Encryption.

## Overview
Swift Homomorphic Encryption requires:
* 64-bit processor with little-endian memory representation
* macOS or Linux operating system
* [Swift](https://www.swift.org/) version 5.10 or later

> Note: Swift Homomorphic Encryption relies on [SystemRandomNumberGenerator](https://developer.apple.com/documentation/swift/systemrandomnumbergenerator) as a cryptographically secure random number generator, which may have platform-dependent behavior.

Swift Homomorphic Encryption is available as a Swift Package Manager package.
To use Swift Homomorphic Encryption, choose a [tag](https://github.com/apple/swift-homomorphic-encryption/tags).
Then, add the following dependency in your `Package.swift`
```swift
.package(
    url: "https://github.com/apple/swift-homomorphic-encryption",
    from: "tag"),
```
replacing `tag` with your chosen tag, e.g. `1.0.0-alpha.1`.

To use the `HomomorphicEncryption` library, add
```swift
.product(name: "HomomorphicEncryption", package: "swift-homomorphic-encryption"),
```
to your target's dependencies.

> Important:
> When linking your executable, make sure to enable `cross-module-optimization`.
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
