# Using Swift Homomorphic Encryption

Get started using Swift Homomorphic Encryption.

## Overview
Swift Homomorphic Encryption requires:
* 64-bit processor with little-endian memory representation
* macOS or Linux operating system
* [Swift](https://www.swift.org/) version 6.0 or later

> Note: Swift Homomorphic Encryption relies on [SystemRandomNumberGenerator](https://developer.apple.com/documentation/swift/systemrandomnumbergenerator) as a cryptographically secure random number generator, which may have platform-dependent behavior.

Swift Homomorphic Encryption is available as a Swift Package Manager package.
To use Swift Homomorphic Encryption, add the following dependency in your `Package.swift`:
```swift
.package(url: "https://github.com/apple/swift-homomorphic-encryption", .upToNextMajor(from: "0.1.0")),
```
To use the `HomomorphicEncryption` library, add
```swift
.product(name: "HomomorphicEncryption", package: "swift-homomorphic-encryption"),
```
to your target's dependencies.
You can then add
```swift
 import HomomorphicEncryption
 ```
to your Swift code to access the functionality in the `HomomorphicEncryption` library.
