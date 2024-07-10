# Using Swift Homomorphic Encryption

Get started using Swift Homomorphic Encryption.

## Overview
Swift Homomorphic Encryption requires:
* 64-bit processor with little-endian memory representation
* macOS or Linux operating system
* [Swift](https://www.swift.org/) version 6.0 or later

> Note: Swift Homomorphic Encryption relies on [SystemRandomNumberGenerator](https://developer.apple.com/documentation/swift/systemrandomnumbergenerator) as a cryptographically secure random number generator, which may have platform-dependent behavior.

Swift Homomorphic Encryption is available as a Swift Package Manager package.
To use Swift Homomorphic Encryption, choose a [tag](https://github.com/apple/swift-homomorphic-encryption/tags).
Then, add the following dependency in your `Package.swift`, adding the commit hash associated with the tag.
```swift
.package(
    url: "https://github.com/apple/swift-homomorphic-encryption",
    revision: "git-commit-associated-with-the-tag"),
```

> Note:
> Due to the use of `unsafeFlags` in Swift Homomorphic Encryption, you shouldn't depend on a git tag, which could prevent tagged releases of downstream projects.
> In particular, without the `cross-module-optimization` flag, performance degrades dramatically.
> One workaround is to add `SwiftHomomorphicEncryption` as a submodule rather than a package dependency.

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
