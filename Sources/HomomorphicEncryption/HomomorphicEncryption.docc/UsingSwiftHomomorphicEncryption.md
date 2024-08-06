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
replacing `tag` with your chosen tag, e.g. `1.0.0-alpha.3`.

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

### Examples
We give a few examples for how to use ``HomomorphicEncryption``.
#### Basics
We start with the basics.
@Snippet(path: "swift-homomorphic-encryption/Snippets/HomomorphicEncryption/BasicsSnippet", slice:"encryption")

#### HE Addition and Subtraction
Continuing from the previous example, we can also compute on the encrypted data.
We can add a ciphertext with a ciphertext or a plaintext.
@Snippet(path: "swift-homomorphic-encryption/Snippets/HomomorphicEncryption/BasicsSnippet", slice:"addition")

Continuing from the previous example, we can also subtract a ciphertext by a ciphertext or a plaintext.
@Snippet(path: "swift-homomorphic-encryption/Snippets/HomomorphicEncryption/BasicsSnippet", slice:"subtraction")

#### HE Multiplication
@Snippet(path: "swift-homomorphic-encryption/Snippets/HomomorphicEncryption/MultiplicationSnippet")

#### Evaluation Key
@Snippet(path: "swift-homomorphic-encryption/Snippets/HomomorphicEncryption/EvaluationKeySnippet")

#### Noise budget
@Snippet(path: "swift-homomorphic-encryption/Snippets/HomomorphicEncryption/NoiseBudgetSnippet")

#### Serialization
@Snippet(path: "swift-homomorphic-encryption/Snippets/HomomorphicEncryption/SerializationSnippet")

#### Encryption Parameters
@Snippet(path: "swift-homomorphic-encryption/Snippets/HomomorphicEncryption/EncryptionParametersSnippet")
