# Swift Homomorphic Encryption

*Swift Homomorphic Encryption* is a Swift implementation of homomorphic encryption (HE) and applications including Private Information Retrieval (PIR).

Applications of Swift Homomorphic Encryption include:
* [Live Caller ID Lookup](https://github.com/apple/live-caller-id-lookup-example)

## Overview
Swift Homomorphic Encryption is a collection of libraries and executables.
For more information, refer to documentation for the libraries:
* [HomomorphicEncryption](Sources/HomomorphicEncryption/HomomorphicEncryption.docc/HomomorphicEncryption.md)
* [HomomorphicEncryptionProtobuf](Sources/HomomorphicEncryptionProtobuf/HomomorphicEncryptionProtobuf.docc/HomomorphicEncryptionProtobuf.md)
* [PrivateInformationRetrievalProtobuf](Sources/PrivateInformationRetrievalProtobuf/PrivateInformationRetrievalProtobuf.docc/PrivateInformationRetrievalProtobuf.md)

and executables:
* [PIRGenerateDatabase](Sources/PIRGenerateDatabase/PIRGenerateDatabase.docc/PIRGenerateDatabase.md)
* [PIRProcessDatabase](Sources/PIRProcessDatabase/PIRProcessDatabase.docc/PIRProcessDatabase.md)
* [PIRShardDatabase](Sources/PIRShardDatabase/PIRShardDatabase.docc/PIRShardDatabase.md)

## Background
### Homomorphic Encryption (HE)
Homomorphic encryption (HE) is a cryptosystem which enables computation on encrypted data.
The computation is performed directly on the encrypted data, without decryption or use of a secret key.
HE thereby enables a client to offload computation on its sensitive data to a server by the following workflow:
* The client encrypts its sensitive data and sends the resulting ciphertext to the server.
* The server performs HE computation on the ciphertext (and perhaps its own plaintext inputs), without learning what any ciphertext decrypts to.
* The server sends the resulting ciphertext response to the client.
* The client decrypts to learn the response.

Swift Homomorphic Encryption implements the Brakerski-Fan-Vercauteren (BFV) HE scheme, which is based on the ring learning with errors (RLWE) hardness problem.
This scheme can be configured to support post-quantum 128-bit security.

> [!WARNING]
> BFV does not provide IND-CCA security, and should be used accordingly.
> In particular, as little information as possible about each decrypted ciphertext should be sent back to the server. To protect against a malicious server, the client should also validate the decrypted content is in the expected format.
>
> Consult a cryptography expert when developing and deploying homomorphic encryption applications.

### Private Information Retrieval (PIR)
Private information retrieval (PIR) is one application of HE.
PIR allows a client to perform a database lookup from a server hosting a keyword-value database, *without the server learning the keyword in the client's query.*.
Each row in the database is a *keyword* with an associated *value*.
During the PIR protocol, the client issues a query using its private keyword, and learns the value associated with the keyword.

A trivial implementation of PIR is to have the client issue a generic "fetch database" request, independent of its private keyword.
Then the server server sends the entire database to the client.
While this *trivial PIR* protocol satisfies the privacy and correctness requirements of PIR, it is only feasible for small databases.

The PIR implementation in Swift Homomorphic Encryption uses HE to improve upon the trivial PIR protocol.

## Using Swift Homomorphic Encryption
Swift Homomorphic Encryption requires:
* 64-bit processor with little-endian memory representation
* macOS or Linux operating system
* [Swift](https://www.swift.org/) version 6.0 or later

> [!NOTE]
> Swift Homomorphic Encryption relies on [SystemRandomNumberGenerator](https://developer.apple.com/documentation/swift/systemrandomnumbergenerator) as a cryptographically secure random number generator, which may have platform-dependent behavior.

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

## Developing Swift Homomorphic Encryption
### Dependencies
Building Swift Homomorphic Encryption requires:
* [Swift](https://www.swift.org/) version 6.0 or later

Additionally, developing Swift Homomorphic Encryption requires:
* [Nick Lockwood swiftformat](https://github.com/nicklockwood/SwiftFormat), v0.54.0
* [pre-commit](https://pre-commit.com)
* [swift-format](https://github.com/apple/swift-format), v510.1.0
* [swift-protobuf](https://github.com/apple/swift-protobuf), v1.27.0
* [swiftlint](https://github.com/realm/SwiftLint), v0.55.1

### Building
You can build Swift Homomorphic Encryption either via XCode or via command line in a terminal.

After cloning the repository, run
```sh
cd swift-homomorphic-encryption
git submodule update --init --recursive
```

#### XCode
To build Swift Homomorphic Encryption from XCode, simply open the root directory in XCode.
See the [XCode documentation](https://developer.apple.com/documentation/xcode) for more details on developing with XCode.

#### Command line
To build Swift Homomorphic Encryption from command line, open the root directory (i.e., the `swift-homomorphic-encryption` directory) of the cloned repository in a terminal, and run
```sh
swift build -c release
```
The build products will be in the `.build/release/` folder.

To build in debug mode, run
```sh
swift build
```
The build products will be in the `.build/debug/` folder.
> [!WARNING]
> Runtimes may be much slower in debug mode.

### Installing
To install Swift Homomorphic Encryption targets,  use the `experimental-install` feature of Swift Package Manager.

First ensure sure that the `~/.swiftpm/bin` directory is on your `$PATH`.
For example, if using the `zsh` shell, add the following line to your `~/.zshrc`
```sh
export PATH="$HOME/.swiftpm/bin:$PATH"
```
Make sure to reload the path via (`source ~/.zshrc`) or by restarting your terminal emulator.

Then, to install the `PIRProcessDatabase`, executable, e.g., run
```sh
swift package experimental-install -c release --product PIRProcessDatabase
```

### Testing
Run unit tests via
```sh
swift test -c release --parallel
```
To run tests in debug mode, run
```sh
swift test --parallel
```
> [!WARNING]
> Tests will be slow in debug mode.

### Benchmarking
Swift homomorphic encryption uses [Benchmark](https://github.com/ordo-one/package-benchmark) for benchmarking.
By default, benchmarking requires the [jemalloc](http://jemalloc.net) dependency.

> [!WARNING]
> The benchmark may crash intermittently due to a known [issue](https://github.com/ordo-one/package-benchmark/issues/60).
> For reliable execution, benchmark can be run without `jemalloc` as described [here](https://github.com/ordo-one/package-benchmark/releases/tag/1.2.0).

Two ways to run the benchmarks are:
* XCode
  * Open the `swift-homomorphic-encryption` folder in XCode.
  * Switch to a benchmark target.
  * Run the target, e.g., via the `Product` menu.
* Command line
  * Run `swift package benchmark`.
  * See the [Benchmark](https://github.com/ordo-one/package-benchmark) documentation for more information on running benchmarks.

### Contributing
If you would like to make a pull request to Swift Homomorphic Encryption, please run `pre-commit install`. Then each commit will run some basic formatting checks.

# Documentation
Swift Homomorphic Encryption uses DocC for documentation.
For more information, refer to [the DocC documentation](https://www.swift.org/documentation/docc) and the [Swift-DocC Plugin](https://swiftlang.github.io/swift-docc-plugin/documentation/swiftdoccplugin/).

## XCode
The documentation can be built from XCode via `Product -> Build Documentation`.

## Command line
The documentation can be built from command line by running
```sh
swift package generate-documentation
```
and previewed by running
```sh
swift package --disable-sandbox preview-documentation --target HomomorphicEncryption
```