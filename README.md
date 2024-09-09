# Swift Homomorphic Encryption

*Swift Homomorphic Encryption* is a Swift implementation of homomorphic encryption (HE) and applications including Private Information Retrieval (PIR).

Applications of Swift Homomorphic Encryption include:
* [Live Caller ID Lookup](https://github.com/apple/live-caller-id-lookup-example)

## Overview
Swift Homomorphic Encryption is a collection of libraries and executables.
For more information, refer to documentation for the libraries:
* [HomomorphicEncryption](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/homomorphicencryption)
* [PrivateInformationRetrieval](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/privateinformationretrieval)
* [HomomorphicEncryptionProtobuf](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/homomorphicencryptionprotobuf)
* [PrivateInformationRetrievalProtobuf](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/privateinformationretrievalprotobuf)

and executables:
* [PIRGenerateDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirgeneratedatabase)
* [PIRProcessDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirprocessdatabase)
* [PIRShardDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirsharddatabase)

The documentation is hosted on the [Swift Package Index](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/documentation/homomorphicencryption).

## Background
### Homomorphic Encryption (HE)
Swift Homomorphic Encryption implements a special form of cryptography called homomorphic encryption (HE).
HE is a cryptosystem which enables computation on encrypted data.
The computation is performed directly on the encrypted data, *without revealing the plaintext of that data to the operating process*.
HE computations therefore happen without decryption or access to the decryption key.

HE thereby allows a client to enable a server to perform operations on encrypted data, and therefore without revealing the data to server.
A typical HE workflow might be:
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

> [!WARNING]
> PIR is asymmetric, meaning the client may learn keyword-value pairs not requested, as happens in trivial PIR for instance.
> A variant of PIR, known as *symmetric PIR*, would be required to ensure the client does not learn anything about values it did not request.

## Using Swift Homomorphic Encryption
Swift Homomorphic Encryption requires:
* 64-bit processor with little-endian memory representation
* macOS or Linux operating system
* [Swift](https://www.swift.org/) version 5.10 or later

> [!NOTE]
> Swift Homomorphic Encryption relies on [SystemRandomNumberGenerator](https://developer.apple.com/documentation/swift/systemrandomnumbergenerator) as a cryptographically secure random number generator, which may have platform-dependent behavior.

Swift Homomorphic Encryption is available as a Swift Package Manager package.
To use Swift Homomorphic Encryption, choose a [tag](https://github.com/apple/swift-homomorphic-encryption/tags).
Then, add the following dependency in your `Package.swift`
```swift
.package(
    url: "https://github.com/apple/swift-homomorphic-encryption",
    from: "tag"),
```
, replacing `tag` with your chosen tag, e.g. `1.0.0-alpha.3`.

To use the `HomomorphicEncryption` library, add
```swift
.product(name: "HomomorphicEncryption", package: "swift-homomorphic-encryption"),
```
to your target's dependencies.

> [!IMPORTANT]
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
> ```

You can then add
```swift
 import HomomorphicEncryption
 ```
to your Swift code to access the functionality in the `HomomorphicEncryption` library.

See the example [Snippets](https://github.com/apple/swift-homomorphic-encryption/tree/main/Snippets) for examples of using `HomomorphicEncryption`.
To run the `EncryptionParametersSnippet` example, run
```
swift run -c release EncryptionParametersSnippet
```

> [!NOTE]
> If you are using Swift Homomorphic Encryption for research, please cite using the
> [CITATION.cff](CITATION.cff) file.

## Developing Swift Homomorphic Encryption
### Dependencies
Building Swift Homomorphic Encryption requires:
* [Swift](https://www.swift.org/) version 5.10 or later

Additionally, developing Swift Homomorphic Encryption requires:
* [Nick Lockwood SwiftFormat](https://github.com/nicklockwood/SwiftFormat), v0.54.0
* [pre-commit](https://pre-commit.com)
* [swift-format](https://github.com/apple/swift-format), v510.1.0
* [swift-protobuf](https://github.com/apple/swift-protobuf), v1.27.0
* [SwiftLint](https://github.com/realm/SwiftLint), v0.55.1

### Building
You can build Swift Homomorphic Encryption either via Xcode or via command line in a terminal.

After cloning the repository, run
```sh
cd swift-homomorphic-encryption
git submodule update --init --recursive
```

#### Xcode
To build Swift Homomorphic Encryption from Xcode, simply open the root directory in Xcode.
See the [Xcode documentation](https://developer.apple.com/documentation/Xcode) for more details on developing with Xcode.

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
* Xcode
  * Open the `swift-homomorphic-encryption` folder in Xcode.
  * Switch to a benchmark target.
  * Run the target, e.g., via the `Product` menu.
* Command line
  * Run `swift package benchmark`.
  * See the [Benchmark](https://github.com/ordo-one/package-benchmark) documentation for more information on running benchmarks.

### Contributing
If you are interested in making a contribution to Swift Homomorphic Encryption, see our [contributing guide](CONTRIBUTING.md).

# Documentation
Swift Homomorphic Encryption uses DocC for documentation.
For more information, refer to [the DocC documentation](https://www.swift.org/documentation/docc) and the [Swift-DocC Plugin](https://swiftlang.github.io/swift-docc-plugin/documentation/swiftdoccplugin/).

## Xcode
The documentation can be built from Xcode via `Product -> Build Documentation`.

## Command line
The documentation can be built from command line by running
```sh
swift package generate-documentation
```
and previewed by running
```sh
swift package --disable-sandbox preview-documentation --target HomomorphicEncryption
```
