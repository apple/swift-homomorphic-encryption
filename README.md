# Swift Homomorphic Encryption

*Swift Homomorphic Encryption* is a Swift implementation of homomorphic encryption (HE) and applications including Private Information Retrieval (PIR).

Applications of Swift Homomorphic Encryption include:
* [Live Caller ID Lookup](https://developer.apple.com/documentation/identitylookup/getting-up-to-date-calling-and-blocking-information-for-your-app) & [Network Extension URL Filter](https://developer.apple.com/documentation/networkextension/url-filters)
  * See https://github.com/apple/pir-service-example for a sample service

## Overview
Swift Homomorphic Encryption is a collection of libraries and executables.
For more information, refer to documentation for the libraries:
* [HomomorphicEncryptionProtobuf](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/homomorphicencryptionprotobuf)
* [HomomorphicEncryption](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/homomorphicencryption)
* [PrivateInformationRetrievalProtobuf](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/privateinformationretrievalprotobuf)
* [PrivateInformationRetrieval](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/privateinformationretrieval)
* [PrivateNearestNeighborSearchProtobuf](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/privatenearestneighborsearchprotobuf)
* [PrivateNearestNeighborSearch](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/privatenearestneighborsearch)

and executables:
* [PIRGenerateDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirgeneratedatabase)
* [PIRProcessDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirprocessdatabase)
* [PIRShardDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirsharddatabase)
* [PNNSGenerateDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pnnsgeneratedatabase)
* [PNNSProcessDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pnnsprocessdatabase)

The documentation is hosted on the [Swift Package Index](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/documentation).

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
> BFV does not provide IND-CCA security, nor does it provide IND-CPA<sup>D</sup> security when there is a non-negligible decryption error probability. BFV should be used accordingly.
> In particular, no information about each decrypted ciphertext should be sent back to the server. To protect against a malicious server, the client should also validate the decrypted content is in the expected format.
>
> Consult a cryptography expert when developing and deploying homomorphic encryption applications.

### Private Information Retrieval (PIR)
Private information retrieval (PIR) is one application of HE.
PIR enables a client to perform a database lookup from a server hosting a keyword-value database, *without the server learning the keyword in the client's query.*.
Each row in the database is a *keyword* with an associated *value*.
During the PIR protocol, the client issues a query using its private keyword, and learns the value associated with the keyword.

A trivial implementation of PIR is to have the client issue a generic "fetch database" request, independent of its private keyword.
Then the server sends the entire database to the client.
While this *trivial PIR* protocol satisfies the privacy and correctness requirements of PIR, it is only feasible for small databases.

The PIR implementation in Swift Homomorphic Encryption uses HE to improve upon the trivial PIR protocol.

> [!WARNING]
> PIR is asymmetric, meaning the client may learn keyword-value pairs not requested, as happens in trivial PIR for instance.
> A variant of PIR, known as *symmetric PIR*, would be required to ensure the client does not learn anything about values it did not request.

### Private Nearest Neighbor Search (PNNS)
Private nearest neighbor search (PNNS) enables a client with a private vector to search for the nearest vectors in a database hosted by a server, *without the server learning the client's vector.*.
Each row in the database is a *vector* with an associated *entry identifier* and *entry metadata*.
During the PNNS protocol, the client issues a query using its private vector, and learns the nearest neighbor according to a ``DistanceMetric``.
Specifically, the client learns the distances between the client's query vector to the nearest neighbor, as well as the entry identifier and entry metadata of the nearest neighbor.

A trivial implementation of PNNS is to have the client issue a generic "fetch database" request, independent of its private vector.
Then the server sends the entire database to the client, who computes the distances locally.
While this *trivial PNNS* protocol satisfies the privacy and correctness requirements of PNNS, it is only feasible for small databases.

The PNNS implementation in Swift Homomorphic Encryption uses homomorphic encryption to improve upon the trivial PNNS protocol.

## Using Swift Homomorphic Encryption
Swift Homomorphic Encryption is available as a Swift Package Manager package.
To use Swift Homomorphic Encryption, choose a [tag](https://github.com/apple/swift-homomorphic-encryption/tags).
Then, add the following dependency in your `Package.swift`
```swift
.package(
    url: "https://github.com/apple/swift-homomorphic-encryption",
    from: "tag"),
```
, replacing `tag` with your chosen tag, e.g. `1.0.0`.

To use the `HomomorphicEncryption` library, add
```swift
.product(name: "HomomorphicEncryption", package: "swift-homomorphic-encryption"),
```
to your target's dependencies.

> [!IMPORTANT]
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
> ```

You can then add
```swift
 import HomomorphicEncryption
 ```
to your Swift code to access the functionality in the `HomomorphicEncryption` library.

> [!NOTE]
> If you are using Swift Homomorphic Encryption for research, please cite using the
> [CITATION.cff](CITATION.cff) file.

#### Examples
See the [Snippets](https://github.com/apple/swift-homomorphic-encryption/tree/main/Snippets) for examples using `HomomorphicEncryption`.
To run the `EncryptionParametersSnippet`, run
```
swift run -c release EncryptionParametersSnippet
```

### Supported Platforms
Swift Homomorphic Encryption aims to support all of the platforms where Swift is supported.

> [!NOTE]
> Swift Homomorphic Encryption relies on [SystemRandomNumberGenerator](https://developer.apple.com/documentation/swift/systemrandomnumbergenerator) as a cryptographically secure random number generator, which may have platform-dependent behavior.

### Swift / Xcode versions
The following table maps Swift Homomorphic Encryption package versions to required Swift and Xcode versions:

Package version | Swift version | Xcode version
----------------|---------------|-----------------------------------------
1.0.x           | >= Swift 5.10 | >= Xcode 15.3
main            | >= Swift 6.0  | >= Xcode 16.1

### Source Stability
Swift Homomorphic Encryption follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Source breaking changes to the public API can only land in a new major version, with the following exception:

* Adding a new `case` to a public `enum` type will require only a minor version bump. For instance, we may add a new `enum` to an [HeError](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/documentation/homomorphicencryption/heerror). To avoid breaking source code, add a  `default` case when adding a `switch` on the enum values.

Future minor versions of the package may introduce changes to these rules as needed.

We'd like this package to quickly embrace Swift language and toolchain improvements that are relevant to its mandate. Accordingly, from time to time, we expect that new versions of this package will require clients to upgrade to a more recent Swift toolchain release. Requiring a new Swift release will only require a minor version bump.

> [!WARNING]
> Any symbol beginning with an underscore, and any product beginning with an underscore, is not subject to semantic versioning: these APIs may change without warning.

## Developing Swift Homomorphic Encryption
### Dependencies
Developing Swift Homomorphic Encryption requires:
* [Nick Lockwood SwiftFormat](https://github.com/nicklockwood/SwiftFormat), 0.56.4
* [pre-commit](https://pre-commit.com)
* [swift-format](https://github.com/swiftlang/swift-format), 600.0.0
* [swift-protobuf](https://github.com/apple/swift-protobuf), 1.29.0
* [SwiftLint](https://github.com/realm/SwiftLint), 0.59.1

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

First ensure that the `~/.swiftpm/bin` directory is on your `$PATH`.
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
swift test -c release
```
To run tests in debug mode, run
```sh
swift test
```
> [!WARNING]
> Tests will be slow in debug mode.

### Benchmarking
Swift homomorphic encryption uses [Benchmark](https://github.com/ordo-one/package-benchmark) for benchmarking.
To enable benchmarking, set the environment variable `SWIFT_HOMOMORPHIC_ENCRYPTION_ENABLE_BENCHMARKING=1`.
By default, benchmarking requires the [jemalloc](http://jemalloc.net) dependency.

> [!WARNING]
> The benchmark may crash intermittently due to a known [issue](https://github.com/ordo-one/package-benchmark/issues/60).
> For reliable execution, benchmark can be run without `jemalloc` as described [here](https://github.com/ordo-one/package-benchmark/releases/tag/1.2.0).

Two ways to run the benchmarks are:
* Xcode
  * Open the `swift-homomorphic-encryption` folder in Xcode with `SWIFT_HOMOMORPHIC_ENCRYPTION_ENABLE_BENCHMARKING=1` set, e.g.:
    * `open --env SWIFT_HOMOMORPHIC_ENCRYPTION_ENABLE_BENCHMARKING=1 Package.swift`
  * Switch to a benchmark target.
  * Run the target, e.g., via the `Product` menu.
* Command line
  * Run `SWIFT_HOMOMORPHIC_ENCRYPTION_ENABLE_BENCHMARKING=1 swift package benchmark`.
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
