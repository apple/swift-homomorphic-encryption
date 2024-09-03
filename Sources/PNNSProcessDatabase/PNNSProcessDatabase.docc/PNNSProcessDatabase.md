# ``PNNSProcessDatabase``

Private Nearest Neighbors Search database processing

## Overview
PNNS database processing will transform a database in preparation for hosting PNNS queries.
The `PNNSProcessDatabase` binary performs the processing.

### Requirements
First ensure sure that the `~/.swiftpm/bin` directory is on your `$PATH`.
For example, if using the `zsh` shell, add the following line to your `~/.zshrc`
```sh
export PATH="$HOME/.swiftpm/bin:$PATH"
```
Make sure to reload the path via (`source ~/.zshrc`) or by restarting your terminal emulator.

Then, to install the `PNNSProcessDatabase`, executable, e.g., run
```sh
swift package experimental-install -c release --product PNNSProcessDatabase
```

### Processing
PNNS database processing is determined by its parameters.
All parameters are set with a configuration `.json` file.
The database is processed by running the `PNNSProcessDatabase` binary using
```sh
PNNSProcessDatabase path/to/config.json
```

Run `PNNSProcessDatabase --help` to get a sample JSON configuration.

#### Required Configuration Parameters

There are three required parameters:
1. `rlweParameters` is one of the [PredefinedRlweParameters](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/homomorphicencryption/predefinedrlweparameters),
e.g., `n_8192_logq_3x55_logt_30`.
2. `inputDatabase` is the path to the unprocessed input database. It must be a
serialized `Apple_SwiftHomomorphicEncryption_Pnns_V1_Database`.

> Note: The `PNNSGenerateDatabase` binary can be used to generate a sample database.

3. `outputDatabase` is the path to where the processed database will be
written. This string should have extension either `.txtpb` or `.binpb`.

A minimal configuration sample is
```json
{
    "rlweParameters": "n_8192_logq_3x55_logt_30",
    "inputDatabase": "/path/to/input/database.binpb",
    "outputDatabase": "/path/to/output/database.binpb",
}
```
The only required parameter variable which affects performance is
`rlweParameters`. These parameters are picked from a set of [PredefinedRlweParameters](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/homomorphicencryption/predefinedrlweparameters).
See the [EncryptionParameters snippet]( https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/homomorphicencryption/usingswifthomomorphicencryption#Encryption-Parameters) for more information on encryption parameters.

For vector dimensions, e.g. 128 or below, `n_4096_logq_27_28_28_logt_16` may be a good choice.
For larger vector dimensions, `n_8192_logq_3x55_logt_30` may be a good choice.

### Optional Configuration Parameters

* `outputServerConfig`. This is a path to the output server configuration. While not required, it can be useful to see what configuration was used to process the database.

* `distanceMetric`. Specifies the metric to use for distance computation. For instance, to specify cosine similarity, use `"distanceMetric" : { "cosineSimilarity" : { } },`.

* `extraPlaintextModuli`. To increase precision of the distance computation, we can use multiple plaintext moduli. For instance, if `n_4096_logq_27_28_28_logt_16` gives too low precision, you might include `extraPlaintextModuli: [65537]` in your configuration.

* `batchSize`. The maximum number of vectors entries in each client query.

* `scalingFactor`. The amount to scale each query vector entry before rounding. A larger `scalingFactor` will increase precision, but may require a larger plaintext modulus for accurate results. If unspecified, the maximum scaling factor will be used.

* `databasePacking`. How the database should packing entries into a matrix.

* `queryPacking`. How the client should pack entries into a matrix.

* `trials`. How many test queries to run against the processed database.
For each trial, a query is checked for correctness.

* `trialDistanceTolerance`. The absolute value of the distance between the test query and the expected result.

### Example

Our example relies in the `PNNSGenerateDatabase` executable.
To install it, run `PNNSProcessDatabase`, executable, run
```sh
swift package experimental-install -c release --product PNNSProcessDatabase
```

```sh
PNNSGenerateDatabase \
    --output-database database.txtpb \
    --row-count 4096 \
    --metadata-size 3 \
    --vector-dimension 128 \
    --vector-type unit
```

To process the data, write the following configuration into a file called `config.json`.
```json
{
    "batchSize" : 1,
    "databasePacking" : {
    "diagonal" : {
        "babyStepGiantStep" : {
            "babyStep" : 12,
            "giantStep" : 11,
            "vectorDimension" : 128
        }
    }
    },
    "distanceMetric" : {
        "cosineSimilarity" : { }
    },
    "extraPlaintextModuli" : [ ],
    "inputDatabase" : "database.txtpb",
    "outputDatabase" : "processed-database.binpb",
    "outputServerConfig" : "server-config.txtpb",
    "queryPacking" : {
        "denseRow" : { }
    },
    "rlweParameters" : "n_4096_logq_27_28_28_logt_17",
    "trialTolerance" : 0.01,
    "trials" : 10
}
```

Now call the executable.
```sh
PNNSProcessDatabase config.json
```

You might observe logs like the below
```
2024-08-29T12:58:12-0700 info PNNSProcessDatabase : [PNNSProcessDatabase] ValidationResult {
  evaluation key size : 170.2 KB (2 keys),
  noise budget : 4.1,
  query size : 28.2 KB (1 ciphertexts),
  response size : 52.1 KB (1 ciphertexts),
  runtime (ms) : [10.4, 10.7, 10.8, 10.9, 11.0, 11.1, 11.2, 11.2, 12.3, 12.5]
}
```

The executable should also have saved `server-config.txtpb` and `processed-database.binpb`.
You can then load `processed-database.binpb` to host PNNS queries, for example via

```swift
let databasePath = "processed-database.binpb"
let serializedDatabase = try Apple_SwiftHomomorphicEncryption_Pnns_V1_SerializedProcessedDatabase(
    from: databasePath
)
let native: SerializedProcessedDatabase<Scheme> = try serializedDatabase.native()
let database = try ProcessedDatabase<Scheme>(from: native)
let server = try Server<Scheme>(database: database)
```
