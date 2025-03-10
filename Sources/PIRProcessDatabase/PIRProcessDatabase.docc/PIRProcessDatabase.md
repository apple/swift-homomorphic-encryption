# ``PIRProcessDatabase``

Keyword PIR database processing

## Overview
Keyword PIR database processing will transform a database in preparation for hosting PIR queries.
The `PIRProcessDatabase` binary performs the processing.

### Requirements
Build the `PIRProcessDatabase` executable by running:
```sh
swift build -c release --target PIRProcessDatabase
```
The binary will be generated in `.build/release/PIRProcessDatabase`.

### Processing
Keyword PIR's database processing is determined by its parameters.
All parameters are set with a configuration `.json` file.
The database is processed by running the `PIRProcessDatabase` binary using
```sh
PIRProcessDatabase path/to/config.json
```

Run `PIRProcessDatabase --help` to get a sample JSON configuration.

### Required Configuration Parameters

There are four required parameters:
1. `rlweParameters` is one of the [PredefinedRlweParameters](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/1.0.3/documentation/homomorphicencryption/predefinedrlweparameters),
e.g., `n_4096_logq_27_28_28_logt_5`.
2. `inputDatabase` is the path to the unprocessed input database. It must be a
serialized [Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/1.0.3/documentation/privateinformationretrievalprotobuf/apple_swifthomomorphicencryption_pir_v1_keyworddatabase).

> Note: The `PIRGenerateDatabase` binary can be used to generate a sample database.

3. `outputDatabase` is the path to where the processed database’s shards will be
written. This string must contain `SHARD_ID`, unless `sharding` is
`shardCount(1)`. `SHARD_ID` will be replaced with the shard number of each shard.
4. `outputPirParameters` is the path to where each shard’s PIR parameters will be
written. This string must end contain `SHARD_ID`, unless `sharding` is
`shardCount(1)`, and have extension `.txtpb` or `.binpb`. Again, `SHARD_ID` will
be replaced with the shard number of each shard.

A minimal configuration sample is
```json
{
    "rlweParameters": "n_4096_logq_27_28_28_logt_5",
    "inputDatabase": "/path/to/input/database.txtpb",
    "outputDatabase": "/path/to/output/database-SHARD_ID.bin",
    "outputPirParameters": "/path/to/output/pir-params-SHARD_ID.txtpb",
}
```
The only required parameter variable which affects performance is
`rlweParameters`. These parameters are picked from a set of [PredefinedRlweParameters](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/1.0.3/documentation/homomorphicencryption/predefinedrlweparameters).
RLWE parameters are defined by ring dimension `n`, a ciphertext modulus bit
length `log q`, and plaintext modulus bit length, `log t`.

Our secure RLWE parameters can be divided into two groups, ring dimension
`n = 4096` and `n = 8192`. The query and response sizes of the latter are roughly
four times larger than the former since the size of the numbers also, roughly,
doubles when going from `n = 4096` to `n = 8192`. Conversely, larger ring
dimension allows for more homomorphic operations and more plaintext data per
ciphertext.

A ciphertext modulus’s bit length `log q` is generally a function of `n` and its
bit length is fixed for each `n` in order to achieve post-quantum 128-bit
security. Besides ring dimension `n`, the other important parameter is the number
of bits in a plaintext modulus, `log t`. Larger `log t` increases each
ciphertext’s capacity but also increases the chance of a decryption error.
Importantly, each ciphertext can hold `n log t` plaintext bits as a payload. Some
possible RLWE parameters are:

```
n_4096_logq_27_28_28_logt_4
n_4096_logq_27_28_28_logt_5
n_4096_logq_27_28_28_logt_6
n_4096_logq_27_28_28_logt_13
n_4096_logq_27_28_28_logt_16
n_4096_logq_27_28_28_logt_17
n_8192_logq_3x55_logt_24
n_8192_logq_3x55_logt_29
n_8192_logq_3x55_logt_30
n_8192_logq_3x55_logt_42
```
Note, each RLWE ciphertext has an associated noise budget which decreases with the
number of server operations done. If the noise budget gets too low, then the
ciphertext cannot be decrypted and a decryption error occurs. In general, larger
plaintext moduli store more message bits per ciphertext but also incur larger
noise growth. Further, the ciphertext modulus bits determines the noise budget
for each ciphertext.

### Optional Parameters
#### Sharding
Our keyword PIR shards the server’s database to improve performance: the keyword
PIR protocol is run on a database the size the query’s destination shard. The
only sharding parameter is the number of shards. This can be set manually with:
* `shardCount`, e.g., `"shardCount" : 10` will divide the database into 10 roughly equal-sized shards.
* `entryCountPerShard`, e.g. `entryCountPerShard: 1000`, which will divide the database into as many shards as needed to
  average 100 entries per shard.

More shards, or equivalently, fewer entries per shard, lowers the query load per shard. However,
there is a privacy loss in having too many shards since the query’s shard is
leaked to the server. Leakage is determined by the universe size divided by the
number of shards. For example, a universe size of 1 million keywords with two
shards means 500k keywords map to each shard.

#### Symmetric PIR
Some PIR algorithms, such as MulPir, include an optimization which returns multiple keyword-value pairs in the PIR
response, beyond the keyword-value pair requested by the client. However, this may be undesirable, e.g., if the database
contains sensitive IP. `Symmetric PIR` is a variant of PIR which protects the unrequested server values from the client,
in addition to the standard PIR guarantee protecting the client's keyword from the server. A best-effort approach
towards enabling symmetric PIR is to pad the entries, such that only a limited number of entries are in the server
response. However, this approach will increase server runtime.

> Warning: This is only a best-effort approach, because HE does not guarantee *circuit privacy*.

That is, the output of HE computation, though encrypted, can leak to the client information about the computation that
was performed to yield the ciphertext. For instance, the noise budget can leak the encrypted operations were performed
on the query, as well as any plaintext arguments, e.g. database entries.

Three arguments enable this best-effort approach towards symmetric PIR:
* `slotCount`. The maximum number of keyword-value pairs that can be stored in a hash bucket.
* `maxSerializedBucketSize`. We can set size equal to the number of bytes in a plaintexts. This roughly says that each
  bucket can hold as many bytes as a single plaintext.
* `useMaxSerializedBucketSize`. When enabled, the IndexPIR layer will assume that each entry is as large as
  `maxSerializedBucketSize`. This avoids packing multiple hash buckets into a single plaintexts.

Together these options can be used to control the number of entries in a response.

For example, if we want to limit the number of entries in a response to 8, we can set the parameters like this:

In code
```swift
let numberOfEntriesPerResponse = 8
let hashFunctionCount = 2
let config = try KeywordPirConfig(
        dimensionCount: 2,
        cuckooTableConfig: CuckooTableConfig(
            hashFunctionCount: hashFunctionCount,
            maxEvictionCount: 100,
            maxSerializedBucketSize: context.bytesPerPlaintext,
            bucketCount: .allowExpansion(expansionFactor: 1.1, targetLoadFactor: 0.5),
            slotCount: numberOfEntriesPerResponse / hashFunctionCount),
        unevenDimensions: true,
        keyCompression: .noCompression,
        useMaxSerializedBucketSize: true)
```

#### Cryptographic Parameters
Other cryptographic parameters are the following:

* `trialsPerShard` is a positive integer which decides how many test queries
to run for each shard of the processed database.
This test query checks for correctness and that the test response ciphertext has a sufficiently large noise budget.
The suggested value is 1.
* `outputEvaluationKeyConfig` stores the path to the evaluation keys’ parameters.

> Note: Different shards may require different evaluation key configurations.
The `outputEvaluationKeyConfig` argument will store a configuration that is
suitable for any of the processed shards.

* `keyCompression`. The evaluation key can be made smaller at the cost of extra server runtime. For fastest runtime, leave unspecified. For smallest key size, choose `maxCompression`. For a middle ground, choose `hybridCompression`.

#### Cuckoo Table Parameters
Keyword PIR uses bucketed cuckoo hashing to map a keyword to an index in the
database/shard which stores a bucket of keywords’ metadata. All cuckoo table
parameters are stored in the `cuckooTableArguments`, containing the following:
* `hashFunctionCount` is the number of hash functions used in cuckoo hashing.
The suggested value is two.  Two hash functions means that there are two tables
where the second table is where cuckoo evictions go.
* `maxEvictionCount` is the number of evictions before the tables are re-made
with fresh hash functions. One suggested value of 100, but empirically should
never be larger than 1000 since 1000 evictions is statistically unlikely.
* `bucketCount` is the number of buckets in the cuckoo table, and can be set to either `allowExpansion` or `fixedSize`.
  * `allowExpansion`: The number of buckets per shard has two settings:
    * `expansionFactor` indicates how much the cuckoo table can expand while inserting elements. A suggested value for `expansionFactor` is 1.1.

    * `targetLoadFactor` is a measure of how "full" the cuckoo table is, and must be a value in `[0, 1.0]`. A suggested value for `targetLoadFactor` is:
      * 0.9 for `hashFunctionCount = 2`
      * 0.5 for `hashFunctionCount = 1`.

    * A sample `bucketCount` configuration using `allowExpansion`:
        ```json
        "bucketCount": {
            "allowExpansion": {
                "targetLoadFactor": 0.9,
                "expansionFactor": 1.1
            }
        }
        ```
  * `fixedSize` indicates the cuckoo table will not grow in size, so it will always have `bucketCount` buckets.
    > Note: The cuckoo configuration needs to be synced with the client whenever it changes. So a `fixedSize` is useful to ensure changing the database doesn't change the cuckoo configuration.
    * A sample configuration using `fixedSize`:
        ```json
        "bucketCount": {
            "fixedSize": {
                "bucketCount": 4,
          }
        }
        ```

* `maxSerializedBucketSize` determines how many bytes can be in each bucket.
It should be the number of bytes per metadata times the number of buckets in
each table entry. Then, each PIR response is the number of buckets per entry times
the number of hash functions. For example, two hash functions and three buckets
means each response has metadata for six database entries.
  > Note: `maxSerializedBucketSize` can be tweaked for best performance depending on the database, but should generally not need to be changed.

In general, the cuckoo table parameters are chosen after the cryptographic parameters above.
If a response does not fit into one response ciphertext, then it is best to use two
cuckoo tables instead of increasing the cryptographic parameters to a larger ring dimension
`n`. This is because increasing the ring dimension roughly quadruples the query size and response
size whereas two cuckoo tables doubles these parameters, more or less. Also, large metadata entries
are handled automatically by running multiple keyword PIR protocols in parallel. Each response contains
metadata for `r = bucketCount x hashFunctionCount` tables' keywords.
