# Parameter Tuning

 Keyword PIR Parameter Tuning

## Overview

The parameters used by keyword PIR determine its performance
and are influenced by the shape of the input database.
Notably, Keyword PIR's server runtime is linear in the shard size,
independent of the keyword size, and dependent on the value size.
Large values, such as images, should be compressed when possible.
Parameters are read in by a JSON file as described in-detail in
[PIRProcessDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirprocessdatabase) documentation.

```sh
PIRProcessDatabase ~/config.json
```

### Basic Parameters

Sharding parameters determine the number of shards and the number of entries
per shard. Sharding sets a hard upper bound on how much privacy the keyword PIR application
has since the server sees the client's desired shard. However, more shards
improves server runtime. Sharding parameters are stored in the `sharding` variable.
They can be set by either `shardCount`, which sets the total
number of shards, or `entryCountPerShard`, which shards the database so each
shard has a minimum of `entryCountPerShard`.

After sharding, the database parameters are determined by the maximum shard
size and the entry size. A "thin" database has many small entries, say a few bytes each,
and a "wide" database has fewer larger entries in each shard.
Wide databases have their entries split across multiple, parallel keyword
PIRs automatically. For thin databases, smaller RLWE plaintexts in
`rlweParameters` offer better performance since each ciphertext
fits many buckets. Large plaintexts are more efficient for
wide databases.

Otherwise, the observed [noise budget](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/homomorphicencryption/ciphertext/noisebudget(using:variabletime:)) is an important parameter to track. If it is low,
then it is best to increase the ciphertext-to-plaintext modulus ratio.
This can be done by either decreasing the plaintext modulus with the same ring dimension
or increasing the ring dimension and ciphertext modulus while keeping the
plaintext somewhat similar. For example, if `n_4096_logq_27_28_28_logt_16`
exhausts the noise budget, consider trying `n_4096_logq_27_28_28_logt_4`.

### Advanced Parameters

Here, thin databases benefit from using one hash function, `hashFunctionCount` = 1,
instead of two when constructing the cuckoo table. This is because many more entries
will fit in one ciphertext and only one ciphertext is sent back to the client.
Response sizes are smaller as a result. Settings with
one hash function can also have a smaller `targetLoadFactor`, e.g., 0.75 instead of 0.9.

The parameter `bucketCount` should mostly be used in the `allowExpansion` form.
Otherwise, `bucketCount` can be set manually with `fixedSize` and `bucketCount`
as the number of buckets per database. More buckets means smaller communication but
larger computation times.

### Examples

The examples rely on the
[PIRGenerateDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirgeneratedatabase)
and
[PIRProcessDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirprocessdatabase)
executables.

#### Thin Database
```sh
PIRGenerateDatabase \
    --output-database thinDatabase.txtpb \
    --row-count 100000 \
    --value-size '2' \
    --value-type random
```

Say we run `PIRProcessDatabase` with RLWE
parameters `n_4096_logq_27_28_28_logt_4`, one shard, and see the
following:
* An evaluation key size of 680.8 KB.
* Query size 28.2 KB and response size 22.6 KB (two ciphertexts).
* A server runtime of about 51 ms.

Then, we can try reducing the response to one ciphertext with
```json
  "cuckooTableArguments": {
    "hashFunctionCount": 1,
    "maxEvictionCount": 100,
    "bucketCount": {
      "allowExpansion": {
        "targetLoadFactor": 0.75,
        "expansionFactor": 1.1,
      }
    },
    "maxSerializedBucketSize": 200,
  },
  ```
This yields a response with one ciphertext with size 11.3 KB
and a server compute time of about 65 ms.
Note, increasing `maxSerializedBucketSize` from 99 to 200 lowers server
runtime by 50% since each database entry now holds twice as many
keyword-value pairs, making the database smaller for keyword PIR.

#### Wide Database

```json
PIRGenerateDatabase \
    --output-database wideDatabase.txtpb \
    --row-count 1000 \
    --value-size '60000' \
    --value-type random
```

Say we run `PIRProcessDatabase` with RLWE parameters
`n_4096_logq_27_28_28_logt_5` and notice we have a large
response size, 738.3 KB. We can reduce the response
size to 387.2 KB by switching to RLWE parameters `n_8192_logq_3x55_logt_24`,
and server runtime goes from about 610 ms to about 840 ms.
We can also reduce the response size further
by using one hash function, as above, at the cost of
much higher server runtime, about 3.5 seconds.
