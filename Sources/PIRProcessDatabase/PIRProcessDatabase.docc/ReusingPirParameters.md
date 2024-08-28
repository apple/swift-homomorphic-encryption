# Reusing PIR Parameters

Learn how to reuse PIR parameters across database updates.

## Overview
Database updates may lead to different PIR configurations, which need to be synced to the client.
We can configure the database processing to yield the same PIR configuration across database updates.

### Requirements
This example assumes that you have the following binaries available on your `$PATH`.
The binaries are:
 - `PIRGenerateDatabase`
 - `PIRProcessDatabase`

The way to add these to your path is by first making sure that the `~/.swiftpm/bin` directory is on your `$PATH`. To do
so, add the following line to your `~/.zshrc` or appropriate shell configuration file.
```sh
export PATH="$HOME/.swiftpm/bin:$PATH"
```
Make sure to reload it (`source ~/.zshrc`) or by restarting your terminal emulator. Then we are going to use the
`experimental-install` feature of Swift Package Manager.

Change directory to a checkout of this repository and run the following command.
```sh
swift package experimental-install -c release --product PIRGenerateDatabase
swift package experimental-install -c release --product PIRProcessDatabase
```

### Example
#### Database Creation

1. We start by generating a sample database.

```sh
PIRGenerateDatabase \
    --output-database /tmp/database-v1.txtpb \
    --row-count 10000 \
    --value-size '10...20' \
    --value-type repeated
```

This will generate a database of 10000 rows, with keywords 0 to 9999, and each value repeating the keyword for 10 to 20 bytes.

We view a few rows from the database with
```sh
head /tmp/database-v1.txtpb
```
which shows
```json
rows {
  keyword: "0"
  value: "000000000000000"
}
rows {
  keyword: "1"
  value: "111111111111111111"
}
rows {
  keyword: "2"
```

2. To simulate an updated database, we generate a database update with 1000 more rows and different value sizes.
```
PIRGenerateDatabase \
    --output-database /tmp/database-update.txtpb \
    --row-count 1000 \
    --first-keyword 10000 \
    --value-size '10..<25' \
    --value-type repeated
```

We combine the initial database with the update to create `/tmp/database-v2.txtpb`.
```sh
cat /tmp/database-v1.txtpb /tmp/database-update.txtpb > /tmp/database-v2.txtpb
```

#### Processing
To ensure processing the update database yields the same configuration, we use the `.fixedSize` cuckoo table argument, specifying a bucket count.
A larger bucket count will leave more room for new entries, without changing the configuration.
However, a larger bucket count will also increase server runtime.
One way to choose the `bucketCount` is to start with `bucketCount : 1` and try larger `bucketCounts` until the processing works.
If the processing throws a `PirError.failedToConstructCuckooTable` or logs `Failed to construct Cuckoo table`, this is an indication the chosen bucket count was too small.

We create `/tmp/config-v1-fixed-size.json` with the following contents
```
{
  "algorithm" : "mulPir",
  "cuckooTableArguments" : {
    "bucketCount" : {
      "fixedSize" : {
        "bucketCount" : 256,
      }
    },
    "hashFunctionCount" : 2,
    "maxEvictionCount" : 100,
    "maxSerializedBucketSize" : 1024
  },
  "inputDatabase" : "/tmp/database-v1.txtpb",
  "keyCompression" : "noCompression",
  "outputDatabase" : "/tmp/database-v1-SHARD_ID.bin",
  "outputEvaluationKeyConfig" : "/tmp/database-v1-evaluation-key-config.txtpb",
  "outputPirParameters" : "/tmp/database-v1-pir-parameters-SHARD_ID.txtpb",
  "rlweParameters" : "n_4096_logq_27_28_28_logt_5",
  "sharding" : {
    "shardCount" : 2
  },
  "trialsPerShard" : 1
}
```
and process the original database with
```sh
PIRProcessDatabase /tmp/config-v1-fixed-size.json
```

We can get a hash of the output parameters with `cat /tmp/database-v1-pir-parameters-*.txtpb | shasum`

We create `/tmp/config-v2-fixed-size.json` by replacing `v1` with `v2`:
```sh
sed 's/v1/v2/g' /tmp/config-v1-fixed-size.json > /tmp/config-v2-fixed-size.json
```
and process the updated database with
```sh
PIRProcessDatabase /tmp/config-v2-fixed-size.json
```
We can get a hash of the output parameters with `cat /tmp/database-v2-pir-parameters-*.txtpb | shasum`.
This should match the shasum from `cat /tmp/database-v1-pir-parameters-*.txtpb | shasum`.
