# Encoding pipeline

Learn how to scale data encoding for Private Information Retrieval.

## Overview

While
[PIRProcessDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirprocessdatabase)
documentation shows how to process small datasets, this page should give you an idea how to process large datasets.

We start by introducing the sharding function. Once a database has been sharded, each shard can be processed
independently. In the end the evaluation key configurations for all shards can be joined together for single evaluation
key configuration that works for all shards.

To encode as fast as possible, one could have multiple nodes that shard slices of the whole dataset. A second set of
nodes will collect the rows from the sharding nodes. Once the whole dataset has been divided into shards, each node
holding a completed shard worth of rows can start processing them. Each node will upload the processed shard & the
resulting PIR parameters to shared storage. A post-processing job can merge all the PIR parameters to construct a
[PIRConfig](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/applicationprotobuf/apple_swifthomomorphicencryption_api_v1_pirconfig)
protobuf message that contains a shared evaluation key configuration and configuration for every shard.

## Sharding function

While we do offer sharding as a convenience feature in ``KeywordDatabase/init(rows:sharding:shardingFunction:symmetricPirConfig:)`` and even as a binary
([PIRShardDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirsharddatabase)),
it might be beneficial to understand how the sharding actually works and to incorporate that directly into your encoding
pipeline. In Swift you can use ``Swift/Array/shardIndex(shardCount:)``, implemented as follows:

```swift
extension KeywordValuePair.Keyword {
    func shardIndex(shardCount: Int) -> Int {
        let digest = SHA256.hash(data: self)
        let truncatedHash = digest.withUnsafeBytes { buffer in
           buffer.load(as: UInt64.self)
        }
        return Int(truncatedHash % UInt64(shardCount))
    }
}
```

So to get a shard index from a keyword you do these steps:
1. Calculate the SHA256 hash of the keyword.
2. Truncate the hash to first 8 bytes.
3. Interpret the truncated hash as little-endian 64 bit unsigned integer.
4. Take the remainder between truncatedHash and shard count.

The output is the index of the shard where this keyword and associated value should be placed in.

## Processing a shard
To process a single shard we recommend writing your own tool that imports data in the format most convenient for your
data. Each data row needs to be converted to ``KeywordValuePair`` with ``KeywordValuePair/init(keyword:value:)``, where
`keyword` and `value` are both `[UInt8]`. Once you have a collection of ``KeywordValuePair``s you have two options:
1. You can use ``KeywordPirServer/process(database:config:with:onEvent:symmetricPirConfig:)`` to process the shard directly.
2. Or you can construct a ``KeywordDatabaseShard`` by using ``KeywordDatabaseShard/init(shardID:rows:)`` and then
``ProcessKeywordDatabase/processShard(shard:with:onEvent:)``.

Both options give as output a ``ProcessedDatabaseWithParameters``.

## Storing processed shards

It makes sense to store the processed shards, so compute nodes can load them and you have them available when you need
to scale the number of compute nodes. A ``ProcessedDatabaseWithParameters`` can be saved in two parts.
1. The ``ProcessedDatabaseWithParameters/database`` can be saved by using ``ProcessedDatabase/save(to:)`` or
   ``ProcessedDatabase/serialize()``.
2. The rest of the parameters can be converted to protobuf:
```swift
let pirParameters = try processedDatabaseWithParameters.proto(context: context)
```

## Loading processed shard

To load a processed shard, one needs two parts:
1. ``ProcessedDatabase`` can be loaded using ``ProcessedDatabase/init(from:context:)-9ppkq`` or
``ProcessedDatabase/init(from:context:)-4pmcl``.
2. Use the `pirParameters` from protobuf and add them in like this:

```swift
let processedDatabase = ProcessedDatabase(from: "someFile.bin", context: context)
let pirParameters = ... // load them from protobuf
let loadedProcessedDatabaseWithParameters = try pirParameters.native(database: processedDatabase)
```

## Merging evaluation key configurations

Each shard also contains its own evaluation key configuration. But to give a single evaluation key configuration to the
PIR client, we need to merge the evaluation key configurations from all shards. For that we can use
[union()](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/homomorphicencryption/swift/sequence/union())
on a sequence of evaluation key configurations.
