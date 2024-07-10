# ``PIRShardDatabase``

Keyword PIR database sharding

## Overview

`PIRShardDatabase` is a executable which divides a database into disjoint shards.
Each resulting shard is suitable for processing with the `PIRProcessDatabase` executable.

`PIRShardDatabase` supports two sharding settings:
* `shardCount` randomly shards the database using the specified of shards.
* `entryCountPerShard` shards the database using enough shards such that the average shard contains the specified number of entries.

### Requirements
Build the `PIRProcessDatabase` executable by running:
```sh
swift build -c release --target PIRProcessDatabase
```
The binary will be generated in `.build/release/PIRProcessDatabase`.


For the example below, you'll also need to install the `PIRGenerateDatabase` executable in a similar manner as `PIRShardDatabase`.

### Example

1. We start by generating a sample database.
```sh
PIRGenerateDatabase --output-database database.txtpb \
    --row-count 100 \
    --value-size '10..<20' \
    --value-type repeated
```

2. We view a few rows from the database with

```sh
head database.txtpb
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

3. We shard the database with both sharding options:
    * `shardCount`.
        To shard the database into 10 shards, run
        ```sh
        PIRShardDatabase \
            --input-database database.txtpb \
            --output-database database-shard-SHARD_ID.txtpb \
            --sharding shardCount \
            --sharding-count 10
        ```
        This will generate 10 shards, saved as `database-shard-0.txtpb` through `database-shard-9.txtpb`.
        Each shard will contain a random subset of the database.
        For instance, `head database-shard-0.txtpb` might show
        ```json
        rows {
          keyword: "50"
          value: "50505050505050505"
        }
        rows {
          keyword: "93"
          value: "939393939393"
        }
        rows {
          keyword: "24"
        ```

  * `entryCountPerShard`. To shard the database with an average of at most 15 entries per shard, run
    ```sh
    PIRShardDatabase \
        --input-database database.txtpb \
        --output-database database-entry-count-SHARD_ID.txtpb \
        --sharding entryCountPerShard \
        --sharding-count 15
    ```
    This will generate `floor(100/15) = 6` shards, saved to `database-entry-count-0.txtpb` through `database-entry-count-5.txtpb`.

> Note: For a more compact format, use the `.binpb` extension to load the input database, and save the sharded databases in protocol buffer binary format.
