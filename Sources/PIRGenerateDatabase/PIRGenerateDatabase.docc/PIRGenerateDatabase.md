# ``PIRGenerateDatabase``

Keyword PIR database generation

## Overview

`PIRGenerateDatabase` is an executable which generates a sample database for testing.
The resulting database can be processed with the `PIRProcessDatabase` executable or sharded with the `PIRShardDatabase` executable.

### Requirements
*  Build the `PIRGenerateDatabase` executable by running:
```sh
swift build -c release --target PIRGenerateDatabase
```
The binary will be generated in `.build/release/PIRGenerateDatabase`.

* Install the binary, e.g., by adding it to your path.

### Example

1. We start by generating a sample database.
```sh
PIRGenerateDatabase \
    --output-database database.txtpb \
    --row-count 100 \
    --value-size '10...20' \
    --value-type repeated
```

This will generate a database of 100 rows, with keywords 0 to 99, and each value repeating the keyword for 10 to 20 bytes.

The database is a serialized [Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/1.0.3/documentation/privateinformationretrievalprotobuf/apple_swifthomomorphicencryption_pir_v1_keyworddatabase).
For readability, the `.txtpb` extension ensures the output database will be saved in protocol buffer text format.

> Note: For a more compact format, use the `.binpb` extension to save the database in protocol buffer binary format.

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
