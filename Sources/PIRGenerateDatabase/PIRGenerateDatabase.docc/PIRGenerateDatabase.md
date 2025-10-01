# ``PIRGenerateDatabase``

Keyword PIR database generation

## Overview

`PIRGenerateDatabase` is an executable which generates a sample database for testing.
The resulting database can be sharded with the [PIRShardDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirsharddatabase) executable and processed with the [PIRProcessDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirprocessdatabase) executable.

### Requirements
To install the `PIRGenerateDatabase` executable, first make sure that the `~/.swiftpm/bin` directory is on your `$PATH`. To do
so, add the following line to your `~/.zshrc` or appropriate shell configuration file.
```sh
export PATH="$HOME/.swiftpm/bin:$PATH"
```
Make sure to reload it (`source ~/.zshrc`) or by restarting your terminal emulator. Then we are going to use the
`experimental-install` feature of Swift Package Manager.

Change directory to a checkout of this repository and run the following command.
```sh
swift package experimental-install -c release --product PIRGenerateDatabase
```

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

The database is a serialized [Apple_SwiftHomomorphicEncryption_Pir_V1_KeywordDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/applicationprotobuf/apple_swifthomomorphicencryption_pir_v1_keyworddatabase).
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
