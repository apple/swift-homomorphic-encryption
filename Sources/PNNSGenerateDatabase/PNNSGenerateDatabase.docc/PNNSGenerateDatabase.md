# ``PNNSGenerateDatabase``

Private Nearest Neighbors Search database generation

## Overview

`PNNSGenerateDatabase` is an executable which generates a sample database for testing.
The resulting database can be processed with the `PNNSProcessDatabase` executable.

### Requirements
First ensure sure that the `~/.swiftpm/bin` directory is on your `$PATH`.
For example, if using the `zsh` shell, add the following line to your `~/.zshrc`
```sh
export PATH="$HOME/.swiftpm/bin:$PATH"
```
Make sure to reload the path via (`source ~/.zshrc`) or by restarting your terminal emulator.

Then, to install the `PNNSGenerateDatabase`, executable, e.g., run
```sh
swift package experimental-install -c release --product PNNSGenerateDatabase
```

### Example

1. We start by generating a sample database.
```sh
PNNSGenerateDatabase \
    --output-database database.txtpb \
    --row-count 100 \
    --metadata-size 3 \
    --vector-dimension 10 \
    --vector-type unit
```

This will generate a database of 100 entries, with entry identifiers 0 to 99, 3 byte metadata for each row, and each vector a 10-dimensional unit vector.

The database is a serialized `Apple_SwiftHomomorphicEncryption_Pnns_V1_Database`
For readability, the `.txtpb` extension ensures the output database will be saved in protocol buffer text format.

> Note: For a more compact format, use the `.binpb` extension to save the database in protocol buffer binary format.

2. We view a few rows from the database with
```sh
head database.txtpb
```
which shows
```json
rows {
  entry_metadata: "000"
  vector: [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
}
rows {
  entry_id: 1
  entry_metadata: "111"
  vector: [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
}
rows {
```

You can use `PNNSProcessDatabase` to prepare the database for hosting PNNS queries.
