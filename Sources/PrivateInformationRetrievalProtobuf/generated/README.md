# Generated files

Files in this directory are auto-generated using swift-protobuf.
See the [dependencies](../../../README.md#dependencies) for the swift-protobuf version.

## Requirements
* [swift-protobuf](https://github.com/apple/swift-protobuf)

## Generate Swift files
To generate the Swift files:

1. Change directory to `<REPOSITORY_ROOT>/swift-homomorphic-encryption-protobuf`
2. Run the following commands:
```sh
find apple/swift_homomorphic_encryption/pir/ apple/swift_homomorphic_encryption/api/ -name "*.proto" -exec protoc \
    --swift_opt=ProtoPathModuleMappings=../Sources/PrivateInformationRetrievalProtobuf/protobuf_module_mappings.txtpb \
    --swift_opt=Visibility=Public \
    --swift_opt=FileNaming=PathToUnderscores \
    --swift_out ../Sources/PrivateInformationRetrievalProtobuf/generated  {} \;
```

> [!NOTE]
> When updating the protobuf files, remember to also update files in [HomomorphicEncryptionProtobuf](../../HomomorphicEncryptionProtobuf/generated/README.md) as needed.
