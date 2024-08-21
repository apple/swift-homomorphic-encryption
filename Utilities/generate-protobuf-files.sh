#!/bin/bash

# Updates swift protobuf files

echo "Updating protobuf files"
cd swift-homomorphic-encryption-protobuf

echo "Removing HomomorphicEncryptionProtobuf swift protobuf files"
rm ../Sources/HomomorphicEncryptionProtobuf/generated/*.pb.swift
echo "Regenerating HomomorphicEncryptionProtobuf swift protobuf files"
find apple/swift_homomorphic_encryption/v1/ -name "*.proto" -exec protoc --swift_opt=Visibility=Public --swift_opt=FileNaming=PathToUnderscores --swift_out ../Sources/HomomorphicEncryptionProtobuf/generated  {} \;

echo "Removing PrivateInformationRetrievalProtobuf swift protobuf files"
rm ../Sources/PrivateInformationRetrievalProtobuf/generated/*.pb.swift
echo "Regenerating PrivateInformationRetrievalProtobuf swift protobuf files"
find apple/swift_homomorphic_encryption/pir/ apple/swift_homomorphic_encryption/api/ -name "*.proto" -exec protoc \
    --swift_opt=ProtoPathModuleMappings=../Sources/PrivateInformationRetrievalProtobuf/protobuf_module_mappings.txtpb \
    --swift_opt=Visibility=Public \
    --swift_opt=FileNaming=PathToUnderscores \
    --swift_out ../Sources/PrivateInformationRetrievalProtobuf/generated  {} \;

echo "Removing PrivateNearestNeighborsSearchProtobuf swift protobuf files"
rm ../Sources/PrivateNearestNeighborsSearchProtobuf/generated/*.pb.swift
echo "Regenerating PrivateNearestNeighborsSearchProtobuf swift protobuf files"
find apple/swift_homomorphic_encryption/pnns/ -name "*.proto" -exec protoc \
    --swift_opt=ProtoPathModuleMappings=../Sources/PrivateNearestNeighborsSearchProtobuf/protobuf_module_mappings.txtpb \
    --swift_opt=Visibility=Public \
    --swift_opt=FileNaming=PathToUnderscores \
    --swift_out ../Sources/PrivateNearestNeighborsSearchProtobuf/generated  {} \;

cd -
echo "Done updating protobuf files"
