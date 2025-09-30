#!/bin/bash
## Copyright 2024-2025 Apple Inc. and the Swift Homomorphic Encryption project authors
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

# Updates swift protobuf files

set -e

echo "Updating protobuf files"
cd swift-homomorphic-encryption-protobuf

echo "Removing HomomorphicEncryptionProtobuf swift protobuf files"
rm -f ../Sources/HomomorphicEncryptionProtobuf/generated/*.pb.swift
echo "Regenerating HomomorphicEncryptionProtobuf swift protobuf files"
find apple/swift_homomorphic_encryption/v1/ \
    -name "*.proto" -exec protoc \
    --swift_opt=Visibility=Public \
    --swift_opt=FileNaming=PathToUnderscores \
    --swift_out ../Sources/HomomorphicEncryptionProtobuf/generated  {} \;

echo "Removing PrivateInformationRetrievalProtobuf swift protobuf files"
rm -f ../Sources/PrivateInformationRetrievalProtobuf/generated/*.pb.swift
echo "Regenerating PrivateInformationRetrievalProtobuf swift protobuf files"
find apple/swift_homomorphic_encryption/pir/ \
    apple/swift_homomorphic_encryption/api/shared/v1/ \
    apple/swift_homomorphic_encryption/api/pir/v1/ \
    -name "*.proto" -exec protoc \
    --swift_opt=ProtoPathModuleMappings=../Sources/PrivateInformationRetrievalProtobuf/protobuf_module_mappings.txtpb \
    --swift_opt=Visibility=Public \
    --swift_opt=FileNaming=PathToUnderscores \
    --swift_out ../Sources/PrivateInformationRetrievalProtobuf/generated  {} \;

echo "Removing PrivateNearestNeighborSearchProtobuf swift protobuf files"
rm ../Sources/PrivateNearestNeighborSearchProtobuf/generated/*.pb.swift
echo "Regenerating PrivateNearestNeighborSearchProtobuf swift protobuf files"
find apple/swift_homomorphic_encryption/pnns/ \
    apple/swift_homomorphic_encryption/api/shared/v1/ \
    apple/swift_homomorphic_encryption/api/pnns/v1/ \
    -name "*.proto" -exec protoc \
    --swift_opt=ProtoPathModuleMappings=../Sources/PrivateNearestNeighborSearchProtobuf/protobuf_module_mappings.txtpb \
    --swift_opt=Visibility=Public \
    --swift_opt=FileNaming=PathToUnderscores \
    --swift_out ../Sources/PrivateNearestNeighborSearchProtobuf/generated  {} \;

echo "Removing ApplicationProtobuf swift protobuf files"
rm -f ../Sources/ApplicationProtobuf/generated/*.pb.swift
echo "Regenerating ApplicationProtobuf swift protobuf files"
find apple/swift_homomorphic_encryption/pnns/ \
    apple/swift_homomorphic_encryption/pir/ \
    apple/swift_homomorphic_encryption/api/shared/ \
    apple/swift_homomorphic_encryption/api/v1/ \
    apple/swift_homomorphic_encryption/api/pir/v1/pir.proto \
    apple/swift_homomorphic_encryption/api/pnns/v1/pnns.proto \
    -name "*.proto" -exec protoc \
    --swift_opt=ProtoPathModuleMappings=../Sources/ApplicationProtobuf/protobuf_module_mappings.txtpb \
    --swift_opt=Visibility=Public \
    --swift_opt=FileNaming=PathToUnderscores \
    --swift_out ../Sources/ApplicationProtobuf/generated  {} \;

cd -
echo "Done updating protobuf files"
