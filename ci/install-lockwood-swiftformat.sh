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

set -e

echo "installing Lockwood swiftformat"
DIR=$PWD
mkdir -p /tmp/swiftformat
cd /tmp/swiftformat || exit 1
git clone --depth 1 --branch "$SWIFTFORMAT_VERSION" https://github.com/nicklockwood/SwiftFormat
cd SwiftFormat || exit 1
swift build -c release
export PATH=$PATH:$PWD/.build/release/
cd "$DIR" || exit 1
which swiftformat
