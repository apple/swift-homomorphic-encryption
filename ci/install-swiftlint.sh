#!/bin/bash

set -e

echo "installing swiftlint"
DIR=$PWD
mkdir -p /tmp/swiftlint
cd /tmp/swiftlint || exit 1
git clone --depth 1 --branch "$SWIFTLINT_VERSION" https://github.com/realm/SwiftLint
cd SwiftLint || exit
swift build -c release
export PATH=$PATH:$PWD/.build/release/
cd "$DIR" || exit 1
which swiftlint
