#!/bin/bash

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
