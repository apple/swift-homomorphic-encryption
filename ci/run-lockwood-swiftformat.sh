#!/bin/bash

function install_swiftformat {
    echo "installing swiftformat"
    # Keep in sync with README
    SWIFTFORMAT_VERSION="0.54.0"
    DIR=$PWD
    mkdir -p /tmp/swiftformat
    cd /tmp/swiftformat || exit 1
    git clone --depth 1 --branch $SWIFTFORMAT_VERSION https://github.com/nicklockwood/SwiftFormat
    cd SwiftFormat || exit 1
    swift build -c release
    export PATH=$PATH:$PWD/.build/release/
    cd "$DIR" || exit 1
    which swiftformat
}
install_swiftformat

swiftformat .
