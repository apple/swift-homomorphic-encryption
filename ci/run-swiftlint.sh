#!/bin/bash

function install_swiftlint {
    echo "installing swiftlint"
    # Keep in sync with README
    SWIFTLINT_VERSION="0.55.1"
    DIR=$PWD
    mkdir -p /tmp/swiftlint
    cd /tmp/swiftlint || exit 1
    git clone --depth 1 --branch $SWIFTLINT_VERSION https://github.com/realm/SwiftLint
    cd SwiftLint || exit
    # release build is slow, and linting is fast enough we don't need release mode
    swift build
    export PATH=$PATH:$PWD/.build/debug/
    cd "$DIR" || exit 1
    which swiftlint
}
install_swiftlint

swiftlint lint --strict
