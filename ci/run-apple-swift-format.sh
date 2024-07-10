#!/bin/bash

function install_swiftformat {
    if ! [ -x "$(command -v swift-format)" ]; then
        echo "installing Apple swift-format"
        # Keep in sync with README
        VERSION=510.1.0
        DIR=$PWD
        git clone https://github.com/apple/swift-format.git
        cd swift-format || exit 1
        git checkout "tags/$VERSION"
        swift build -c release
        export PATH=$PATH:$PWD/.build/release/
        cd "$DIR" || exit 1
        which swift-format
    fi
}
install_swiftformat

# There's no way to disable rules from swift-format, so we manually filter the output
lint_folders="\
    Benchmarks \
    Sources \
    Tests \
    "
!(swift-format lint --recursive $lint_folders 2>&1 | grep Documentation)
