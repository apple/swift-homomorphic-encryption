#!/bin/bash

set -e

lint_folders="\
    Benchmarks \
    Snippets \
    Sources \
    Tests \
    "
# There's no way to disable whitespace lints from swift-format, so we manually filter the output
# https://github.com/swiftlang/swift-format/issues/764
# shellcheck disable=SC1035
!(swift-format lint --recursive "$lint_folders" 2>&1 | grep Documentation)
