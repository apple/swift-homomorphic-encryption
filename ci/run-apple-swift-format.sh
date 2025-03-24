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
