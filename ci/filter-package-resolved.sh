#!/bin/bash
## Copyright 2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

# ============================================================
# Pre-commit hook: filter-package-resolve.sh
#
# Removes unwanted pins from Package.resolved.
# Triggered by pre-commit only when Package.resolved is staged.
#
# Requirements: jq  (brew install jq)
# ============================================================

set -euo pipefail

if ! command -v jq &> /dev/null; then
  echo 2>&1 "jq not found"
  exit 44
fi

if [[ -z $(git diff HEAD Package.resolved) ]]; then
  # Nothing to check
  exit 0
fi

# ------------------------------------------------------------
# ✏️  CONFIGURE: add/remove package identities here.
# ------------------------------------------------------------
UNWANTED_PINS=(
  "hdrhistogram-swift"
  "package-benchmark"
  "package-jemalloc"
  "swift-atomics"
  "swift-system"
  "texttable"
)

# ------------------------------------------------------------
# Build jq filter and remove pins in-place
# ------------------------------------------------------------

printf -v JOINED '"%s",' "${UNWANTED_PINS[@]}"
FILTER="del(.pins[] | select(.identity | IN(${JOINED%,})))"

jq --indent 2 "$FILTER" Package.resolved \
  | sed 's/": /\" : /g' \
  > Package.resolved.tmp \
  && mv Package.resolved.tmp Package.resolved

# If the only remaining diff against HEAD is the originHash line, restore it
CHANGED_LINES="$(git diff HEAD Package.resolved | grep '^[+-]' | grep -v '^---' | grep -v '^+++')"
if [[ "$(echo "$CHANGED_LINES" | wc -l)" -eq 2 ]] \
  && echo "$CHANGED_LINES" | grep -q 'originHash' \
  && [[ "$(echo "$CHANGED_LINES" | grep -v 'originHash')" == "" ]]; then
  ORIGINAL_HASH="$(git diff HEAD Package.resolved | grep '^-.*originHash' | sed 's/^-.*"originHash" : "//' | sed 's/".*//')"
  sed -i '' "s/\"originHash\" : \".*\"/\"originHash\" : \"$ORIGINAL_HASH\"/" Package.resolved
fi
