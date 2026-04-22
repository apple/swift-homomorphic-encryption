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

set -uo pipefail

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

RED='\033[0;31m'; GREEN='\033[0;32m'; RESET='\033[0m'

GEN="$(which PIRGenerateDatabase)"
PROC="$(which PIRProcessDatabase)"

INPUT="$WORK_DIR/input.txtpb"
RLWE="n_4096_logq_27_28_28_logt_5"

echo "==> Generating 100-row keyword database..."
"$GEN" --database-type keyword \
       --output-database "$INPUT" \
       --row-count 100 \
       --value-size 10 \
       --value-type random

PASS=0; FAIL=0

check() {
    local name="$1"
    local sharding_json="$2"
    local expected="$3"   # integer (expected shard file count) or "fail"

    local out_db="$WORK_DIR/$name-db-SHARD_ID.bin"
    local out_params="$WORK_DIR/$name-params-SHARD_ID.txtpb"
    local out_key="$WORK_DIR/$name-eval-key.txtpb"
    local config="$WORK_DIR/$name-config.json"
    local log="$WORK_DIR/$name.log"

    jq -n \
        --arg rlwe "$RLWE" \
        --arg input "$INPUT" \
        --arg outDb "$out_db" \
        --arg outParams "$out_params" \
        --arg outKey "$out_key" \
        --argjson sharding "$sharding_json" \
        '{rlweParameters: $rlwe, databaseType: "keyword", inputDatabase: $input,
          outputDatabase: $outDb, outputPirParameters: $outParams,
          outputEvaluationKeyConfig: $outKey, sharding: $sharding, trialsPerShard: 1}' \
        > "$config"

    if [ "$expected" = "fail" ]; then
        if "$PROC" "$config" > "$log" 2>&1; then
            echo -e "${RED}FAIL${RESET} [$name]: expected rejection but succeeded"
            ((FAIL++))
        else
            echo -e "${GREEN}PASS${RESET} [$name]: correctly rejected"
            ((PASS++))
        fi
    else
        if "$PROC" "$config" > "$log" 2>&1; then
            local actual
            actual=$(find "$WORK_DIR" -maxdepth 1 -name "$name-db-*.bin" | wc -l | tr -d ' ')
            if [ "$actual" -eq "$expected" ]; then
                echo -e "${GREEN}PASS${RESET} [$name]: $actual shard(s)"
                ((PASS++))
            else
                echo -e "${RED}FAIL${RESET} [$name]: expected $expected shard(s), got $actual"
                cat "$log"
                ((FAIL++))
            fi
        else
            echo -e "${RED}FAIL${RESET} [$name]: unexpected failure"
            cat "$log"
            ((FAIL++))
        fi
    fi
}

echo ""
echo "==> Running tests..."

# Valid: fixed shard counts
check "shardcount-4"          '{"shardCount": 4}'                                       4
check "shardcount-1"          '{"shardCount": 1}'                                       1
check "shardcount-max-ok"     '{"shardCount": 4, "maxShardCount": 8}'                   4
check "shardcount-pow2-ok"    '{"shardCount": 4, "requirePowerOfTwoShardCount": true}'  4

# Valid: entry-count-per-shard  (100 rows)
check "entry-basic"           '{"entryCountPerShard": 25}'                                      4  # 100/25 = 4
check "entry-capped"          '{"entryCountPerShard": 30, "maxShardCount": 2}'                  2  # 100/30=3 → cap 2
check "entry-pow2"            '{"entryCountPerShard": 30, "requirePowerOfTwoShardCount": true}' 2  # 3 → floor 2
check "entry-both"            '{"entryCountPerShard": 30, "maxShardCount": 6, "requirePowerOfTwoShardCount": true}' 2  # 3 → cap 6 (no-op) → floor 2

# Invalid: rejected at config decode time (no processing occurs)
check "err-shardcount-zero"   '{"shardCount": 0}'                                             fail
check "err-shardcount-max"    '{"shardCount": 5, "maxShardCount": 3}'                         fail
check "err-shardcount-pow2"   '{"shardCount": 3, "requirePowerOfTwoShardCount": true}'        fail
check "err-entrycount-zero"   '{"entryCountPerShard": 0}'                                     fail

echo ""
echo "Results: $PASS passed, $FAIL failed"
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All tests passed.${RESET}"
else
    echo -e "${RED}$FAIL test(s) failed.${RESET}"
    exit 1
fi
