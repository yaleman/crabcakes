#!/bin/bash

TARGET_STRING='target/debug/crabcakes.*--port.*test_config'

if [[ $(pgrep -f "$TARGET_STRING" | wc -l) -gt 0 ]]; then
    echo "Crabcakes is still running. Stopping it before testing..."
    pkill -f "$TARGET_STRING"
fi

./inner_test_main.sh  || echo "❌ Test failed ❌"


if [[ $(pgrep -f "$TARGET_STRING" | wc -l) -gt 0 ]]; then
    echo "Crabcakes is still running. Stopping it."
    pkill -f "$TARGET_STRING"
fi
