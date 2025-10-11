#!/bin/bash


./inner_test_main.sh || {
    echo "❌ Test failed ❌"
    exit 1
}
    if [[ $(pgrep crabcakes | wc -l) -gt 0 ]]; then
        echo "Crabcakes is still running. Stopping it."
        killall crabcakes
    fi
