#!/bin/bash

SERVER_PORT=19000


FRONTEND_WITHOUT_PORT="$(echo "${CRABCAKES_FRONTEND_URL:-http://localhost}" | awk -F':' '{print $1 ":" $2}')"
SERVER_ADDRESS="${FRONTEND_WITHOUT_PORT}:$SERVER_PORT"

echo "SERVER ADDRESS=$SERVER_ADDRESS"


export TEST_BUCKET="bucket1"
export TEST_BUCKET2="bucket2"
export TEST_FILE="testuser/test.txt"

if [[ -z "$(which -a jq)" ]]; then
    echo "jq is required for this script"
    exit 1
fi

if [[ -z "$(which -a aws)" ]]; then
    echo "The AWS cli command (aws) is required for this script"
    exit 1
fi

pkill -f target/debug/crabcakes


# Use test credentials from test_config/credentials/testuser.json
AWS_ACCESS_KEY_ID="$(jq -r .access_key_id test_config/credentials/testuser.json)"
AWS_SECRET_ACCESS_KEY="$(jq -r .secret_access_key test_config/credentials/testuser.json)"
export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
export AWS_MAX_ATTEMPTS=1
export AWS_REGION="crabcakes"
TEMPDIR="$(mktemp -d)"
export TEMPDIR
TEMPDIR2="$(mktemp -d)"
export TEMPDIR2



RUST_LOG=debug cargo run --quiet --bin crabcakes -- \
    --port "$SERVER_PORT" \
    --config-dir ./test_config \
    --root-dir "$TEMPDIR" &
CRABCAKES_PID=$!
echo "Started crabcakes with PID $CRABCAKES_PID"

echo "Copying test files to $TEMPDIR"
cp -R testfiles/* "$TEMPDIR/"


COUNTER=0
while true; do
    if curl -sk "$SERVER_ADDRESS" > /dev/null; then
        echo "Server is up!"
        break
    else
        echo "Waiting for server to start... checking ${SERVER_ADDRESS}"
        COUNTER=$((COUNTER + 1))
        if [ $COUNTER -ge 10 ]; then
            echo "Server did not start within expected time"
            exit 1
        fi
        sleep 1
    fi
done