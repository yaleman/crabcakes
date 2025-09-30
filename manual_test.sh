#!/bin/bash

# set -e

SERVER_PORT=18090
SERVER_ADDRESS="127.0.0.1:$SERVER_PORT"

TEST_BUCKET="bucket1"
TEST_FILE="test.txt"

cargo run --quiet --bin crabcakes -- --port $SERVER_PORT &

sleep 2

LSTEXT="$(AWS_ACCESS_KEY_ID="lol" AWS_SECRET_ACCESS_KEY="asdf" aws s3 ls s3://$TEST_BUCKET/$TEST_FILE --endpoint-url http://$SERVER_ADDRESS)"

if [[ "$LSTEXT" == *"test.txt" ]]; then
    echo "The output contains test.txt"
else
    echo "The output does not contain test.txt"
    exit 1
fi

LSTEXT="$(AWS_ACCESS_KEY_ID="lol" AWS_SECRET_ACCESS_KEY="asdf" aws s3 ls s3://$TEST_BUCKET/foo.txt --endpoint-url http://$SERVER_ADDRESS)"

if [[ -z "$LSTEXT" ]]; then
    echo "The output is empty"
else
    echo "The output is not empty"
    exit 1
fi


LSTEXT="$(AWS_ACCESS_KEY_ID="lol" AWS_SECRET_ACCESS_KEY="asdf" aws s3 ls s3://$TEST_BUCKET/ --endpoint-url http://$SERVER_ADDRESS)"

if [[ -z "$LSTEXT" ]]; then
    echo "The output is empty"
    exit 1
else
    echo "The output is not empty (expected since bucket1/test.txt exists)"
fi

HEADRES="$(AWS_ACCESS_KEY_ID="lol" AWS_SECRET_ACCESS_KEY="asdf" aws s3api head-object \
    --bucket $TEST_BUCKET --key $TEST_FILE \
    --endpoint-url http://$SERVER_ADDRESS)"

if [[ -z "$HEADRES" ]]; then
    echo "The output is empty"
    exit 1
else
    echo "The aws s3api head-object output is not empty and that's OK"
    echo "$HEADRES"
fi


pkill -f crabcakes