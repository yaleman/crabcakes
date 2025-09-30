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

# Test PutObject - upload a new file
TEST_UPLOAD_FILE="uploaded-test.txt"
echo "Testing file upload" > /tmp/$TEST_UPLOAD_FILE

if AWS_ACCESS_KEY_ID="lol" AWS_SECRET_ACCESS_KEY="asdf" aws s3 cp /tmp/$TEST_UPLOAD_FILE \
    s3://$TEST_BUCKET/$TEST_UPLOAD_FILE \
    --endpoint-url http://$SERVER_ADDRESS; then
    echo "File upload successful"
else
    echo "File upload failed"
    exit 1
fi

# Verify the uploaded file can be retrieved
GETRES="$(AWS_ACCESS_KEY_ID="lol" AWS_SECRET_ACCESS_KEY="asdf" aws s3 cp \
    s3://$TEST_BUCKET/$TEST_UPLOAD_FILE - \
    --endpoint-url http://$SERVER_ADDRESS)"

if [[ "$GETRES" == "Testing file upload" ]]; then
    echo "Retrieved uploaded file successfully"
else
    echo "Failed to retrieve uploaded file or content mismatch"
    exit 1
fi

rm /tmp/$TEST_UPLOAD_FILE

pkill -f crabcakes