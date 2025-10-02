#!/bin/bash

# set -e

SERVER_PORT=18090
SERVER_ADDRESS="${CRABCAKES_HOSTNAME:-127.0.0.1}:$SERVER_PORT"

if [ -n "${CRABCAKES_TLS_CERT}" ]; then
    echo "Running tests with TLS enabled"
    SERVER_ADDRESS="https://$SERVER_ADDRESS"
else
    echo "Running tests without TLS"
    SERVER_ADDRESS="http://$SERVER_ADDRESS"
fi

TEST_BUCKET="bucket1"
TEST_FILE="test.txt"

if [[ -z "$(which -a jq)" ]]; then
    echo "jq is required for this script"
    exit 1
fi

pkill -f target/debug/crabcakes

# Use test credentials from test_config/credentials/testuser.json
AWS_ACCESS_KEY_ID="$(jq -r .access_key_id test_config/credentials/testuser.json)"
AWS_SECRET_ACCESS_KEY="$(jq -r .secret_access_key test_config/credentials/testuser.json)"
export AWS_REGION="crabcakes"

TEMPDIR="$(mktemp -d)"
TEMPDIR2="$(mktemp -d)"

RUST_LOG=debug cargo run --quiet --bin crabcakes -- \
    --port $SERVER_PORT \
    --config-dir ./test_config \
    --root-dir "$TEMPDIR" &
CRABCAKES_PID=$!
echo "Started crabcakes with PID $CRABCAKES_PID"


cp -R testfiles/* "$TEMPDIR/"


while true; do
    if curl -sk "$SERVER_ADDRESS" > /dev/null; then
        echo "Server is up"
        break
    else
        echo "Waiting for server to start..."
        sleep 1
    fi
done


LSTEXT="$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 ls s3://$TEST_BUCKET/$TEST_FILE --endpoint-url "$SERVER_ADDRESS")"

if [[ "$LSTEXT" == *"test.txt" ]]; then
    echo "The output contains test.txt"
else
    echo "The output does not contain test.txt"
    exit 1
fi

LSTEXT="$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 ls s3://$TEST_BUCKET/foo.txt --endpoint-url "$SERVER_ADDRESS")"

if [[ -z "$LSTEXT" ]]; then
    echo "The output is empty"
else
    echo "The output is not empty"
    exit 1
fi


LSTEXT="$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 ls s3://$TEST_BUCKET/ --endpoint-url "$SERVER_ADDRESS")"

if [[ -z "$LSTEXT" ]]; then
    echo "The output is empty"
    exit 1
else
    echo "The output is not empty (expected since bucket1/test.txt exists)"
fi

HEADRES="$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3api head-object \
    --bucket $TEST_BUCKET --key $TEST_FILE \
    --endpoint-url "$SERVER_ADDRESS")"

if [[ -z "$HEADRES" ]]; then
    echo "The output is empty"
    exit 1
else
    echo "The aws s3api head-object output is not empty and that's OK"
    echo "$HEADRES"
fi

# Test PutObject - upload a new file
TEST_UPLOAD_FILE="uploaded-test.txt"
echo "Testing file upload" > "$TEMPDIR2/$TEST_UPLOAD_FILE"

if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 cp "$TEMPDIR2/$TEST_UPLOAD_FILE" \
    s3://$TEST_BUCKET/$TEST_UPLOAD_FILE \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "File upload successful"
else
    echo "File upload failed"
    exit 1
fi

# Verify the uploaded file can be retrieved
GETRES="$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 cp \
    s3://$TEST_BUCKET/$TEST_UPLOAD_FILE - \
    --endpoint-url "$SERVER_ADDRESS")"

if [[ "$GETRES" == "Testing file upload" ]]; then
    echo "Retrieved uploaded file successfully"
else
    echo "Failed to retrieve uploaded file or content mismatch"
    exit 1
fi

rm "$TEMPDIR2/$TEST_UPLOAD_FILE"

# Test CreateBucket
TEST_NEW_BUCKET="test-new-bucket"
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 mb \
    s3://$TEST_NEW_BUCKET \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "CreateBucket successful"
else
    echo "CreateBucket failed"
    exit 1
fi

# Test HeadBucket on newly created bucket
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3api head-bucket \
    --bucket $TEST_NEW_BUCKET \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "HeadBucket successful - bucket exists"
else
    echo "HeadBucket failed - bucket should exist"
    exit 1
fi

# Test HeadBucket on non-existent bucket
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3api head-bucket \
    --bucket "nonexistent-bucket" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "HeadBucket on non-existent bucket should fail"
    exit 1
else
    echo "HeadBucket correctly returned error for non-existent bucket"
fi

# Test GetBucketLocation on existing bucket
LOCATION_RESULT="$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3api get-bucket-location \
    --bucket $TEST_BUCKET \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)"

if echo "$LOCATION_RESULT" | jq -e '.LocationConstraint == "crabcakes"' > /dev/null 2>&1; then
    echo "GetBucketLocation successful - region is crabcakes"
else
    echo "GetBucketLocation failed or returned wrong region: $LOCATION_RESULT"
    exit 1
fi

# Test GetBucketLocation on non-existent bucket (should fail)
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3api get-bucket-location \
    --bucket "nonexistent-bucket" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "GetBucketLocation on non-existent bucket should fail"
    exit 1
else
    echo "GetBucketLocation correctly returned error for non-existent bucket"
fi

# Test DeleteObject - delete the uploaded file
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 rm \
    s3://$TEST_BUCKET/$TEST_UPLOAD_FILE \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "DeleteObject successful"
else
    echo "DeleteObject failed"
    exit 1
fi

# Verify the file was deleted
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3api head-object \
    --bucket $TEST_BUCKET --key $TEST_UPLOAD_FILE \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "File still exists after delete - should have been deleted"
    exit 1
else
    echo "File successfully deleted - head-object correctly returns error"
fi

# Test DeleteObject idempotency - deleting non-existent object should succeed
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 rm \
    s3://$TEST_BUCKET/nonexistent-file.txt \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "DeleteObject idempotent - deleting non-existent object succeeded"
else
    echo "DeleteObject should be idempotent"
    exit 1
fi

# Test DeleteBucket on empty bucket (should succeed)
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 rb \
    s3://$TEST_NEW_BUCKET \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "DeleteBucket successful on empty bucket"
else
    echo "DeleteBucket failed on empty bucket"
    exit 1
fi

# Test DeleteBucket on non-empty bucket (should fail)
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 rb \
    s3://$TEST_BUCKET \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "DeleteBucket should fail on non-empty bucket"
    exit 1
else
    echo "DeleteBucket correctly failed on non-empty bucket"
fi

# Test CreateBucket with invalid name (should fail)
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 mb \
    s3://INVALID-BUCKET-NAME \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "CreateBucket should fail on invalid bucket name"
    exit 1
else
    echo "CreateBucket correctly rejected invalid bucket name"
fi

# Test CreateBucket duplicate (should fail)
DUPLICATE_BUCKET="bucket1"
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 mb \
    s3://$DUPLICATE_BUCKET \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "CreateBucket should fail on duplicate bucket"
    exit 1
else
    echo "CreateBucket correctly rejected duplicate bucket"
fi

echo "All tests passed, killing crabcakes (PID $CRABCAKES_PID) and cleaning up $TEMPDIR"
rm -rf "$TEMPDIR"
kill "$CRABCAKES_PID"
pkill -f target/debug/crabcakes