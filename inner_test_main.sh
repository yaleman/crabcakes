#!/bin/bash

# set -e

# shellcheck disable=SC1091
source ./inner_setup_test.sh

# SERVER_PORT=19000


# FRONTEND_WITHOUT_PORT="$(echo "${CRABCAKES_FRONTEND_URL:-http://localhost}" | awk -F':' '{print $1 ":" $2}')"
# SERVER_ADDRESS="${FRONTEND_WITHOUT_PORT}:$SERVER_PORT"

# echo "SERVER ADDRESS=$SERVER_ADDRESS"


# TEST_BUCKET="bucket1"
# TEST_BUCKET2="bucket2"
# TEST_FILE="testuser/test.txt"

# if [[ -z "$(which -a jq)" ]]; then
#     echo "jq is required for this script"
#     exit 1
# fi

# if [[ -z "$(which -a aws)" ]]; then
#     echo "The AWS cli command (aws) is required for this script"
#     exit 1
# fi

# pkill -f target/debug/crabcakes



echo "########################################"
echo "Testing ListObjectsV2 - list files in ${TEST_BUCKET2}"
echo "########################################"
LSTEXT="$(aws s3 ls "s3://${TEST_BUCKET2}/" --endpoint-url "$SERVER_ADDRESS")"

if [[ "$LSTEXT" == *"test.txt" ]]; then
    echo "The output contains test.txt"
else
    echo "The output does not contain test.txt"
    echo "Output was: '$LSTEXT'"
    exit 1
fi

echo "########################################"
echo "Testing ListObjectsV2 - list files in ${TEST_BUCKET} (non-existent file)"
echo "########################################"
if [ -f "$TEMPDIR/foo.txt" ]; then
    echo "Removing existing foo.txt"
    rm "$TEMPDIR/foo.txt"
fi

LSTEXT="$(aws s3 ls "s3://$TEST_BUCKET/testuser/foo.txt" --endpoint-url "$SERVER_ADDRESS")"

if [[ -z "$LSTEXT" ]]; then
    echo "The output is empty"
else
    echo "The output is not empty"
    exit 1
fi


echo "########################################"
echo "Testing ListObjectsV2 - list all files in bucket1/testuser/"
echo "########################################"

TARGET_FILE="$TEMPDIR/bucket1/testuser/test.txt"

if [ ! -f "${TARGET_FILE}" ]; then
    echo "the test file  ${TARGET_FILE} should exist"
    find "${TEMPDIR}"
    exit 1
fi

LSTEXT="$(aws s3 ls s3://${TEST_BUCKET}/testuser/ --endpoint-url "$SERVER_ADDRESS")"

if [[ -z "$LSTEXT" ]]; then
    echo "The output is empty, expected to find something"
    exit 1
else
    echo "The output is not empty (expected since bucket1/test.txt exists)"
fi

echo "########################################"
echo "Testing HeadObject"
echo "########################################"
HEADRES="$(aws s3api head-object \
    --bucket $TEST_BUCKET --key $TEST_FILE \
    --endpoint-url "$SERVER_ADDRESS")"

if [[ -z "$HEADRES" ]]; then
    echo "The output is empty"
    exit 1
else
    echo "The aws s3api head-object output is not empty and that's OK"
    echo "$HEADRES"
fi


echo "########################################"
echo "Testing PutObject - upload a new file"
echo "########################################"
# Test PutObject - upload a new file
TEST_UPLOAD_FILE="uploaded-test.txt"
TEST_UPLOAD_FILE_KEY="testuser/uploaded-test.txt"
echo "Testing file upload s3://${TEST_BUCKET}/${TEST_UPLOAD_FILE_KEY}" | tee "$TEMPDIR2/$TEST_UPLOAD_FILE"


if aws s3 cp "$TEMPDIR2/$TEST_UPLOAD_FILE" \
    "s3://${TEST_BUCKET}/${TEST_UPLOAD_FILE_KEY}" \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "File upload successful"
else
    echo "File upload failed"
    exit 1
fi

echo "################################################"
echo "Verifying the uploaded file can be retrieved..."
echo "################################################"
FILE_CONTENT_RESULT="$(aws s3 cp \
    "s3://${TEST_BUCKET}/${TEST_UPLOAD_FILE_KEY}" - \
    --endpoint-url "$SERVER_ADDRESS")"

if [[ "$FILE_CONTENT_RESULT" == "Testing file upload s3://${TEST_BUCKET}/${TEST_UPLOAD_FILE_KEY}" ]]; then
    echo "Retrieved uploaded file successfully"
else
    echo "Failed to retrieve uploaded file or content mismatch"
    exit 1
fi

rm "$TEMPDIR2/$TEST_UPLOAD_FILE"

echo "#######################################"
echo "Testing CreateBucket"
echo "#######################################"

if aws s3 mb \
    "s3://${TEST_BUCKET2}1" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "CreateBucket successful"
else
    echo "CreateBucket failed"
    exit 1
fi

echo "##########################################"
echo "Testing HeadBucket on newly created bucket"
echo "##########################################"
if aws s3api head-bucket \
        --bucket "${TEST_BUCKET2}1" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "HeadBucket successful - bucket exists"
else
    echo "HeadBucket failed - bucket should exist"
    exit 1
fi

echo "##########################################"
echo "Testing HeadBucket on non-existent bucket"
echo "##########################################"
if aws s3api head-bucket \
    --bucket "nonexistent-bucket" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "HeadBucket on non-existent bucket should fail"
    exit 1
else
    echo "HeadBucket correctly returned error for non-existent bucket"
fi

echo "###############################################"
echo "Testing GetBucketLocation on existing bucket $TEST_BUCKET2"
echo "###############################################"
LOCATION_RESULT="$(aws s3api get-bucket-location \
    --bucket $TEST_BUCKET2 \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)"

if echo "$LOCATION_RESULT" | jq -e '.LocationConstraint == "crabcakes"' > /dev/null 2>&1; then
    echo "GetBucketLocation successful - region is crabcakes"
else
    echo "GetBucketLocation failed or returned wrong region: $LOCATION_RESULT"
    exit 1
fi

echo "################################################################"
echo "Testing GetBucketLocation on non-existent bucket (should fail)"
echo "################################################################"
if aws s3api get-bucket-location \
    --bucket "nonexistent-bucket" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "GetBucketLocation on non-existent bucket should fail"
    exit 1
else
    echo "GetBucketLocation correctly returned error for non-existent bucket"
fi

echo "################################################################"
echo "Testing CopyObject - server-side copy of existing object"
echo "################################################################"
TEST_COPY_KEY="testuser/test-copy.txt"
if aws s3api copy-object \
    --copy-source "$TEST_BUCKET2/$TEST_FILE" \
    --bucket $TEST_BUCKET2 \
    --key $TEST_COPY_KEY \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "CopyObject successful"
else
    echo "CopyObject failed"
    exit 1
fi

echo "########################################################"
echo "Verifying copied object exists and has correct content"
echo "########################################################"
ORIGINAL_CONTENT="$(aws s3 cp \
    "s3://$TEST_BUCKET2/$TEST_FILE" - \
    --endpoint-url "$SERVER_ADDRESS")"

COPY_CONTENT="$(aws s3 cp \
    "s3://$TEST_BUCKET2/$TEST_COPY_KEY" - \
    --endpoint-url "$SERVER_ADDRESS")"

if [[ "$COPY_CONTENT" == "$ORIGINAL_CONTENT" ]]; then
    echo "CopyObject - copied content matches original"
else
    echo "CopyObject - copied content does not match original"
    echo "Original: '$ORIGINAL_CONTENT'"
    echo "Copied:   '$COPY_CONTENT'"
    exit 1
fi

echo "Cleaning up copied object"
aws s3 rm \
    s3://$TEST_BUCKET/$TEST_COPY_KEY \
    --endpoint-url "$SERVER_ADDRESS" > /dev/null 2>&1

echo "############################################################"
echo "Testing CopyObject with non-existent source (should fail)"
echo "############################################################"
if aws s3api copy-object \
    --bucket $TEST_BUCKET \
    --key "copy-dest.txt" \
    --copy-source "$TEST_BUCKET/nonexistent-source.txt" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "CopyObject should fail for non-existent source"
    exit 1
else
    echo "CopyObject correctly failed for non-existent source"
fi

echo "############################################################"
echo "Testing DeleteObject - delete the uploaded file"
echo "############################################################"
if aws s3 rm \
    "s3://$TEST_BUCKET2/$TEST_UPLOAD_FILE" \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "DeleteObject successful"
else
    echo "DeleteObject failed"
    exit 1
fi

# Verify the file was deleted
if aws s3api head-object \
    --bucket $TEST_BUCKET --key $TEST_UPLOAD_FILE \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "File still exists after delete - should have been deleted"
    exit 1
else
    echo "File successfully deleted - head-object correctly returns error"
fi

# Test DeleteObject idempotency - deleting non-existent object should succeed
if aws s3 rm \
    "s3://$TEST_BUCKET2/nonexistent-file.txt" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "DeleteObject idempotent - deleting non-existent object succeeded"
else
    echo "DeleteObject should be idempotent"
    exit 1
fi

# Test DeleteObjects (batch delete) - upload multiple test files first
TEST_BATCH_FILE1="batch-delete-1.txt"
TEST_BATCH_FILE2="batch-delete-2.txt"
TEST_BATCH_FILE3="batch-delete-3.txt"

echo "Test batch 1" > "$TEMPDIR2/$TEST_BATCH_FILE1"
echo "Test batch 2" > "$TEMPDIR2/$TEST_BATCH_FILE2"
echo "Test batch 3" > "$TEMPDIR2/$TEST_BATCH_FILE3"

if aws s3 cp "$TEMPDIR2/$TEST_BATCH_FILE1" \
    s3://$TEST_BUCKET2/$TEST_BATCH_FILE1 \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "Batch file 1 upload successful"
else
    echo "Batch file 1 upload failed"
    exit 1
fi

if aws s3 cp "$TEMPDIR2/$TEST_BATCH_FILE2" \
    s3://$TEST_BUCKET2/$TEST_BATCH_FILE2 \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "Batch file 2 upload successful"
else
    echo "Batch file 2 upload failed"
    exit 1
fi

if aws s3 cp "$TEMPDIR2/$TEST_BATCH_FILE3" \
    s3://$TEST_BUCKET2/$TEST_BATCH_FILE3 \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "Batch file 3 upload successful"
else
    echo "Batch file 3 upload failed"
    exit 1
fi

# Create delete request JSON for batch delete
cat > "$TEMPDIR2/delete.json" <<EOF
{
  "Objects": [
    {"Key": "$TEST_BATCH_FILE1"},
    {"Key": "$TEST_BATCH_FILE2"},
    {"Key": "$TEST_BATCH_FILE3"}
  ],
  "Quiet": false
}
EOF

# Test DeleteObjects batch operation
if aws s3api delete-objects \
    --bucket $TEST_BUCKET \
    --delete "file://$TEMPDIR2/delete.json" \
    --endpoint-url "$SERVER_ADDRESS" > "$TEMPDIR2/delete-result.json" 2>&1; then
    echo "DeleteObjects batch operation successful"

    # Verify all 3 objects were deleted
    DELETED_COUNT=$(jq -r '.Deleted | length' "$TEMPDIR2/delete-result.json")
    if [ "$DELETED_COUNT" = "3" ]; then
        echo "DeleteObjects correctly deleted 3 objects"
    else
        echo "DeleteObjects failed - expected 3 deleted objects, got $DELETED_COUNT"
        cat "$TEMPDIR2/delete-result.json"
        exit 1
    fi
else
    echo "DeleteObjects batch operation failed"
    cat "$TEMPDIR2/delete-result.json"
    exit 1
fi

# Test DeleteObjects idempotency - deleting non-existent objects should succeed
cat > "$TEMPDIR2/delete-nonexistent.json" <<EOF
{
  "Objects": [
    {"Key": "nonexistent-batch-1.txt"},
    {"Key": "nonexistent-batch-2.txt"}
  ],
  "Quiet": false
}
EOF

if aws s3api delete-objects \
    --bucket $TEST_BUCKET \
    --delete "file://$TEMPDIR2/delete-nonexistent.json" \
    --endpoint-url "$SERVER_ADDRESS" > "$TEMPDIR2/delete-nonexistent-result.json" 2>&1; then
    echo "DeleteObjects idempotent - deleting non-existent objects succeeded"

    # Verify we got success responses
    DELETED_COUNT=$(jq -r '.Deleted | length' "$TEMPDIR2/delete-nonexistent-result.json")
    if [ "$DELETED_COUNT" = "2" ]; then
        echo "DeleteObjects correctly returned success for 2 non-existent objects"
    else
        echo "DeleteObjects idempotency check failed - expected 2 deleted objects, got $DELETED_COUNT"
        cat "$TEMPDIR2/delete-nonexistent-result.json"
        exit 1
    fi
else
    echo "DeleteObjects idempotency test failed"
    cat "$TEMPDIR2/delete-nonexistent-result.json"
    exit 1
fi

rm "$TEMPDIR2/$TEST_BATCH_FILE1" "$TEMPDIR2/$TEST_BATCH_FILE2" "$TEMPDIR2/$TEST_BATCH_FILE3" 2>/dev/null

# Test DeleteBucket on empty bucket (should succeed)
if aws s3 rb \
    "s3://${TEST_BUCKET2}1" \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "DeleteBucket successful on empty bucket"
else
    echo "DeleteBucket failed on empty bucket"
    exit 1
fi

# Test DeleteBucket on non-empty bucket (should fail)
if aws s3 rb \
    s3://$TEST_BUCKET \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "DeleteBucket should fail on non-empty bucket"
    exit 1
else
    echo "DeleteBucket correctly failed on non-empty bucket"
fi

# Test CreateBucket with invalid name (should fail)
if aws s3 mb \
    s3://INVALID-BUCKET-NAME \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "CreateBucket should fail on invalid bucket name"
    exit 1
else
    echo "CreateBucket correctly rejected invalid bucket name"
fi

# Test CreateBucket duplicate (should fail)
DUPLICATE_BUCKET="bucket1"
if aws s3 mb \
    s3://$DUPLICATE_BUCKET \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "CreateBucket should fail on duplicate bucket"
    exit 1
else
    echo "CreateBucket correctly rejected duplicate bucket"
fi

./test_tagging.sh || {
    echo "❌ Tagging tests failed ❌"
    exit 1
}

./test_multipart.sh || {
    echo "❌ Multipart tests failed ❌"
    exit 1
}

echo ""
echo "✅ ALL TESTS PASSED! ✅"