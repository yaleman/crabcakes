#!/bin/bash

# set -e

SERVER_PORT=18090
SERVER_ADDRESS="${CRABCAKES_HOSTNAME:-localhost}:$SERVER_PORT"

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

# Test CopyObject - server-side copy of existing object
TEST_COPY_KEY="test-copy.txt"
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3api copy-object \
    --bucket $TEST_BUCKET \
    --key $TEST_COPY_KEY \
    --copy-source "$TEST_BUCKET/$TEST_FILE" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "CopyObject successful"
else
    echo "CopyObject failed"
    exit 1
fi

# Verify copied object exists and has correct content
COPY_CONTENT="$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 cp \
    s3://$TEST_BUCKET/$TEST_COPY_KEY - \
    --endpoint-url "$SERVER_ADDRESS")"

ORIGINAL_CONTENT="$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 cp \
    s3://$TEST_BUCKET/$TEST_FILE - \
    --endpoint-url "$SERVER_ADDRESS")"

if [[ "$COPY_CONTENT" == "$ORIGINAL_CONTENT" ]]; then
    echo "CopyObject - copied content matches original"
else
    echo "CopyObject - copied content does not match original"
    exit 1
fi

# Clean up copied object
AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 rm \
    s3://$TEST_BUCKET/$TEST_COPY_KEY \
    --endpoint-url "$SERVER_ADDRESS" > /dev/null 2>&1

# Test CopyObject with non-existent source (should fail)
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3api copy-object \
    --bucket $TEST_BUCKET \
    --key "copy-dest.txt" \
    --copy-source "$TEST_BUCKET/nonexistent-source.txt" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "CopyObject should fail for non-existent source"
    exit 1
else
    echo "CopyObject correctly failed for non-existent source"
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

# Test DeleteObjects (batch delete) - upload multiple test files first
TEST_BATCH_FILE1="batch-delete-1.txt"
TEST_BATCH_FILE2="batch-delete-2.txt"
TEST_BATCH_FILE3="batch-delete-3.txt"

echo "Test batch 1" > "$TEMPDIR2/$TEST_BATCH_FILE1"
echo "Test batch 2" > "$TEMPDIR2/$TEST_BATCH_FILE2"
echo "Test batch 3" > "$TEMPDIR2/$TEST_BATCH_FILE3"

if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 cp "$TEMPDIR2/$TEST_BATCH_FILE1" \
    s3://$TEST_BUCKET/$TEST_BATCH_FILE1 \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "Batch file 1 upload successful"
else
    echo "Batch file 1 upload failed"
    exit 1
fi

if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 cp "$TEMPDIR2/$TEST_BATCH_FILE2" \
    s3://$TEST_BUCKET/$TEST_BATCH_FILE2 \
    --endpoint-url "$SERVER_ADDRESS"; then
    echo "Batch file 2 upload successful"
else
    echo "Batch file 2 upload failed"
    exit 1
fi

if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3 cp "$TEMPDIR2/$TEST_BATCH_FILE3" \
    s3://$TEST_BUCKET/$TEST_BATCH_FILE3 \
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
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3api delete-objects \
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

if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" aws s3api delete-objects \
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

# Test Multipart Upload
echo "Testing multipart upload..."
MULTIPART_KEY="multipart-test-file.bin"
MULTIPART_FILE="$TEMPDIR2/multipart-source.bin"

# Create a 10MB test file using dd
dd if=/dev/urandom of="$MULTIPART_FILE" bs=1M count=10 2>/dev/null
if [ ! -f "$MULTIPART_FILE" ]; then
    echo "Failed to create test file with dd"
    exit 1
fi
echo "Created 10MB test file"

# Split into 2 parts (5MB each)
split -b 5M "$MULTIPART_FILE" "$TEMPDIR2/part-"
PART1="$TEMPDIR2/part-aa"
PART2="$TEMPDIR2/part-ab"

if [ ! -f "$PART1" ] || [ ! -f "$PART2" ]; then
    echo "Failed to split file into parts"
    exit 1
fi
echo "Split file into 2 parts"

# Initiate multipart upload
UPLOAD_OUTPUT=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api create-multipart-upload \
    --bucket $TEST_BUCKET \
    --key $MULTIPART_KEY \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo "Failed to initiate multipart upload: $UPLOAD_OUTPUT"
    exit 1
fi

UPLOAD_ID=$(echo "$UPLOAD_OUTPUT" | jq -r '.UploadId')
if [ -z "$UPLOAD_ID" ] || [ "$UPLOAD_ID" = "null" ]; then
    echo "Failed to get upload ID from response: $UPLOAD_OUTPUT"
    exit 1
fi
echo "Initiated multipart upload with ID: $UPLOAD_ID"

# Upload part 1
PART1_OUTPUT=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api upload-part \
    --bucket $TEST_BUCKET \
    --key $MULTIPART_KEY \
    --part-number 1 \
    --upload-id "$UPLOAD_ID" \
    --body "$PART1" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo "Failed to upload part 1: $PART1_OUTPUT"
    exit 1
fi

ETAG1=$(echo "$PART1_OUTPUT" | jq -r '.ETag')
echo "Uploaded part 1 with ETag: $ETAG1"

# Upload part 2
PART2_OUTPUT=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api upload-part \
    --bucket $TEST_BUCKET \
    --key $MULTIPART_KEY \
    --part-number 2 \
    --upload-id "$UPLOAD_ID" \
    --body "$PART2" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo "Failed to upload part 2: $PART2_OUTPUT"
    exit 1
fi

ETAG2=$(echo "$PART2_OUTPUT" | jq -r '.ETag')
echo "Uploaded part 2 with ETag: $ETAG2"

# List parts to verify
LIST_PARTS_OUTPUT=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api list-parts \
    --bucket $TEST_BUCKET \
    --key $MULTIPART_KEY \
    --upload-id "$UPLOAD_ID" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

PARTS_COUNT=$(echo "$LIST_PARTS_OUTPUT" | jq '.Parts | length')
if [ "$PARTS_COUNT" != "2" ]; then
    echo "ListParts failed - expected 2 parts, got $PARTS_COUNT"
    echo "$LIST_PARTS_OUTPUT"
    exit 1
fi
echo "ListParts successful - found 2 parts"

# Create completion JSON
cat > "$TEMPDIR2/complete-multipart.json" <<EOF
{
  "Parts": [
    {
      "PartNumber": 1,
      "ETag": $ETAG1
    },
    {
      "PartNumber": 2,
      "ETag": $ETAG2
    }
  ]
}
EOF

# Complete multipart upload
COMPLETE_OUTPUT=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api complete-multipart-upload \
    --bucket $TEST_BUCKET \
    --key $MULTIPART_KEY \
    --upload-id "$UPLOAD_ID" \
    --multipart-upload "file://$TEMPDIR2/complete-multipart.json" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo "Failed to complete multipart upload: $COMPLETE_OUTPUT"
    exit 1
fi
echo "Completed multipart upload"

# Download the file and verify it matches the original
DOWNLOADED_FILE="$TEMPDIR2/downloaded-multipart.bin"
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3 cp "s3://$TEST_BUCKET/$MULTIPART_KEY" "$DOWNLOADED_FILE" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "Downloaded multipart file"
else
    echo "Failed to download multipart file"
    exit 1
fi

# Compare checksums
ORIGINAL_MD5=$(md5 -q "$MULTIPART_FILE" 2>/dev/null || md5sum "$MULTIPART_FILE" | awk '{print $1}')
DOWNLOADED_MD5=$(md5 -q "$DOWNLOADED_FILE" 2>/dev/null || md5sum "$DOWNLOADED_FILE" | awk '{print $1}')

if [ "$ORIGINAL_MD5" = "$DOWNLOADED_MD5" ]; then
    echo "Multipart upload successful - checksums match"
else
    echo "Multipart upload failed - checksum mismatch"
    echo "Original: $ORIGINAL_MD5"
    echo "Downloaded: $DOWNLOADED_MD5"
    exit 1
fi

# Clean up multipart test files
rm -f "$MULTIPART_FILE" "$PART1" "$PART2" "$DOWNLOADED_FILE" "$TEMPDIR2/complete-multipart.json"

# Test UploadPartCopy (copy parts from existing object)
echo "Testing UploadPartCopy..."

# Create a source object for copying (10MB)
SOURCE_KEY="source-object.bin"
dd if=/dev/urandom of="$TEMPDIR2/$SOURCE_KEY" bs=1M count=10 2>/dev/null

# Upload the source object
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3 cp "$TEMPDIR2/$SOURCE_KEY" "s3://$TEST_BUCKET/$SOURCE_KEY" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "Source object uploaded successfully"
else
    echo "Failed to upload source object"
    exit 1
fi

# Initiate multipart upload for destination
COPY_UPLOAD_OUTPUT=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api create-multipart-upload \
    --bucket $TEST_BUCKET \
    --key "copied-object.bin" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

COPY_UPLOAD_ID=$(echo "$COPY_UPLOAD_OUTPUT" | jq -r '.UploadId')
echo "Created multipart upload for copy with ID: $COPY_UPLOAD_ID"

# Copy first 5MB using UploadPartCopy
echo "Copying part 1 (bytes 0-5242879)..."
COPY_PART1_OUTPUT=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api upload-part-copy \
    --bucket $TEST_BUCKET \
    --key "copied-object.bin" \
    --part-number 1 \
    --upload-id "$COPY_UPLOAD_ID" \
    --copy-source "$TEST_BUCKET/$SOURCE_KEY" \
    --copy-source-range "bytes=0-5242879" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

COPY_PART1_ETAG=$(echo "$COPY_PART1_OUTPUT" | jq -r '.CopyPartResult.ETag')
echo "Part 1 copied with ETag: $COPY_PART1_ETAG"

# Copy second 5MB using UploadPartCopy
echo "Copying part 2 (bytes 5242880-10485759)..."
COPY_PART2_OUTPUT=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api upload-part-copy \
    --bucket $TEST_BUCKET \
    --key "copied-object.bin" \
    --part-number 2 \
    --upload-id "$COPY_UPLOAD_ID" \
    --copy-source "$TEST_BUCKET/$SOURCE_KEY" \
    --copy-source-range "bytes=5242880-10485759" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

COPY_PART2_ETAG=$(echo "$COPY_PART2_OUTPUT" | jq -r '.CopyPartResult.ETag')
echo "Part 2 copied with ETag: $COPY_PART2_ETAG"

# Create complete request JSON for UploadPartCopy
cat > "$TEMPDIR2/complete-copy.json" << EOF
{
  "Parts": [
    {
      "ETag": $COPY_PART1_ETAG,
      "PartNumber": 1
    },
    {
      "ETag": $COPY_PART2_ETAG,
      "PartNumber": 2
    }
  ]
}
EOF

# Complete multipart upload
echo "Completing multipart upload for copy..."
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api complete-multipart-upload \
    --bucket $TEST_BUCKET \
    --key "copied-object.bin" \
    --upload-id "$COPY_UPLOAD_ID" \
    --multipart-upload "file://$TEMPDIR2/complete-copy.json" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "Multipart upload completed successfully"
else
    echo "Failed to finish full multipart upload"
    exit 1
fi

# Download copied object and verify
AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3 cp "s3://$TEST_BUCKET/copied-object.bin" "$TEMPDIR2/copied-downloaded.bin" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1

# Verify copied object matches source
if command -v md5 &> /dev/null; then
    SOURCE_MD5=$(md5 -q "$TEMPDIR2/$SOURCE_KEY")
    COPIED_MD5=$(md5 -q "$TEMPDIR2/copied-downloaded.bin")
elif command -v md5sum &> /dev/null; then
    SOURCE_MD5=$(md5sum "$TEMPDIR2/$SOURCE_KEY" | awk '{print $1}')
    COPIED_MD5=$(md5sum "$TEMPDIR2/copied-downloaded.bin" | awk '{print $1}')
else
    echo "md5 or md5sum command not found, skipping checksum verification"
    SOURCE_MD5=""
    COPIED_MD5=""
fi

if [ -n "$SOURCE_MD5" ] && [ "$SOURCE_MD5" = "$COPIED_MD5" ]; then
    echo "UploadPartCopy successful - checksums match (MD5: $SOURCE_MD5)"
else
    echo "UploadPartCopy checksum verification failed or skipped"
    if [ -n "$SOURCE_MD5" ]; then
        echo "Expected: $SOURCE_MD5, Got: $COPIED_MD5"
        exit 1
    fi
fi

# Clean up copy test files
rm -f "$TEMPDIR2/$SOURCE_KEY" "$TEMPDIR2/copied-downloaded.bin" "$TEMPDIR2/complete-copy.json"

# Test abort multipart upload (create a new upload and abort it)
echo "Testing abort multipart upload..."
ABORT_UPLOAD_OUTPUT=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api create-multipart-upload \
    --bucket $TEST_BUCKET \
    --key "abort-test.bin" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

ABORT_UPLOAD_ID=$(echo "$ABORT_UPLOAD_OUTPUT" | jq -r '.UploadId')
echo "Created upload to abort with ID: $ABORT_UPLOAD_ID"

if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api abort-multipart-upload \
    --bucket $TEST_BUCKET \
    --key "abort-test.bin" \
    --upload-id "$ABORT_UPLOAD_ID" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "AbortMultipartUpload successful"
else
    echo "AbortMultipartUpload failed"
    exit 1
fi

# Test object tagging
echo "Testing object tagging operations..."

# Upload a test object for tagging
TAGGING_KEY="tagging-test.txt"
echo "test content for tagging" > "$TEMPDIR2/tagging-test.txt"

if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3 cp "$TEMPDIR2/tagging-test.txt" "s3://$TEST_BUCKET/$TAGGING_KEY" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "Test object uploaded for tagging"
else
    echo "Failed to upload test object for tagging"
    exit 1
fi

# Create tagging JSON
cat > "$TEMPDIR2/tagging.json" << EOF
{
  "TagSet": [
    {
      "Key": "Environment",
      "Value": "Test"
    },
    {
      "Key": "Project",
      "Value": "Crabcakes"
    }
  ]
}
EOF

# Put object tagging
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api put-object-tagging \
    --bucket $TEST_BUCKET \
    --key "$TAGGING_KEY" \
    --tagging "file://$TEMPDIR2/tagging.json" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "PutObjectTagging successful"
else
    echo "PutObjectTagging failed"
    exit 1
fi

# Get object tagging
TAGS_OUTPUT=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api get-object-tagging \
    --bucket $TEST_BUCKET \
    --key "$TAGGING_KEY" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

TAGS_COUNT=$(echo "$TAGS_OUTPUT" | jq '.TagSet | length')
if [ "$TAGS_COUNT" -eq 2 ]; then
    echo "GetObjectTagging successful - found $TAGS_COUNT tags"
else
    echo "GetObjectTagging failed - expected 2 tags, got $TAGS_COUNT"
    exit 1
fi

# Verify tag values
ENV_TAG=$(echo "$TAGS_OUTPUT" | jq -r '.TagSet[] | select(.Key == "Environment") | .Value')
PROJECT_TAG=$(echo "$TAGS_OUTPUT" | jq -r '.TagSet[] | select(.Key == "Project") | .Value')

if [ "$ENV_TAG" = "Test" ] && [ "$PROJECT_TAG" = "Crabcakes" ]; then
    echo "Tag values verified successfully"
else
    echo "Tag values incorrect - Environment: $ENV_TAG, Project: $PROJECT_TAG"
    exit 1
fi

# Delete object tagging
if AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api delete-object-tagging \
    --bucket $TEST_BUCKET \
    --key "$TAGGING_KEY" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "DeleteObjectTagging successful"
else
    echo "DeleteObjectTagging failed"
    exit 1
fi

# Verify tags were deleted
TAGS_AFTER_DELETE=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    aws s3api get-object-tagging \
    --bucket $TEST_BUCKET \
    --key "$TAGGING_KEY" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

TAGS_COUNT_AFTER=$(echo "$TAGS_AFTER_DELETE" | jq '.TagSet | length')
if [ "$TAGS_COUNT_AFTER" -eq 0 ]; then
    echo "Tags successfully deleted - verified empty tag set"
else
    echo "Failed to delete tags - still found $TAGS_COUNT_AFTER tags"
    exit 1
fi

# Clean up tagging test files
rm -f "$TEMPDIR2/tagging-test.txt" "$TEMPDIR2/tagging.json"

echo "All tests passed, killing crabcakes (PID $CRABCAKES_PID) and cleaning up $TEMPDIR"
rm -rf "$TEMPDIR"
kill "$CRABCAKES_PID"
pkill -f target/debug/crabcakes