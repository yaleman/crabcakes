#!/bin/bash

MYDIR=$(dirname "$0")

set -o pipefail

if [ -z "$FRONTEND_WITHOUT_PORT" ]; then
    # shellcheck disable=SC1091
    source "$MYDIR/inner_setup_test.sh"
fi
if [ -z "$SERVER_ADDRESS" ]; then
    # shellcheck disable=SC1091
    source "$MYDIR/inner_setup_test.sh"
fi
# Test Multipart Upload
echo "Testing multipart upload..."
MULTIPART_KEY="testuser/multipart-test-file.bin"
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
echo "########################################################"
echo "Split file into 2 parts"
echo "Starting multipart upload..."
echo "########################################################"
# Initiate multipart upload
UPLOAD_OUTPUT=$(aws s3api create-multipart-upload \
    --bucket "$TEST_BUCKET2" \
    --key $MULTIPART_KEY \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)


# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo "Failed to initiate multipart upload: $UPLOAD_OUTPUT"
    exit 1
else
    echo "CreateMultipartUpload output: $UPLOAD_OUTPUT"
fi
echo "########################################################"

UPLOAD_ID=$(echo "$UPLOAD_OUTPUT" | jq -r '.UploadId')
if [ -z "$UPLOAD_ID" ] || [ "$UPLOAD_ID" = "null" ]; then
    echo "Failed to get upload ID from response: $UPLOAD_OUTPUT"
    exit 1
fi
echo "########################################################"
echo "Initiated multipart upload with ID: $UPLOAD_ID"
echo "########################################################"
# Upload part 1
PART1_OUTPUT=$(\
    aws s3api upload-part \
    --bucket "$TEST_BUCKET2" \
    --key "$MULTIPART_KEY" \
    --part-number 1 \
    --upload-id "$UPLOAD_ID" \
    --body "$PART1" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo "Failed to upload part 1: $PART1_OUTPUT"
    exit 1
fi

echo "########################################################"
ETAG1=$(echo "$PART1_OUTPUT" | jq -r '.ETag' | tr -d '"')
echo "PART1_OUTPUT=${PART1_OUTPUT}"
echo "Uploaded part 1 with ETag: '$ETAG1'"
echo "########################################################"

# Upload part 2
PART2_OUTPUT=$(\
    aws s3api upload-part \
    --bucket "$TEST_BUCKET2" \
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

echo "########################################################"
echo "PART2_OUTPUT=${PART2_OUTPUT}"
ETAG2=$(echo "$PART2_OUTPUT" | jq -r '.ETag'| tr -d '"')
echo "Uploaded part 2 with ETag: '$ETAG2'"
echo "########################################################"

# List parts to verify
LIST_PARTS_OUTPUT=$(aws s3api list-parts \
    --bucket "$TEST_BUCKET2" \
    --key $MULTIPART_KEY \
    --upload-id "$UPLOAD_ID" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

echo "########################################################"
PARTS_COUNT=$(echo "$LIST_PARTS_OUTPUT" | jq '.Parts | length')
if [ "$PARTS_COUNT" != "2" ]; then
    echo "ListParts failed - expected 2 parts, got $PARTS_COUNT"
    echo "$LIST_PARTS_OUTPUT"
    exit 1
fi
echo "ListParts successful - found 2 parts"
echo "########################################################"

# Create completion JSON
cat > "$TEMPDIR2/complete-multipart.json" <<EOF
{
  "Parts": [
    {
      "PartNumber": 1,
      "ETag": "\"$ETAG1\""
    },
    {
      "PartNumber": 2,
      "ETag": "\"$ETAG2\""
    }
  ]
}
EOF
cat "$TEMPDIR2/complete-multipart.json"

# Complete multipart upload
COMPLETE_OUTPUT=$(\
    aws s3api complete-multipart-upload \
    --bucket "$TEST_BUCKET2" \
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

echo "#######################################"
echo "Downloading the file to verify it matches the original"
echo "#######################################"

DOWNLOADED_FILE="$TEMPDIR2/downloaded-multipart.bin"
if aws s3 cp "s3://$TEST_BUCKET2/$MULTIPART_KEY" "$DOWNLOADED_FILE" \
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
    echo "Original: $ORIGINAL_MD5 size: $(find "$(pwd)" -name "$MULTIPART_FILE"  -exec ls -l "{}" \; | awk '{print $5}')"
    echo "Downloaded: $DOWNLOADED_MD5 size: $(find "$(pwd)" -name "$DOWNLOADED_FILE"  -exec ls -l "{}" \; | awk '{print $5}')"
    exit 1
fi

# Clean up multipart test files
rm -f "$MULTIPART_FILE" "$PART1" "$PART2" "$DOWNLOADED_FILE" "$TEMPDIR2/complete-multipart.json"

# Test UploadPartCopy (copy parts from existing object)
echo "#######################################"
echo "Testing UploadPartCopy..."
echo "#######################################"

# Create a source object for copying (10MB)
SOURCE_KEY="testuser/source-object.bin"
mkdir "$(dirname "$TEMPDIR2/$SOURCE_KEY")" 2>/dev/null
dd if=/dev/urandom of="$TEMPDIR2/$SOURCE_KEY" bs=1M count=10 2>/dev/null


echo "#######################################"
echo "Uploading source object for UploadPartCopy test..."
echo "#######################################"
# Upload the source object
if aws s3 cp "$TEMPDIR2/$SOURCE_KEY" "s3://$TEST_BUCKET2/$SOURCE_KEY" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "Source object uploaded successfully"
else
    echo "Failed to upload source object"
    exit 1
fi

echo "Initiate multipart upload for destination"
COPY_UPLOAD_OUTPUT=$(\
    aws s3api create-multipart-upload \
    --bucket "$TEST_BUCKET2" \
    --key "copied-object.bin" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

COPY_UPLOAD_ID=$(echo "$COPY_UPLOAD_OUTPUT" | jq -r '.UploadId')
echo "Created multipart upload for copy with ID: $COPY_UPLOAD_ID"
if [ -z "$COPY_UPLOAD_ID" ] || [ "$COPY_UPLOAD_ID" = "null" ]; then
    echo "Failed to get upload ID for copy: $COPY_UPLOAD_OUTPUT"
    exit 1
fi

# Copy first 5MB using UploadPartCopy
echo "Copying part 1 (bytes 0-5242879)..."
COPY_PART1_OUTPUT=$(\
    aws s3api upload-part-copy \
    --bucket "$TEST_BUCKET2" \
    --key "copied-object.bin" \
    --part-number 1 \
    --upload-id "$COPY_UPLOAD_ID" \
    --copy-source "$TEST_BUCKET2/$SOURCE_KEY" \
    --copy-source-range "bytes=0-5242879" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

echo "########################################################"
COPY_PART1_ETAG=$(echo "$COPY_PART1_OUTPUT" | jq -r '.CopyPartResult.ETag')
echo "Part 1 copied with ETag: '${COPY_PART1_ETAG}'"

if [ -z "$COPY_PART1_ETAG" ] || [ "$COPY_PART1_ETAG" = "null" ]; then
    echo "Failed to get ETag for copied part 1: $COPY_PART1_OUTPUT"
    exit 1
fi
echo "########################################################"
# Copy second 5MB using UploadPartCopy
echo "Copying part 2 (bytes 5242880-10485759)..."
echo "########################################################"

COPY_PART2_OUTPUT=$(\
    aws s3api upload-part-copy \
    --bucket "$TEST_BUCKET2" \
    --key "copied-object.bin" \
    --part-number 2 \
    --upload-id "$COPY_UPLOAD_ID" \
    --copy-source "$TEST_BUCKET2/$SOURCE_KEY" \
    --copy-source-range "bytes=5242880-10485759" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

COPY_PART2_ETAG=$(echo "$COPY_PART2_OUTPUT" | jq -r '.CopyPartResult.ETag')
echo "Part 2 copied with ETag: '${COPY_PART2_ETAG}'"

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

echo "JSON request to complete UploadPartCopy:"
cat "$TEMPDIR2/complete-copy.json"

# Complete multipart upload
echo "Completing multipart upload for copy..."
if \
    aws s3api complete-multipart-upload \
    --bucket "$TEST_BUCKET2" \
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
aws s3 cp "s3://$TEST_BUCKET2/copied-object.bin" "$TEMPDIR2/copied-downloaded.bin" \
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
ABORT_UPLOAD_OUTPUT=$(\
    aws s3api create-multipart-upload \
    --bucket "$TEST_BUCKET2" \
    --key "abort-test.bin" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1)

ABORT_UPLOAD_ID=$(echo "$ABORT_UPLOAD_OUTPUT" | jq -r '.UploadId')
echo "Created upload to abort with ID: $ABORT_UPLOAD_ID"

if aws s3api abort-multipart-upload \
    --bucket "$TEST_BUCKET2" \
    --key "abort-test.bin" \
    --upload-id "$ABORT_UPLOAD_ID" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "AbortMultipartUpload successful"
else
    echo "AbortMultipartUpload failed"
    exit 1
fi


echo ""
echo "✅ MULTIPART TESTS PASSED! ✅"