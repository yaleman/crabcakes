#!/bin/bash

set -o pipefail

if [ -z "$FRONTEND_WITHOUT_PORT" ]; then
    # shellcheck disable=SC1091
    source ./inner_setup_test.sh
fi

# Test object tagging
echo "Testing object tagging operations..."

# Upload a test object for tagging
TAGGING_KEY="tagging-test.txt"
echo "test content for tagging" > "$TEMPDIR2/tagging-test.txt"

if aws s3 cp "$TEMPDIR2/tagging-test.txt" "s3://$TEST_BUCKET2/$TAGGING_KEY" \
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
if aws s3api put-object-tagging \
    --bucket "$TEST_BUCKET2" \
    --key "$TAGGING_KEY" \
    --tagging "file://$TEMPDIR2/tagging.json" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "PutObjectTagging successful"
else
    echo "PutObjectTagging failed"
    exit 1
fi

# Get object tagging
TAGS_OUTPUT=$(\
    aws s3api get-object-tagging \
    --bucket "$TEST_BUCKET2" \
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
if aws s3api delete-object-tagging \
    --bucket "$TEST_BUCKET2" \
    --key "$TAGGING_KEY" \
    --endpoint-url "$SERVER_ADDRESS" 2>&1; then
    echo "DeleteObjectTagging successful"
else
    echo "DeleteObjectTagging failed"
    exit 1
fi

# Verify tags were deleted
TAGS_AFTER_DELETE=$(aws s3api get-object-tagging \
    --bucket "$TEST_BUCKET2" \
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
kill "$CRABCAKES_PID"
pkill -f target/debug/crabcakes
rm -rf "$TEMPDIR"



echo ""
echo "✅ TAGGING TESTS PASSED! ✅"