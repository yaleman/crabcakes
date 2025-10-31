#!/bin/bash
MYDIR=$(dirname "$0")
set -o pipefail

if [ -z "$FRONTEND_WITHOUT_PORT" ]; then
    # shellcheck disable=SC1091
    source "$MYDIR/inner_setup_test.sh"
fi

echo "========================================"
echo "TESTING S3 BUCKET WEBSITE HOSTING"
echo "========================================"

# Helper function to test anonymous access (without credentials)
test_anonymous_request() {
    local url="$1"
    local expected_status="$2"
    local expected_content="$3"
    local description="$4"

    echo "  Testing: $description"

    # Temporarily unset AWS credentials for anonymous request
    local saved_key="$AWS_ACCESS_KEY_ID"
    local saved_secret="$AWS_SECRET_ACCESS_KEY"
    unset AWS_ACCESS_KEY_ID
    unset AWS_SECRET_ACCESS_KEY

    local RESPONSE
    local STATUS_CODE
    local BODY
    RESPONSE=$(curl -s -w "\n%{http_code}" "$url")
    STATUS_CODE=$(echo "$RESPONSE" | tail -n 1)
    BODY=$(echo "$RESPONSE" | sed '$d')  # Remove last line (macOS compatible)


    # Restore credentials
    export AWS_ACCESS_KEY_ID="$saved_key"
    export AWS_SECRET_ACCESS_KEY="$saved_secret"

    if [ "$STATUS_CODE" != "$expected_status" ]; then
        echo "  ❌ FAILED: Expected status $expected_status, got $STATUS_CODE"
        echo "  Response: $BODY"
        exit 1
    fi

    if [ -n "$expected_content" ]; then
        if echo "$BODY" | grep -q "$expected_content"; then
            echo "  ✅ PASSED: Got $STATUS_CODE with expected content"
        else
            echo "  ❌ FAILED: Expected content '$expected_content' not found"
            echo "  Response: $BODY"
            exit 1
        fi
    else
        echo "  ✅ PASSED: Got expected status $STATUS_CODE"
    fi
}

# Helper function to enable website hosting
enable_website() {
    local bucket="$1"
    local index_suffix="${2:-index.html}"
    local error_key="$3"

    echo "Enabling website hosting for $bucket..."

    local config
    if [ -n "$error_key" ]; then
        config="{\"IndexDocument\":{\"Suffix\":\"$index_suffix\"},\"ErrorDocument\":{\"Key\":\"$error_key\"}}"
    else
        config="{\"IndexDocument\":{\"Suffix\":\"$index_suffix\"}}"
    fi

    local output
    output=$(aws s3api put-bucket-website \
        --bucket "$bucket" \
        --website-configuration "$config" \
        --endpoint-url "$SERVER_ADDRESS" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "✅ Website hosting enabled for $bucket"
        return 0
    else
        echo "❌ Failed to enable website hosting for $bucket"
        echo "$output" | grep -v "InsecureRequestWarning"
        exit 1
    fi
}

# Helper function to disable website hosting
disable_website() {
    local bucket="$1"

    echo "Disabling website hosting for $bucket..."

    local output
    output=$(aws s3api delete-bucket-website \
        --bucket "$bucket" \
        --endpoint-url "$SERVER_ADDRESS" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "✅ Website hosting disabled for $bucket"
        return 0
    else
        echo "❌ Failed to disable website hosting for $bucket"
        echo "$output" | grep -v "InsecureRequestWarning"
        exit 1
    fi
}

# Helper function to verify website config
verify_website_config() {
    local bucket="$1"
    local expected_index="$2"
    local expected_error="$3"

    echo "Verifying website config for $bucket..."

    local config
    config=$(aws s3api get-bucket-website \
        --bucket "$bucket" \
        --endpoint-url "$SERVER_ADDRESS" 2>&1)
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo "❌ Failed to get website config for $bucket"
        echo "$config" | grep -v "InsecureRequestWarning"
        exit 1
    fi

    if echo "$config" | jq -e ".IndexDocument.Suffix == \"$expected_index\"" > /dev/null; then
        echo "✅ Index document verified: $expected_index"
    else
        echo "❌ Index document mismatch"
        echo "$config"
        exit 1
    fi

    if [ -n "$expected_error" ]; then
        if echo "$config" | jq -e ".ErrorDocument.Key == \"$expected_error\"" > /dev/null; then
            echo "✅ Error document verified: $expected_error"
        else
            echo "❌ Error document mismatch"
            echo "$config"
            exit 1
        fi
    fi
}

echo ""
echo "========================================"
echo "TEST 1: bucket_with_index_and_error"
echo "========================================"

BUCKET1="bucket_with_index_and_error"

# Enable website with both index and error documents
enable_website "$BUCKET1" "index.html" "error.html"
verify_website_config "$BUCKET1" "index.html" "error.html"

# Test anonymous access to index
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET1/" \
    "200" \
    "bucket with index and error" \
    "Anonymous access to /$BUCKET1/ should serve index.html"

# Test anonymous access to missing file (should serve error.html)
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET1/nonexistent.txt" \
    "404" \
    "error for bucket_with_index_and_error" \
    "Anonymous 404 should serve error.html"

# Test authenticated access still works
echo "  Testing authenticated GET request..."
if aws s3api get-object \
    --bucket "$BUCKET1" \
    --key "index.html" \
    "$TEMPDIR2/downloaded-index.html" \
    --endpoint-url "$SERVER_ADDRESS" > /dev/null 2>&1; then
    if grep -q "bucket with index and error" "$TEMPDIR2/downloaded-index.html"; then
        echo "  ✅ PASSED: Authenticated access still works"
    else
        echo "  ❌ FAILED: Wrong content in downloaded file"
        exit 1
    fi
else
    echo "  ❌ FAILED: Authenticated GET failed"
    exit 1
fi

# Disable website hosting
disable_website "$BUCKET1"

# Test anonymous access is now denied
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET1/" \
    "403" \
    "" \
    "Anonymous access should be denied after disabling website"

# Test authenticated access still works after disabling
echo "  Testing authenticated access after disable..."
if aws s3api get-object \
    --bucket "$BUCKET1" \
    --key "index.html" \
    "$TEMPDIR2/downloaded-index2.html" \
    --endpoint-url "$SERVER_ADDRESS" > /dev/null 2>&1; then
    echo "  ✅ PASSED: Authenticated access works after disable"
else
    echo "  ❌ FAILED: Authenticated access failed after disable"
    exit 1
fi

echo ""
echo "========================================"
echo "TEST 2: bucket_with_index_only"
echo "========================================"

BUCKET2="bucket_with_index_only"

# Enable website with only index document
enable_website "$BUCKET2" "index.html"
verify_website_config "$BUCKET2" "index.html"

# Test anonymous access to index
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET2/" \
    "200" \
    "bucket with index only" \
    "Anonymous access to /$BUCKET2/ should serve index.html"

# Test anonymous access to missing file (should get 404 without error.html)
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET2/nonexistent.txt" \
    "404" \
    "" \
    "Anonymous 404 without error document"

# Disable and verify denial
disable_website "$BUCKET2"
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET2/" \
    "403" \
    "" \
    "Anonymous access denied after disabling website"

echo ""
echo "========================================"
echo "TEST 3: bucket_no_index_but_error"
echo "========================================"

BUCKET3="bucket_no_index_but_error"

# Enable website with only error document (no index)
enable_website "$BUCKET3" "index.html" "error.html"
verify_website_config "$BUCKET3" "index.html" "error.html"

# Test anonymous access to root (should 404 since no index.html exists)
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET3/" \
    "404" \
    "error for bucket no index but error" \
    "Anonymous access to /$BUCKET3/ should serve error.html (no index exists)"

# Test anonymous access to missing file (should serve error.html)
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET3/nonexistent.txt" \
    "404" \
    "error for bucket no index but error" \
    "Anonymous 404 should serve error.html"

# Test authenticated access to error.html directly
echo "  Testing authenticated GET of error.html..."
if aws s3api get-object \
    --bucket "$BUCKET3" \
    --key "error.html" \
    "$TEMPDIR2/downloaded-error.html" \
    --endpoint-url "$SERVER_ADDRESS" > /dev/null 2>&1; then
    if grep -q "error for bucket no index but error" "$TEMPDIR2/downloaded-error.html"; then
        echo "  ✅ PASSED: Can retrieve error.html directly"
    else
        echo "  ❌ FAILED: Wrong content in error.html"
        exit 1
    fi
else
    echo "  ❌ FAILED: Could not retrieve error.html"
    exit 1
fi

disable_website "$BUCKET3"

echo ""
echo "========================================"
echo "TEST 4: bucket_no_index_or_error"
echo "========================================"

BUCKET4="bucket_no_index_or_error"

# Enable website but bucket has neither index nor error document
enable_website "$BUCKET4" "index.html"
verify_website_config "$BUCKET4" "index.html"

# Test anonymous access to root (should 404)
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET4/" \
    "404" \
    "" \
    "Anonymous access to empty bucket should 404"

# Test anonymous access to missing file (should 404)
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET4/nonexistent.txt" \
    "404" \
    "" \
    "Anonymous 404 in empty bucket"

disable_website "$BUCKET4"

echo ""
echo "========================================"
echo "TEST 5: Directory path handling"
echo "========================================"

# Re-enable website on bucket_with_index_and_error
enable_website "$BUCKET1" "index.html" "error.html"

# Test that trailing slash serves index
test_anonymous_request \
    "$SERVER_ADDRESS/$BUCKET1/" \
    "200" \
    "bucket with index and error" \
    "Directory path with trailing slash serves index"

# Clean up
disable_website "$BUCKET1"

echo ""
echo "========================================"
echo "Cleaning up..."
echo "========================================"

echo "Killing crabcakes (PID $CRABCAKES_PID) and cleaning up $TEMPDIR"

"$MYDIR/inner_test_pkill_instance.sh"

rm -rf "$TEMPDIR" "$TEMPDIR2"

echo ""
echo "✅ ALL WEBSITE TESTS PASSED! ✅"
