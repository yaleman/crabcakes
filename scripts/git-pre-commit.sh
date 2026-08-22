#!/bin/bash


JS_BUILD_RESULT=$(mise build-js 2>&1);

if [ "$(git status --porcelain | grep -E '^\s*$' | grep -c 'static/js/')" -gt 0 ]; then

    echo "$JS_BUILD_RESULT"

    git status
    echo "##################################################################################"
    echo "🚨 There are uncommitted changes after build-js. Please review and commit them. 🚨"
    echo "##################################################################################"
    exit 1
else
    echo "✅ No uncommitted changes after build-js."
fi