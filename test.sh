#!/bin/bash

# Test script for mypwd password manager

set -e

SCRIPT="python3 ./mypwd.py"
TEST_MASTER_PASSWORD="TestMasterPass123!"

echo "=== Testing mypwd Password Manager ==="
echo ""

# Clean up any existing test data
rm -rf ~/.mypwd
echo "✓ Cleaned up existing data"

# Test 1: Add a password
echo ""
echo "Test 1: Adding password for 'github'"
echo "$TEST_MASTER_PASSWORD" | $SCRIPT --add github MyGitHubPass123
sleep 1

# Test 2: List tags
echo ""
echo "Test 2: Listing tags"
echo "$TEST_MASTER_PASSWORD" | $SCRIPT --list
sleep 1

# Test 3: Add another password
echo ""
echo "Test 3: Adding password for 'email'"
echo "$TEST_MASTER_PASSWORD" | $SCRIPT --add email MyEmailPass456
sleep 1

# Test 4: List tags again
echo ""
echo "Test 4: Listing tags (should show 2)"
echo "$TEST_MASTER_PASSWORD" | $SCRIPT --list
sleep 1

# Test 5: Get password with output
echo ""
echo "Test 5: Getting password for 'github' with --output"
echo "$TEST_MASTER_PASSWORD" | $SCRIPT --get github --output
sleep 1

# Test 6: Get password with output (email)
echo ""
echo "Test 6: Getting password for 'email' with --output"
echo "$TEST_MASTER_PASSWORD" | $SCRIPT --get email --output
sleep 1

# Test 7: Wrong master password
echo ""
echo "Test 7: Testing wrong master password (should fail)"
echo "WrongPassword" | $SCRIPT --list 2>&1 || echo "✓ Correctly rejected wrong password"
sleep 1

# Test 8: Update existing password
echo ""
echo "Test 8: Updating password for 'github'"
echo "$TEST_MASTER_PASSWORD" | $SCRIPT --add github UpdatedGitHubPass789
sleep 1

# Test 9: Verify updated password
echo ""
echo "Test 9: Verifying updated password"
echo "$TEST_MASTER_PASSWORD" | $SCRIPT --get github --output
sleep 1

# Test 10: Get non-existent tag
echo ""
echo "Test 10: Getting non-existent tag (should fail)"
echo "$TEST_MASTER_PASSWORD" | $SCRIPT --get nonexistent --output 2>&1 || echo "✓ Correctly reported missing tag"

echo ""
echo "=== All tests completed ==="
echo ""
echo "API specification:"
echo "  mypwd --add <tag> <password>"
echo "  mypwd --get <tag>"
echo "  mypwd --get <tag> --output"
echo "  mypwd --list"
