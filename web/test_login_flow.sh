#!/bin/bash
# Simulate the exact browser login flow step by step
COOKIE_JAR=/tmp/test_cookies.txt
BASE="http://localhost:1234"

echo "=== Step 1: GET /api/setup-status ==="
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE/api/setup-status"
echo ""

echo "=== Step 2: GET /api/auth/me (before login) ==="
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE/api/auth/me"
echo ""

echo "=== Step 3: GET /api/auth/login-hints ==="
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE/api/auth/login-hints?email=wee.wa@gmail.com"
echo ""

echo "=== Step 4: POST /api/auth/login ==="
LOGIN_RESP=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"wee.wa@gmail.com","password":"wee.wa@gmail.comAwee.wa@gmail.com"}')
echo "$LOGIN_RESP"
echo ""

echo "=== Step 5: GET /api/auth/me (after login) ==="
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE/api/auth/me"
echo ""

echo "=== Step 6: GET /api/vault/folders ==="
FOLDERS_RESP=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE/api/vault/folders")
echo "$FOLDERS_RESP" | head -c 200
echo ""

echo "=== Step 7: GET /api/vault/credentials ==="
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE/api/vault/credentials"
echo ""

echo "=== Step 8: GET /api/vault/asset-holder ==="
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE/api/vault/asset-holder"
echo ""

echo "=== Step 9: Test WebSocket handshake ==="
# Test basic ws upgrade
curl -s -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: http://localhost:1234" \
  "$BASE/ws" 2>&1 | head -20
echo ""

echo "=== Done ==="
