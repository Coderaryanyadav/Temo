#!/bin/bash

set -euo pipefail

BASE_URL="${KNOT_STAGING_API:-}"
ORDER_ID="${TEST_ORDER_ID:-}"
TOKEN="${KNOT_TEST_TOKEN:-}"

if [[ -z "$BASE_URL" || -z "$ORDER_ID" || -z "$TOKEN" ]]; then
    echo "Missing required staging configuration."
    echo "Set KNOT_STAGING_API, TEST_ORDER_ID and KNOT_TEST_TOKEN."
    exit 1
fi

if [[ "$BASE_URL" != https://* ]]; then
    echo "HTTPS is required."
    exit 1
fi

if [[ "$BASE_URL" == *sapi.knotnow.co* ]]; then
    echo "Live production API is not permitted for this test."
    exit 1
fi

echo "Testing verification behaviour in staging."
echo "Endpoint: $BASE_URL/gift-cards/txn/verify"
echo "Order ID: [REDACTED]"

HTTP_CODE=$(
    curl -sS \
        --max-time 20 \
        -o /tmp/knot-wallet-response.json \
        -w "%{http_code}" \
        -X POST "$BASE_URL/gift-cards/txn/verify" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"order_id\":\"$ORDER_ID\"}"
)

echo "HTTP status: $HTTP_CODE"
echo "Response:"
jq 'del(.access_token, .refresh_token, .token)' \
    /tmp/knot-wallet-response.json 2>/dev/null \
    || echo "Response is not valid JSON."

echo
echo "IMPORTANT: An HTTP success response alone does not prove a wallet credit."
echo "Compare the test wallet ledger before and after this request."
