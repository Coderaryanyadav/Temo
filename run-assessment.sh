#!/bin/bash
set -euo pipefail

BASE="$PWD"
OUT="$BASE/reports/full-assessment"
JS="$BASE/reports/flutter/main.dart.js"

mkdir -p "$OUT"

echo "=========================================="
echo " KNOT SECURITY ASSESSMENT"
echo "=========================================="

if [ ! -f "$JS" ]; then
  echo "ERROR: Flutter bundle not found: $JS"
  exit 1
fi

echo "[1/6] Collecting public API information..."

curl -sS --max-time 20 \
  -D "$OUT/api-headers.txt" \
  -o "$OUT/api-response.json" \
  https://sapi.knotnow.co/ || true

echo "[2/6] Extracting API endpoint references..."

python3 - <<'PY'
from pathlib import Path
import re

root = Path.cwd()
jsfile = root / "reports/flutter/main.dart.js"
out = root / "reports/full-assessment"

data = jsfile.read_text(errors="replace")

pattern = re.compile(
    r'["\'](/(?:orders|order|user|user_address|'
    r'gift-cards|gift_card|payments|payment|refund|'
    r'cart|cancel_order|add_new_bank_account)[^"\']*)["\']'
)

routes = sorted(set(pattern.findall(data)))

(out / "endpoint-references.txt").write_text(
    "\n".join(routes) + "\n"
)

print(f"Found {len(routes)} unique endpoint references.")
PY

echo "[3/6] Extracting endpoint contexts..."

python3 - <<'PY'
from pathlib import Path

root = Path.cwd()
data = (root / "reports/flutter/main.dart.js").read_text(errors="replace")
routes = (root / "reports/full-assessment/endpoint-references.txt").read_text().splitlines()
out = root / "reports/full-assessment/endpoint-contexts.txt"

keywords = [
    "endpoint", "request_type", "body", "params",
    "Authorization", "order_id", "address_id",
    "user_id", "wallet", "bank", "refund"
]

with out.open("w") as f:
    for route in routes:
        positions = []
        start = 0

        while len(positions) < 4:
            pos = data.find(route, start)
            if pos < 0:
                break
            positions.append(pos)
            start = pos + len(route)

        for pos in positions:
            context = data[max(0, pos-500):pos+900]
            if any(k.lower() in context.lower() for k in keywords):
                f.write("\n" + "="*75 + "\n")
                f.write("ENDPOINT: " + route + "\n")
                f.write(context + "\n")

print("Endpoint contexts saved.")
PY

echo "[4/6] Generating security review checklist..."

cat > "$OUT/security-checklist.txt" <<'EOF'
KNOT SECURITY REVIEW

AUTHENTICATION
[ ] API rejects unauthenticated requests to private endpoints.
[ ] Expired sessions are rejected.
[ ] Logout invalidates the session.
[ ] Refresh-token handling is secure.

AUTHORIZATION / BOLA / IDOR
[ ] Order IDs are checked against authenticated account ownership.
[ ] Address IDs are checked against authenticated account ownership.
[ ] Profile data is restricted to the authenticated account.
[ ] Gift-card wallet data is restricted to the authenticated account.
[ ] Refund details are restricted to the order owner.
[ ] Bank account information is restricted to the account owner.

FINANCIAL SECURITY
[ ] Wallet balance is calculated server-side.
[ ] Gift-card balance cannot be changed by client-side values.
[ ] Refund ownership and eligibility are checked server-side.
[ ] Payment amount is validated server-side.
[ ] Bank-account ownership is verified server-side.

SESSION / DATA SECURITY
[ ] Tokens are not exposed in logs.
[ ] Sensitive API responses are not publicly cached.
[ ] Sensitive responses have suitable Cache-Control headers.
[ ] CORS policy is restrictive.
[ ] No personal information is exposed in public API responses.

IMPORTANT:
A checkbox is not a finding until tested and evidenced.
Cross-account checks require two authorized test accounts.
Do not test real customer IDs or modify production financial data.
EOF

echo "[5/6] Creating endpoint classification..."

python3 - <<'PY'
from pathlib import Path

root = Path.cwd()
out = root / "reports/full-assessment"
routes = (out / "endpoint-references.txt").read_text().splitlines()

categories = {
    "ORDER / REFUND": ["order", "cancel_order", "refund"],
    "PROFILE / ACCOUNT": ["profile", "manage_acc", "logout"],
    "ADDRESS": ["address"],
    "WALLET / FINANCIAL": ["wallet", "payment", "bank", "gift-card"],
    "CART": ["cart"],
}

with (out / "classified-endpoints.txt").open("w") as f:
    for category, keywords in categories.items():
        f.write("\n" + "="*55 + "\n")
        f.write(category + "\n")
        f.write("="*55 + "\n")

        matches = [
            route for route in routes
            if any(word in route.lower() for word in keywords)
        ]

        for route in matches:
            f.write(route + "\n")

print("Classification complete.")
PY

echo "[6/6] Creating final report..."

cat > "$OUT/README.txt" <<EOF
KNOT SECURITY ASSESSMENT
Generated: $(date)

Target:
https://knotnow.co
https://sapi.knotnow.co

Files:
endpoint-references.txt
endpoint-contexts.txt
classified-endpoints.txt
security-checklist.txt
api-headers.txt
api-response.json

Scope:
Static frontend analysis and public API root inspection.

Limitations:
No cross-account access was attempted.
No customer data was accessed.
No financial transactions were performed.
No production records were modified.

A second authorized test identity is required to conclusively
test cross-account BOLA/IDOR behavior.
EOF

echo
echo "=========================================="
echo " ASSESSMENT COLLECTION COMPLETED"
echo "=========================================="
echo
echo "Report folder:"
echo "$OUT"
echo
echo "Files:"
ls -lh "$OUT"
echo
echo "Next: create a ZIP for sharing."
cd "$BASE"
zip -qr reports/full-assessment.zip reports/full-assessment
echo "Created: $BASE/reports/full-assessment.zip"
echo
echo "Send me the ZIP or the contents of:"
echo "$OUT/endpoint-contexts.txt"
