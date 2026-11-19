#!/bin/bash
set -euo pipefail

TARGET="https://knotnow.co"
DOMAIN="knotnow.co"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$ROOT/reports" "$ROOT/logs"

echo "Starting passive KNOT reconnaissance..."

{
    echo "KNOT SECURITY ASSESSMENT"
    echo "Date: $(date)"
    echo "Target: $TARGET"
    echo
} > "$ROOT/reports/initial-report.txt"

echo "[1] HTTP headers"

curl -sS -I --max-time 15 "$TARGET" \
    > "$ROOT/reports/http-headers.txt" || true

echo "[2] DNS records"

{
    echo "A records:"
    dig "$DOMAIN" A +short
    echo
    echo "AAAA records:"
    dig "$DOMAIN" AAAA +short
    echo
    echo "Nameservers:"
    dig "$DOMAIN" NS +short
    echo
    echo "MX records:"
    dig "$DOMAIN" MX +short
} > "$ROOT/reports/dns-records.txt"

echo "[3] TLS certificate"

if command -v openssl >/dev/null 2>&1; then
    timeout_cmd=""
    if command -v gtimeout >/dev/null 2>&1; then
        timeout_cmd="gtimeout 15"
    fi

    $timeout_cmd openssl s_client \
        -connect "$DOMAIN:443" \
        -servername "$DOMAIN" </dev/null 2>/dev/null |
        openssl x509 -noout -subject -issuer -dates \
        > "$ROOT/reports/tls-certificate.txt" || true
fi

echo "[4] Public robots.txt"

curl -sS --max-time 15 "$TARGET/robots.txt" \
    -o "$ROOT/reports/robots.txt" || true

echo "[5] Public sitemap.xml"

curl -sS --max-time 15 "$TARGET/sitemap.xml" \
    -o "$ROOT/reports/sitemap.xml" || true

echo "[6] HTTP security header summary"

python3 - "$ROOT/reports/http-headers.txt" \
    > "$ROOT/reports/security-header-summary.txt" <<'PY'
import sys

path = sys.argv[1]
wanted = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy"
]

headers = {}
with open(path, errors="replace") as f:
    for line in f:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

for name in wanted:
    print(f"{name}: {headers.get(name, 'Not observed')}")
PY

echo "[7] Generate report"

{
    echo
    echo "Files generated:"
    find "$ROOT/reports" -maxdepth 1 -type f -print
    echo
    echo "Initial passive checks completed."
    echo "Findings require manual verification."
} >> "$ROOT/reports/initial-report.txt"

echo "Reconnaissance completed."
