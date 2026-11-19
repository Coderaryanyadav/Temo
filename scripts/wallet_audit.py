import json
import sys
import os
import getpass
import urllib.request
import urllib.error
from datetime import datetime

BASE = "https://sapi.knotnow.co"

def request(path, token):
    url = BASE + path
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Origin": "https://knotnow.co",
            "Referer": "https://knotnow.co/",
            "operatingSystem": "web",
            "x-version": "1.2.6+00"
        },
        method="GET"
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
            print(f"\n[{response.status}] GET {path}")
            try:
                print(json.dumps(json.loads(body), indent=2))
            except json.JSONDecodeError:
                print(body[:5000])
    except urllib.error.HTTPError as e:
        print(f"\n[HTTP {e.code}] GET {path}")
        print(e.read().decode("utf-8", errors="replace")[:2000])
    except Exception as e:
        print(f"\n[ERROR] {path}: {e}")

def main():
    print("KNOT Wallet Read-Only Audit")
    print("Target:", BASE)
    print("Time:", datetime.now().isoformat(timespec="seconds"))
    print("\nNo payment or wallet mutation requests will be sent.")

    token = os.getenv("KNOT_ACCESS_TOKEN", "").strip()
    if not token:
        if not sys.stdin.isatty():
            token = sys.stdin.readline().strip()
        else:
            token = getpass.getpass("\nPaste your own access token (hidden): ").strip()

    if not token:
        print("No token supplied. Exiting.")
        return

    for path in ["/gift-cards/wallet", "/gift-cards"]:
        request(path, token)

    print("\nAudit complete. No wallet changes were made.")

if __name__ == "__main__":
    main()
