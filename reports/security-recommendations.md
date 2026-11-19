# KNOT – Security Recommendations and Remediation Plan

This guide provides concrete, actionable remediation steps for developers and systems administrators to resolve the security vulnerabilities and architectural risks identified during the KNOT assessment.

---

## 1. Prioritized Remediation Matrix

| Priority | Finding ID | Focus Area | Impact | Remediation Effort |
|---|---|---|---|---|
| **P0 (Immediate)** | FINDING-01 | Fix Permissive CORS Reflection on API | Prevents cross-origin data theft and unauthorized API calls from external sites. | Low (Config change) |
| **P0 (Immediate)** | FINDING-07 | Validate Razorpay Payments Server-to-Server | Guarantees that wallet balance cannot be credited without verified funds. | Medium (Backend API logic) |
| **P1 (High)** | FINDING-05 / FINDING-06 | Enforce Server-Side BOLA / IDOR Ownership Checks | Protects customer order histories, item details, and home addresses. | Medium (Query / Middleware) |
| **P1 (High)** | FINDING-03 | Deploy Essential HTTP Security Headers (CSP, Frame-Options) | Prevents clickjacking and mitigates frontend script injection / XSS. | Low (CDN / Header rule) |
| **P2 (Medium)** | FINDING-02 | Strip Plaintext Token Logging in Production | Eliminates token leaks to browser console and external telemetry/Sentry. | Low (Dart code cleanup) |
| **P2 (Medium)** | FINDING-04 | Remove `LocalStorageBridge.debug()` from Production | Eliminates trivial client storage dumping capability via console/scripts. | Low (JS file cleanup) |
| **P3 (Hardening)**| FINDING-08 | Transition from localStorage to `HttpOnly` Cookies | Protects session tokens from theft in the event of client-side DOM injection. | High (Architectural change) |

---

## 2. Detailed Technical Remediation Instructions

### 2.1 Remediate Insecure CORS (FINDING-01)
- **Current Vulnerability**: The API server echoes back whatever `Origin` is passed in the request and sets `Access-Control-Allow-Credentials: true`.
- **Target Architecture**: Restrict allowed origins strictly to the official production frontend and trusted staging origins. Never dynamically reflect arbitrary origins when credentials are supported.

#### Recommended Implementation:
```python
# FastAPI / Starlette / Python Example
from fastapi.middleware.cors import CORSMiddleware

ALLOWED_ORIGINS = [
    "https://knotnow.co",
    "https://www.knotnow.co",
    "https://staging.knotnow.co",  # If applicable
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "x-version", "x-device-id", "x-address-id"],
    expose_headers=["server_timestamp", "x-azure-ref"],
    max_age=600,
)
```

```javascript
// Express.js / Node.js Example
const cors = require('cors');

const allowedOrigins = [
  'https://knotnow.co',
  'https://www.knotnow.co'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS policy'));
    }
  },
  credentials: true
}));
```

---

### 2.2 Secure Payment & Wallet Verification (FINDING-07)
- **Current Vulnerability**: Client issues `POST /gift-cards/txn/verify` passing only `{"order_id": "<id>"}`.
- **Target Architecture**:
  1. Capture `razorpay_payment_id`, `razorpay_order_id`, and `razorpay_signature` in the frontend callback.
  2. Send all three parameters to `/gift-cards/txn/verify`.
  3. Validate HMAC-SHA256 signature on the server:
     $$\text{HMAC-SHA256}(\text{order\_id} + "|" + \text{payment\_id}, \text{RAZORPAY\_KEY\_SECRET}) == \text{signature}$$
  4. Perform server-to-server inquiry against Razorpay API to confirm `order.status == 'paid'` and `order.amount_paid == transaction.expected_amount`.
  5. Use atomic database transactions with unique constraints on `order_id` to prevent duplicate crediting.

#### Server-Side Verification Logic:
```python
import hmac
import hashlib
import requests
from django.db import transaction

def verify_and_credit_wallet(user_id, razorpay_order_id, razorpay_payment_id, razorpay_signature):
    # 1. Verify cryptographic signature
    generated_signature = hmac.new(
        key=settings.RAZORPAY_KEY_SECRET.encode(),
        msg=f"{razorpay_order_id}|{razorpay_payment_id}".encode(),
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(generated_signature, razorpay_signature):
        raise SecurityException("Invalid Razorpay payment signature.")

    # 2. Query Razorpay API directly
    resp = requests.get(
        f"https://api.razorpay.com/v1/orders/{razorpay_order_id}",
        auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET),
        timeout=10
    )
    order_data = resp.json()
    if order_data.get("status") != "paid":
        raise SecurityException("Order has not been marked as paid by payment gateway.")

    # 3. Atomic database credit with idempotency check
    with transaction.atomic():
        txn = WalletTransaction.objects.select_for_update().get(
            gateway_order_id=razorpay_order_id,
            user_id=user_id,
            status="PENDING"
        )
        
        # Verify amount matches expected value in paise
        if order_data.get("amount_paid") < txn.amount_in_paise:
            raise SecurityException("Amount paid is less than transaction invoice.")

        txn.status = "COMPLETED"
        txn.gateway_payment_id = razorpay_payment_id
        txn.save()

        # Update user wallet ledger
        WalletLedger.objects.create(
            user_id=user_id,
            amount=txn.amount,
            type="CREDIT",
            reference_id=txn.id
        )
```

---

### 2.3 Enforce Server-Side BOLA / IDOR Authorization (FINDING-05 & FINDING-06)
- **Current Vulnerability**: `/orders/order/{id}`, `/orders/order_updt`, and `/user_address/loc_page_data?address_id={id}` rely on client-supplied IDs.
- **Target Architecture**: Every database query accessing a user-owned resource MUST filter by the authenticated user's ID extracted from the validated session/JWT.

#### Defensive Query Patterns:
```sql
-- Insecure: Allows IDOR
SELECT * FROM orders WHERE id = :order_id;

-- Secure: Enforces Object-Level Authorization
SELECT * FROM orders WHERE id = :order_id AND user_id = :authenticated_user_id;
```

```sql
-- Insecure: Allows address disclosure
SELECT * FROM user_addresses WHERE id = :address_id;

-- Secure: Enforces Object-Level Authorization
SELECT * FROM user_addresses WHERE id = :address_id AND user_id = :authenticated_user_id;
```

---

### 2.4 Deploy HTTP Security Headers on Azure Front Door / Web Host (FINDING-03)
Deploy the following headers on all responses from `knotnow.co`:

```http
# Prevent Clickjacking
Content-Security-Policy: frame-ancestors 'self';
X-Frame-Options: SAMEORIGIN

# Prevent MIME-Sniffing
X-Content-Type-Options: nosniff

# Control Referrer Information
Referrer-Policy: strict-origin-when-cross-origin

# Restrict Browser Hardware Features
Permissions-Policy: camera=(), microphone=(), geolocation=(self)

# Enforce HTTPS (already active, ensure preload remains valid)
Strict-Transport-Security: max-age=31556926; includeSubDomains; preload
```

#### Azure Front Door Rules Engine Configuration:
1. Navigate to **Front Door and CDN profiles** in Azure Portal.
2. Select your profile > **Rule sets**.
3. Add a rule:
   - **Condition**: If Request URL matches `*`
   - **Action**: Add Response Header:
     - `X-Content-Type-Options: nosniff`
     - `X-Frame-Options: SAMEORIGIN`
     - `Referrer-Policy: strict-origin-when-cross-origin`
     - `Permissions-Policy: camera=(), microphone=(), geolocation=(self)`
     - `Content-Security-Policy: default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self';`

---

### 2.5 Sanitize Client-Side Logging (FINDING-02 & FINDING-04)
1. **Remove Token Logs**:
   In `TokensStorage` (Dart source), remove `log()` or `print()` calls outputting token values:
   ```dart
   // Remove:
   // log("Updated access token: $token");
   // log("Initialized access token: $token");
   
   // Replace with non-sensitive lifecycle indicator:
   log("Access token updated successfully.");
   ```
2. **Remove `debug()` from `local_storage_bridge.js`**:
   Delete lines 84-106 of [local_storage_bridge.js](file:///Users/aryan/KNOT-Security/reports/flutter/local_storage_bridge.js#L84-L106) in production builds so `window.LocalStorageBridge.debug()` is not available.
