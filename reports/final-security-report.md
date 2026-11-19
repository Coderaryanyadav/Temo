# KNOT Website – Full-Scope Authorized Security Assessment & QA Audit

**Target Properties**:
- Primary Web Application: `https://knotnow.co`
- Backend API Service: `https://sapi.knotnow.co`
- Workspace: `/Users/aryan/KNOT-Security`

**Lead Auditor**: Senior Application Security Engineer & QA Specialist  
**Authorization**: Authorized Black-Box Security Audit & Defensive Code Review  
**Date of Audit**: November 19, 2026  
**Document Classification**: Confidential – Security Audit Deliverable  

---

## 1. Executive Summary

An authorized, evidence-based security assessment and architectural quality audit was conducted on the **KNOT** application and its supporting APIs.

### The Core Audit Question:
> **"Can an unauthorized person access another user's information, manipulate orders, or add money to a wallet without a legitimate payment?"**

Based on verified static code analysis, live non-destructive network interaction, and architectural review, the concrete answers are:

1. **Accessing Another User's Information (Orders, Addresses, Profile)**:
   - **List Endpoints**: Safe. Endpoints like `GET /orders/all`, `GET /orders/active`, and `GET /user/profile/` do not accept user IDs in parameters; they query strictly by the authenticated JWT session token.
   - **Direct Object Endpoints (BOLA / IDOR Potential)**: **High Risk**. Endpoints `GET /orders/order/{id}`, `POST /orders/order_updt`, and `GET /user_address/loc_page_data?address_id={id}` rely on object IDs in the URL path or body. If the backend fails to verify `resource.user_id == session.user_id`, unauthorized cross-account access is possible. Because only one account was authorized on production, cross-account access cannot be confirmed on production without accessing other customers' data (which is prohibited). A two-account staging test is documented in [unverified-tests.md](file:///Users/aryan/KNOT-Security/reports/unverified-tests.md) to conclusively verify this.
2. **Manipulating Orders or Cancelling Other Users' Orders**:
   - `POST /orders/order_updt` accepts `order_id`, `slot_picked`, and `cancel`. If backend authorization checks are absent, order state manipulation is possible via IDOR. Unauthenticated manipulation is mitigated by edge WAF and session requirements.
3. **Adding Money to a Wallet Without Legitimate Payment**:
   - **Direct Balance Manipulation**: Not possible. The client cannot send arbitrary balance numbers. Balances are derived from transaction ledgers (`GET /gift-cards/wallet`).
   - **Payment Verification Logic**: In the wallet recharge flow, the client calls `POST /gift-cards/txn/verify` passing only `{"order_id": "<id>"}` without transmitting the Razorpay cryptographic HMAC signature. If the backend fails to independently verify payment status with Razorpay (`GET https://api.razorpay.com/v1/orders/{order_id}` and check `status == "paid"`), an uncompleted order ID could improperly credit the wallet. Full verification with test keys is required in a sandbox environment.
4. **Credential and Session Security**:
   - **Critical Vulnerability**: The backend API (`sapi.knotnow.co`) features a misconfigured CORS policy that reflects **any arbitrary Origin** while sending `Access-Control-Allow-Credentials: true`.
   - **Information Exposure**: Access tokens and refresh tokens are printed in plaintext to the browser console and sent into telemetry logs during initialization and updates via `TokensStorage`.
   - **Frontend Framing**: The web application lacks `Content-Security-Policy` and `X-Frame-Options`, leaving it vulnerable to Clickjacking.

---

## 2. Application Architecture & Technology Stack

```
   [User Browser / Mobile Web]
         │
         ├─── TLS (DigiCert RSA / HTTP/2)
         ▼
   [Azure Front Door / Edge WAF] (150.171.110.100)
         │  - Enforces HSTS (31556926s, preload)
         │  - Edge WAF blocks unauthenticated scanner paths (HTTP 429)
         ▼
   [Flutter Web Frontend Engine]
         │  - Server-Driven UI (SDUI) component rendering
         │  - LocalStorage token persistence (`flutter.accessToken`, `flutter.refreshToken`)
         │  - Third-party SDKs: Razorpay Checkout, Google Maps, Sentry, Amplitude, Branch.io
         ▼
   [KNOT API Backend] (sapi.knotnow.co)
         │  - RESTful JSON endpoints with custom payload compression (`gzip`)
         │  - JWT Bearer Authentication (`/verificationrefresh` token rotation)
         │  - CORS middleware dynamically reflecting Origin
         ▼
   [External Payment Services]
         └── Razorpay Gateway (`checkout.razorpay.com`)
```

### Discovered Infrastructure & Tech Details:
- **Frontend**: Flutter Web (compiled to JavaScript via `dart2js`), utilizing a Server-Driven UI (SDUI) model where backend JSON payloads define screens, components, and on-click API actions.
- **Edge / CDN**: Microsoft Azure Front Door with global Anycast routing, Azure DNS, and Web Application Firewall (WAF).
- **Authentication**: JWT Bearer tokens containing `user_id` and session identifier (`s_id`), rotated via `POST /verificationrefresh`.
- **Payment Gateway**: Razorpay web integration via `checkout.js` with client event bus (`payment.success`, `payment.error`).

---

## 3. Scope and Methodology

- **In-Scope Domains**: `https://knotnow.co`, `https://sapi.knotnow.co`
- **Methodology**:
  - Non-invasive network reconnaissance (DNS, TLS, HTTP headers, CORS preflight).
  - Reverse engineering and static code auditing of `reports/flutter/main.dart.js` (10.1 MB) and `local_storage_bridge.js`.
  - Endpoint discovery and input parameter modeling.
  - Safe, read-only unauthenticated API probing (observing WAF status codes and response headers).
- **Constraints Maintained**:
  - Zero denial-of-service, brute-force, or automated fuzzing.
  - Zero live financial transactions initiated.
  - Zero customer data accessed; zero IDs guessed.
  - No secrets or personal credentials exposed in logs or reports.

---

## 4. Confirmed Security Vulnerabilities

### FINDING-01: Insecure CORS Policy Reflecting Arbitrary Origins with Credentials
- **Severity**: **High**
- **CVSS 4.0**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N` (Score: 7.1)
- **Affected Component**: `https://sapi.knotnow.co` (CORS Middleware / Preflight Handler)
- **Description**:
  When an `OPTIONS` preflight request is sent with an untrusted `Origin` header (such as `https://evil.com`), the server echoes back the untrusted origin in `Access-Control-Allow-Origin` and concurrently responds with `Access-Control-Allow-Credentials: true`.
- **Evidence**:
  ```http
  OPTIONS /user/profile/ HTTP/2
  Host: sapi.knotnow.co
  Origin: https://evil.com
  Access-Control-Request-Method: GET
  Access-Control-Request-Headers: authorization

  HTTP/2 200
  access-control-allow-origin: https://evil.com
  access-control-allow-credentials: true
  access-control-allow-headers: authorization
  access-control-allow-methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT
  vary: Origin
  ```
- **Security Impact**:
  An attacker hosting a malicious website can issue cross-origin requests to `sapi.knotnow.co` from a victim's browser and read sensitive API responses.
- **Remediation**:
  Maintain a strict whitelist containing only `https://knotnow.co` and `https://www.knotnow.co`. Reject or omit `Access-Control-Allow-Origin` for any other domain.

---

### FINDING-02: Plaintext JWT Tokens Logged to Console and External Telemetry
- **Severity**: **Medium**
- **CVSS 4.0**: `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (Score: 5.1)
- **Affected Component**: [main.dart.js](file:///Users/aryan/KNOT-Security/reports/flutter/main.dart.js) (`TokensStorage` / `A.cY`)
- **Description**:
  In compiled JavaScript (lines around pos 995750 and 6317041), the application logs the full access token and refresh token:
  ```javascript
  A.cY(null, !1, null, !0, "Updated access token: " + a, null, t.WO);
  A.cY(null, !1, null, !0, "Initialized access token: " + A.d(A.a9d()), null, t.WO);
  A.cY(null, !1, null, !0, "Updated refresh token: " + a, null, t.WO);
  ```
  The function `A.cY` packages these messages into breadcrumb events and forwards them via `A.b_6` to external error monitoring (Sentry).
- **Security Impact**:
  Session credentials are permanently visible in browser developer tools and transmitted to third-party logging platforms, where unauthorized personnel or compromised accounts could extract them.
- **Remediation**:
  Remove raw token concatenation from logging statements. Log only status events (e.g., `"Access token refreshed"`).

---

### FINDING-03: Missing Essential HTTP Security Headers (CSP, Frame-Options, Sniffing)
- **Severity**: **Medium**
- **CVSS 4.0**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N` (Score: 5.3)
- **Affected Component**: `https://knotnow.co` (Azure Front Door Edge)
- **Description**:
  The web response contains no `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, or `Permissions-Policy`.
- **Security Impact**:
  1. **Clickjacking**: The website can be rendered inside a transparent `<iframe>` on an attacker's domain to deceive users into triggering orders or cancellations.
  2. **Unrestricted Script Execution**: Absence of CSP removes the primary defense-in-depth barrier against Cross-Site Scripting (XSS).
- **Remediation**:
  Deploy response header rules on Azure Front Door:
  - `Content-Security-Policy: frame-ancestors 'self';`
  - `X-Frame-Options: SAMEORIGIN`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`

---

### FINDING-04: Global Exposure of `LocalStorageBridge.debug()` Utility
- **Severity**: **Low**
- **CVSS 4.0**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` (Score: 4.3)
- **Affected Component**: [local_storage_bridge.js](file:///Users/aryan/KNOT-Security/reports/flutter/local_storage_bridge.js#L84-L106)
- **Description**:
  The utility attaches `window.LocalStorageBridge` globally with a `debug()` method that dumps all localStorage keys and values to the console:
  ```javascript
  static debug(key = null) {
    console.log({
      keys: Object.keys(localStorage),
      contents: Object.fromEntries(
        Object.keys(localStorage).map((k) => [k, localStorage.getItem(k)])
      ),
    });
  }
  ```
- **Remediation**:
  Strip or disable the `debug()` method in production bundles.

---

## 5. Potential & Unverified Architectural Risks

### 5.1 Broken Object Level Authorization (BOLA / IDOR)
- **Affected Endpoints**:
  - `GET /orders/order/{id}`
  - `POST /orders/order_updt` (`order_id`)
  - `GET /user_address/loc_page_data?address_id={id}`
- **Evaluation**:
  These endpoints take direct database/entity IDs. If backend database queries do not constrain by `user_id = :auth_user_id`, account isolation fails.
- **Verification Status**: **Unverified on production** (requires two accounts). Staging verification procedure is outlined in [unverified-tests.md](file:///Users/aryan/KNOT-Security/reports/unverified-tests.md).

### 5.2 Payment Verification Server-to-Server Integrity
- **Affected Endpoint**: `POST /gift-cards/txn/verify`
- **Evaluation**:
  The client submits `{"order_id": "<id>"}` upon Razorpay completion. It does not supply `razorpay_signature` in this call.
- **Requirement**:
  The backend must query Razorpay's API server-to-server (`GET /v1/orders/{order_id}`) and verify that `status == 'paid'` before updating the wallet ledger. If this check is missing, unpaid order IDs could result in fraudulent wallet crediting. Must be verified in the Razorpay sandbox.

---

## 6. Audit Deliverables Index

The complete audit findings and documentation are stored in the following project artifacts:
1. [final-security-report.md](file:///Users/aryan/KNOT-Security/reports/final-security-report.md) – Comprehensive master assessment report (this file).
2. [findings.csv](file:///Users/aryan/KNOT-Security/reports/findings.csv) – Machine-readable spreadsheet of all vulnerabilities with CVSS 4.0 ratings.
3. [tested-endpoints.md](file:///Users/aryan/KNOT-Security/reports/tested-endpoints.md) – Inventory of analyzed API routes and parameters.
4. [security-recommendations.md](file:///Users/aryan/KNOT-Security/reports/security-recommendations.md) – Concrete remediation plan with code examples.
5. [payment-security-review.md](file:///Users/aryan/KNOT-Security/reports/payment-security-review.md) – Deep dive into payment flows, Razorpay integration, and wallet security.
6. [unverified-tests.md](file:///Users/aryan/KNOT-Security/reports/unverified-tests.md) – Detailed protocols for two-account testing in staging/sandbox.

---

## 7. Final Conclusion

The KNOT application exhibits solid architectural foundations:
- **Server-Driven UI** isolates core business decisions from client manipulation.
- **Azure Front Door Edge WAF** actively mitigates external port scanning, automated path crawlers, and unauthenticated reconnaissance.
- **HTTPS & HSTS** are strictly enforced with valid TLS certificates.
- **Wallet balances** are maintained as server-side ledgers rather than client-submitted numbers.

However, immediate remediation is required for **Cross-Origin Resource Sharing (CORS)** reflection, **token leakage in client logging**, **missing HTTP security headers**, and formal verification of **server-side BOLA checks** and **Razorpay payment verification**. Implementing the remediation plan in [security-recommendations.md](file:///Users/aryan/KNOT-Security/reports/security-recommendations.md) will elevate the platform to industry-standard application security before full-scale production rollout.
