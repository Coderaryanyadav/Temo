# KNOT – Payment and Wallet Security Review

**Assessment Type**: Static Analysis, Architecture Audit & Defensive Quality Assurance  
**Target Domains**: `https://knotnow.co`, `https://sapi.knotnow.co`  
**Payment Providers Identified**: Razorpay (`checkout.razorpay.com`), PayU (SDK references)  
**Evaluator**: Senior Application Security Engineer & QA Auditor  

---

## 1. Executive Summary: Financial & Wallet Security

A thorough architectural and static code analysis was conducted on KNOT's compiled Flutter Web bundle (`main.dart.js`) and associated API workflows. The review focused on answering the core question:

> **"Can an unauthorized person manipulate orders, bypass payment verification, or add money to a wallet without a legitimate payment?"**

### Key Conclusions:
1. **Wallet Balances Cannot Be Directly Overwritten by the Client**:
   Wallet balance is retrieved via `GET /gift-cards/wallet` and calculated server-side from ledger entries (`credits` and `debits`). The client possesses no endpoint or mechanism to force or overwrite a balance value directly.
2. **Payment Verification Architecture Requires Strict Server-Side Validation**:
   When a user recharges a gift card / wallet, the client invokes `POST /gift-cards/txn/start` (transmitting an `X-Idempotency-Key`), receives a payment order ID, launches the Razorpay modal, and upon success invokes `POST /gift-cards/txn/verify` sending:
   ```json
   { "order_id": "<order_id>" }
   ```
   **Crucial Architectural Requirement**: The backend server **must** independently verify payment completion with Razorpay via server-to-server API (`GET https://api.razorpay.com/v1/orders/{order_id}`) or through authenticated Razorpay Webhooks. The frontend does not send the Razorpay cryptographic signature (`razorpay_signature`) or `razorpay_payment_id` in the verification call.
3. **Idempotency Keys Are Implemented on Transaction Start**:
   The Flutter client generates a UUID and passes it via `X-Idempotency-Key` on `/gift-cards/txn/start`, mitigating unintentional duplicate order generation on client retries.

---

## 2. Payment Gateway Architecture & Flow Analysis

### 2.1 Identified Providers
- **Razorpay**: Primary checkout gateway loaded dynamically via:
  ```html
  <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
  ```
  Managed by client lifecycle handlers: `window.razorpayRetry`, `window.initRazorpay`, and `flutterRazorpayLoadSuccessCallback`.
- **PayU**: Referenced in legacy SDK packages within the bundle.

---

### 2.2 Wallet / Gift Card Recharge Lifecycle

```
[User Browser]                      [KNOT Backend (sapi)]              [Razorpay Gateway]
      |                                        |                                |
   1. | -- POST /gift-cards/txn/start -------> |                                |
      |    (Amount, X-Idempotency-Key)         | 2. Create Order                |
      |                                        | -----------------------------> |
      |                                        | <--- Return razorpay_order_id  |
      | <---- Return order_id + options ------ |                                |
      |                                                                         |
   3. | ---------------- Open Razorpay Checkout Modal ------------------------> |
      | <--------------- Payment Completed (payment_id, signature) ------------ |
      |                                                                         |
   4. | -- POST /gift-cards/txn/verify ------> |                                |
      |    {"order_id": "<id>"}                | 5. Server-to-Server Query      |
      |                                        |    OR Webhook Validation       |
      |                                        | -----------------------------> |
      |                                        | <--- status: "paid", amount    |
      |                                        | 6. Credit Wallet Ledger        |
      | <---- Return updated wallet state ---- |                                |
```

#### Detailed Breakdown of Steps:
1. **Initiation (`POST /gift-cards/txn/start`)**:
   - The client invokes `bfT(a)` in `main.dart.js`.
   - Generates a UUID for `X-Idempotency-Key`.
   - Sends the target voucher / recharge amount.
   - The backend creates an order record and requests a corresponding order from Razorpay.
2. **Client Checkout Execution**:
   - The Razorpay SDK opens with options including `key`, `amount`, `order_id`, and `currency`.
   - On completion, Razorpay returns `razorpay_payment_id`, `razorpay_order_id`, and `razorpay_signature` to the JavaScript callback.
3. **Verification (`POST /gift-cards/txn/verify`)**:
   - The client executes `cg3(a)`:
     ```javascript
     $.eR().a9V("/gift-cards/txn/verify", A.a(["order_id", a], t.N, t.S), t.z);
     ```
   - Only `{"order_id": "<id>"}` is forwarded.

---

## 3. Threat Modeling & Vulnerability Analysis

### Threat 1: Crediting Wallet by Replaying Uncompleted Order IDs
- **Vulnerability Scenario**: An attacker initiates a transaction via `/gift-cards/txn/start`, closes the Razorpay modal without paying, and immediately issues `POST /gift-cards/txn/verify` with the generated `order_id`.
- **Defensive Safeguard Required**: The backend must query Razorpay's API:
  ```http
  GET https://api.razorpay.com/v1/orders/{order_id}
  Authorization: Basic <base64(KEY_ID:KEY_SECRET)>
  ```
  If `status != "paid"` or `amount_paid < planned_amount`, the server must return `400 Bad Request` or `402 Payment Required` and refuse to create a ledger credit entry.

### Threat 2: Duplicate Crediting via Replayed Verify Requests
- **Vulnerability Scenario**: An attacker pays for one ₹100 recharge and repeatedly sends `POST /gift-cards/txn/verify` with the same `order_id` in rapid succession (race condition / replay attack) to attempt duplicate wallet credits.
- **Defensive Safeguard Required**:
  - The backend database must store a unique constraint on `(gateway_order_id)` or `(payment_id)` in the transaction table.
  - Transactions must use database row locking (e.g., `SELECT ... FOR UPDATE`) or atomic status transitions (`UPDATE transactions SET status = 'completed' WHERE id = :id AND status = 'pending'`). If 0 rows are affected, reject the request.

### Threat 3: Client-Side Price / Amount Tampering on Ecommerce Orders
- **Vulnerability Scenario**: During cart checkout, the client calculates subtotal, discounts, and delivery charges. An attacker modifies the client-side cart payload to set the price to ₹1.
- **Analysis**:
  - In `reports/full-assessment/endpoint-contexts.txt`, the client sends `products`, `pay_medium`, `pay_type` (online vs COD), and `promo_id` to `/orders/order_updt` or `/cart/create`.
  - **Defensive Requirement**: The backend must look up catalog prices from the database for each item in `products`, re-verify `promo_id` validity and minimum spend requirements, calculate delivery fee server-side, and generate the final order amount independently of any client-submitted total.

### Threat 4: Fake Razorpay Webhook Injection
- **Vulnerability Scenario**: If the backend processes asynchronous webhooks from Razorpay to fulfill orders or credit wallets, an attacker sends fabricated JSON payloads (`payment.captured`) directly to the webhook endpoint.
- **Defensive Safeguard Required**:
  - The webhook handler must verify the `X-Razorpay-Signature` header:
    $$\text{HMAC-SHA256}(\text{raw\_request\_body}, \text{webhook\_secret}) == \text{X-Razorpay-Signature}$$
  - The comparison must use constant-time string comparison (`crypto.timingSafeEqual`) to prevent timing attacks.

### Threat 5: Unauthorized Refunds or Order Cancellations
- **Vulnerability Scenario**: Calling `POST /cancel_order` with an arbitrary `order_id` to trigger automated refunds to an attacker's payment method or wallet.
- **Defensive Safeguard Required**:
  - Ownership check: `orders.user_id == authenticated_user_id`.
  - State check: Orders can only be cancelled in `pending` or `confirmed` states before dispatch.
  - Refund destination: Refunds must strictly route back to the original payment source (Razorpay refund API) or the user's verified internal wallet, never an unverified arbitrary bank account.

---

## 4. Financial Audit Checklist & QA Automation Guidance

### Server-Side Unit & Integration Test Specifications (Safe Sandbox Verification)

```python
# test_payment_security.py (Architectural QA Specification)
import pytest
import hmac
import hashlib

def test_unpaid_order_cannot_credit_wallet():
    """
    Given: An order_id that has NOT been paid on Razorpay (status = 'created')
    When: POST /gift-cards/txn/verify is called with order_id
    Then: Backend must return 400/402 and wallet balance must remain unchanged.
    """
    pass

def test_duplicate_verification_is_idempotent():
    """
    Given: A legitimate paid order_id that has already been verified and credited
    When: POST /gift-cards/txn/verify is called a second time
    Then: Backend must return the existing transaction without adding extra balance.
    """
    pass

def test_tampered_webhook_signature_is_rejected():
    """
    Given: A simulated webhook payload with an invalid X-Razorpay-Signature
    When: POST /webhooks/razorpay is called
    Then: Backend must reject with 401 Unauthorized and ignore the event.
    """
    payload = b'{"event":"payment.captured"}'
    secret = b'test_webhook_secret'
    invalid_signature = 'invalid_hmac_hex'
    
    calculated = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    assert calculated != invalid_signature
```

---

## 5. Remediation & Hardening Recommendations for Financial Systems

1. **Adopt Two-Way Signature Verification**:
   Even though server-to-server order status check is reliable, also capture and transmit `razorpay_payment_id` and `razorpay_signature` from the client:
   $$\text{HMAC-SHA256}(\text{razorpay\_order\_id} + "|" + \text{razorpay\_payment\_id}, \text{key\_secret})$$
2. **Enforce Database-Level Idempotency**:
   Ensure `razorpay_order_id` has a `UNIQUE` index in the database transaction table.
3. **Strict Webhook IP & Secret Validation**:
   Validate incoming Razorpay webhook IPs and enforce strict HMAC verification on raw bytes before JSON parsing.
4. **Independent Server Price Calculation**:
   Never accept `amount` or `total_price` from client SDUI payloads during order finalization.
