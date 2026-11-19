# KNOT – Unverified Tests and Two-Account Testing Procedures

**Document Purpose**: In accordance with the assessment constraints and production safety guidelines, tests that require multiple identities, state-changing destructive operations, or live financial transactions were intentionally withheld from execution against production.

This document details:
1. Every test that remains **Unverified** on production.
2. The exact prerequisites and environmental requirements to safely complete them.
3. Safe, step-by-step test procedures for two controlled accounts on staging or sandbox environments.

---

## 1. Inventory of Unverified Tests

| Test ID | Objective | Endpoint / Component | Why Unverified on Production | Environmental Prerequisite |
|---|---|---|---|---|
| **UV-01** | BOLA / IDOR on Order Retrieval | `GET /orders/order/{id}` | Only one authorized user account exists. Testing requires requesting an order ID belonging to a different customer, which is strictly prohibited on production. | Two controlled test accounts (User A & User B) on Staging or Dev. |
| **UV-02** | BOLA / IDOR on Order Modification / Slot Update | `POST /orders/order_updt` | Requires attempting to modify delivery slot or cancel an order owned by a separate user ID. Modifying production customer data is prohibited. | Two controlled test accounts on Staging. |
| **UV-03** | BOLA / IDOR on Saved Customer Addresses | `GET /user_address/loc_page_data?address_id={id}` | Querying arbitrary `address_id` values could expose another customer's physical home address and contact details. | Two controlled test accounts with saved addresses on Staging. |
| **UV-04** | BOLA / IDOR on Order Cancellation | `POST /cancel_order` | Cancelling real production customer orders is prohibited. | Two controlled test accounts on Staging. |
| **UV-05** | Live Payment Verification Bypass on Wallet Recharge | `POST /gift-cards/txn/verify` | Submitting unpaid or manipulated order IDs to production could corrupt financial ledger state or trigger gateway anti-fraud blocks. | Razorpay Sandbox / Test Mode environment. |
| **UV-06** | Race Condition / Duplicate Credit on Concurrent Verify | `POST /gift-cards/txn/verify` | Sending high-concurrency requests against live payment infrastructure violates safe testing rules. | Isolated local or staging environment with Razorpay test keys. |
| **UV-07** | Server-Side JWT Invalidation upon Logout | `GET /user/logout` | Verifying whether the backend invalidates access tokens before expiration requires testing token reuse across multiple server nodes. | Controlled test identity on staging. |
| **UV-08** | Insecure File Upload / Stored Polyglot Execution | `POST /upload_handler/profile` | Uploading non-standard binary test files could trigger CDN caching or permanent profile corruption. | Staging / QA environment. |

---

## 2. Safe Testing Procedures for Two Controlled Accounts

When a second test account (or isolated staging environment) is provisioned, execute the following non-destructive test procedures:

### Procedure A: BOLA / IDOR on Order Details (`GET /orders/order/{id}`)
- **Actors**:
  - **Account A (Attacker Role)**: Authenticated with `Token_A`
  - **Account B (Victim Role)**: Authenticated with `Token_B`, owns Order `#9001`
- **Execution Steps**:
  1. Log in as Account B. Place a test order or locate Account B's existing test order ID: `Order_ID_B`.
  2. Verify that Account B can retrieve the order:
     ```http
     GET /orders/order/Order_ID_B HTTP/1.1
     Host: sapi.knotnow.co
     Authorization: Bearer <Token_B>
     ```
     *Expected Response*: `200 OK` with order items and shipping details.
  3. Switch credentials to Account A. Issue the exact same request using `Token_A`:
     ```http
     GET /orders/order/Order_ID_B HTTP/1.1
     Host: sapi.knotnow.co
     Authorization: Bearer <Token_A>
     ```
- **Evaluation Criteria**:
  - **PASS (Secure)**: Server returns `403 Forbidden` or `404 Not Found`.
  - **FAIL (Vulnerable - BOLA/IDOR)**: Server returns `200 OK` containing Account B's order details.

---

### Procedure B: BOLA / IDOR on Saved Addresses (`GET /user_address/loc_page_data`)
- **Actors**:
  - **Account A**: Authenticated with `Token_A`
  - **Account B**: Authenticated with `Token_B`, owns Address `Address_ID_B = 1050`
- **Execution Steps**:
  1. As Account B, create a test address labeled `"Test Address B"`. Note the assigned `address_id`.
  2. As Account A, request Account B's address:
     ```http
     GET /user_address/loc_page_data?address_id=1050 HTTP/1.1
     Host: sapi.knotnow.co
     Authorization: Bearer <Token_A>
     ```
- **Evaluation Criteria**:
  - **PASS (Secure)**: Server returns `403 Forbidden` or empty data.
  - **FAIL (Vulnerable - BOLA/IDOR)**: Server returns `200 OK` containing Account B's street, apartment number, phone number, and location pin.

---

### Procedure C: BOLA / IDOR on Order Manipulation (`POST /orders/order_updt`)
- **Actors**:
  - **Account A**: Authenticated with `Token_A`
  - **Account B**: Owns pending test order `Order_ID_B`
- **Execution Steps**:
  1. As Account A, attempt to reschedule Account B's delivery slot:
     ```http
     POST /orders/order_updt HTTP/1.1
     Host: sapi.knotnow.co
     Authorization: Bearer <Token_A>
     Content-Type: application/json

     {
       "order_id": "<Order_ID_B>",
       "cancel": false,
       "slot_picked": ["16:00", "17:00"]
     }
     ```
- **Evaluation Criteria**:
  - **PASS (Secure)**: Server returns `403 Forbidden` or `400 Bad Request` ("Unauthorized order reference").
  - **FAIL (Vulnerable)**: Server returns `200 OK` and Account B's order slot is altered.

---

### Procedure D: Payment Verification Bypass (Razorpay Sandbox)
- **Environment**: Staging API connected to Razorpay Test Mode (`rzp_test_...`).
- **Execution Steps**:
  1. Call `POST /gift-cards/txn/start` to obtain a test `order_id` (e.g. `order_TEST_12345`).
  2. Without initiating or completing the payment in Razorpay (order remains in `created` status in Razorpay dashboard), issue the verification call:
     ```http
     POST /gift-cards/txn/verify HTTP/1.1
     Host: sapi-staging.knotnow.co
     Authorization: Bearer <Token_A>
     Content-Type: application/json

     {
       "order_id": "order_TEST_12345"
     }
     ```
  3. Check the response and the wallet balance via `GET /gift-cards/wallet`.
- **Evaluation Criteria**:
  - **PASS (Secure)**: Server returns `400 Bad Request` or `402 Payment Required` stating that the transaction is unpaid; wallet balance does NOT increase.
  - **FAIL (Vulnerable)**: Server credits the wallet balance without verifying Razorpay payment state.

---

### Procedure E: Session Revocation / Token Invalidation
- **Execution Steps**:
  1. Authenticate and obtain `Token_1`.
  2. Perform an authenticated request (`GET /user/profile/`) with `Token_1` and verify it succeeds (`200 OK`).
  3. Call `GET /user/logout` with `Token_1`.
  4. Immediately reissue `GET /user/profile/` with `Token_1`.
- **Evaluation Criteria**:
  - **PASS (Secure)**: Server rejects `Token_1` with `401 Unauthorized` (indicating the token was revoked or blacklisted on the server).
  - **PARTIAL / WARNING**: Server still accepts `Token_1` until its natural JWT `exp` timestamp elapses. In this case, ensure token lifespan is short ($\le 15$ minutes) and refresh tokens are strictly revoked.
