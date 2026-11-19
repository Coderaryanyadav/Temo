# KNOT – Automated Payment & Wallet QA Test Results

**Document Path**: `reports/full-assessment/qa-test-results.md`  
**Execution Script**: [test_payment_qa.py](file:///Users/aryan/KNOT-Security/scripts/test_payment_qa.py)  
**Execution Timestamp**: November 19, 2026  
**Auditor**: Senior Backend Security Engineer & Financial Systems QA Auditor  

---

## 1. Test Execution Summary

The automated QA test suite [test_payment_qa.py](file:///Users/aryan/KNOT-Security/scripts/test_payment_qa.py) was executed to validate the 10 core financial scenarios required to guarantee wallet ledger integrity, payment verification robustness, and anti-tampering protection.

### Overall Results:
- **Total Test Cases Executed**: 10
- **Passed**: 10
- **Failed**: 0
- **Blocked**: 0
- **Overall Evaluation**: **PASS (Architectural Specification Compliant)**

---

## 2. Test Execution Matrix

| Test ID | Test Scenario | Initial Balance | Final Balance | Delta | Result | Integrity Requirement Verified |
|---|---|---|---|---|---|---|
| **QA-PAY-01** | Unsuccessful / Failed Payment Verification | ₹1,000.00 | ₹1,000.00 | ₹0.00 | **PASS** | Unpaid or failed orders must never credit wallet balance. |
| **QA-PAY-02** | Pending Payment Verification | ₹1,000.00 | ₹1,000.00 | ₹0.00 | **PASS** | Incomplete/unsettled gateway orders must not credit balance. |
| **QA-PAY-03** | Legitimate Captured Payment Crediting | ₹1,000.00 | ₹1,500.00 | +₹500.00 | **PASS** | Fully settled payments must credit wallet balance exactly once. |
| **QA-PAY-04** | Payment Amount Tampering Validation | ₹1,000.00 | ₹1,000.00 | ₹0.00 | **PASS** | Underpaid transactions must be rejected; zero credit applied. |
| **QA-PAY-05** | Sequential Duplicate Verification Idempotency | ₹1,000.00 | ₹1,200.00 | +₹200.00 | **PASS** | Repeated verification of an already-credited order is idempotent. |
| **QA-PAY-06** | Concurrent Verification Race Condition | ₹1,000.00 | ₹1,500.00 | +₹500.00 | **PASS** | 5 simultaneous verify threads produce exactly 1 credit; 4 rejected. |
| **QA-PAY-07** | Duplicate Razorpay Webhook Idempotency | ₹1,000.00 | ₹1,000.00 | ₹0.00 | **PASS** | Redelivered webhooks acknowledge 200 OK without double crediting. |
| **QA-PAY-08** | Invalid Webhook Signature Forgery Rejection | ₹1,000.00 | ₹1,000.00 | ₹0.00 | **PASS** | Forged webhook signatures rejected via constant-time HMAC check. |
| **QA-PAY-09** | Refunded Transaction Ledger Reconciliation | ₹1,000.00 | ₹700.00 | -₹300.00 | **PASS** | Refund events correctly record ledger debits and adjust balance. |
| **QA-PAY-10** | Cross-User Transaction Ownership Isolation | ₹1,000.00 | ₹1,000.00 | ₹0.00 | **PASS** | Attempting to verify another user's order is rejected with 403. |

---

## 3. Scenario-by-Scenario Technical Details

### QA-PAY-01: Unsuccessful Payment Verification
- **Objective**: Verify that when a user abandons payment or the bank declines the charge, calling `POST /gift-cards/txn/verify` does not produce a credit.
- **Input**:
  ```json
  POST /gift-cards/txn/verify
  { "order_id": "order_FAILED_2087e032" }
  ```
- **Backend Trace**: The server queries Razorpay: `GET /v1/orders/order_FAILED_2087e032`. Razorpay returns `status: "attempted"`, `amount_paid: 0`.
- **Result**: Server returns `400 Bad Request` (`"Payment not captured"`).
- **Ledger Verification**: Initial balance: ₹1,000.00, Final balance: ₹1,000.00. Delta: ₹0.00. **PASS**.

---

### QA-PAY-02: Pending Payment Verification
- **Objective**: Verify that an order created on Razorpay that is still awaiting user action cannot be verified prematurely.
- **Input**:
  ```json
  POST /gift-cards/txn/verify
  { "order_id": "order_PENDING_3fdd592f" }
  ```
- **Backend Trace**: Server queries Razorpay: `status: "created"`.
- **Result**: Server returns `400 Bad Request` (`"Payment pending settlement"`).
- **Ledger Verification**: Initial balance: ₹1,000.00, Final balance: ₹1,000.00. Delta: ₹0.00. **PASS**.

---

### QA-PAY-03: Legitimate Captured Payment Crediting
- **Objective**: Verify that a verified, captured payment updates the transaction status to `COMPLETED` and creates a single ledger credit.
- **Input**:
  ```json
  POST /gift-cards/txn/verify
  { "order_id": "order_PAID_12484d99" }
  ```
- **Backend Trace**: Server queries Razorpay: `status: "paid"`, `amount_paid: 50000`, `currency: "INR"`.
- **Result**: Transaction marked `COMPLETED`. Immutable credit entry recorded.
- **Ledger Verification**: Initial balance: ₹1,000.00, Final balance: ₹1,500.00. Delta: +₹500.00. **PASS**.

---

### QA-PAY-04: Payment Amount Tampering Validation
- **Objective**: Verify that if an order expected ₹1,000.00 (100,000 paise) but only ₹10.00 (1,000 paise) was settled, the transaction is rejected.
- **Input**: Order invoice expected 100,000 paise. Gateway recorded `amount_paid: 1000`.
- **Result**: Server detects amount mismatch: `1000 < 100000`. Transaction flagged `FAILED`.
- **Ledger Verification**: Initial balance: ₹1,000.00, Final balance: ₹1,000.00. Delta: ₹0.00. **PASS**.

---

### QA-PAY-05: Sequential Duplicate Verification Idempotency
- **Objective**: Verify that calling verify a second time for an already completed order does not credit the wallet again.
- **Execution**:
  - Request 1: `POST /gift-cards/txn/verify {"order_id": "order_SEQ_59546ab0"}` -> Credits +₹200.00 (Balance: ₹1,200.00).
  - Request 2: `POST /gift-cards/txn/verify {"order_id": "order_SEQ_59546ab0"}` -> Returns `ALREADY_COMPLETED`.
- **Ledger Verification**: Balance remains ₹1,200.00. Delta: ₹0.00. **PASS**.

---

### QA-PAY-06: Concurrent Verification Race Condition
- **Objective**: Verify that 5 threads calling verify simultaneously cannot exploit a race condition.
- **Execution**: 5 concurrent HTTP POST requests dispatched using `ThreadPoolExecutor`.
- **Backend Trace**: The first thread acquires row lock `SELECT ... FOR UPDATE` and transitions status from `PENDING` to `COMPLETED`. Subsequent 4 threads read status `COMPLETED` and exit.
- **Ledger Verification**: Initial balance: ₹1,000.00, Final balance: ₹1,500.00. Exactly 1 credit applied. **PASS**.

---

### QA-PAY-07: Duplicate Razorpay Webhook Idempotency
- **Objective**: Verify that multiple deliveries of the same Razorpay webhook event do not cause duplicate ledger credits.
- **Result**: Handled idempotently by matching unique `gateway_order_id`. Balance delta: ₹0.00. **PASS**.

---

### QA-PAY-08: Invalid Webhook Signature Forgery Rejection
- **Objective**: Verify that forged webhooks without valid Razorpay HMAC signatures are rejected.
- **Input**:
  - Payload: `{"event":"order.paid","payload":{"order":{"entity":{"id":"order_FORGED"}}}}`
  - Header: `X-Razorpay-Signature: invalid_hmac_hex_abcdef0123456789`
- **Result**: Signature mismatch verified using constant-time `hmac.compare_digest`. Request rejected with `401 Unauthorized`. **PASS**.

---

### QA-PAY-09: Refunded Transaction Ledger Reconciliation
- **Objective**: Verify that refund events from Razorpay correctly record ledger debits.
- **Result**: Deducts ₹300.00 from ledger. Initial balance: ₹1,000.00, Final balance: ₹700.00. Delta: -₹300.00. **PASS**.

---

### QA-PAY-10: Cross-User Transaction Ownership Isolation
- **Objective**: Verify that User A cannot verify or complete an order generated by User B.
- **Result**: Backend ownership check `txn.user_id == current_user.id` fails. Server returns `403 Forbidden`. Balance unchanged. **PASS**.
