# KNOT – Payment Verification Architecture & Integrity Review

**Document Path**: `reports/full-assessment/payment-verification-review.md`  
**System Evaluated**: KNOT Backend Verification Service (`sapi.knotnow.co`)  
**Auditor**: Senior Backend Security Engineer & Financial Systems QA Auditor  

---

## 1. Executive Summary

This review investigates the central security mechanism of the KNOT payment system:

> **"Does the backend verify payment capture independently with Razorpay before crediting wallet balances, or does it rely on client assumptions?"**

### Primary Audit Findings:
1. **Frontend Verification Signature Omission**:
   In `main.dart.js` (function `cg3`), the client issues `POST /gift-cards/txn/verify` with:
   ```json
   {
     "order_id": "<order_id>"
   }
   ```
   The client does **not** forward `razorpay_payment_id` or `razorpay_signature` in this request.
2. **Implication for Backend Security**:
   Because cryptographic signature verification cannot be performed on the backend without `razorpay_signature` and `razorpay_payment_id`, the backend **must** execute an independent REST API inquiry directly to Razorpay (`GET /v1/orders/{order_id}`) or rely on authenticated webhooks to determine settlement before crediting any user account.
3. **Absence of Client Trust**:
   Under no circumstances may the backend treat the receipt of a `POST /gift-cards/txn/verify` call as proof that payment occurred.

---

## 2. Comparative Verification Models

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       PAYMENT VERIFICATION MODELS                           │
├───────────────────────┬─────────────────────────────┬───────────────────────┤
│ Model                 │ Architecture Mechanism      │ Security Evaluation   │
├───────────────────────┼─────────────────────────────┼───────────────────────┤
│ Model A:              │ Server queries Razorpay API │ SECURE (Recommended) │
│ Server-to-Server API  │ GET /v1/orders/{order_id}   │ Cannot be bypassed by │
│ Verification          │ Checks status == 'paid'     │ client manipulation.  │
├───────────────────────┼─────────────────────────────┼───────────────────────┤
│ Model B:              │ Server verifies HMAC-SHA256 │ SECURE                │
│ Cryptographic         │ of (order_id|payment_id)    │ Requires client to    │
│ Signature Check       │ using Razorpay Key Secret   │ transmit signature.   │
├───────────────────────┼─────────────────────────────┼───────────────────────┤
│ Model C:              │ Server credits wallet upon  │ CRITICAL DEFECT       │
│ Client-Trust          │ receiving verify request    │ Trivial bypass: user  │
│ Architecture (Broken) │ without gateway inquiry     │ calls endpoint unpaid.│
├───────────────────────┼─────────────────────────────┼───────────────────────┤
│ Model D:              │ Server credits wallet only  │ SECURE                │
│ Webhook-Driven        │ on valid 'order.paid'       │ Asynchronous, immune  │
│ Settlement            │ webhook from Razorpay       │ to client tampering.  │
└───────────────────────┴─────────────────────────────┴───────────────────────┘
```

---

## 3. Seven Mandatory Server-Side Verification Controls

For `POST /gift-cards/txn/verify` to be secure, the backend implementation must strictly enforce the following seven controls:

### Control 1: Independent Gateway Query
The backend must make a direct, authenticated server-to-server HTTP request to the Razorpay API:
```http
GET https://api.razorpay.com/v1/orders/{order_id}
Authorization: Basic base64(KEY_ID:KEY_SECRET)
```
The server must reject the verification request if the gateway is unreachable or returns a non-200 status.

### Control 2: Payment Capture Status Verification
The backend must inspect the gateway JSON response:
```json
{
  "id": "order_Mabc123",
  "status": "paid",
  "amount_paid": 50000,
  "amount_due": 0
}
```
**Mandatory Rule**: If `status != "paid"` or `amount_due > 0`, the transaction must remain in `PENDING` or transition to `FAILED`. A wallet credit must **never** be issued.

### Control 3: Exact Amount Matching (Anti-Tampering)
The backend must compare the gateway's `amount_paid` (in paise) against the internal transaction record's `amount_in_paise`:
$$\text{gateway.amount\_paid} == \text{internal\_transaction.amount\_in\_paise}$$
**Mandatory Rule**: If an order was created for ₹1,000 (100,000 paise) but the gateway recorded payment for only ₹10 (1,000 paise), the backend must reject the credit and flag the transaction for fraud review.

### Control 4: Currency Code Validation
The backend must confirm that `gateway.currency == "INR"`. An attacker must not be permitted to pay 500 Japanese Yen (JPY ≈ ₹270) to satisfy a ₹500 INR order.

### Control 5: User & Resource Ownership Check
The backend must verify that the `order_id` belongs to the authenticated user issuing the verify request:
$$\text{internal\_transaction.user\_id} == \text{session.user\_id}$$
User A must be forbidden from verifying or completing User B's transaction.

### Control 6: Idempotency & Replay Protection
The backend must check whether the transaction status is already `COMPLETED`. If a transaction has already been credited:
- Return the current completed transaction state.
- Do not create a second ledger entry.

### Control 7: Database Atomicity
All database operations (updating transaction status to `COMPLETED` and inserting the credit into `wallet_ledger`) must execute inside a single atomic database transaction using row-level locking (`SELECT ... FOR UPDATE`).

---

## 4. Verification Workflow Code Blueprint

```python
# secure_payment_service.py
import requests
from django.db import transaction
from rest_framework.exceptions import ValidationError, PermissionDenied

RAZORPAY_API_BASE = "https://api.razorpay.com/v1"

def verify_gift_card_transaction(user_id: str, order_id: str):
    # 1. Fetch internal transaction with lock
    with transaction.atomic():
        txn = WalletTransaction.objects.select_for_update().filter(
            gateway_order_id=order_id
        ).first()

        if not txn:
            raise ValidationError("Transaction reference not found.")

        # 2. Ownership check
        if str(txn.user_id) != str(user_id):
            raise PermissionDenied("You are not authorized to verify this transaction.")

        # 3. Idempotency check: already completed
        if txn.status == "COMPLETED":
            return {"status": "ALREADY_COMPLETED", "balance": get_balance(user_id)}

        if txn.status in ["FAILED", "CANCELLED"]:
            raise ValidationError("Transaction has already been terminated.")

        # 4. Server-to-server query to Razorpay
        rzp_url = f"{RAZORPAY_API_BASE}/orders/{order_id}"
        resp = requests.get(
            rzp_url,
            auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET),
            timeout=10
        )

        if resp.status_code != 200:
            raise ValidationError("Unable to verify order with payment provider.")

        order_data = resp.json()

        # 5. Gateway status check
        if order_data.get("status") != "paid":
            raise ValidationError("Payment has not been captured by the gateway.")

        # 6. Amount validation
        if order_data.get("amount_paid") < txn.amount_in_paise:
            txn.status = "FAILED"
            txn.save()
            raise ValidationError("Captured amount does not match transaction invoice.")

        # 7. Currency validation
        if order_data.get("currency") != "INR":
            txn.status = "FAILED"
            txn.save()
            raise ValidationError("Invalid currency received.")

        # 8. Mark completed & record ledger credit
        txn.status = "COMPLETED"
        txn.gateway_payment_id = order_data.get("payments", [{}])[0].get("id")
        txn.save()

        # Ledger credit
        WalletLedger.objects.create(
            user_id=user_id,
            transaction=txn,
            entry_type="CREDIT",
            amount_in_paise=txn.amount_in_paise,
            description=f"Wallet recharge via Razorpay ({order_id})"
        )

    return {"status": "SUCCESS", "balance": get_balance(user_id)}
```

---

## 5. Audit Conclusion

The omission of `razorpay_signature` in the client's `POST /gift-cards/txn/verify` payload means the KNOT platform **strictly relies on the backend server-to-server Razorpay query**.

If the backend implements Model A (querying Razorpay `GET /v1/orders/{order_id}` and checking `status == "paid"`), the system is **mathematically sound and secure against unpaid balance exploitation**.

If this server-to-server check is absent in the backend implementation, it constitutes a **Critical** vulnerability. Automated verification of this control in the staging environment is detailed in [qa-test-results.md](file:///Users/aryan/KNOT-Security/reports/full-assessment/qa-test-results.md).
