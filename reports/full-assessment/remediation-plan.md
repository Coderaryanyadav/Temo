# KNOT – Payment & Wallet Security Remediation Plan

**Document Path**: `reports/full-assessment/remediation-plan.md`  
**Target Systems**: Backend API (`sapi.knotnow.co`) & Flutter Web Client (`knotnow.co`)  
**Auditor**: Senior Backend Security Engineer & Financial Systems QA Auditor  

---

## 1. Remediation Roadmap Overview

| Phase | Milestone | Priority | Target Timeline | Impact |
|---|---|---|---|---|
| **Phase 1** | Implement Server-Side Gateway Query on Verification | **P0 (Immediate)** | Day 1–2 | Eliminates risk of crediting unpaid orders. |
| **Phase 2** | Add Database-Level Concurrency Locking & Unique Ledger Constraint | **P0 (Immediate)** | Day 2–3 | Guarantees race-condition immunity on simultaneous requests. |
| **Phase 3** | Transmit & Validate Razorpay HMAC Signatures | **P1 (High)** | Day 3–5 | Introduces dual-layer cryptographic proof of payment. |
| **Phase 4** | Webhook Hardening & Timing-Safe Signature Validation | **P1 (High)** | Day 5–7 | Secures asynchronous payment and refund callbacks. |
| **Phase 5** | Automated Daily Ledger Reconciliation Cron | **P2 (Medium)** | Day 8–10 | Automated detection of financial discrepancies or anomalies. |

---

## 2. Phase-by-Phase Technical Specifications

### Phase 1: Server-Side Gateway Query on Verification (`/gift-cards/txn/verify`)

#### Problem:
The backend currently receives `{"order_id": "<order_id>"}`. If it does not query Razorpay, it cannot distinguish between an order that was actually paid and one where the user simply closed the window.

#### Action Required:
Update the backend route handler for `POST /gift-cards/txn/verify`:

```python
import requests
from django.conf import settings
from rest_framework.exceptions import ValidationError

def verify_with_razorpay(order_id: str) -> dict:
    """
    Direct server-to-server inquiry to Razorpay API.
    """
    url = f"https://api.razorpay.com/v1/orders/{order_id}"
    response = requests.get(
        url,
        auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET),
        timeout=8
    )
    if response.status_code != 200:
        raise ValidationError("Unable to communicate with payment gateway.")

    order_details = response.json()
    if order_details.get("status") != "paid":
        raise ValidationError("Order has not been captured or paid.")

    return order_details
```

---

### Phase 2: Database Concurrency Locking & Unique Constraints

#### Problem:
Simultaneous verify calls can cause double-crediting if two processes read status `PENDING` before either commits `COMPLETED`.

#### Action Required:
1. **Schema Migration**: Add unique constraint on the credit ledger:
   ```sql
   ALTER TABLE wallet_ledger 
   ADD CONSTRAINT unique_order_credit 
   UNIQUE (transaction_id, entry_type);
   ```
2. **Atomic Row Lock in Controller**:
   ```python
   from django.db import transaction

   @transaction.atomic
   def process_wallet_verification(user, order_id):
       # Lock row
       txn = WalletTransaction.objects.select_for_update().filter(
           gateway_order_id=order_id,
           user_id=user.id
       ).first()

       if not txn:
           raise ValidationError("Transaction not found.")

       if txn.status == "COMPLETED":
           return {"status": "SUCCESS", "message": "Already credited."}

       # Verify with Razorpay
       rzp_order = verify_with_razorpay(order_id)

       # Validate amount
       if rzp_order["amount_paid"] < txn.amount_in_paise:
           txn.status = "FAILED"
           txn.save()
           raise ValidationError("Underpaid transaction.")

       # Commit state
       txn.status = "COMPLETED"
       txn.gateway_payment_id = rzp_order.get("payments", [{}])[0].get("id")
       txn.save()

       # Credit ledger
       WalletLedger.objects.create(
           user_id=user.id,
           transaction_id=txn.id,
           entry_type="CREDIT",
           amount_in_paise=txn.amount_in_paise,
           description=f"Wallet top-up (Order: {order_id})"
       )
   ```

---

### Phase 3: Transmit and Validate Razorpay HMAC Signatures

#### Problem:
Client currently drops `razorpay_signature` and `razorpay_payment_id` returned by `checkout.js`.

#### Action Required:
1. **Client Update** (in Flutter / Dart):
   Update `cg3` to pass the full gateway payload:
   ```dart
   // Dart / Flutter Client
   Future<void> verifyPayment({
     required String orderId,
     required String paymentId,
     required String signature,
   }) async {
     await apiClient.post("/gift-cards/txn/verify", data: {
       "order_id": orderId,
       "payment_id": paymentId,
       "signature": signature,
     });
   }
   ```
2. **Server-Side Signature Validation**:
   ```python
   import hmac
   import hashlib

   def verify_razorpay_signature(order_id: str, payment_id: str, signature: str) -> bool:
       generated_signature = hmac.new(
           key=settings.RAZORPAY_KEY_SECRET.encode(),
           msg=f"{order_id}|{payment_id}".encode(),
           digestmod=hashlib.sha256
       ).hexdigest()

       return hmac.compare_digest(generated_signature, signature)
   ```

---

### Phase 4: Webhook Hardening & Timing-Safe Validation

#### Problem:
Webhooks bypass user sessions and must be authenticated exclusively via signature.

#### Action Required:
```python
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, HttpResponseForbidden
import hmac
import hashlib

@csrf_exempt
def razorpay_webhook(request):
    if request.method != "POST":
        return HttpResponse(status=405)

    signature = request.headers.get("X-Razorpay-Signature", "")
    secret = settings.RAZORPAY_WEBHOOK_SECRET.encode()
    raw_body = request.body  # MUST use unparsed raw bytes!

    expected_signature = hmac.new(secret, raw_body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        return HttpResponseForbidden("Invalid webhook signature.")

    event_payload = json.loads(raw_body.decode("utf-8"))
    event_type = event_payload.get("event")

    if event_type == "order.paid":
        handle_order_paid(event_payload)
    elif event_type == "refund.processed":
        handle_refund_processed(event_payload)

    return HttpResponse(status=200)
```

---

### Phase 5: Automated Daily Ledger Reconciliation Cron

#### Action Required:
Schedule a daily automated cron task to cross-check gateway settlements against internal ledgers:
```python
# management/commands/reconcile_wallet_ledger.py
from django.core.management.base import BaseCommand
import requests

class Command(BaseCommand):
    help = "Reconciles Razorpay settlement totals with wallet credit ledgers"

    def handle(self, *args, **options):
        yesterday_credits = WalletLedger.objects.filter(
            entry_type="CREDIT",
            created_at__date=yesterday
        ).aggregate(total=Sum("amount_in_paise"))["total"] or 0

        # Query Razorpay Payments for yesterday
        rzp_total = fetch_razorpay_captured_total(yesterday)

        if yesterday_credits != rzp_total:
            alert_security_team(
                f"DISCREPANCY DETECTED: Ledger credits ({yesterday_credits}) != Gateway settlements ({rzp_total})"
            )
        else:
            self.stdout.write(self.style.SUCCESS("Ledger reconciled successfully: 100% matched."))
```

---

## 3. Deployment Checklist

- [ ] Add `UNIQUE` database constraint on `wallet_ledger (transaction_id, entry_type)`.
- [ ] Deploy `SELECT ... FOR UPDATE` row locking in `process_wallet_verification`.
- [ ] Enable server-to-server `GET /v1/orders/{id}` query in backend verify handler.
- [ ] Add `razorpay_payment_id` and `razorpay_signature` to client `verify` payload.
- [ ] Implement constant-time HMAC check `hmac.compare_digest` on `/webhooks/razorpay`.
- [ ] Run automated QA suite `scripts/test_payment_qa.py` in CI/CD pipeline.
