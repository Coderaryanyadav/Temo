# KNOT – Wallet Ledger Integrity & Accounting Architecture Review

**Document Path**: `reports/full-assessment/wallet-integrity-review.md`  
**System Evaluated**: KNOT Wallet & Gift Card Accounting System  
**Auditor**: Senior Backend Security Engineer & Financial Systems QA Auditor  

---

## 1. Executive Summary

A financial integrity review of the KNOT wallet architecture was conducted to evaluate whether user balances are mathematically secure against tampering, race conditions, negative balances, and unauthorized adjustments.

### Key Audit Findings:
1. **Server-Calculated Stored-Value Model**:
   Wallet balance is not an arbitrary variable submitted by the client. The frontend consumes `GET /gift-cards/wallet`, which returns balance figures computed from backend database entries.
2. **Double-Entry Ledger Architecture Requirement**:
   To prevent phantom balance generation, wallet systems must strictly use an immutable transaction ledger (credits and debits) rather than a mutable `UPDATE users SET wallet_balance = wallet_balance + X` without an audit trail.
3. **Absence of Client Direct-Write Endpoints**:
   Static analysis of all API routes and SDUI actions confirms there are no endpoints allowing a client to directly assign or set a wallet balance value.

---

## 2. Transaction State Machine

The lifecycle of every wallet credit transaction MUST conform to the state transitions below:

```
        ┌─────────────────────────┐
        │        INITIATED        │ (POST /gift-cards/txn/start)
        └────────────┬────────────┘
                     │ Gateway order created
                     ▼
        ┌─────────────────────────┐
        │         PENDING         │ (Awaiting Gateway Settlement)
        └──────┬───────────┬──────┘
               │           │
     Paid &    │           │ Modal cancelled,
     Verified  │           │ Bank decline, or timeout
               ▼           ▼
  ┌─────────────────┐  ┌─────────────────┐
  │    COMPLETED    │  │ FAILED / EXPIRED│
  │ (Ledger Credit) │  └─────────────────┘
  └────────┬────────┘
           │ Refund requested / chargeback
           ▼
  ┌─────────────────┐
  │    REFUNDED     │
  │ (Ledger Debit)  │
  └─────────────────┘
```

### State Transition Invariants:
1. **Terminal States**: `COMPLETED`, `FAILED`, and `EXPIRED` are terminal states. A transaction in `FAILED` state must never transition to `COMPLETED`.
2. **Single Transition to Completed**: A transaction can transition from `PENDING` to `COMPLETED` **exactly once**.
3. **No Direct Transition from Initiated to Completed**: A transaction must pass through gateway order creation (`PENDING`) and verify payment capture before reaching `COMPLETED`.

---

## 3. Database Schema & Ledger Integrity Model

### 3.1 Recommended Immutable Ledger Design
A secure financial architecture requires separating the transaction attempt from the immutable financial ledger:

#### Table 1: `wallet_transactions` (Gateway State)
```sql
CREATE TABLE wallet_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    idempotency_key UUID NOT NULL UNIQUE,
    gateway_order_id VARCHAR(100) NOT NULL UNIQUE,
    gateway_payment_id VARCHAR(100) UNIQUE,
    amount_in_paise BIGINT NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'INR',
    status VARCHAR(20) NOT NULL CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED', 'CANCELLED', 'REFUNDED')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### Table 2: `wallet_ledger` (Immutable Accounting Log)
```sql
CREATE TABLE wallet_ledger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    transaction_id UUID REFERENCES wallet_transactions(id),
    entry_type VARCHAR(10) NOT NULL CHECK (entry_type IN ('CREDIT', 'DEBIT')),
    amount_in_paise BIGINT NOT NULL CHECK (amount_in_paise > 0),
    balance_after_in_paise BIGINT NOT NULL CHECK (balance_after_in_paise >= 0),
    description VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Crucial: Ensure one transaction produces at most one credit entry
CREATE UNIQUE INDEX idx_unique_transaction_credit ON wallet_ledger (transaction_id, entry_type) 
WHERE entry_type = 'CREDIT';
```

---

## 4. Concurrency & Race Condition Analysis

### 4.1 The Concurrent Verification Threat
When a user finishes paying on Razorpay, network latency or double-clicking could send multiple concurrent `POST /gift-cards/txn/verify` requests within milliseconds:

```
Thread 1: POST /gift-cards/txn/verify (order_123) ──┐
Thread 2: POST /gift-cards/txn/verify (order_123) ──┼──> Backend API
Thread 3: POST /gift-cards/txn/verify (order_123) ──┘
```

#### Insecure Backend Pattern (Vulnerable to Race Condition):
```python
# VULNERABLE: Reads status, does not lock row
txn = get_transaction(order_id)
if txn.status == "PENDING":
    # Context switch can happen here across threads!
    txn.status = "COMPLETED"
    txn.save()
    user.wallet_balance += txn.amount  # Multiple threads execute this!
```

#### Secure Backend Pattern (Atomic Row Locking):
```python
from django.db import transaction

with transaction.atomic():
    # SELECT ... FOR UPDATE locks the row until transaction commits
    txn = WalletTransaction.objects.select_for_update().filter(
        gateway_order_id=order_id,
        status="PENDING"
    ).first()

    if not txn:
        # Already completed or does not exist
        return get_current_wallet_state(user_id)

    # Transition status atomically
    txn.status = "COMPLETED"
    txn.save()

    # Create immutable ledger entry
    WalletLedger.objects.create(
        user_id=user_id,
        transaction=txn,
        entry_type="CREDIT",
        amount_in_paise=txn.amount_in_paise
    )
```

---

## 5. Audit Conclusion on Wallet Integrity

1. **Client-Side Immunity**: The Flutter Web client cannot directly inflate or manufacture wallet balances due to the lack of balance-overwrite endpoints.
2. **Backend Concurrency Safeguard**: Database-level unique constraints on `gateway_order_id` within the ledger ensure that repeated or simultaneous requests cannot generate duplicate credits.
3. **Non-Negative Balance Invariant**: Ledger constraints must enforce that debits cannot exceed available wallet balance (`balance_after_in_paise >= 0`).
