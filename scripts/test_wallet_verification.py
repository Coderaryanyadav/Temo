#!/usr/bin/env python3
"""
Wallet Verification Quality Assurance Test Suite

This script demonstrates how to write defensive unit and integration tests
for verifying wallet credit logic and payment gateway integrity.

It uses mock responses to validate:
1. That unpaid or abandoned gateway orders are rejected.
2. That legitimate payments credit the ledger exactly once.
3. That duplicate/replayed verification requests do not result in double credits.
4. That underpaid transactions (amount tampering) are rejected.

Usage:
    pytest scripts/test_wallet_verification.py
    # Or run directly:
    python3 scripts/test_wallet_verification.py
"""

import unittest
from unittest.mock import MagicMock, patch

# ==============================================================================
# 1. Reference Implementation of Secure Verification Logic
# ==============================================================================

class SecureWalletService:
    """
    Reference backend service demonstrating the required security checks:
    - Server-to-server gateway query
    - Payment status validation ('paid')
    - Amount validation (matching invoice in paise)
    - Currency check ('INR')
    - Idempotency & double-credit prevention
    """
    def __init__(self, razorpay_client, db_connection):
        self.rzp = razorpay_client
        self.db = db_connection

    def verify_and_credit_wallet(self, user_id: str, order_id: str) -> dict:
        # Step 1: Retrieve internal transaction record
        txn = self.db.get_transaction(order_id)
        if not txn:
            raise ValueError("Transaction record not found.")

        # Step 2: Ownership verification
        if txn["user_id"] != user_id:
            raise PermissionError("User does not own this transaction.")

        # Step 3: Idempotency check - prevent duplicate processing
        if txn["status"] == "COMPLETED":
            return {
                "status": "ALREADY_COMPLETED",
                "message": "Transaction already verified and credited.",
                "balance": self.db.get_balance(user_id)
            }

        if txn["status"] in ["FAILED", "CANCELLED"]:
            raise ValueError(f"Cannot verify transaction in {txn['status']} state.")

        # Step 4: Independent Server-to-Server Gateway Inquiry
        gateway_order = self.rzp.fetch_order(order_id)
        if not gateway_order:
            raise ConnectionError("Payment gateway order lookup failed.")

        # Step 5: Validate Gateway Payment Status
        if gateway_order.get("status") != "paid":
            txn["status"] = "FAILED"
            self.db.update_transaction(txn)
            raise ValueError(
                f"Payment incomplete: gateway reported status '{gateway_order.get('status')}'."
            )

        # Step 6: Validate Amount (Anti-tampering)
        expected_amount_paise = txn["amount_in_paise"]
        actual_paid_paise = gateway_order.get("amount_paid", 0)
        if actual_paid_paise < expected_amount_paise:
            txn["status"] = "FAILED"
            self.db.update_transaction(txn)
            raise ValueError(
                f"Underpaid amount: expected {expected_amount_paise} paise, got {actual_paid_paise} paise."
            )

        # Step 7: Validate Currency
        if gateway_order.get("currency") != "INR":
            txn["status"] = "FAILED"
            self.db.update_transaction(txn)
            raise ValueError("Invalid currency detected.")

        # Step 8: Atomic Commit & Ledger Update
        txn["status"] = "COMPLETED"
        txn["gateway_payment_id"] = gateway_order.get("payment_id")
        self.db.update_transaction(txn)

        credit_amount = expected_amount_paise / 100.0
        new_balance = self.db.add_ledger_credit(user_id, order_id, credit_amount)

        return {
            "status": "SUCCESS",
            "credited_amount": credit_amount,
            "new_balance": new_balance
        }


# ==============================================================================
# 2. Defensive Automated QA Test Cases
# ==============================================================================

class TestWalletVerificationIntegrity(unittest.TestCase):

    def setUp(self):
        # In-memory mock database for isolated testing
        self.mock_db = MagicMock()
        self.mock_rzp = MagicMock()
        self.service = SecureWalletService(self.mock_rzp, self.mock_db)

        # Baseline user and transaction fixtures
        self.user_id = "user_178807"
        self.order_id = "order_test_998877"
        self.initial_balance = 500.0

        self.mock_db.get_balance.return_value = self.initial_balance
        self.mock_db.get_transaction.return_value = {
            "order_id": self.order_id,
            "user_id": self.user_id,
            "amount_in_paise": 50000,  # 500.00 INR
            "status": "PENDING",
            "currency": "INR"
        }

        # Simulated ledger credit method
        def mock_add_credit(user_id, order_id, amount):
            self.initial_balance += amount
            self.mock_db.get_balance.return_value = self.initial_balance
            return self.initial_balance

        self.mock_db.add_ledger_credit.side_effect = mock_add_credit

    def test_unpaid_order_must_not_credit_wallet(self):
        """
        GIVEN an order that was abandoned or declined by the bank
        WHEN verify is executed
        THEN the service must reject the request and the wallet balance must remain unchanged.
        """
        # Razorpay reports order was created but never paid
        self.mock_rzp.fetch_order.return_value = {
            "id": self.order_id,
            "status": "created",
            "amount_paid": 0,
            "currency": "INR"
        }

        with self.assertRaises(ValueError) as context:
            self.service.verify_and_credit_wallet(self.user_id, self.order_id)

        self.assertIn("Payment incomplete", str(context.exception))
        self.assertEqual(
            self.mock_db.get_balance(self.user_id),
            500.0,
            "SECURITY VULNERABILITY: Unpaid order resulted in a wallet credit!"
        )

    def test_paid_order_credits_wallet_successfully(self):
        """
        GIVEN an order successfully captured by Razorpay
        WHEN verify is executed
        THEN the transaction is marked COMPLETED and wallet balance is credited.
        """
        self.mock_rzp.fetch_order.return_value = {
            "id": self.order_id,
            "status": "paid",
            "amount_paid": 50000,
            "currency": "INR",
            "payment_id": "pay_test_12345"
        }

        res = self.service.verify_and_credit_wallet(self.user_id, self.order_id)

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["credited_amount"], 500.0)
        self.assertEqual(self.mock_db.get_balance(self.user_id), 1000.0)

    def test_duplicate_verification_is_idempotent(self):
        """
        GIVEN a valid transaction that has already been verified and completed
        WHEN verify is called a second time (e.g. network retry or replay)
        THEN the service must return the existing status without adding extra balance.
        """
        self.mock_rzp.fetch_order.return_value = {
            "id": self.order_id,
            "status": "paid",
            "amount_paid": 50000,
            "currency": "INR",
            "payment_id": "pay_test_12345"
        }

        # First verification: adds 500
        self.service.verify_and_credit_wallet(self.user_id, self.order_id)
        self.assertEqual(self.mock_db.get_balance(self.user_id), 1000.0)

        # Set transaction status to COMPLETED as database would
        self.mock_db.get_transaction.return_value["status"] = "COMPLETED"

        # Second verification (replay)
        replay_res = self.service.verify_and_credit_wallet(self.user_id, self.order_id)

        self.assertEqual(replay_res["status"], "ALREADY_COMPLETED")
        self.assertEqual(
            self.mock_db.get_balance(self.user_id),
            1000.0,
            "SECURITY VULNERABILITY: Replaying verify resulted in duplicate credits!"
        )

    def test_underpaid_transaction_is_rejected(self):
        """
        GIVEN an order invoice for 500.00 INR (50,000 paise)
        WHEN the gateway reports only 10.00 INR (1,000 paise) was settled
        THEN the transaction must be flagged FAILED and zero credit applied.
        """
        self.mock_rzp.fetch_order.return_value = {
            "id": self.order_id,
            "status": "paid",
            "amount_paid": 1000,  # 10.00 INR instead of 500.00 INR
            "currency": "INR"
        }

        with self.assertRaises(ValueError) as context:
            self.service.verify_and_credit_wallet(self.user_id, self.order_id)

        self.assertIn("Underpaid amount", str(context.exception))
        self.assertEqual(self.mock_db.get_balance(self.user_id), 500.0)

    def test_cross_user_verification_is_forbidden(self):
        """
        GIVEN an order owned by user A
        WHEN user B attempts to verify it
        THEN the service must raise PermissionError and deny access.
        """
        attacker_id = "user_999999"
        with self.assertRaises(PermissionError):
            self.service.verify_and_credit_wallet(attacker_id, self.order_id)

        self.assertEqual(self.mock_db.get_balance(self.user_id), 500.0)


if __name__ == "__main__":
    unittest.main()
