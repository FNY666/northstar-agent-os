"""Tests for compute_budget.py (one-hundred-ninth batch)."""

import sys
import unittest

sys.path.insert(0, "components/northstar-agent-runtime")

from canonical_json import jcs_sha256_hex
from compute_budget import (
    AuthorityRegistry,
    BudgetLedger,
    ComputeBudgetError,
    DENY_BUDGET_EXHAUSTED,
    DENY_DEVICE_CLASS,
    DENY_EXPIRED_BUDGET,
    DENY_MISSING_PURPOSE,
    DENY_TIER_MISMATCH,
    DENY_UNKNOWN_BUDGET,
    DENY_WEAK_EVIDENCE,
    authority_keypair,
    issue_budget,
    sign_budget_digest,
    _budget_payload,
)

SEED = bytes(range(32))
OTHER_SEED = bytes([255 - b for b in range(32)])


def _registry(pub=None):
    pub = pub if pub is not None else authority_keypair(SEED)[0]
    return AuthorityRegistry(public_keys={"ops-authority": pub})


def _signed(registry_seed=SEED, **over):
    params = dict(
        budget_id="bud-1",
        owner="agent-7",
        units_total=1000,
        unit_kind="tokens",
        hardware_tier="datacenter",
        device_class="cloud",
        issued_by="ops-authority",
        issued_at=1000,
        expires_at=2000,
    )
    params.update(over)
    digest = jcs_sha256_hex(_budget_payload(
        budget_id=params["budget_id"],
        owner=params["owner"],
        units_total=params["units_total"],
        unit_kind=params["unit_kind"],
        hardware_tier=params["hardware_tier"],
        device_class=params["device_class"],
        issued_by=params["issued_by"],
        issued_at=params["issued_at"],
        expires_at=params["expires_at"],
        prev_hash=params.get("prev_hash", ""),
    ))
    sig = sign_budget_digest(registry_seed, digest)
    return issue_budget(_registry(), signature=sig, **params)


def _ledger_with_budget(**over):
    ledger = BudgetLedger()
    ledger.issue(_signed(**over))
    return ledger


def _spend_kwargs(**over):
    kw = dict(
        budget_id="bud-1",
        units=100,
        purpose="inference",
        spend_tier="datacenter",
        device_class="cloud",
        evidence_kind="tee",
        created_unix=1500,
    )
    kw.update(over)
    return kw


class TestIssuance(unittest.TestCase):
    def test_valid_issue(self):
        b = _signed()
        self.assertEqual(b.units_total, 1000)
        self.assertEqual(b.unit_kind, "tokens")
        self.assertTrue(b.budget_digest)

    def test_self_issuance_refused(self):
        with self.assertRaises(ComputeBudgetError):
            _signed(issued_by="ops-authority", owner="ops-authority")

    def test_unregistered_authority_refused(self):
        with self.assertRaises(ComputeBudgetError):
            _signed(issued_by="mallory")

    def test_bad_signature_refused(self):
        with self.assertRaises(ComputeBudgetError):
            _signed(registry_seed=OTHER_SEED)

    def test_bad_unit_kind(self):
        with self.assertRaises(ComputeBudgetError):
            _signed(unit_kind="bananas")

    def test_bad_tier(self):
        with self.assertRaises(ComputeBudgetError):
            _signed(hardware_tier="quantum")

    def test_expiry_not_after_issue(self):
        with self.assertRaises(ComputeBudgetError):
            _signed(expires_at=1000)

    def test_duplicate_budget_id(self):
        ledger = _ledger_with_budget()
        with self.assertRaises(ComputeBudgetError):
            ledger.issue(_signed())


class TestSpendGate(unittest.TestCase):
    def test_clean_spend(self):
        ledger = _ledger_with_budget()
        v = ledger.spend(**_spend_kwargs())
        self.assertTrue(v.allowed)
        self.assertEqual(v.remaining, 900)
        self.assertEqual(ledger.remaining("bud-1"), 900)
        self.assertTrue(v.receipt.receipt_hash())
        self.assertEqual(v.audit_event["event"], "compute.spend")

    def test_spend_chain_links(self):
        ledger = _ledger_with_budget()
        r1 = ledger.spend(**_spend_kwargs()).receipt
        r2 = ledger.spend(**_spend_kwargs(units=50, purpose="eval")).receipt
        self.assertEqual(r2.prev_hash, r1.receipt_hash())
        self.assertEqual(ledger.remaining("bud-1"), 850)

    def test_overspend_denies_and_stops(self):
        ledger = _ledger_with_budget()
        v = ledger.spend(**_spend_kwargs(units=1001))
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_BUDGET_EXHAUSTED)
        self.assertEqual(v.audit_event["event"], "compute.budget_exhausted")
        # Balance untouched; a later fitting spend still works.
        v2 = ledger.spend(**_spend_kwargs(units=1000))
        self.assertTrue(v2.allowed)
        self.assertEqual(v2.remaining, 0)
        v3 = ledger.spend(**_spend_kwargs(units=1))
        self.assertFalse(v3.allowed)
        self.assertEqual(v3.reason, DENY_BUDGET_EXHAUSTED)

    def test_missing_purpose_denies(self):
        ledger = _ledger_with_budget()
        v = ledger.spend(**_spend_kwargs(purpose=""))
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_MISSING_PURPOSE)

    def test_unknown_budget_denies(self):
        ledger = _ledger_with_budget()
        v = ledger.spend(**_spend_kwargs(budget_id="nope"))
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_UNKNOWN_BUDGET)

    def test_expired_budget_denies(self):
        ledger = _ledger_with_budget()
        v = ledger.spend(**_spend_kwargs(created_unix=2001))
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_EXPIRED_BUDGET)

    def test_tier_widening_denies(self):
        ledger = _ledger_with_budget(hardware_tier="edge")
        v = ledger.spend(**_spend_kwargs(spend_tier="datacenter"))
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_TIER_MISMATCH)

    def test_tier_narrowing_allows(self):
        ledger = _ledger_with_budget(hardware_tier="datacenter")
        v = ledger.spend(**_spend_kwargs(spend_tier="edge", evidence_kind="software"))
        self.assertTrue(v.allowed)

    def test_weak_evidence_denies(self):
        ledger = _ledger_with_budget(hardware_tier="datacenter")
        v = ledger.spend(**_spend_kwargs(evidence_kind="software"))
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_WEAK_EVIDENCE)

    def test_strong_evidence_allows(self):
        ledger = _ledger_with_budget(hardware_tier="hpc")
        v = ledger.spend(**_spend_kwargs(spend_tier="hpc", evidence_kind="tee"))
        self.assertTrue(v.allowed)

    def test_cloud_spend_on_edge_budget_denies(self):
        ledger = _ledger_with_budget(device_class="edge", hardware_tier="edge")
        v = ledger.spend(**_spend_kwargs(device_class="cloud", spend_tier="edge",
                                         evidence_kind="software"))
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_DEVICE_CLASS)

    def test_edge_spend_on_cloud_budget_allows(self):
        ledger = _ledger_with_budget(device_class="cloud")
        v = ledger.spend(**_spend_kwargs(device_class="edge"))
        self.assertTrue(v.allowed)

    def test_nonpositive_units_raise(self):
        ledger = _ledger_with_budget()
        with self.assertRaises(ComputeBudgetError):
            ledger.spend(**_spend_kwargs(units=0))
        with self.assertRaises(ComputeBudgetError):
            ledger.spend(**_spend_kwargs(units=-5))

    def test_denial_emits_audit_event(self):
        ledger = _ledger_with_budget()
        v = ledger.spend(**_spend_kwargs(units=9999))
        self.assertFalse(v.allowed)
        self.assertEqual(v.audit_event["budget_id"], "bud-1")
        self.assertFalse(v.audit_event["allowed"])


class TestTierProbe(unittest.TestCase):
    def test_probe_direct(self):
        ledger = _ledger_with_budget(hardware_tier="datacenter")
        ok, reason = ledger.check_hardware_tier("bud-1", "datacenter", "tee")
        self.assertTrue(ok)
        ok, reason = ledger.check_hardware_tier("bud-1", "hpc", "tee")
        self.assertFalse(ok)
        self.assertEqual(reason, DENY_TIER_MISMATCH)
        ok, reason = ledger.check_hardware_tier("bud-1", "datacenter", "software")
        self.assertFalse(ok)
        self.assertEqual(reason, DENY_WEAK_EVIDENCE)
        ok, reason = ledger.check_hardware_tier("ghost", "edge", "software")
        self.assertFalse(ok)
        self.assertEqual(reason, DENY_UNKNOWN_BUDGET)


class TestLedger(unittest.TestCase):
    def test_roi_ledger_aggregation(self):
        ledger = _ledger_with_budget()
        ledger.spend(**_spend_kwargs(units=100, purpose="inference"))
        ledger.spend(**_spend_kwargs(units=50, purpose="inference"))
        ledger.spend(**_spend_kwargs(units=25, purpose="eval"))
        roi = ledger.roi_ledger()
        self.assertEqual(roi["by_purpose"]["inference"], {"tokens": 150})
        self.assertEqual(roi["by_purpose"]["eval"], {"tokens": 25})
        self.assertEqual(roi["by_budget"]["bud-1"]["spent"], 175)
        self.assertEqual(roi["by_budget"]["bud-1"]["remaining"], 825)
        self.assertEqual(roi["n_spends"], 3)

    def test_chain_verifies(self):
        ledger = _ledger_with_budget()
        ledger.spend(**_spend_kwargs())
        ok, reason = ledger.verify_spend_chain("bud-1")
        self.assertTrue(ok)

    def test_tampered_chain_detected(self):
        ledger = _ledger_with_budget()
        ledger.spend(**_spend_kwargs())
        chain = ledger._chains["bud-1"]
        # Tamper by replacing the receipt with one that misstates remaining.
        good = chain[0]
        from compute_budget import SpendReceipt
        chain[0] = SpendReceipt(
            receipt_id=good.receipt_id,
            budget_id=good.budget_id,
            units=good.units,
            purpose=good.purpose,
            remaining=999999,  # lie
            prev_hash=good.prev_hash,
            created_unix=good.created_unix,
        )
        ok, reason = ledger.verify_spend_chain("bud-1")
        self.assertFalse(ok)
        # And future spend on the broken chain fail-closes.
        v = ledger.spend(**_spend_kwargs(units=10, purpose="inference"))
        self.assertFalse(v.allowed)

    def test_authority_keypair_helper(self):
        pub, seed = authority_keypair(SEED)
        self.assertEqual(len(pub), 32)
        self.assertEqual(seed, SEED)
        with self.assertRaises(ComputeBudgetError):
            authority_keypair(b"short")


if __name__ == "__main__":
    unittest.main()
