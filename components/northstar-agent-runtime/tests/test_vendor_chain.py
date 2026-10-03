"""Tests for vendor_chain (one-hundred-third batch): vendor-chain provenance receipts."""
import hashlib
import unittest

from vendor_chain import (
    DENY_ATTESTATION_MISMATCH,
    DENY_CHAIN_GAP,
    DENY_EMPTY_CHAIN,
    DENY_OUTSIDE_ENVELOPE,
    DENY_RECEIPT_DIGEST_MISMATCH,
    DENY_TAINTED_CHAIN,
    DENY_UNKNOWN_VENDOR,
    VENDOR_ACTION_EVENT,
    ActionEnvelope,
    ActionVerdict,
    AutonomousAction,
    ChainVerdict,
    VendorChainError,
    VendorReceipt,
    VendorRegistry,
    authorize_autonomous_action,
    build_autonomous_action,
    build_vendor_receipt,
    vendor_action_event,
    verify_chain,
)


def _pin(label: str) -> str:
    return hashlib.sha256(f"northstar-vendor-test:{label}".encode()).hexdigest()


def _registry(**kw):
    pins = {"vendor:acme": _pin("acme"), "vendor:globex": _pin("globex")}
    pins.update(kw.get("pins", {}))
    return VendorRegistry(
        attestation_pins=pins,
        tainted_vendors=frozenset(kw.get("tainted", ())),
    )


def _hop(receipt_id, vendor, prev_hash="", action_id="act-1"):
    return build_vendor_receipt(
        receipt_id=receipt_id,
        action_id=action_id,
        vendor_id=vendor,
        vendor_attestation_digest=_pin(vendor.split(":", 1)[1]),
        prev_hash=prev_hash,
        created_unix=1000,
    )


def _chain(n=2):
    receipts = []
    prev = ""
    vendors = ["vendor:acme", "vendor:globex"]
    for i in range(n):
        r = _hop(f"r-{i}", vendors[i % 2], prev)
        receipts.append(r)
        prev = r.receipt_hash()
    return receipts


def _envelope():
    return ActionEnvelope(
        max_value_cents=5000, max_quantity=10, allowed_skus=frozenset({"SKU-1"})
    )


def _action(**kw):
    base = dict(action_id="act-1", sku="SKU-1", quantity=2, value_cents=1000,
                agent_id="agent:logi-1")
    base.update(kw)
    return build_autonomous_action(**base)


class BuildValidationTests(unittest.TestCase):
    def test_empty_ids_rejected(self):
        with self.assertRaises(VendorChainError):
            build_vendor_receipt(receipt_id="", action_id="a", vendor_id="v",
                                 vendor_attestation_digest=_pin("x"))

    def test_bad_attestation_digest_rejected(self):
        with self.assertRaises(VendorChainError):
            build_vendor_receipt(receipt_id="r", action_id="a", vendor_id="v",
                                 vendor_attestation_digest="not-hex")

    def test_bad_prev_hash_rejected(self):
        with self.assertRaises(VendorChainError):
            build_vendor_receipt(receipt_id="r", action_id="a", vendor_id="v",
                                 vendor_attestation_digest=_pin("x"),
                                 prev_hash="short")

    def test_receipt_hash_deterministic(self):
        r = _hop("r-1", "vendor:acme")
        self.assertEqual(r.receipt_hash(), r.receipt_hash())
        self.assertEqual(len(r.receipt_hash()), 64)

    def test_registry_rejects_bad_pin(self):
        with self.assertRaises(VendorChainError):
            VendorRegistry(attestation_pins={"v": "nope"})

    def test_envelope_rejects_negative(self):
        with self.assertRaises(VendorChainError):
            ActionEnvelope(max_value_cents=-1, max_quantity=1)

    def test_action_rejects_zero_quantity(self):
        with self.assertRaises(VendorChainError):
            build_autonomous_action(action_id="a", sku="s", quantity=0,
                                    value_cents=1, agent_id="g")


class ChainVerifyTests(unittest.TestCase):
    def test_clean_chain_verifies(self):
        receipts = _chain(2)
        v = verify_chain(receipts, _registry())
        self.assertTrue(v.allowed)
        self.assertFalse(v.tainted)
        self.assertEqual(v.reason, "chain_verified")
        self.assertEqual(len(v.chain_digest), 64)

    def test_empty_chain_denies(self):
        v = verify_chain([], _registry())
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_EMPTY_CHAIN)

    def test_unknown_vendor_denies(self):
        receipts = [_hop("r-1", "vendor:mallory")]
        v = verify_chain(receipts, _registry())
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_UNKNOWN_VENDOR)

    def test_attestation_mismatch_denies(self):
        r = build_vendor_receipt(
            receipt_id="r-1", action_id="act-1", vendor_id="vendor:acme",
            vendor_attestation_digest=_pin("forged"), created_unix=1000)
        v = verify_chain([r], _registry())
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_ATTESTATION_MISMATCH)

    def test_tampered_link_detected_via_claimed_hashes(self):
        receipts = _chain(2)
        claimed = [r.receipt_hash() for r in receipts]
        # tamper: rebuild second hop with a different receipt_id but keep claim
        tampered = build_vendor_receipt(
            receipt_id="r-EVIL", action_id="act-1", vendor_id="vendor:globex",
            vendor_attestation_digest=_pin("globex"),
            prev_hash=receipts[0].receipt_hash(), created_unix=1000)
        v = verify_chain([receipts[0], tampered], _registry(), claimed)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_RECEIPT_DIGEST_MISMATCH)

    def test_chain_gap_denies(self):
        receipts = _chain(2)
        # drop the first hop: second hop's prev_hash no longer resolves
        v = verify_chain([receipts[1]], _registry())
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_CHAIN_GAP)

    def test_tainted_vendor_propagates_no_washing(self):
        receipts = _chain(3)  # acme, globex, acme — globex tainted in middle
        v = verify_chain(receipts, _registry(tainted=("vendor:globex",)))
        self.assertFalse(v.allowed)
        self.assertTrue(v.tainted)
        self.assertEqual(v.reason, DENY_TAINTED_CHAIN)

    def test_revoked_vendor_denies_as_unknown(self):
        receipts = [_hop("r-1", "vendor:globex")]
        reg = VendorRegistry(attestation_pins={"vendor:acme": _pin("acme")})
        v = verify_chain(receipts, reg)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_UNKNOWN_VENDOR)


class AuthorizeTests(unittest.TestCase):
    def test_clean_chain_inside_envelope_allows(self):
        v = authorize_autonomous_action(
            action=_action(), receipts=_chain(2), registry=_registry(),
            envelope=_envelope(), created_unix=2000)
        self.assertTrue(v.allowed)
        self.assertEqual(v.audit_event["event"], VENDOR_ACTION_EVENT)
        self.assertTrue(v.audit_event["allowed"])

    def test_tainted_chain_denies_action(self):
        v = authorize_autonomous_action(
            action=_action(), receipts=_chain(2),
            registry=_registry(tainted=("vendor:acme",)),
            envelope=_envelope())
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_TAINTED_CHAIN)
        self.assertFalse(v.audit_event["allowed"])

    def test_value_over_envelope_denies(self):
        v = authorize_autonomous_action(
            action=_action(value_cents=5001), receipts=_chain(1),
            registry=_registry(), envelope=_envelope())
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_OUTSIDE_ENVELOPE)

    def test_quantity_over_envelope_denies(self):
        v = authorize_autonomous_action(
            action=_action(quantity=11), receipts=_chain(1),
            registry=_registry(), envelope=_envelope())
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_OUTSIDE_ENVELOPE)

    def test_sku_outside_envelope_denies(self):
        v = authorize_autonomous_action(
            action=_action(sku="SKU-9"), receipts=_chain(1),
            registry=_registry(), envelope=_envelope())
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_OUTSIDE_ENVELOPE)

    def test_envelope_boundary_allows(self):
        v = authorize_autonomous_action(
            action=_action(quantity=10, value_cents=5000), receipts=_chain(1),
            registry=_registry(), envelope=_envelope())
        self.assertTrue(v.allowed)

    def test_audit_event_shape(self):
        action = _action()
        ev = vendor_action_event(action=action, allowed=True,
                                 reason="x", chain_digest="0" * 64,
                                 created_unix=7)
        self.assertEqual(ev["action_digest"], action.action_digest())
        self.assertEqual(ev["created_unix"], 7)
        self.assertIn("agent_id", ev)


if __name__ == "__main__":
    unittest.main()
