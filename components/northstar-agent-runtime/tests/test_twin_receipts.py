"""Twin-sync receipts (ninety-sixth batch).

Covers ``twin_receipts`` (the ``metrics.twin_sync`` bench track):

- Freshness gate: fresh / boundary-inclusive / stale / from-future.
- Sensor manifest: exact match authoritative; added/removed sensors and
  unpinned twins classify NON_AUTHORITATIVE.
- Chain integrity: linked, ordered chains verify; broken links, mixed
  twins, and backwards time fail.
- Actuation gate: happy path, no card, binding mismatch, stale, sensor
  mismatch, replay, unknown receipt, malformed args.
- Determinism: two runs give identical metrics.
"""
from __future__ import annotations

import unittest

import support  # noqa: F401

from action_card import ActionCard, ActionProvenance, GateDecision
from evidence_tiers import EvidenceTier
from permissions import digest_arguments
from twin_receipts import (
    DENY_CARD_BINDING_MISMATCH,
    DENY_NO_CARD,
    DENY_RECEIPT_REPLAY,
    DENY_SENSOR_MISMATCH,
    DENY_STALE_STATE,
    DENY_UNKNOWN_RECEIPT,
    ReceiptRegistry,
    SensorManifestRegistry,
    TwinReceiptError,
    check_freshness,
    gate_actuation,
    mint_receipt,
    run_twin_sync,
)

NOW = 1_700_000_000
TWIN = "twin/test-line"
BUDGET = 300


def _hex(seed: str) -> str:
    import hashlib

    return hashlib.sha256(("twin-test:" + seed).encode()).hexdigest()


SENSORS = (_hex("s/a"), _hex("s/b"), _hex("s/c"))


def make_card(call_id: str, args: dict) -> ActionCard:
    return ActionCard(
        card_id=_hex("card/" + call_id)[:32],
        tool="twin.actuate",
        call_id=call_id,
        arguments_digest=digest_arguments(args),
        risk_tier="tier3",
        provenance=ActionProvenance(agent="main", session_id="t"),
        gate=GateDecision(
            would_auto_approve=False, auto_approved=False, policy_basis="t"
        ),
        created_unix=float(NOW),
    )


def issue(registry, rid, observed_at=NOW - 10, sensors=SENSORS, prev_hash=""):
    return registry.issue(
        mint_receipt(
            receipt_id=rid,
            twin_id=TWIN,
            state_digest=_hex("state/" + rid),
            observed_at=observed_at,
            source_sensor_set=sensors,
            staleness_budget=BUDGET,
            prev_hash=prev_hash,
        )
    )


class TestMint(unittest.TestCase):
    def test_rejects_garbage(self) -> None:
        with self.assertRaises(TwinReceiptError):
            mint_receipt(
                receipt_id="", twin_id=TWIN, state_digest=_hex("x"),
                observed_at=NOW, source_sensor_set=SENSORS, staleness_budget=BUDGET,
            )
        with self.assertRaises(TwinReceiptError):
            mint_receipt(
                receipt_id="r", twin_id=TWIN, state_digest="not-hex",
                observed_at=NOW, source_sensor_set=SENSORS, staleness_budget=BUDGET,
            )
        with self.assertRaises(TwinReceiptError):
            mint_receipt(
                receipt_id="r", twin_id=TWIN, state_digest=_hex("x"),
                observed_at=NOW, source_sensor_set=[], staleness_budget=BUDGET,
            )
        with self.assertRaises(TwinReceiptError):
            mint_receipt(
                receipt_id="r", twin_id=TWIN, state_digest=_hex("x"),
                observed_at=NOW, source_sensor_set=SENSORS, staleness_budget=-1,
            )

    def test_duplicate_receipt_id_rejected(self) -> None:
        reg = ReceiptRegistry()
        issue(reg, "dup")
        with self.assertRaises(TwinReceiptError):
            issue(reg, "dup")


class TestFreshness(unittest.TestCase):
    def test_fresh_and_boundary(self) -> None:
        reg = ReceiptRegistry()
        r = issue(reg, "f1", NOW - 10)
        self.assertEqual(check_freshness(r, now=NOW), (True, "fresh"))
        r2 = issue(reg, "f2", NOW - BUDGET)
        self.assertEqual(check_freshness(r2, now=NOW), (True, "fresh"))

    def test_stale_one_second_past(self) -> None:
        reg = ReceiptRegistry()
        r = issue(reg, "s1", NOW - BUDGET - 1)
        ok, reason = check_freshness(r, now=NOW)
        self.assertFalse(ok)
        self.assertIn("stale", reason)

    def test_from_future_fails(self) -> None:
        reg = ReceiptRegistry()
        r = issue(reg, "fu", NOW + 1)
        ok, reason = check_freshness(r, now=NOW)
        self.assertFalse(ok)
        self.assertIn("future", reason)

    def test_non_int_now_rejected(self) -> None:
        reg = ReceiptRegistry()
        r = issue(reg, "ni", NOW - 10)
        with self.assertRaises(TwinReceiptError):
            check_freshness(r, now="now")  # type: ignore[arg-type]


class TestSensorManifest(unittest.TestCase):
    def test_exact_match_authoritative(self) -> None:
        man = SensorManifestRegistry()
        man.pin(TWIN, SENSORS)
        reg = ReceiptRegistry()
        r = issue(reg, "m1")
        self.assertIs(man.check_window(r), EvidenceTier.AUTHORITATIVE)

    def test_added_sensor_non_authoritative(self) -> None:
        man = SensorManifestRegistry()
        man.pin(TWIN, SENSORS)
        reg = ReceiptRegistry()
        r = issue(reg, "m2", sensors=list(SENSORS) + [_hex("rogue")])
        self.assertIs(man.check_window(r), EvidenceTier.NON_AUTHORITATIVE)

    def test_removed_sensor_non_authoritative(self) -> None:
        man = SensorManifestRegistry()
        man.pin(TWIN, SENSORS)
        reg = ReceiptRegistry()
        r = issue(reg, "m3", sensors=SENSORS[:2])
        self.assertIs(man.check_window(r), EvidenceTier.NON_AUTHORITATIVE)

    def test_unpinned_twin_non_authoritative(self) -> None:
        man = SensorManifestRegistry()
        reg = ReceiptRegistry()
        r = issue(reg, "m4")
        self.assertIs(man.check_window(r), EvidenceTier.NON_AUTHORITATIVE)


class TestChain(unittest.TestCase):
    def test_linked_chain_verifies(self) -> None:
        reg = ReceiptRegistry()
        a = issue(reg, "c1", NOW - 200)
        b = issue(reg, "c2", NOW - 100, prev_hash=a.receipt_hash())
        c = issue(reg, "c3", NOW - 10, prev_hash=b.receipt_hash())
        ok, _ = reg.verify_chain([a, b, c])
        self.assertTrue(ok)

    def test_broken_link_fails(self) -> None:
        reg = ReceiptRegistry()
        a = issue(reg, "d1", NOW - 200)
        b = issue(reg, "d2", NOW - 100, prev_hash="wrong")
        ok, reason = reg.verify_chain([a, b])
        self.assertFalse(ok)
        self.assertIn("broken link", reason)

    def test_dropped_receipt_fails(self) -> None:
        # a -> c without b: c's prev_hash names b, not a -> broken.
        reg = ReceiptRegistry()
        a = issue(reg, "e1", NOW - 200)
        b = issue(reg, "e2", NOW - 100, prev_hash=a.receipt_hash())
        c = issue(reg, "e3", NOW - 10, prev_hash=b.receipt_hash())
        ok, _ = reg.verify_chain([a, c])
        self.assertFalse(ok)

    def test_mixed_twins_fail(self) -> None:
        reg = ReceiptRegistry()
        a = issue(reg, "f1", NOW - 200)
        other = mint_receipt(
            receipt_id="f2", twin_id="twin/other", state_digest=_hex("s"),
            observed_at=NOW - 100, source_sensor_set=SENSORS,
            staleness_budget=BUDGET, prev_hash=a.receipt_hash(),
        )
        reg.issue(other)
        ok, reason = reg.verify_chain([a, other])
        self.assertFalse(ok)
        self.assertIn("mixes twins", reason)


class TestActuationGate(unittest.TestCase):
    def _env(self):
        man = SensorManifestRegistry()
        man.pin(TWIN, SENSORS)
        return man, ReceiptRegistry()

    def test_happy_path_consumes_single_use(self) -> None:
        man, reg = self._env()
        issue(reg, "g1")
        args = {"twin_receipt_id": "g1", "command": "x", "value": 1}
        v = gate_actuation(
            card=make_card("c1", args), call_id="c1", arguments=args,
            registry=reg, manifests=man, now=NOW,
        )
        self.assertTrue(v.allowed)
        self.assertIs(v.window_tier, EvidenceTier.AUTHORITATIVE)
        self.assertTrue(reg.is_consumed("g1"))

    def test_no_card_denied(self) -> None:
        man, reg = self._env()
        issue(reg, "g2")
        args = {"twin_receipt_id": "g2"}
        v = gate_actuation(
            card=None, call_id="c2", arguments=args,
            registry=reg, manifests=man, now=NOW,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_NO_CARD)

    def test_stale_denied_with_code(self) -> None:
        man, reg = self._env()
        issue(reg, "g3", NOW - BUDGET - 5)
        args = {"twin_receipt_id": "g3"}
        v = gate_actuation(
            card=make_card("c3", args), call_id="c3", arguments=args,
            registry=reg, manifests=man, now=NOW,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_STALE_STATE)

    def test_sensor_mismatch_denied_non_authoritative(self) -> None:
        man, reg = self._env()
        issue(reg, "g4", sensors=list(SENSORS) + [_hex("rogue")])
        args = {"twin_receipt_id": "g4"}
        v = gate_actuation(
            card=make_card("c4", args), call_id="c4", arguments=args,
            registry=reg, manifests=man, now=NOW,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_SENSOR_MISMATCH)
        self.assertIs(v.window_tier, EvidenceTier.NON_AUTHORITATIVE)

    def test_replay_denied(self) -> None:
        man, reg = self._env()
        issue(reg, "g5")
        args = {"twin_receipt_id": "g5"}
        v1 = gate_actuation(
            card=make_card("c5a", args), call_id="c5a", arguments=args,
            registry=reg, manifests=man, now=NOW,
        )
        self.assertTrue(v1.allowed)
        v2 = gate_actuation(
            card=make_card("c5b", args), call_id="c5b", arguments=args,
            registry=reg, manifests=man, now=NOW,
        )
        self.assertFalse(v2.allowed)
        self.assertEqual(v2.reason, DENY_RECEIPT_REPLAY)

    def test_binding_mismatch_denied(self) -> None:
        man, reg = self._env()
        issue(reg, "g6")
        args = {"twin_receipt_id": "g6", "value": 1}
        other = {"twin_receipt_id": "g6", "value": 2}
        v = gate_actuation(
            card=make_card("c6", other), call_id="c6", arguments=args,
            registry=reg, manifests=man, now=NOW,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_CARD_BINDING_MISMATCH)

    def test_unknown_receipt_denied(self) -> None:
        man, reg = self._env()
        args = {"twin_receipt_id": "nope"}
        v = gate_actuation(
            card=make_card("c7", args), call_id="c7", arguments=args,
            registry=reg, manifests=man, now=NOW,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_UNKNOWN_RECEIPT)

    def test_malformed_args_denied(self) -> None:
        man, reg = self._env()
        args = {"command": "x"}  # no twin_receipt_id
        v = gate_actuation(
            card=make_card("c8", args), call_id="c8", arguments=args,
            registry=reg, manifests=man, now=NOW,
        )
        self.assertFalse(v.allowed)


class TestBenchTrack(unittest.TestCase):
    def test_ground_truth_closed(self) -> None:
        m = run_twin_sync()
        self.assertEqual(m["n_scenarios"], 12)
        self.assertEqual(m["mismatches"], [])

    def test_allow_set_exact(self) -> None:
        m = run_twin_sync()
        self.assertEqual(
            m["allowed_ids"],
            [
                "allow_boundary_fresh",
                "allow_fresh_receipt_actuation",
                "allow_second_receipt_new_chain",
            ],
        )
        self.assertEqual(m["n_allowed"], 3)
        self.assertEqual(m["n_denied"], 9)

    def test_denial_codes(self) -> None:
        m = run_twin_sync()
        d = m["detail"]
        self.assertIn(DENY_STALE_STATE, d["deny_stale_receipt"])
        self.assertIn(DENY_NO_CARD, d["deny_actuation_without_card"])
        self.assertIn(DENY_RECEIPT_REPLAY, d["deny_receipt_replay"])
        self.assertIn(DENY_UNKNOWN_RECEIPT, d["deny_unknown_receipt"])
        self.assertIn(DENY_SENSOR_MISMATCH, d["deny_sensor_added"])

    def test_deterministic(self) -> None:
        self.assertEqual(run_twin_sync(), run_twin_sync())


if __name__ == "__main__":
    unittest.main()
