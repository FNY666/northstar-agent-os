"""Binary evidence tiers + LOG_DROP policy (eighty-seventh batch).

Covers ``evidence_tiers.py``:
- Binary classification: AUTHORITATIVE requires ALL of runtime authority,
  valid seal, complete window, no LOG_DROP, valid chain. Everything else
  (including sealed-with-drops) is NON_AUTHORITATIVE — no "partial"
  footgun, per Tesserae's verifier_core stance.
- Window classification over hash-chained audit records: authority
  isolation (agent may never emit runtime-authority events), link-by-link
  chain verification, sequence-gap detection (a gap without LOG_DROP is
  an integrity violation, fail closed).
- LOG_DROP construction: explicit, sequenced, hash-linkable; malformed
  ranges fail closed (a lying loss record is worse than none).
- Compaction policy: only agent-claimed informational records, with a
  receipt; runtime events, LOG_DROP records, seals, and decision records
  never compact.
- High-stakes gate: tier3+ decisions require AUTHORITATIVE evidence.
"""
from __future__ import annotations

import hashlib
import unittest

import support  # noqa: F401

import audit_chain
import evidence_tiers
from evidence_tiers import (
    HIGH_STAKES_TIERS,
    PRODUCER_AGENT,
    PRODUCER_RUNTIME,
    EvidenceTier,
    classify_audit_window,
    classify_evidence,
    compaction_receipt,
    digest_compacted_range,
    emit_log_drop,
    evidence_audit_event,
    may_compact,
    require_authoritative,
    trust_assumptions,
)


def _genesis() -> str:
    params = audit_chain.build_genesis_params("evidence-test", session_id="s1")
    return audit_chain.genesis_hash(params)


def _chain(records):
    """Chain raw records with audit_chain, assigning seq numbers first.

    seq is part of the hashed body (as in Tesserae), so it must be set
    before chaining, not after.
    """
    raw = list(records)
    for i, rec in enumerate(raw):
        rec.setdefault("seq", i + 1)
    return audit_chain.chain_records(raw, component="evidence-test", session_id="s1")


def _rec(event_type, producer=PRODUCER_RUNTIME):
    return {"event_type": event_type, "producer": producer, "note": "x"}


class TestClassifyEvidence(unittest.TestCase):
    def test_all_conditions_authoritative(self) -> None:
        c = classify_evidence(
            authority=PRODUCER_RUNTIME,
            sealed=True,
            complete=True,
            has_drops=False,
            chain_valid=True,
        )
        self.assertEqual(c.tier, EvidenceTier.AUTHORITATIVE)
        self.assertEqual(c.reasons, ())

    def test_each_missing_condition_disqualifies(self) -> None:
        base = dict(
            authority=PRODUCER_RUNTIME,
            sealed=True,
            complete=True,
            has_drops=False,
            chain_valid=True,
        )
        for flip in (
            {"authority": PRODUCER_AGENT},
            {"sealed": False},
            {"complete": False},
            {"has_drops": True},
            {"chain_valid": False},
        ):
            kwargs = {**base, **flip}
            c = classify_evidence(**kwargs)
            self.assertEqual(c.tier, EvidenceTier.NON_AUTHORITATIVE, flip)
            self.assertTrue(c.reasons, flip)

    def test_sealed_with_drops_is_not_partial(self) -> None:
        # The binary rule's whole point: a sealed chain WITH drops must not
        # launder itself through a "partial" middle rung.
        c = classify_evidence(
            authority=PRODUCER_RUNTIME,
            sealed=True,
            complete=True,
            has_drops=True,
            chain_valid=True,
        )
        self.assertEqual(c.tier, EvidenceTier.NON_AUTHORITATIVE)
        self.assertIn("LOG_DROP", c.reasons[0])

    def test_empty_window_fails_closed(self) -> None:
        c = classify_audit_window([], genesis_hash=_genesis())
        self.assertEqual(c.tier, EvidenceTier.NON_AUTHORITATIVE)


class TestClassifyAuditWindow(unittest.TestCase):
    def test_clean_runtime_window_is_authoritative(self) -> None:
        genesis = _genesis()
        events = _chain(
            [_rec("tool_call"), _rec("approval"), _rec("chain_seal")]
        )
        # Fix prev_hash of first record to the genesis we passed.
        c = classify_audit_window(events, genesis_hash=events[0]["prev_hash"])
        self.assertEqual(c.tier, EvidenceTier.AUTHORITATIVE)
        self.assertTrue(c.sealed)
        self.assertFalse(c.has_drops)

    def test_agent_claimed_record_disqualifies(self) -> None:
        events = _chain(
            [_rec("tool_call"), _rec("tool_result", PRODUCER_AGENT), _rec("chain_seal")]
        )
        c = classify_audit_window(events, genesis_hash=events[0]["prev_hash"])
        self.assertEqual(c.tier, EvidenceTier.NON_AUTHORITATIVE)
        self.assertIn("authority", c.reasons[0])

    def test_agent_spoofing_runtime_event_disqualifies(self) -> None:
        events = _chain([_rec("chain_seal", PRODUCER_AGENT)])
        c = classify_audit_window(events, genesis_hash=events[0]["prev_hash"])
        self.assertEqual(c.tier, EvidenceTier.NON_AUTHORITATIVE)

    def test_log_drop_downgrades_permanently(self) -> None:
        genesis = _genesis()
        drop = emit_log_drop(
            count=2,
            reason=evidence_tiers.LOG_DROP_REASON_BUFFER_OVERFLOW,
            seq_range_start=4,
            seq_range_end=5,
            session_id="s1",
            seq=99,
            prev_hash="0" * 64,
        )
        drop.pop("seq")
        drop.pop("prev_hash")
        events = _chain([_rec("tool_call"), drop, _rec("chain_seal")])
        c = classify_audit_window(events, genesis_hash=events[0]["prev_hash"])
        self.assertEqual(c.tier, EvidenceTier.NON_AUTHORITATIVE)
        self.assertTrue(c.has_drops)

    def test_tampered_chain_link_fails(self) -> None:
        events = _chain([_rec("tool_call"), _rec("chain_seal")])
        events[1]["chain_hash"] = "f" * 64  # tamper
        c = classify_audit_window(events, genesis_hash=events[0]["prev_hash"])
        self.assertEqual(c.tier, EvidenceTier.NON_AUTHORITATIVE)
        self.assertFalse(c.chain_valid)

    def test_sequence_gap_without_log_drop_fails_closed(self) -> None:
        # A genuine gap: records chained from the start with skipped seq
        # numbers, so the chain is valid but the sequence is not.
        raw = [_rec("tool_call"), _rec("chain_seal")]
        raw[0]["seq"] = 1
        raw[1]["seq"] = 47  # gap, no LOG_DROP to explain it
        events = audit_chain.chain_records(
            raw, component="evidence-test", session_id="s1"
        )
        c = classify_audit_window(events, genesis_hash=events[0]["prev_hash"])
        self.assertEqual(c.tier, EvidenceTier.NON_AUTHORITATIVE)
        self.assertTrue(c.chain_valid)  # chain itself is fine...
        self.assertFalse(c.complete)  # ...but the window is not complete

    def test_missing_seal_is_not_authoritative(self) -> None:
        events = _chain([_rec("tool_call"), _rec("approval")])
        c = classify_audit_window(events, genesis_hash=events[0]["prev_hash"])
        self.assertEqual(c.tier, EvidenceTier.NON_AUTHORITATIVE)
        self.assertFalse(c.sealed)


class TestLogDrop(unittest.TestCase):
    def test_build_valid(self) -> None:
        drop = emit_log_drop(
            count=3,
            reason=evidence_tiers.LOG_DROP_REASON_AUTHORITY_VIOLATION,
            seq_range_start=10,
            seq_range_end=12,
            session_id="s1",
            seq=13,
            prev_hash="a" * 64,
        )
        self.assertEqual(drop["event_type"], "evidence.log_drop")
        self.assertEqual(drop["count"], 3)
        self.assertEqual(drop["reason"], "authority_violation")
        self.assertEqual(
            (drop["seq_range_start"], drop["seq_range_end"]), (10, 12)
        )

    def test_zero_count_rejected(self) -> None:
        with self.assertRaises(ValueError):
            emit_log_drop(
                count=0,
                reason=evidence_tiers.LOG_DROP_REASON_BUFFER_OVERFLOW,
                seq_range_start=1,
                seq_range_end=1,
                session_id="s1",
                seq=2,
                prev_hash="a" * 64,
            )

    def test_inverted_range_rejected(self) -> None:
        with self.assertRaises(ValueError):
            emit_log_drop(
                count=1,
                reason=evidence_tiers.LOG_DROP_REASON_INTERNAL_ERROR,
                seq_range_start=5,
                seq_range_end=4,
                session_id="s1",
                seq=6,
                prev_hash="a" * 64,
            )

    def test_unknown_reason_rejected(self) -> None:
        with self.assertRaises(ValueError):
            emit_log_drop(
                count=1,
                reason="mystery",
                seq_range_start=1,
                seq_range_end=1,
                session_id="s1",
                seq=2,
                prev_hash="a" * 64,
            )

    def test_drop_participates_in_chain(self) -> None:
        drop = emit_log_drop(
            count=1,
            reason=evidence_tiers.LOG_DROP_REASON_BUFFER_OVERFLOW,
            seq_range_start=2,
            seq_range_end=2,
            session_id="s1",
            seq=99,
            prev_hash="b" * 64,
        )
        drop.pop("seq")
        drop.pop("prev_hash")
        events = _chain([_rec("tool_call"), drop, _rec("chain_seal")])
        c = classify_audit_window(events, genesis_hash=events[0]["prev_hash"])
        # The chain still verifies link-by-link; only the tier drops.
        self.assertTrue(c.chain_valid)
        self.assertEqual(c.tier, EvidenceTier.NON_AUTHORITATIVE)


class TestCompactionPolicy(unittest.TestCase):
    def test_agent_informational_may_compact_with_receipt(self) -> None:
        v = may_compact(_rec("tool_result", PRODUCER_AGENT))
        self.assertTrue(v.allowed)

    def test_runtime_records_never_compact(self) -> None:
        v = may_compact(_rec("tool_call", PRODUCER_RUNTIME))
        self.assertFalse(v.allowed)

    def test_log_drop_never_compacted(self) -> None:
        drop = emit_log_drop(
            count=1,
            reason=evidence_tiers.LOG_DROP_REASON_BUFFER_OVERFLOW,
            seq_range_start=1,
            seq_range_end=1,
            session_id="s1",
            seq=2,
            prev_hash="a" * 64,
        )
        v = may_compact(drop)
        self.assertFalse(v.allowed)

    def test_seal_never_compacted(self) -> None:
        v = may_compact(_rec("chain_seal"))
        self.assertFalse(v.allowed)

    def test_approval_record_never_compacted(self) -> None:
        v = may_compact(_rec("approval"))
        self.assertFalse(v.allowed)

    def test_compaction_receipt_round_trip(self) -> None:
        hashes = ["ab" * 32, "cd" * 32]
        digest = digest_compacted_range(hashes)
        self.assertEqual(
            digest, hashlib.sha256(bytes.fromhex("ab" * 32 + "cd" * 32)).hexdigest()
        )
        receipt = compaction_receipt(
            seq_range_start=1,
            seq_range_end=2,
            event_count=2,
            range_digest=digest,
            session_id="s1",
            seq=3,
            prev_hash="a" * 64,
        )
        self.assertEqual(receipt["event_type"], "evidence.compaction_receipt")
        self.assertEqual(receipt["producer"], PRODUCER_RUNTIME)

    def test_bad_digest_rejected(self) -> None:
        with self.assertRaises(ValueError):
            compaction_receipt(
                seq_range_start=1,
                seq_range_end=2,
                event_count=2,
                range_digest="not-hex",
                session_id="s1",
                seq=3,
                prev_hash="a" * 64,
            )

    def test_bad_chain_hash_rejected(self) -> None:
        with self.assertRaises(ValueError):
            digest_compacted_range(["zzz"])


class TestHighStakesGate(unittest.TestCase):
    def _auth(self):
        return classify_evidence(
            authority=PRODUCER_RUNTIME,
            sealed=True,
            complete=True,
            has_drops=False,
            chain_valid=True,
        )

    def _nonauth(self):
        return classify_evidence(
            authority=PRODUCER_RUNTIME,
            sealed=True,
            complete=True,
            has_drops=True,
            chain_valid=True,
        )

    def test_low_tier_passes_with_any_evidence(self) -> None:
        r = require_authoritative(self._nonauth(), "tier1")
        self.assertTrue(r.allowed)

    def test_high_tier_requires_authoritative(self) -> None:
        for tier in sorted(HIGH_STAKES_TIERS):
            r = require_authoritative(self._auth(), tier)
            self.assertTrue(r.allowed, tier)
            r = require_authoritative(self._nonauth(), tier)
            self.assertFalse(r.allowed, tier)
            self.assertIn("denied", r.reason)

    def test_denial_names_the_reason(self) -> None:
        r = require_authoritative(self._nonauth(), "tier3")
        self.assertIn("LOG_DROP", r.reason)

    def test_unknown_tier_is_not_high_stakes(self) -> None:
        r = require_authoritative(self._nonauth(), "tier9")
        self.assertTrue(r.allowed)


class TestTrustAssumptions(unittest.TestCase):
    def test_hardcoded_not_configurable(self) -> None:
        ta = trust_assumptions()
        self.assertFalse(ta["byzantine_host_defended"])
        self.assertFalse(ta["session_freshness_verified"])
        self.assertEqual(ta["instrumentation_complete"], "unknown")
        self.assertFalse(ta["agent_claims_trusted"])
        # No parameters accepted: the signature takes nothing.
        import inspect

        self.assertEqual(list(inspect.signature(trust_assumptions).parameters), [])

    def test_evidence_audit_event_kinds(self) -> None:
        ev = evidence_audit_event(
            kind="evidence.gate_denied",
            tier=EvidenceTier.NON_AUTHORITATIVE,
            detail="tier3 without authoritative evidence",
            session_id="s1",
            seq=7,
            prev_hash="a" * 64,
        )
        self.assertEqual(ev["producer"], PRODUCER_RUNTIME)
        self.assertEqual(ev["evidence_tier"], "non_authoritative")
        with self.assertRaises(ValueError):
            evidence_audit_event(
                kind="evidence.made_up",
                tier=EvidenceTier.AUTHORITATIVE,
                detail="x",
                session_id="s1",
                seq=1,
                prev_hash="a" * 64,
            )


if __name__ == "__main__":
    unittest.main()
