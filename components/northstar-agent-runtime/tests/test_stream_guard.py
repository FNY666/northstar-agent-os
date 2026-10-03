"""Tests for the streaming output guard (one-hundred-sixth batch)."""
from __future__ import annotations

import unittest

from stream_guard import (
    CHUNK_HALT,
    CHUNK_RELEASE,
    DENY_MALFORMED_CHUNK,
    DENY_MALFORMED_POLICY,
    DENY_PATTERN_MATCH,
    DENY_RISK_BUDGET,
    DENY_STALE_GUARD,
    STREAM_HALTED_EVENT,
    STREAM_REFUSED_EVENT,
    STREAM_RELEASED_EVENT,
    UNVERIFIABLE_STREAM,
    VERIFIED_STREAM,
    DenyPattern,
    GuardPolicy,
    classify_stream,
    default_policy,
    guard_liveness,
    screen_chunk,
    screen_stream,
    verify_chain,
)


def _pin(policy: GuardPolicy) -> str:
    return policy.digest()


class TestPolicyValidation(unittest.TestCase):
    def test_default_policy_valid_and_pinned(self):
        policy = default_policy()
        self.assertIsNone(policy.validate())
        self.assertTrue(guard_liveness(policy, _pin(policy))["live"])

    def test_empty_pattern_malforms_policy(self):
        policy = GuardPolicy("p", "v1", (DenyPattern("", 1, "r"),))
        self.assertEqual(policy.validate(), DENY_MALFORMED_POLICY)
        self.assertFalse(guard_liveness(policy, "anything")["live"])

    def test_nonpositive_weight_malforms_policy(self):
        policy = GuardPolicy("p", "v1", (DenyPattern("x", 0, "r"),))
        self.assertEqual(policy.validate(), DENY_MALFORMED_POLICY)

    def test_duplicate_pattern_malforms_policy(self):
        policy = GuardPolicy(
            "p", "v1", (DenyPattern("x", 1, "r1"), DenyPattern("x", 2, "r2"))
        )
        self.assertEqual(policy.validate(), DENY_MALFORMED_POLICY)

    def test_digest_changes_when_policy_changes(self):
        a = default_policy()
        b = GuardPolicy(
            "northstar.stream-guard.default",
            "2026-10-04",
            a.deny_patterns + (DenyPattern("evil", 1, "evil"),),
            0,
            64,
        )
        self.assertNotEqual(a.digest(), b.digest())
        # A swapped-in weaker policy fails liveness against the old pin.
        self.assertEqual(
            guard_liveness(b, _pin(a))["reason"], DENY_STALE_GUARD
        )


class TestGuardLiveness(unittest.TestCase):
    def test_stale_guard_refused(self):
        policy = default_policy()
        live = guard_liveness(policy, "deadbeef" * 8)
        self.assertFalse(live["live"])
        self.assertEqual(live["reason"], DENY_STALE_GUARD)

    def test_empty_pin_is_unknown_guard(self):
        policy = default_policy()
        live = guard_liveness(policy, "")
        self.assertFalse(live["live"])


class TestScreenStream(unittest.TestCase):
    def test_clean_stream_releases_all(self):
        policy = default_policy()
        result = screen_stream(
            ["Hello, ", "this is ", "a clean stream."],
            policy,
            _pin(policy),
            stream_label="t1",
        )
        self.assertFalse(result.halted)
        self.assertEqual(result.released, ["Hello, ", "this is ", "a clean stream."])
        self.assertEqual(result.classification, VERIFIED_STREAM)
        self.assertEqual(len(result.receipts), 3)
        self.assertTrue(all(r.verdict == CHUNK_RELEASE for r in result.receipts))

    def test_midstream_violation_halts_immediately(self):
        policy = default_policy()
        result = screen_stream(
            ["safe prefix ", "leaking sk-live-abc123 now ", "never released"],
            policy,
            _pin(policy),
            stream_label="t2",
        )
        self.assertTrue(result.halted)
        self.assertEqual(result.halt_index, 1)
        self.assertEqual(result.halt_reason, DENY_PATTERN_MATCH)
        self.assertEqual(result.released, ["safe prefix "])
        self.assertEqual(result.classification, UNVERIFIABLE_STREAM)
        self.assertIn("live_secret_key_prefix", result.receipts[1].matched)

    def test_boundary_split_pattern_caught(self):
        # The deny pattern is split across the chunk boundary; the
        # overlap window must still catch it.
        policy = default_policy()
        result = screen_stream(
            ["token sk-", "live-xyz follows"],
            policy,
            _pin(policy),
            stream_label="t3",
        )
        self.assertTrue(result.halted)
        self.assertEqual(result.halt_index, 1)
        self.assertIn("live_secret_key_prefix", result.receipts[1].matched)

    def test_stale_guard_releases_nothing(self):
        policy = default_policy()
        result = screen_stream(
            ["anything at all"], policy, "wrong" * 16, stream_label="t4"
        )
        self.assertTrue(result.halted)
        self.assertEqual(result.halt_reason, DENY_STALE_GUARD)
        self.assertEqual(result.released, [])
        self.assertEqual(result.receipts, [])

    def test_malformed_chunk_halts(self):
        policy = default_policy()
        result = screen_stream(
            ["ok ", 123, "later"], policy, _pin(policy), stream_label="t5"
        )
        self.assertTrue(result.halted)
        self.assertEqual(result.halt_index, 1)
        self.assertEqual(result.halt_reason, DENY_MALFORMED_CHUNK)

    def test_empty_stream_is_verified(self):
        policy = default_policy()
        result = screen_stream([], policy, _pin(policy), stream_label="t6")
        self.assertFalse(result.halted)
        self.assertEqual(result.classification, VERIFIED_STREAM)

    def test_risk_budget_semantics(self):
        budgeted = GuardPolicy(
            "p",
            "v1",
            (
                DenyPattern("low-a", 1, "low_a"),
                DenyPattern("low-b", 1, "low_b"),
            ),
            max_chunk_risk=1,
            overlap_bytes=8,
        )
        pin = _pin(budgeted)
        ok = screen_stream(["has low-a only"], budgeted, pin, stream_label="t7a")
        self.assertFalse(ok.halted)
        over = screen_stream(
            ["has low-a and low-b"], budgeted, pin, stream_label="t7b"
        )
        self.assertTrue(over.halted)
        self.assertEqual(over.halt_reason, DENY_RISK_BUDGET)

    def test_second_opinion_is_advisory_not_gating(self):
        policy = default_policy()
        calls: list[str] = []

        def noisy_opinion(text: str) -> dict:
            calls.append(text)
            return {"flagged": True, "reason": "model thinks this is bad"}

        result = screen_stream(
            ["perfectly clean text"],
            policy,
            _pin(policy),
            stream_label="t8",
            second_opinion=noisy_opinion,
        )
        self.assertFalse(result.halted)
        self.assertEqual(calls, ["perfectly clean text"])

    def test_zero_overlap_is_legal_but_recorded(self):
        policy = GuardPolicy("p", "v1", (), 0, 0)
        result = screen_stream(["a", "b"], policy, _pin(policy), stream_label="t9")
        self.assertFalse(result.halted)
        import hashlib

        empty = hashlib.sha256(b"").hexdigest()
        self.assertTrue(all(r.window_digest == empty for r in result.receipts))


class TestChainVerification(unittest.TestCase):
    def _clean(self, label: str = "chain"):
        policy = default_policy()
        result = screen_stream(
            ["alpha ", "beta ", "gamma"], policy, _pin(policy), stream_label=label
        )
        return policy, result

    def test_clean_chain_verifies(self):
        policy, result = self._clean()
        check = verify_chain(result.receipts, result.released, policy)
        self.assertTrue(check["ok"], check["reason"])

    def test_dropped_receipt_detected(self):
        policy, result = self._clean()
        check = verify_chain(result.receipts[:2], result.released[:2], policy)
        # indices 0,1 verify fine on their own...
        self.assertTrue(check["ok"])
        # ...but the released stream had 3 chunks: count mismatch on full list.
        check2 = verify_chain(result.receipts[:2], result.released, policy)
        self.assertFalse(check2["ok"])

    def test_tampered_receipt_detected(self):
        policy, result = self._clean()
        tampered = [
            __import__("dataclasses").replace(result.receipts[1], risk=999)
        ]
        receipts = [result.receipts[0], tampered[0], result.receipts[2]]
        check = verify_chain(receipts, result.released, policy)
        self.assertFalse(check["ok"])
        self.assertIn("receipt digest mismatch", check["reason"])

    def test_narrowed_window_detected(self):
        policy = default_policy()
        result = screen_stream(
            ["alpha ", "beta ", "gamma"], policy, _pin(policy), stream_label="w1"
        )
        self.assertFalse(result.halted)
        # Attacker narrows the overlap window when re-verifying.
        narrow = GuardPolicy(
            policy.policy_id,
            policy.version,
            policy.deny_patterns,
            policy.max_chunk_risk,
            1,
        )
        check = verify_chain(result.receipts, result.released, narrow)
        self.assertFalse(check["ok"])
        self.assertIn("overlap window inconsistent", check["reason"])

    def test_chunks_after_halt_detected(self):
        policy = default_policy()
        result = screen_stream(
            ["safe ", "sk-live-abc"], policy, _pin(policy), stream_label="h1"
        )
        self.assertTrue(result.halted)
        # Host appends an unscreened chunk after the halt.
        check = verify_chain(
            result.receipts, result.released + ["smuggled"], policy
        )
        self.assertFalse(check["ok"])

    def test_window_digest_matches_emitted_tail(self):
        policy, result = self._clean("wtail")
        import hashlib

        for i, receipt in enumerate(result.receipts):
            expected = "".join(result.released[:i])[-policy.overlap_bytes :]
            self.assertEqual(
                receipt.window_digest,
                hashlib.sha256(expected.encode()).hexdigest(),
            )


class TestAuditAndClassification(unittest.TestCase):
    def test_audit_events(self):
        policy = default_policy()
        pin = _pin(policy)
        clean = screen_stream(["ok"], policy, pin, stream_label="a1")
        self.assertEqual(clean.audit_event()["event"], STREAM_RELEASED_EVENT)
        halted = screen_stream(["x sk-live-1"], policy, pin, stream_label="a2")
        ev = halted.audit_event()
        self.assertEqual(ev["event"], STREAM_HALTED_EVENT)
        self.assertEqual(ev["halt_reason"], DENY_PATTERN_MATCH)
        refused = screen_stream(["x"], policy, "nope" * 16, stream_label="a3")
        self.assertEqual(refused.audit_event()["event"], STREAM_REFUSED_EVENT)

    def test_classify_stream(self):
        policy = default_policy()
        pin = _pin(policy)
        self.assertEqual(
            classify_stream(screen_stream(["ok"], policy, pin, stream_label="c1")),
            VERIFIED_STREAM,
        )
        self.assertEqual(classify_stream(None), UNVERIFIABLE_STREAM)

    def test_screen_chunk_direct(self):
        policy = default_policy()
        ok = screen_chunk("hello", "", policy)
        self.assertEqual(ok.verdict, CHUNK_RELEASE)
        bad = screen_chunk("key AKIA123", "", policy)
        self.assertEqual(bad.verdict, CHUNK_HALT)
        self.assertIn("aws_access_key_prefix", bad.matched)


if __name__ == "__main__":
    unittest.main()
