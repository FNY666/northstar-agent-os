"""Tests for evaluator_access.py (one-hundred-thirteenth batch)."""

import unittest

from evaluator_access import (
    CHEAT_DETECTED_EVENT,
    EVALUATOR_MISMATCH_EVENT,
    EvaluationRegistry,
    EvaluatorAccessError,
    build_cheat_probe,
    cheat_probe,
    evaluator_audit_event,
)

T0 = 1_700_000_000
MODEL = "ab" * 32
OTHER = "cd" * 32


def _registry():
    return EvaluationRegistry()


def _register(reg, **over):
    kw = dict(
        evaluator_id="uk-aisi",
        model_digest=MODEL,
        checkpoint="ckpt-042",
        scope="cyber",
        evaluated_at=T0,
        expires_at=T0 + 1_000_000,
    )
    kw.update(over)
    return reg.register(**kw)


class InvocationGateTests(unittest.TestCase):
    def test_exact_pair_allowed(self):
        reg = _registry()
        _register(reg)
        v = reg.check_invocation(model_digest=MODEL, checkpoint="ckpt-042", now=T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "evaluated-invocation")

    def test_unknown_pair_denied(self):
        reg = _registry()
        _register(reg)
        v = reg.check_invocation(model_digest=OTHER, checkpoint="ckpt-042", now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, "unverifiable-evaluation")
        self.assertIn("no evaluation receipt", v.reason)

    def test_checkpoint_mismatch_denied(self):
        reg = _registry()
        _register(reg)
        v = reg.check_invocation(model_digest=MODEL, checkpoint="ckpt-043", now=T0)
        self.assertFalse(v.allowed)

    def test_expired_denied(self):
        reg = _registry()
        _register(reg)
        v = reg.check_invocation(
            model_digest=MODEL, checkpoint="ckpt-042", now=T0 + 2_000_000
        )
        self.assertFalse(v.allowed)
        self.assertIn("expired", v.reason)

    def test_revoked_denied(self):
        reg = _registry()
        _register(reg)
        self.assertTrue(reg.revoke(model_digest=MODEL, checkpoint="ckpt-042"))
        v = reg.check_invocation(model_digest=MODEL, checkpoint="ckpt-042", now=T0)
        self.assertFalse(v.allowed)
        self.assertIn("revoked", v.reason)

    def test_revoke_nothing_live(self):
        reg = _registry()
        self.assertFalse(reg.revoke(model_digest=MODEL, checkpoint="ckpt-042"))

    def test_empty_registry_denied(self):
        reg = _registry()
        v = reg.check_invocation(model_digest=MODEL, checkpoint="ckpt-042", now=T0)
        self.assertFalse(v.allowed)

    def test_bad_scope_rejected(self):
        reg = _registry()
        with self.assertRaises(EvaluatorAccessError):
            _register(reg, scope="marketing")

    def test_bad_digest_rejected(self):
        reg = _registry()
        with self.assertRaises(EvaluatorAccessError):
            _register(reg, model_digest="nope")

    def test_expiry_before_eval_rejected(self):
        reg = _registry()
        with self.assertRaises(EvaluatorAccessError):
            _register(reg, evaluated_at=T0, expires_at=T0)

    def test_chain_intact_and_tamper(self):
        reg = _registry()
        _register(reg)
        _register(reg, model_digest=OTHER, checkpoint="ckpt-009")
        ok, _ = reg.verify_chain()
        self.assertTrue(ok)
        import dataclasses
        first = reg._receipts[0]
        reg._receipts[0] = dataclasses.replace(first, scope="capability")
        ok, reason = reg.verify_chain()
        self.assertFalse(ok)
        self.assertIn("tampered", reason)

    def test_audit_events(self):
        reg = _registry()
        _register(reg)
        v = reg.check_invocation(model_digest=MODEL, checkpoint="ckpt-042", now=T0)
        self.assertEqual(
            evaluator_audit_event(v, model_digest=MODEL, checkpoint="ckpt-042")["event"],
            "evaluator.matched",
        )
        v2 = reg.check_invocation(model_digest=OTHER, checkpoint="ckpt-042", now=T0)
        self.assertEqual(
            evaluator_audit_event(v2, model_digest=OTHER)["event"],
            EVALUATOR_MISMATCH_EVENT,
        )


class CheatProbeTests(unittest.TestCase):
    def _probe(self):
        return build_cheat_probe(
            probe_id="cyber-shell-01",
            description="must demonstrate constrained shell use, not exfil shortcut",
            shortcut_markers=["curl_exfil", "pastebin_dump"],
            required_steps=["sandbox_check", "capability_demonstration"],
        )

    def test_clean_trace_passes(self):
        v = cheat_probe(self._probe(), ["sandbox_check", "capability_demonstration"])
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "verified-integrity")
        self.assertFalse(v.cheat_detected)

    def test_shortcut_detected(self):
        v = cheat_probe(
            self._probe(),
            ["sandbox_check", "curl_exfil", "capability_demonstration"],
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.cheat_detected)
        self.assertEqual(v.classification, "non_authoritative")
        self.assertIn("curl_exfil", v.reasons[0])
        ev = evaluator_audit_event(v, probe_id="cyber-shell-01")
        self.assertEqual(ev["event"], CHEAT_DETECTED_EVENT)

    def test_incomplete_trace(self):
        v = cheat_probe(self._probe(), ["sandbox_check"])
        self.assertFalse(v.allowed)
        self.assertFalse(v.cheat_detected)
        self.assertEqual(v.classification, "incomplete-trace")

    def test_empty_markers_rejected(self):
        with self.assertRaises(EvaluatorAccessError):
            build_cheat_probe(
                probe_id="p", description="d", shortcut_markers=[],
                required_steps=["a"],
            )

    def test_bad_trace_rejected(self):
        with self.assertRaises(EvaluatorAccessError):
            cheat_probe(self._probe(), "not-a-list")


if __name__ == "__main__":
    unittest.main()
