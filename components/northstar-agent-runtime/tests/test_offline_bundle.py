"""Tests for offline_bundle (ninety-seventh batch)."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ed25519
from offline_bundle import (
    BUNDLE_SCHEMA_VERSION,
    BundleEnvelope,
    BundleError,
    BundleVerdict,
    bundle_audit_event,
    canonical_json,
    compile_bundle,
    offline_check,
    run_offline_bundle,
    sha256_hex,
    verify_bundle,
)


SEED = bytes(range(32))
PUB = ed25519.public_key(SEED)
OTHER_SEED = bytes([200 - b for b in range(32)])
OTHER_PUB = ed25519.public_key(OTHER_SEED)

TOOLS = {
    "sensor.read": {
        "name": "sensor.read",
        "description": "read a sensor",
        "params": [{"name": "channel", "type": "string", "required": True}],
    },
    "actuator.move": {
        "name": "actuator.move",
        "description": "move an actuator",
        "params": [{"name": "position", "type": "integer", "required": True}],
    },
}

POLICY = [
    {"tool": "sensor.read", "effect": "allow", "conditions": []},
    {"tool": "actuator.move", "effect": "allow",
     "conditions": [{"arg": "position", "type": "integer"}]},
    {"tool": "actuator.move", "effect": "deny",
     "conditions": [{"arg": "position", "equals": 999}]},
]

T0 = 1_800_000_000
CEILING = 86_400
EXP = T0 + 7 * 86_400


def make_bundle(version=3, **kw):
    params = dict(
        policy=POLICY, tools=TOOLS, expiry_epoch=EXP,
        issuer_secret=SEED, bundle_version=version,
        staleness_ceiling_s=CEILING, issued_at=T0,
    )
    params.update(kw)
    return compile_bundle(**params)


def digests():
    from offline_bundle import _tool_digest

    return {n: _tool_digest(d) for n, d in TOOLS.items()}


def verify(b, **kw):
    params = dict(issuer_pubkey=PUB, now_epoch=T0 + 100, min_version=3,
                  registry_digests=digests())
    params.update(kw)
    return verify_bundle(b, **params)


class CompileTests(unittest.TestCase):
    def test_valid_bundle_verifies(self):
        v = verify(make_bundle())
        self.assertTrue(v.ok, v.reason)
        self.assertEqual(v.reason, "bundle verified")

    def test_signature_covers_canonical_bytes(self):
        b = make_bundle()
        payload = {k: v for k, v in b.items() if k != "signature"}
        canon = canonical_json(payload).encode()
        self.assertTrue(ed25519.verify(PUB, canon, bytes.fromhex(b["signature"])))

    def test_rejects_empty_policy(self):
        with self.assertRaises(BundleError):
            make_bundle(policy=[])

    def test_rejects_policy_naming_unknown_tool(self):
        bad = [{"tool": "nope.tool", "effect": "allow", "conditions": []}]
        with self.assertRaises(BundleError):
            make_bundle(policy=bad)

    def test_rejects_expiry_before_issue(self):
        with self.assertRaises(BundleError):
            make_bundle(expiry_epoch=T0 - 1)

    def test_rejects_bad_secret_length(self):
        with self.assertRaises(BundleError):
            make_bundle(issuer_secret=b"short")

    def test_rejects_nonpositive_version(self):
        with self.assertRaises(BundleError):
            make_bundle(bundle_version=0)

    def test_rejects_invalid_regex_condition(self):
        bad = [{"tool": "sensor.read", "effect": "allow",
                "conditions": [{"arg": "channel", "pattern": "(unclosed"}]}]
        with self.assertRaises(BundleError):
            make_bundle(policy=bad)


class VerifyTests(unittest.TestCase):
    def test_expired_bundle_denied(self):
        v = verify(make_bundle(), now_epoch=EXP + 1)
        self.assertFalse(v.ok)
        self.assertIn("expired", v.reason)

    def test_tampered_payload_denied(self):
        b = json.loads(json.dumps(make_bundle()))
        b["policy"][0]["effect"] = "deny"
        v = verify(b)
        self.assertFalse(v.ok)
        self.assertIn("signature invalid", v.reason)

    def test_tampered_signature_denied(self):
        b = dict(make_bundle())
        b["signature"] = "00" * 64
        v = verify(b)
        self.assertFalse(v.ok)

    def test_rollback_denied(self):
        b = make_bundle(version=2)
        v = verify(b, min_version=3)
        self.assertFalse(v.ok)
        self.assertIn("rollback", v.reason)

    def test_unknown_signer_denied(self):
        b = make_bundle(issuer_secret=OTHER_SEED)
        v = verify(b)
        self.assertFalse(v.ok)
        self.assertIn("unknown signer", v.reason)

    def test_stale_policy_denied(self):
        v = verify(make_bundle(), now_epoch=T0 + CEILING + 1)
        self.assertFalse(v.ok)
        self.assertIn("stale", v.reason)

    def test_digest_mismatch_denied(self):
        d = digests()
        d["sensor.read"] = "ff" * 64
        v = verify(make_bundle(), registry_digests=d)
        self.assertFalse(v.ok)
        self.assertIn("digest mismatch", v.reason)

    def test_malformed_bundle_never_raises(self):
        for bad in (None, 42, "bundle", {}, {"signature": "zz"},
                    {"signature": "00" * 64}):
            v = verify_bundle(bad, issuer_pubkey=PUB, now_epoch=T0,
                              min_version=1)
            self.assertFalse(v.ok, bad)

    def test_verify_never_raises_on_garbage(self):
        v = verify_bundle({"signature": "00" * 64, "schema_version": 999},
                          issuer_pubkey=PUB, now_epoch=T0, min_version=1)
        self.assertFalse(v.ok)


class GateTests(unittest.TestCase):
    def test_allow_matching_rule(self):
        v = verify(make_bundle())
        ok, reason = offline_check(v, "sensor.read", {"channel": "a"})
        self.assertTrue(ok, reason)

    def test_explicit_deny_wins(self):
        v = verify(make_bundle())
        ok, reason = offline_check(v, "actuator.move", {"position": 999})
        self.assertFalse(ok)
        self.assertIn("explicit deny", reason)

    def test_unknown_tool_denied(self):
        v = verify(make_bundle())
        ok, _ = offline_check(v, "net.egress", {})
        self.assertFalse(ok)

    def test_no_allow_rule_denied(self):
        v = verify(make_bundle())
        ok, reason = offline_check(v, "actuator.move", {"position": "fast"})
        self.assertFalse(ok)
        self.assertIn("default-deny", reason)

    def test_unverified_bundle_authorizes_nothing(self):
        bad = BundleVerdict(ok=False, reason="expired")
        ok, reason = offline_check(bad, "sensor.read", {"channel": "a"})
        self.assertFalse(ok)
        self.assertIn("must not operate", reason)

    def test_condition_type_check(self):
        v = verify(make_bundle())
        ok, _ = offline_check(v, "actuator.move", {"position": 5})
        self.assertTrue(ok)
        ok, _ = offline_check(v, "actuator.move", {})
        self.assertFalse(ok)  # absent arg fails strict


class AuditTests(unittest.TestCase):
    def test_audit_event_shape(self):
        v = verify(make_bundle())
        ev = bundle_audit_event(v, tool_name="sensor.read")
        self.assertEqual(ev["event"], "offline_bundle.verified")
        self.assertEqual(ev["bundle_version"], 3)
        bad = verify(make_bundle(), now_epoch=EXP + 1)
        ev2 = bundle_audit_event(bad)
        self.assertEqual(ev2["event"], "offline_bundle.denied")


class CorpusTests(unittest.TestCase):
    def test_corpus_ground_truth_closed(self):
        m = run_offline_bundle()
        self.assertEqual(m["n_scenarios"], 12)
        self.assertEqual(m["mismatches"], [])
        self.assertEqual(m["allowed_ids"], [
            "allow_valid_bundle",
            "allow_actuator_valid_arg",
            "allow_newer_version",
            "allow_no_registry_check",
        ])
        self.assertIn("rollback", m["rollback_detail"])
        self.assertIn("stale", m["stale_detail"])
        self.assertIn("digest mismatch", m["digest_detail"])
        self.assertIn("unknown signer", m["signer_detail"])
        self.assertIn("expired", m["expired_detail"])
        self.assertIn("signature invalid", m["tamper_detail"])

    def test_corpus_deterministic(self):
        a = run_offline_bundle()
        b = run_offline_bundle()
        self.assertEqual(a["allowed_ids"], b["allowed_ids"])
        self.assertEqual(a["mismatches"], b["mismatches"])


if __name__ == "__main__":
    unittest.main()
