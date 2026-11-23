"""Tests for apikey_manager."""

import unittest

from apikey_manager import (
    APIKeyError,
    APIKeyManager,
    APIKEY_MANAGER_VERSION,
    AlreadyRevokedError,
    DuplicateKeyError,
    KEY_HEX_LEN,
    KEY_PREFIX,
    RevokedKeyError,
    SCHEMA_PIN,
    SeqOrderError,
    UnknownKeyError,
    apikey_manager_audit_event,
)

SEED = b"apikey-manager-test-seed-32bytes!!!!!"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(APIKEY_MANAGER_VERSION, "apikey-manager.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.apikey-manager.v1")


class TestIssue(unittest.TestCase):
    def test_issue_happy_path(self):
        mgr = APIKeyManager(seed=SEED)
        key = mgr.issue("k-1", "billing", 1, scopes=("write", "read"))
        self.assertEqual(key.key_id, "k-1")
        self.assertEqual(key.name, "billing")
        self.assertEqual(key.scopes, ("read", "write"))  # sorted
        self.assertTrue(key.secret.startswith(KEY_PREFIX))
        self.assertEqual(len(key.secret), len(KEY_PREFIX) + KEY_HEX_LEN)
        int(key.secret[len(KEY_PREFIX):], 16)  # hex body
        self.assertTrue(key.key_digest.startswith("sha256:"))
        self.assertTrue(key.digest.startswith("sha256:"))
        self.assertEqual(key.issued_seq, 1)
        self.assertIsNone(key.expires_at_seq)

    def test_issue_digest_deterministic_with_seed(self):
        a = APIKeyManager(seed=SEED).issue("k-1", "n", 1)
        b = APIKeyManager(seed=SEED).issue("k-1", "n", 1)
        self.assertEqual(a.secret, b.secret)
        self.assertEqual(a.digest, b.digest)

    def test_issue_different_seed_different_secret(self):
        a = APIKeyManager(seed=SEED).issue("k-1", "n", 1)
        b = APIKeyManager(seed=b"other-test-seed-32bytes!!!!!!!!!!").issue(
            "k-1", "n", 1
        )
        self.assertNotEqual(a.secret, b.secret)

    def test_duplicate_key_id_refused(self):
        mgr = APIKeyManager(seed=SEED)
        mgr.issue("k-1", "a", 1)
        with self.assertRaises(DuplicateKeyError):
            mgr.issue("k-1", "b", 2)

    def test_bad_inputs(self):
        mgr = APIKeyManager(seed=SEED)
        with self.assertRaises(APIKeyError):
            mgr.issue("", "n", 1)
        with self.assertRaises(APIKeyError):
            mgr.issue("k-1", "", 1)
        with self.assertRaises(APIKeyError):
            mgr.issue("k-1", "n", -1)
        with self.assertRaises(APIKeyError):
            mgr.issue("k-1", "n", True)
        with self.assertRaises(APIKeyError):
            mgr.issue("k-1", "n", 1, scopes=("read", "read"))
        with self.assertRaises(APIKeyError):
            mgr.issue("k-1", "n", 1, scopes=("ok", ""))

    def test_born_expired_refused(self):
        mgr = APIKeyManager(seed=SEED)
        with self.assertRaises(APIKeyError):
            mgr.issue("k-1", "n", 5, expires_at_seq=5)
        with self.assertRaises(APIKeyError):
            mgr.issue("k-1", "n", 5, expires_at_seq=4)


class TestVerify(unittest.TestCase):
    def test_verify_ok(self):
        mgr = APIKeyManager(seed=SEED)
        key = mgr.issue("k-1", "n", 1)
        report = mgr.verify(key.secret, at_seq=2)
        self.assertTrue(report.valid)
        self.assertEqual(report.key_id, "k-1")
        self.assertEqual(report.reason, "ok")
        self.assertTrue(report.digest.startswith("sha256:"))

    def test_verify_unknown(self):
        mgr = APIKeyManager(seed=SEED)
        report = mgr.verify(KEY_PREFIX + "a" * KEY_HEX_LEN, at_seq=1)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, "unknown")
        self.assertIsNone(report.key_id)

    def test_verify_malformed_is_data(self):
        mgr = APIKeyManager(seed=SEED)
        for bad in ("", "nope", KEY_PREFIX + "zzz", KEY_PREFIX + "0"):
            report = mgr.verify(bad, at_seq=1)
            self.assertFalse(report.valid)
            self.assertEqual(report.reason, "malformed")

    def test_verify_wrong_type_raises(self):
        mgr = APIKeyManager(seed=SEED)
        with self.assertRaises(APIKeyError):
            mgr.verify(None, at_seq=1)
        with self.assertRaises(APIKeyError):
            mgr.verify(b"bytes", at_seq=1)

    def test_verify_expired(self):
        mgr = APIKeyManager(seed=SEED)
        key = mgr.issue("k-1", "n", 1, expires_at_seq=10)
        self.assertTrue(mgr.verify(key.secret, at_seq=9).valid)
        expired = mgr.verify(key.secret, at_seq=10)
        self.assertFalse(expired.valid)
        self.assertEqual(expired.reason, "expired")


class TestRevoke(unittest.TestCase):
    def test_revoke_terminal(self):
        mgr = APIKeyManager(seed=SEED)
        key = mgr.issue("k-1", "n", 1)
        rec = mgr.revoke("k-1", 2, reason="compromised")
        self.assertEqual(rec.key_id, "k-1")
        self.assertEqual(rec.reason, "compromised")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertFalse(mgr.verify(key.secret, at_seq=3).valid)
        self.assertEqual(mgr.verify(key.secret, at_seq=3).reason, "revoked")
        self.assertTrue(mgr.key("k-1").revoked)
        self.assertIsNotNone(mgr.revocation("k-1"))

    def test_double_revoke_refused(self):
        mgr = APIKeyManager(seed=SEED)
        mgr.issue("k-1", "n", 1)
        mgr.revoke("k-1", 2)
        with self.assertRaises(AlreadyRevokedError):
            mgr.revoke("k-1", 3)

    def test_revoke_unknown_refused(self):
        mgr = APIKeyManager(seed=SEED)
        with self.assertRaises(UnknownKeyError):
            mgr.revoke("nope", 1)


class TestRotate(unittest.TestCase):
    def test_rotate_replaces(self):
        mgr = APIKeyManager(seed=SEED)
        old = mgr.issue("k-1", "svc", 1, scopes=("read",))
        new_key, rotation = mgr.rotate("k-1", "k-1b", 2)
        self.assertEqual(rotation.old_key_id, "k-1")
        self.assertEqual(rotation.new_key_id, "k-1b")
        self.assertEqual(new_key.name, "svc")
        self.assertEqual(new_key.scopes, ("read",))
        self.assertNotEqual(new_key.secret, old.secret)
        self.assertTrue(mgr.verify(new_key.secret, at_seq=3).valid)
        self.assertEqual(mgr.verify(old.secret, at_seq=3).reason, "revoked")
        self.assertEqual(len(mgr.rotations()), 1)

    def test_rotate_unknown_or_revoked(self):
        mgr = APIKeyManager(seed=SEED)
        with self.assertRaises(UnknownKeyError):
            mgr.rotate("nope", "new", 1)
        mgr.issue("k-1", "n", 2)
        mgr.revoke("k-1", 3)
        with self.assertRaises(RevokedKeyError):
            mgr.rotate("k-1", "k-2", 4)

    def test_rotate_duplicate_new_id(self):
        mgr = APIKeyManager(seed=SEED)
        mgr.issue("k-1", "a", 1)
        mgr.issue("k-2", "b", 2)
        with self.assertRaises(DuplicateKeyError):
            mgr.rotate("k-1", "k-2", 3)


class TestViews(unittest.TestCase):
    def test_key_info_has_no_secret(self):
        mgr = APIKeyManager(seed=SEED)
        mgr.issue("k-1", "n", 1)
        info = mgr.key("k-1")
        self.assertEqual(info.key_id, "k-1")
        self.assertFalse(info.revoked)
        self.assertNotIn("secret", info.as_dict())

    def test_active_ids(self):
        mgr = APIKeyManager(seed=SEED)
        a = mgr.issue("a", "n", 1)
        b = mgr.issue("b", "n", 2, expires_at_seq=5)
        mgr.issue("c", "n", 3)
        mgr.revoke("c", 4)
        self.assertEqual(mgr.active_ids(at_seq=4), ("a", "b"))
        self.assertEqual(mgr.active_ids(at_seq=5), ("a",))
        self.assertEqual(mgr.key_ids(), ("a", "b", "c"))
        self.assertTrue(mgr.verify(a.secret, at_seq=4).valid)
        self.assertTrue(mgr.verify(b.secret, at_seq=4).valid)

    def test_seq_order_enforced(self):
        mgr = APIKeyManager(seed=SEED)
        mgr.issue("k-1", "n", 5)
        with self.assertRaises(SeqOrderError):
            mgr.issue("k-2", "n", 5)
        with self.assertRaises(SeqOrderError):
            mgr.revoke("k-1", 4)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        event = apikey_manager_audit_event(
            "issued", 1, {"key_id": "k-1", "scopes": ["read"]}
        )
        self.assertEqual(event["kind"], "issued")
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["version"], APIKEY_MANAGER_VERSION)
        self.assertEqual(event["audit_seq"], 1)

    def test_audit_rejects_secret(self):
        with self.assertRaises(APIKeyError):
            apikey_manager_audit_event("issued", 1, {"secret": "leak"})
        with self.assertRaises(APIKeyError):
            apikey_manager_audit_event("verified", 1, {"raw_key": "leak"})
        with self.assertRaises(APIKeyError):
            apikey_manager_audit_event("bogus", 1, {})


class TestStdlibOnly(unittest.TestCase):
    def test_no_third_party_imports(self):
        import ast
        from pathlib import Path

        path = Path(__file__).resolve().parent.parent / "apikey_manager.py"
        tree = ast.parse(path.read_text())
        allowed = {
            "__future__", "hashlib", "hmac", "secrets", "threading",
            "dataclasses", "typing", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module == "canonical_json":
                    continue  # the standard guarded fallback
                self.assertIn(node.module.split(".")[0], allowed)


if __name__ == "__main__":
    unittest.main()
