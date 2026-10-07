"""Tests for secret_manager: Vault-style store/rotate/delete bookkeeping."""

import ast
import unittest
from pathlib import Path

from secret_manager import (
    DeletionRecord,
    DestroyedSecretError,
    DuplicateSecretError,
    RetrievedSecret,
    RotationRecord,
    SecretManager,
    SecretManagerError,
    SecretRecord,
    StoredSecret,
    UnknownSecretError,
    UnknownVersionError,
    SECRET_MANAGER_VERSION,
    SCHEMA_PIN,
    secret_manager_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SECRET_MANAGER_VERSION, "secret-manager.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.secret-manager.v1")


class TestPut(unittest.TestCase):
    def test_put_str(self):
        mgr = SecretManager()
        s = mgr.put("k", "v", 0)
        self.assertIsInstance(s, StoredSecret)
        self.assertEqual(s.version, 1)
        self.assertTrue(s.record.digest.startswith("sha256:"))

    def test_put_bytes(self):
        mgr = SecretManager()
        mgr.put("k", b"\x00\x01", 0)
        self.assertEqual(mgr.get("k", 1).value, b"\x00\x01")

    def test_put_digest_deterministic(self):
        a = SecretManager().put("k", "v", 0)
        b = SecretManager().put("k", "v", 0)
        self.assertEqual(a.record.digest, b.record.digest)

    def test_duplicate_put_refused(self):
        mgr = SecretManager()
        mgr.put("k", "v", 0)
        with self.assertRaises(DuplicateSecretError):
            mgr.put("k", "v2", 1)

    def test_put_bad_id(self):
        mgr = SecretManager()
        for bad in ("", True, None, 42):
            with self.assertRaises(SecretManagerError):
                mgr.put(bad, "v", 0)

    def test_put_bad_value(self):
        mgr = SecretManager()
        for bad in (None, True, "", b""):
            with self.assertRaises(SecretManagerError):
                mgr.put("k", bad, 0)

    def test_put_bad_seq(self):
        mgr = SecretManager()
        for bad in (True, -1, "0", None):
            with self.assertRaises(SecretManagerError):
                mgr.put("k", "v", bad)

    def test_put_metadata_roundtrip(self):
        mgr = SecretManager()
        s = mgr.put("k", "v", 0, metadata={"owner": "ops"})
        self.assertEqual(s.record.metadata, (("owner", "ops"),))

    def test_put_bad_metadata(self):
        mgr = SecretManager()
        with self.assertRaises(SecretManagerError):
            mgr.put("k", "v", 0, metadata={"owner": True})


class TestGet(unittest.TestCase):
    def test_get_latest(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        mgr.rotate("k", "v2", 1)
        got = mgr.get("k", 2)
        self.assertIsInstance(got, RetrievedSecret)
        self.assertEqual(got.value, b"v2")
        self.assertEqual(got.version, 2)

    def test_get_unknown(self):
        with self.assertRaises(UnknownSecretError):
            SecretManager().get("nope", 0)

    def test_get_version_specific(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        mgr.rotate("k", "v2", 1)
        old = mgr.get_version("k", 1, 2)
        self.assertEqual(old.value, b"v1")
        self.assertEqual(old.version, 1)

    def test_get_unknown_version(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        with self.assertRaises(UnknownVersionError):
            mgr.get_version("k", 9, 1)

    def test_get_value_immutable(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        # bytes are immutable: aliasing is harmless; the guarantee is
        # the stored value cannot be moved by the caller.
        first = mgr.get("k", 1)
        second = mgr.get("k", 2)
        self.assertEqual(first.value, b"v1")
        self.assertEqual(second.value, b"v1")
        self.assertIsInstance(first.value, bytes)

    def test_get_as_dict_no_leak(self):
        mgr = SecretManager()
        mgr.put("k", "supersecret", 0)
        d = mgr.get("k", 1).as_dict()
        self.assertNotIn("supersecret", str(d))
        self.assertIn("value_digest", d)


class TestRotate(unittest.TestCase):
    def test_rotate(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        rot = mgr.rotate("k", "v2", 1)
        self.assertIsInstance(rot, RotationRecord)
        self.assertEqual((rot.old_version, rot.new_version), (1, 2))
        self.assertEqual(rot.old_value_digest,
                         mgr.get_version("k", 1, 2).value_digest)
        self.assertEqual(rot.new_value_digest, mgr.get("k", 3).value_digest)

    def test_rotate_unknown_secret(self):
        with self.assertRaises(UnknownSecretError):
            SecretManager().rotate("nope", "v", 0)

    def test_rotate_identical_value_refused(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        with self.assertRaises(SecretManagerError):
            mgr.rotate("k", "v1", 1)

    def test_rotate_bad_value(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        with self.assertRaises(SecretManagerError):
            mgr.rotate("k", None, 1)

    def test_rotate_three_versions(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        mgr.rotate("k", "v2", 1)
        mgr.rotate("k", "v3", 2)
        self.assertEqual(len(mgr.versions("k")), 3)
        self.assertEqual(mgr.get("k", 3).value, b"v3")


class TestDelete(unittest.TestCase):
    def test_delete(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        mgr.rotate("k", "v2", 1)
        d = mgr.delete("k", 2)
        self.assertIsInstance(d, DeletionRecord)
        self.assertEqual(d.versions_destroyed, (1, 2))
        self.assertTrue(mgr.is_destroyed("k"))
        self.assertEqual(mgr.secret_ids(), ())

    def test_get_after_delete(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        mgr.delete("k", 1)
        with self.assertRaises(DestroyedSecretError):
            mgr.get("k", 2)

    def test_delete_unknown(self):
        with self.assertRaises(UnknownSecretError):
            SecretManager().delete("nope", 0)

    def test_reput_after_delete_refused(self):
        mgr = SecretManager()
        mgr.put("k", "v1", 0)
        mgr.delete("k", 1)
        with self.assertRaises(DestroyedSecretError):
            mgr.put("k", "v2", 2)


class TestViewsAndVerification(unittest.TestCase):
    def test_secret_ids_sorted(self):
        mgr = SecretManager()
        mgr.put("z", "v", 0)
        mgr.put("a", "v", 1)
        self.assertEqual(mgr.secret_ids(), ("a", "z"))

    def test_verify_record(self):
        mgr = SecretManager()
        s = mgr.put("k", "v", 0)
        self.assertTrue(mgr.verify_record(s.record))
        bad = SecretRecord(
            secret_id="k", version=1, value_digest="sha256:forged",
            created_seq=0, state="active", metadata=(),
            digest=s.record.digest, schema=SCHEMA_PIN,
        )
        self.assertFalse(mgr.verify_record(bad))

    def test_verify_record_type(self):
        with self.assertRaises(TypeError):
            SecretManager().verify_record("nope")


class TestAudit(unittest.TestCase):
    def test_audit_shapes_no_leak(self):
        mgr = SecretManager()
        stored = mgr.put("k", "supersecret", 0)
        got = mgr.get("k", 1)
        rot = mgr.rotate("k", "othersecret", 2)
        for kind, kw in (
            ("secret-stored", {"stored": stored}),
            ("secret-retrieved", {"retrieved": got}),
            ("secret-rotated", {"rotated": rot}),
        ):
            ev = secret_manager_audit_event(kind, 0, **kw)
            self.assertEqual(ev["schema"], SCHEMA_PIN)
            self.assertNotIn("supersecret", str(ev))
            self.assertNotIn("othersecret", str(ev))
        deleted = mgr.delete("k", 3)
        ev = secret_manager_audit_event("secret-deleted", 3, deleted=deleted)
        self.assertEqual(ev["secret_id"], "k")
        self.assertEqual(ev["versions_destroyed"], [1, 2])

    def test_audit_bad_kind(self):
        with self.assertRaises(ValueError):
            secret_manager_audit_event("bogus", 0)

    def test_audit_bad_seq(self):
        with self.assertRaises(SecretManagerError):
            secret_manager_audit_event("secret-stored", -1)

    def test_rejected_kind(self):
        ev = secret_manager_audit_event("rejected", 5)
        self.assertEqual(ev["event"], "secret-manager-rejected")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        src = Path(__file__).resolve().parent.parent / "secret_manager.py"
        tree = ast.parse(src.read_text())
        stdlib = {
            "hashlib", "threading", "dataclasses", "typing", "__future__",
            "canonical_json", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], stdlib)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], stdlib)


class TestMain(unittest.TestCase):
    def test_main(self):
        from secret_manager import main

        main()


if __name__ == "__main__":
    unittest.main()
