"""Targeted tests for the secrets rotation interface."""

import ast
import subprocess
import sys
import unittest
from pathlib import Path

from secrets_rotation import (
    AUDIT_SCHEMA,
    KIND_REJECTED,
    KIND_ROLLED_BACK,
    KIND_ROTATED,
    KIND_SECRET_REGISTERED,
    REASON_COMPROMISED,
    REASON_EXPIRED,
    REASON_INITIAL,
    REASON_MANUAL,
    REASON_SCHEDULED,
    ROTATION_REASONS,
    SECRETS_ROTATION_SCHEMA,
    SECRETS_ROTATION_VERSION,
    STATUS_ACTIVE,
    STATUS_RETIRED,
    BadReasonError,
    BadRollbackError,
    BadSecretError,
    DuplicateSecretError,
    RollbackRecord,
    SecretsRotation,
    SecretsRotationError,
    SecretVersion,
    SeqOrderError,
    UnknownSecretError,
    UnknownVersionError,
    main,
    secrets_rotation_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "secrets_rotation.py"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(SECRETS_ROTATION_VERSION, "secrets-rotation.v1")
        self.assertEqual(SECRETS_ROTATION_SCHEMA, "northstar.secrets-rotation.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(
            ROTATION_REASONS,
            ("initial", "scheduled", "manual", "compromised", "expired"),
        )

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "json", "threading", "dataclasses", "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def setUp(self):
        self.mgr = SecretsRotation(seed=1)

    def test_register_roundtrip(self):
        v = self.mgr.register("db-password", seq=1)
        self.assertIsInstance(v, SecretVersion)
        self.assertTrue(v.verify())
        self.assertEqual(v.version_index, 1)
        self.assertEqual(v.status, STATUS_ACTIVE)
        self.assertEqual(v.reason, REASON_INITIAL)
        self.assertEqual(v.prev_digest, "genesis")
        self.assertTrue(v.material_digest.startswith("sha256:"))
        self.assertEqual(self.mgr.active_version("db-password"), v)
        self.assertEqual(self.mgr.versions("db-password"), (v,))

    def test_register_duplicate_refused(self):
        self.mgr.register("db-password", seq=1)
        with self.assertRaises(DuplicateSecretError):
            self.mgr.register("db-password", seq=2)
        kinds = [e["kind"] for e in self.mgr.audit_log()]
        self.assertIn(KIND_REJECTED, kinds)

    def test_register_bad_ids(self):
        for bad in ("", "   ", None, 123, True):
            with self.assertRaises((BadSecretError, SecretsRotationError)):
                SecretsRotation(seed=1).register(bad, seq=1)


class TestSeqDiscipline(unittest.TestCase):
    def test_rewind_bool_negative_refused(self):
        mgr = SecretsRotation(seed=1)
        mgr.register("s", seq=1)
        for bad in (1, True, -1, 1.5, "2"):
            with self.assertRaises(SecretsRotationError):
                mgr.rotate("s", seq=bad, reason="manual")

    def test_failed_mutation_consumes_seq(self):
        mgr = SecretsRotation(seed=1)
        mgr.register("s", seq=1)
        # Failed rotate on unknown secret consumes seq 2 ...
        with self.assertRaises(UnknownSecretError):
            mgr.rotate("nope", seq=2, reason="manual")
        # ... so the next valid seq is 3, not 2.
        with self.assertRaises(SeqOrderError):
            mgr.register("t", seq=2)
        mgr.register("t", seq=3)
        self.assertEqual(mgr.active_version("t").version_index, 1)


class TestRotate(unittest.TestCase):
    def setUp(self):
        self.mgr = SecretsRotation(seed=3)
        self.mgr.register("api-token", seq=1)

    def test_rotate_mints_version_2(self):
        v1 = self.mgr.version("api-token", 1)
        v2 = self.mgr.rotate("api-token", seq=2, reason="scheduled")
        self.assertTrue(v2.verify())
        self.assertEqual(v2.version_index, 2)
        self.assertEqual(v2.status, STATUS_ACTIVE)
        self.assertEqual(v2.reason, "scheduled")
        self.assertEqual(v2.prev_digest, v1.digest)
        self.assertNotEqual(v2.material_digest, v1.material_digest)
        # The old active version is retired in place.
        retired = self.mgr.version("api-token", 1)
        self.assertEqual(retired.status, STATUS_RETIRED)
        self.assertEqual(self.mgr.active_version("api-token"), v2)

    def test_rotate_reasons_table(self):
        for i, reason in enumerate(
            ("scheduled", "manual", "compromised", "expired"), start=2
        ):
            v = self.mgr.rotate("api-token", seq=i, reason=reason)
            self.assertEqual(v.reason, reason)
            self.assertTrue(v.verify())
        # 'initial' is reserved for register; junk is refused.
        with self.assertRaises(BadReasonError):
            self.mgr.rotate("api-token", seq=10, reason="initial")
        with self.assertRaises(BadReasonError):
            self.mgr.rotate("api-token", seq=11, reason="because-i-said-so")

    def test_rotate_unknown_secret_refused(self):
        with self.assertRaises(UnknownSecretError):
            self.mgr.rotate("ghost", seq=2, reason="manual")


class TestVersionView(unittest.TestCase):
    def test_retired_versions_stay_addressable(self):
        mgr = SecretsRotation(seed=5)
        mgr.register("cert", seq=1)
        mgr.rotate("cert", seq=2, reason="expired")
        v1 = mgr.version("cert", 1)
        self.assertTrue(v1.verify())
        self.assertEqual(v1.status, STATUS_RETIRED)
        # Pure lookup: unknown secret/version refused, no seq consumed.
        with self.assertRaises(UnknownSecretError):
            mgr.version("ghost", 1)
        with self.assertRaises(UnknownVersionError):
            mgr.version("cert", 99)
        self.assertEqual(mgr.secret_ids(), ("cert",))


class TestRollback(unittest.TestCase):
    def setUp(self):
        self.mgr = SecretsRotation(seed=9)
        self.mgr.register("deploy-key", seq=1)
        self.mgr.rotate("deploy-key", seq=2, reason="manual")

    def test_rollback_reactivates_retired(self):
        rb = self.mgr.rollback("deploy-key", seq=3, to_version=1)
        self.assertIsInstance(rb, RollbackRecord)
        self.assertTrue(rb.verify())
        self.assertEqual(rb.from_version, 2)
        self.assertEqual(rb.to_version, 1)
        # Pointer move: no new version index, no new material minted.
        self.assertEqual(len(self.mgr.versions("deploy-key")), 2)
        self.assertEqual(self.mgr.active_version("deploy-key").version_index, 1)
        self.assertEqual(self.mgr.active_version("deploy-key").status, STATUS_ACTIVE)
        self.assertEqual(self.mgr.version("deploy-key", 2).status, STATUS_RETIRED)
        self.assertEqual(len(self.mgr.rollbacks()), 1)
        kinds = [e["kind"] for e in self.mgr.audit_log()]
        self.assertIn(KIND_ROLLED_BACK, kinds)
        # Rolling forward again works: re-activate version 2.
        rb2 = self.mgr.rollback("deploy-key", seq=4, to_version=2)
        self.assertEqual((rb2.from_version, rb2.to_version), (1, 2))
        self.assertEqual(self.mgr.active_version("deploy-key").version_index, 2)

    def test_rollback_refusals(self):
        # Already-active target.
        with self.assertRaises(BadRollbackError):
            self.mgr.rollback("deploy-key", seq=3, to_version=2)
        # Nonexistent version.
        with self.assertRaises(UnknownVersionError):
            self.mgr.rollback("deploy-key", seq=4, to_version=7)
        # Non-int target.
        with self.assertRaises(BadRollbackError):
            self.mgr.rollback("deploy-key", seq=5, to_version="1")
        # Unknown secret.
        with self.assertRaises(UnknownSecretError):
            self.mgr.rollback("ghost", seq=6, to_version=1)


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_material_ban(self):
        mgr = SecretsRotation(seed=11)
        mgr.register("s", seq=1)
        mgr.rotate("s", seq=2, reason="compromised")
        mgr.rollback("s", seq=3, to_version=1)
        log = mgr.audit_log()
        self.assertEqual(
            [e["kind"] for e in log],
            [KIND_SECRET_REGISTERED, KIND_ROTATED, KIND_ROLLED_BACK],
        )
        for event in log:
            self.assertEqual(event["schema"], "audit.ndjson/1")
            self.assertEqual(event["module"], "secrets_rotation")
            blob = str(event)
            self.assertNotIn("material", blob.replace("material_digest", ""))
        # Bad kind refused.
        with self.assertRaises(SecretsRotationError):
            secrets_rotation_audit_event("rotation.nope", 1)


class TestMain(unittest.TestCase):
    def test_main_subprocess(self):
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("secrets-rotation OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
