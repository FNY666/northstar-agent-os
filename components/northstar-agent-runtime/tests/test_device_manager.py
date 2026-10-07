"""Tests for device_manager."""

import unittest

from device_manager import (
    DEVICE_MANAGER_VERSION,
    SCHEMA_PIN,
    AlreadyRevokedError,
    DeviceError,
    DeviceInfo,
    DeviceManager,
    DuplicateDeviceError,
    RevocationRecord,
    SeqOrderError,
    TrustRecord,
    UnknownDeviceError,
    device_manager_audit_event,
)

SEED = b"device-manager-test-seed-32bytes!!!!!"


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(DEVICE_MANAGER_VERSION, "device-manager.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.device-manager.v1")


class TestTrust(unittest.TestCase):
    def test_trust_happy_path(self):
        mgr = DeviceManager(seed=SEED)
        rec = mgr.trust(
            "dev-1", 1, owner="alice", label="laptop",
            fingerprint="sha256:" + "ab" * 32, scopes=("vpn", "ssh"),
        )
        self.assertIsInstance(rec, TrustRecord)
        self.assertEqual(rec.device_id, "dev-1")
        self.assertEqual(rec.owner, "alice")
        self.assertEqual(rec.label, "laptop")
        self.assertTrue(rec.fingerprint.startswith("sha256:"))
        self.assertEqual(rec.scopes, ("ssh", "vpn"))  # sorted
        self.assertEqual(rec.trusted_seq, 1)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version, DEVICE_MANAGER_VERSION)

    def test_trust_defaults(self):
        mgr = DeviceManager(seed=SEED)
        rec = mgr.trust("dev-1", 1)
        self.assertEqual(rec.owner, "")
        self.assertEqual(rec.label, "")
        self.assertEqual(rec.fingerprint, "")
        self.assertEqual(rec.scopes, ())

    def test_trust_deterministic_with_seed(self):
        a = DeviceManager(seed=SEED).trust("dev-1", 1, owner="a")
        b = DeviceManager(seed=SEED).trust("dev-1", 1, owner="a")
        self.assertEqual(a.digest, b.digest)

    def test_trust_different_seed_different_digest(self):
        a = DeviceManager(seed=SEED).trust("dev-1", 1)
        b = DeviceManager(seed=b"other-test-seed-32bytes!!!!!!!!!!!").trust(
            "dev-1", 1
        )
        self.assertNotEqual(a.digest, b.digest)

    def test_duplicate_device_id_refused(self):
        mgr = DeviceManager(seed=SEED)
        mgr.trust("dev-1", 1)
        with self.assertRaises(DuplicateDeviceError):
            mgr.trust("dev-1", 2)

    def test_trust_input_validation(self):
        mgr = DeviceManager(seed=SEED)
        with self.assertRaises(DeviceError):
            mgr.trust("", 1)  # empty device_id
        with self.assertRaises(DeviceError):
            mgr.trust(123, 1)  # wrong type
        with self.assertRaises(DeviceError):
            mgr.trust("dev-x", -1)  # negative seq
        with self.assertRaises(DeviceError):
            mgr.trust("dev-x", True)  # bool is not an int
        with self.assertRaises(DeviceError):
            mgr.trust("dev-x", 1, scopes=("ssh", "ssh"))  # dup scopes
        with self.assertRaises(DeviceError):
            DeviceManager(seed=b"")  # empty seed

    def test_seq_order_enforced(self):
        mgr = DeviceManager(seed=SEED)
        mgr.trust("dev-1", 5)
        with self.assertRaises(SeqOrderError):
            mgr.trust("dev-2", 5)  # not strictly increasing
        with self.assertRaises(SeqOrderError):
            mgr.trust("dev-2", 2)  # backwards
        mgr.trust("dev-2", 6)  # strictly increasing is fine
        self.assertEqual(mgr.device_ids(), ("dev-1", "dev-2"))


class TestVerify(unittest.TestCase):
    def test_is_trusted_true_for_enrolled(self):
        mgr = DeviceManager(seed=SEED)
        mgr.trust("dev-1", 1)
        self.assertTrue(mgr.is_trusted("dev-1"))

    def test_is_trusted_false_for_unknown_is_data(self):
        mgr = DeviceManager(seed=SEED)
        self.assertFalse(mgr.is_trusted("nope"))  # no exception
        mgr.trust("dev-1", 1)
        self.assertFalse(mgr.is_trusted("nope"))

    def test_is_trusted_wrong_type_raises(self):
        mgr = DeviceManager(seed=SEED)
        with self.assertRaises(DeviceError):
            mgr.is_trusted(None)


class TestRevoke(unittest.TestCase):
    def test_revoke_happy_path(self):
        mgr = DeviceManager(seed=SEED)
        mgr.trust("dev-1", 1)
        rec = mgr.revoke("dev-1", 2, reason="lost")
        self.assertIsInstance(rec, RevocationRecord)
        self.assertEqual(rec.device_id, "dev-1")
        self.assertEqual(rec.seq, 2)
        self.assertEqual(rec.reason, "lost")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertFalse(mgr.is_trusted("dev-1"))

    def test_revoke_unknown_raises(self):
        mgr = DeviceManager(seed=SEED)
        with self.assertRaises(UnknownDeviceError):
            mgr.revoke("ghost", 1)

    def test_revoke_twice_raises(self):
        mgr = DeviceManager(seed=SEED)
        mgr.trust("dev-1", 1)
        mgr.revoke("dev-1", 2)
        with self.assertRaises(AlreadyRevokedError):
            mgr.revoke("dev-1", 3)

    def test_duplicate_after_revocation_still_refused(self):
        mgr = DeviceManager(seed=SEED)
        mgr.trust("dev-1", 1)
        mgr.revoke("dev-1", 2)
        with self.assertRaises(DuplicateDeviceError):
            mgr.trust("dev-1", 3)
        # re-enrollment uses a fresh id
        mgr.trust("dev-1b", 4)
        self.assertTrue(mgr.is_trusted("dev-1b"))


class TestViews(unittest.TestCase):
    def test_list_sorted_with_revoked_flags(self):
        mgr = DeviceManager(seed=SEED)
        mgr.trust("dev-b", 1, owner="bob")
        mgr.trust("dev-a", 2, owner="alice")
        mgr.revoke("dev-b", 3)
        infos = mgr.list()
        self.assertEqual(
            [i.device_id for i in infos], ["dev-a", "dev-b"]
        )
        self.assertTrue(all(isinstance(i, DeviceInfo) for i in infos))
        self.assertEqual(
            [i.revoked for i in infos], [False, True]
        )

    def test_trusted_and_revoked_id_views(self):
        mgr = DeviceManager(seed=SEED)
        mgr.trust("dev-1", 1)
        mgr.trust("dev-2", 2)
        mgr.trust("dev-3", 3)
        mgr.revoke("dev-2", 4)
        self.assertEqual(mgr.device_ids(), ("dev-1", "dev-2", "dev-3"))
        self.assertEqual(mgr.trusted_ids(), ("dev-1", "dev-3"))
        self.assertEqual(mgr.revoked_ids(), ("dev-2",))

    def test_device_and_revocation_views(self):
        mgr = DeviceManager(seed=SEED)
        mgr.trust("dev-1", 1, owner="alice", label="phone")
        info = mgr.device("dev-1")
        self.assertEqual(info.owner, "alice")
        self.assertEqual(info.label, "phone")
        self.assertFalse(info.revoked)
        self.assertIsNone(mgr.revocation("dev-1"))
        mgr.revoke("dev-1", 2, reason="stolen")
        self.assertTrue(mgr.device("dev-1").revoked)
        rec = mgr.revocation("dev-1")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.reason, "stolen")
        with self.assertRaises(UnknownDeviceError):
            mgr.device("ghost")

    def test_as_dict_has_pins_and_no_secrets(self):
        mgr = DeviceManager(seed=SEED)
        rec = mgr.trust(
            "dev-1", 1, fingerprint="sha256:" + "cd" * 32
        )
        d = rec.as_dict()
        self.assertEqual(d["device_id"], "dev-1")
        self.assertTrue(d["digest"].startswith("sha256:"))
        for forbidden in ("secret", "private_key", "attestation_secret"):
            self.assertNotIn(forbidden, d)


class TestAuditEvent(unittest.TestCase):
    def test_audit_event_shape(self):
        evt = device_manager_audit_event(
            "trusted", 1, {"device_id": "dev-1", "owner": "alice"}
        )
        self.assertEqual(evt["schema"], SCHEMA_PIN)
        self.assertEqual(evt["version"], DEVICE_MANAGER_VERSION)
        self.assertEqual(evt["event"], "device-manager")
        self.assertEqual(evt["kind"], "trusted")
        self.assertEqual(evt["audit_seq"], 1)
        for kind in ("trusted", "revoked", "verified", "rejected"):
            evt = device_manager_audit_event(kind, 1, {})
            self.assertEqual(evt["kind"], kind)

    def test_audit_event_rejects_bad_kinds_and_material(self):
        with self.assertRaises(DeviceError):
            device_manager_audit_event("enrolled", 1, {})
        with self.assertRaises(DeviceError):
            device_manager_audit_event("trusted", 1, {"private_key": "x"})
        with self.assertRaises(DeviceError):
            device_manager_audit_event(
                "trusted", 1, {"attestation_secret": "x"}
            )
        with self.assertRaises(DeviceError):
            device_manager_audit_event("trusted", -1, {})


if __name__ == "__main__":
    unittest.main()
