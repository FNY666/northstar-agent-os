"""DSSE签名和安全封存原语测试；所有keys仅在测试临时环境生成。"""
from __future__ import annotations

import base64
import copy
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import trusted_common as c
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class ReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes_raw()
        self.key_id = c.sha(pub)
        self.identity = {"repository": "FNY666/northstar-agent-os", "run_id": "unit-run-1", "run_attempt": 1, "source_commit": "a" * 40, "nonce": "b" * 64}
        self.store = {"schema": "northstar.receipt-trust.v1", "keys": {self.key_id: {"public_key": base64.b64encode(pub).decode(), "kinds": ["scan-plan"], "repository": self.identity["repository"], "not_before": c.stamp(self.now - timedelta(days=1)), "not_after": c.stamp(self.now + timedelta(days=1)), "revoked": False}}}
        self.raw = c.create_receipt("scan-plan", self.identity, {"schema": "unit-test-body"}, self.key, self.store, now=self.now)

    def verify(self, raw: bytes | None = None, *, store=None, identity=None, now=None):
        return c.verify_receipt(self.raw if raw is None else raw, self.store if store is None else store, expected_kind="scan-plan", expected_identity=self.identity if identity is None else identity, now=self.now if now is None else now)

    def resign_payload(self, payload, *, typ=c.PAYLOAD_TYPE):
        raw = c.wire(payload) if isinstance(payload, dict) else payload
        return c.wire({"payloadType": typ, "payload": base64.b64encode(raw).decode(), "signatures": [{"keyid": self.key_id, "sig": base64.b64encode(self.key.sign(c.pae(typ, raw))).decode()}]})

    def test_valid_signature(self) -> None:
        self.assertEqual(self.verify()["identity"], self.identity)

    def test_pae_official_vector(self) -> None:
        self.assertEqual(c.pae("http://example.com/HelloWorld", b"hello world"), b"DSSEv1 29 http://example.com/HelloWorld 11 hello world")

    def test_payload_tamper_rejected(self) -> None:
        envelope = json.loads(self.raw)
        payload = json.loads(base64.b64decode(envelope["payload"]))
        payload["body"]["schema"] = "attacker"
        envelope["payload"] = base64.b64encode(c.wire(payload)).decode()
        with self.assertRaises(c.EvidenceError): self.verify(c.wire(envelope))

    def test_type_tamper_rejected(self) -> None:
        envelope = json.loads(self.raw)
        envelope["payloadType"] = "application/json"
        with self.assertRaises(c.EvidenceError): self.verify(c.wire(envelope))

    def test_authenticated_unknown_type_rejected(self) -> None:
        payload = self.verify()
        with self.assertRaises(c.EvidenceError): self.verify(self.resign_payload(payload, typ="other-profile.v2"))

    def test_wrong_key_signature_rejected(self) -> None:
        envelope = json.loads(self.raw)
        raw = base64.b64decode(envelope["payload"])
        envelope["signatures"][0]["sig"] = base64.b64encode(Ed25519PrivateKey.generate().sign(c.pae(c.PAYLOAD_TYPE, raw))).decode()
        with self.assertRaises(c.EvidenceError): self.verify(c.wire(envelope))

    def test_unknown_key_hint_rejected(self) -> None:
        envelope = json.loads(self.raw)
        envelope["signatures"][0]["keyid"] = "f" * 64
        with self.assertRaises(c.EvidenceError): self.verify(c.wire(envelope))

    def test_unauthorized_role_rejected_even_with_valid_key(self) -> None:
        store = copy.deepcopy(self.store)
        store["keys"][self.key_id]["kinds"] = ["build-capture"]
        with self.assertRaises(c.EvidenceError): self.verify(store=store)

    def test_signer_cannot_sign_unauthorized_role(self) -> None:
        with self.assertRaises(c.EvidenceError):
            c.create_receipt("release-seal", self.identity, {}, self.key, self.store, now=self.now)

    def test_repository_scope_rejected(self) -> None:
        store = copy.deepcopy(self.store)
        store["keys"][self.key_id]["repository"] = "other/repository"
        with self.assertRaises(c.EvidenceError): self.verify(store=store)

    def test_each_identity_field_blocks_cross_context_replay(self) -> None:
        changes = {"repository": "other/repository", "run_id": "other-run", "run_attempt": 2, "source_commit": "c" * 40, "nonce": "d" * 64}
        for key, value in changes.items():
            with self.subTest(key=key):
                identity = dict(self.identity)
                identity[key] = value
                with self.assertRaises(c.EvidenceError): self.verify(identity=identity)

    def test_revoked_key_rejected(self) -> None:
        store = copy.deepcopy(self.store)
        store["keys"][self.key_id]["revoked"] = True
        with self.assertRaises(c.EvidenceError): self.verify(store=store)

    def test_expired_receipt_rejected(self) -> None:
        with self.assertRaises(c.EvidenceError): self.verify(now=self.now + timedelta(seconds=1800))

    def test_future_receipt_rejected(self) -> None:
        with self.assertRaises(c.EvidenceError): self.verify(now=self.now - timedelta(seconds=61))

    def test_expired_key_rejected(self) -> None:
        store = copy.deepcopy(self.store)
        store["keys"][self.key_id]["not_after"] = c.stamp(self.now - timedelta(seconds=1))
        with self.assertRaises(c.EvidenceError): self.verify(store=store)

    def test_excess_receipt_lifetime_rejected(self) -> None:
        payload = self.verify()
        payload["expires_at"] = c.stamp(self.now + timedelta(seconds=14401))
        with self.assertRaises(c.EvidenceError): self.verify(self.resign_payload(payload))

    def test_duplicate_envelope_keys_rejected(self) -> None:
        raw = self.raw.rstrip()
        raw = raw[:-1] + b',"payloadType":"application/json"}\n'
        with self.assertRaises(c.EvidenceError): self.verify(raw)

    def test_duplicate_authenticated_payload_keys_rejected(self) -> None:
        raw = base64.b64decode(json.loads(self.raw)["payload"]).rstrip()
        raw = raw[:-1] + b',"kind":"scan-plan"}\n'
        with self.assertRaises(c.EvidenceError): self.verify(self.resign_payload(raw))

    def test_urlsafe_base64_supported(self) -> None:
        envelope = json.loads(self.raw)
        envelope["payload"] = base64.urlsafe_b64encode(base64.b64decode(envelope["payload"])).decode()
        envelope["signatures"][0]["sig"] = base64.urlsafe_b64encode(base64.b64decode(envelope["signatures"][0]["sig"])).decode()
        self.assertEqual(self.verify(c.wire(envelope))["kind"], "scan-plan")

    def test_bad_base64_rejected(self) -> None:
        envelope = json.loads(self.raw)
        envelope["payload"] = "!"
        with self.assertRaises(c.EvidenceError): self.verify(c.wire(envelope))

    def test_extra_signature_rejected(self) -> None:
        envelope = json.loads(self.raw)
        envelope["signatures"].append(copy.deepcopy(envelope["signatures"][0]))
        with self.assertRaises(c.EvidenceError): self.verify(c.wire(envelope))

    def test_boolean_attempt_rejected(self) -> None:
        identity = dict(self.identity, run_attempt=True)
        with self.assertRaises(c.EvidenceError): c.validate_identity(identity)

    def test_key_id_must_match_actual_public_key(self) -> None:
        store = copy.deepcopy(self.store)
        store["keys"][self.key_id]["public_key"] = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
        with self.assertRaises(c.EvidenceError): self.verify(store=store)

    def test_naive_clock_rejected(self) -> None:
        with self.assertRaises(c.EvidenceError): self.verify(now=datetime(2026, 10, 17))

    def test_same_current_identity_can_verify_again_without_single_use_claim(self) -> None:
        self.assertEqual(self.verify(), self.verify())


class SafePublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_atomic_readonly_publication(self) -> None:
        target = self.root / "out"
        c.publish_directory(target, {"receipt.json": b'{}\n'})
        self.assertEqual((target / "receipt.json").read_bytes(), b'{}\n')
        self.assertFalse((target / "receipt.json").stat().st_mode & 0o222)
        self.assertFalse(target.stat().st_mode & 0o222)

    def test_existing_output_not_overwritten_and_staging_cleaned(self) -> None:
        target = self.root / "out"
        c.publish_directory(target, {"receipt.json": b'{}\n'})
        with self.assertRaises(c.EvidenceError): c.publish_directory(target, {"receipt.json": b'{"evil":1}\n'})
        self.assertEqual((target / "receipt.json").read_bytes(), b'{}\n')
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["out"])

    def test_output_parent_symlink_rejected(self) -> None:
        actual = self.root / "actual"
        actual.mkdir()
        (self.root / "link").symlink_to(actual, target_is_directory=True)
        with self.assertRaises(OSError): c.publish_directory(self.root / "link/out", {"a.json": b'{}\n'})

    def test_manifest_detects_changed_bytes(self) -> None:
        (self.root / "a.json").write_bytes(b'{}\n')
        manifest = c.file_manifest({"a.json": b'{}\n'})
        (self.root / "a.json").write_bytes(b'{"x":1}\n')
        with self.assertRaises(c.EvidenceError): c.read_manifest_files(self.root, manifest)

    def test_manifest_rejects_extra_files(self) -> None:
        (self.root / "a.json").write_bytes(b'{}\n')
        (self.root / "extra").write_bytes(b'x')
        with self.assertRaises(c.EvidenceError): c.read_manifest_files(self.root, c.file_manifest({"a.json": b'{}\n'}))

    def test_manifest_rejects_hardlinks(self) -> None:
        (self.root / "a.json").write_bytes(b'{}\n')
        external = self.root.parent / (self.root.name + "-hardlink")
        os.link(self.root / "a.json", external)
        try:
            with self.assertRaises(c.EvidenceError): c.read_manifest_files(self.root, c.file_manifest({"a.json": b'{}\n'}))
        finally: external.unlink()

    def test_manifest_boolean_size_rejected(self) -> None:
        manifest = [{"name": "a.json", "sha256": "a" * 64, "bytes": True}]
        with self.assertRaises(c.EvidenceError): c.read_manifest_files(self.root, manifest)

    def test_private_key_file_must_not_be_group_readable(self) -> None:
        key = Ed25519PrivateKey.generate()
        path = self.root / "key.pem"
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        path.chmod(0o640)
        with self.assertRaises(c.EvidenceError): c.load_private_key(path)
        path.chmod(0o600)
        self.assertEqual(c.load_private_key(path).public_key().public_bytes_raw(), key.public_key().public_bytes_raw())


if __name__ == "__main__":
    unittest.main()
