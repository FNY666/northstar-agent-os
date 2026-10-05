"""EvidenceStore: durable appends, tamper-evident reload, sealed manifests."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from evidence_chain import EvidenceChain
from evidence_contract import EvidenceRef
from evidence_store import (
    EvidenceStore,
    HmacTestSigner,
    verify_manifest,
)


def _signer():
    return HmacTestSigner("test-key-1", b"test-secret-0123456789")


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.path = str(Path(self.tmpdir.name) / "run-001.evidence.jsonl")

    def open_store(self, run_id="run-001"):
        return EvidenceStore(self.path, run_id)

    def append_two(self, store):
        first = store.append(
            source="host",
            kind="authorization.verified",
            occurred_at=1_800_000_000,
            subject={"actor_id": "actor-1"},
            source_id="grant-event-1",
        )
        second = store.append(
            source="durable",
            kind="step.finished",
            occurred_at=1_800_000_001,
            subject=b"canonical source bytes",
            refs=(EvidenceRef("authorization", "grant-1", first.subject_digest),),
            source_id="event-2",
        )
        return first, second

    def test_append_reload_round_trip_verifies(self):
        store = self.open_store()
        first, second = self.append_two(store)
        reopened = self.open_store()
        self.assertEqual(reopened.entry_count, 2)
        self.assertEqual(reopened.head_digest, store.head_digest)
        self.assertEqual(
            [entry.to_dict() for entry in reopened.entries],
            [entry.to_dict() for entry in store.entries],
        )
        report = reopened.verify()
        self.assertTrue(report.ok)
        # File is one canonical-JSON entry per line.
        lines = Path(self.path).read_bytes().split(b"\n")
        self.assertEqual(json.loads(lines[0])["sequence"], 1)
        self.assertEqual(first.sequence, 1)
        self.assertEqual(second.sequence, 2)

    def test_flipped_byte_fails_closed_at_open(self):
        store = self.open_store()
        self.append_two(store)
        raw = bytearray(Path(self.path).read_bytes())
        raw[100] ^= 0x01  # tamper inside the first entry's bytes
        Path(self.path).write_bytes(bytes(raw))
        with self.assertRaises(ValueError) as caught:
            self.open_store()
        message = str(caught.exception)
        self.assertTrue(
            "failed verification" in message or "not a valid entry" in message,
            f"tamper must fail closed, got: {message}",
        )

    def test_truncated_last_line_fails_closed_at_open(self):
        store = self.open_store()
        self.append_two(store)
        raw = Path(self.path).read_bytes()
        Path(self.path).write_bytes(raw[: len(raw) // 2])  # cut mid-entry
        with self.assertRaises(ValueError):
            self.open_store()

    def test_wrong_run_id_on_open_is_refused(self):
        store = self.open_store(run_id="run-001")
        self.append_two(store)
        with self.assertRaises(ValueError):
            self.open_store(run_id="run-002")

    def test_idempotent_retry_after_reload_writes_no_second_line(self):
        store = self.open_store()
        first = store.append(
            source="host",
            kind="session.started",
            occurred_at=1_800_000_000,
            subject={"session_id": "s-1"},
            source_id="retry-1",
        )
        size_after_first = os.path.getsize(self.path)
        reopened = self.open_store()
        again = reopened.append(
            source="host",
            kind="session.started",
            occurred_at=1_800_000_000,
            subject={"session_id": "s-1"},
            source_id="retry-1",
        )
        self.assertEqual(again.entry_digest, first.entry_digest)
        self.assertEqual(reopened.entry_count, 1)
        self.assertEqual(os.path.getsize(self.path), size_after_first)

    def test_conflicting_source_id_is_rejected_before_write(self):
        store = self.open_store()
        store.append(
            source="host",
            kind="session.started",
            occurred_at=1_800_000_000,
            subject={"session_id": "s-1"},
            source_id="dup-1",
        )
        size_before = os.path.getsize(self.path)
        with self.assertRaises(ValueError):
            store.append(
                source="host",
                kind="session.started",
                occurred_at=1_800_000_000,
                subject={"session_id": "s-2"},  # different claim, same source_id
                source_id="dup-1",
            )
        self.assertEqual(os.path.getsize(self.path), size_before)
        self.assertEqual(store.entry_count, 1)

    def test_rejected_append_leaves_no_partial_line(self):
        store = self.open_store()
        with self.assertRaises(ValueError):
            store.append(
                source="HOST",  # invalid: labels must be lowercase
                kind="session.started",
                occurred_at=1_800_000_000,
                subject={},
                source_id="invalid-source-1",
            )
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(store.entry_count, 0)

    def test_seal_and_verify_round_trip(self):
        store = self.open_store()
        self.append_two(store)
        signer = _signer()
        manifest = store.seal(signer, sealed_at=1_800_000_010)
        self.assertEqual(manifest["schema_version"], "northstar.evidence-manifest.v1")
        self.assertEqual(manifest["run_id"], "run-001")
        self.assertEqual(manifest["entry_count"], 2)
        self.assertEqual(manifest["head_digest"], store.head_digest)
        result = store.verify_seal(manifest, {signer.key_id: signer.verifier()})
        self.assertTrue(result.ok)
        self.assertEqual(result.authenticity, "verified")

    def test_tampered_manifest_head_is_not_verified(self):
        store = self.open_store()
        self.append_two(store)
        signer = _signer()
        manifest = store.seal(signer, sealed_at=1_800_000_010)
        manifest["head_digest"] = "sha256:" + "0" * 64  # attacker rewrites the head
        result = verify_manifest(manifest, {signer.key_id: signer.verifier()})
        self.assertFalse(result.ok)
        self.assertEqual(result.authenticity, "bad-signature")

    def test_unknown_key_id_is_unknown_not_ok(self):
        store = self.open_store()
        self.append_two(store)
        manifest = store.seal(_signer(), sealed_at=1_800_000_010)
        result = verify_manifest(manifest, {})  # resolver trusts nobody
        self.assertFalse(result.ok)
        self.assertEqual(result.authenticity, "unknown-key")

    def test_verifier_identity_and_algorithm_must_match_signed_claim(self):
        store = self.open_store()
        self.append_two(store)
        manifest = store.seal(_signer(), sealed_at=1_800_000_010)

        class PermissiveWrongIdentity:
            key_id = "different-key"
            algorithm = "hmac-sha256-test"

            def verify(self, data, signature):
                return True

        class PermissiveWrongAlgorithm:
            key_id = "test-key-1"
            algorithm = "unrelated-algorithm"

            def verify(self, data, signature):
                return True

        for verifier in (PermissiveWrongIdentity(), PermissiveWrongAlgorithm()):
            with self.subTest(verifier=verifier.__class__.__name__):
                result = verify_manifest(manifest, {"test-key-1": verifier})
                self.assertFalse(result.ok)
                self.assertEqual(result.authenticity, "bad-signature")

    def test_seal_bound_to_store_contents(self):
        store = self.open_store()
        self.append_two(store)
        manifest = store.seal(_signer(), sealed_at=1_800_000_010)
        # The seal is genuine, but the store moved on: it must not verify.
        store.append(
            source="host",
            kind="session.ended",
            occurred_at=1_800_000_002,
            subject={},
            source_id="end-1",
        )
        result = store.verify_seal(manifest, {"test-key-1": _signer().verifier()})
        self.assertFalse(result.ok)

    def test_seal_of_empty_chain_is_refused(self):
        store = self.open_store()
        with self.assertRaises(ValueError):
            store.seal(_signer())

    def test_malformed_manifest_shapes_are_rejected(self):
        signer = _signer()
        for bad in (
            "not-a-dict",
            {"schema_version": "wrong", "run_id": "run-001"},
            dict(self._good_manifest(signer), signature="!!!not-base64!!!"),
            dict(self._good_manifest(signer), entry_count=0),
        ):
            result = verify_manifest(bad, {signer.key_id: signer.verifier()})
            self.assertFalse(result.ok, f"should reject {bad!r}")

    def _good_manifest(self, signer):
        store = self.open_store()
        self.append_two(store)
        return store.seal(signer, sealed_at=1_800_000_010)

    def test_chain_class_still_interoperates(self):
        # A store's entries verify through the pure in-memory primitives too.
        store = self.open_store()
        self.append_two(store)
        chain = EvidenceChain("run-001")
        for entry in store.entries:
            chain.append_entry(entry.to_dict())
        self.assertTrue(chain.verify().ok)
        self.assertEqual(chain.head_digest, store.head_digest)


if __name__ == "__main__":
    unittest.main()
