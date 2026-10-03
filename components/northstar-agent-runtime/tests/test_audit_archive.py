"""WORM archive packages: build, verify, tamper detection (all offline)."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401

from audit_archive import (
    ARCHIVE_VERSION,
    DEFAULT_RETENTION_DAYS,
    ArchiveResult,
    verify_archive,
    write_archive,
)
from audit_chain import anchor_manifest, chain_records


def _chained_feed_bytes(n: int = 4) -> bytes:
    records = [
        {
            "schema_version": "audit.ndjson/1",
            "component": "northstar-agent-runtime",
            "event": "assistant",
            "seq": i,
            "ts": f"2026-10-03T10:00:{i:02d}.000Z",
            "level": "info",
            "payload": {"i": i},
        }
        for i in range(n)
    ]
    chained = chain_records(records, component="northstar-agent-runtime", session_id="s-9")
    return (
        "\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in chained) + "\n"
    ).encode()


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.feed_bytes = _chained_feed_bytes()

    def tearDown(self):
        self.tmp.cleanup()

    def _build(self, **kwargs):
        target = Path(self.tmp.name) / "pkg"
        write_archive(target, self.feed_bytes, session_id="s-9", **kwargs)
        return target

    def test_round_trip(self):
        target = self._build()
        result = verify_archive(target)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.files, 2)  # feed + anchor manifest (the archive manifest is the trust root)
        self.assertEqual(result.records, 4)
        self.assertEqual(result.external_anchor, {"present": False})
        manifest = json.loads((target / "archive-manifest.json").read_text())
        self.assertEqual(manifest["archive"], ARCHIVE_VERSION)
        self.assertEqual(manifest["retention_days"], DEFAULT_RETENTION_DAYS)
        self.assertTrue(manifest["retain_until"] > manifest["created_at"])

    def test_retention_window_is_180_days(self):
        target = self._build(created_at="2026-10-03T10:00:00Z")
        manifest = json.loads((target / "archive-manifest.json").read_text())
        self.assertEqual(manifest["retain_until"], "2027-04-01T10:00:00Z")

    def test_tampered_feed_detected(self):
        target = self._build()
        feed = target / "feed.ndjson"
        feed.write_bytes(feed.read_bytes() + b'{"evil": true}\n')
        result = verify_archive(target)
        self.assertFalse(result.ok)
        self.assertIn("modified", result.reason)

    def test_truncated_feed_detected(self):
        target = self._build()
        feed = target / "feed.ndjson"
        lines = feed.read_text().splitlines()
        feed.write_text("\n".join(lines[:-1]) + "\n")
        result = verify_archive(target)
        self.assertFalse(result.ok)

    def test_tampered_anchor_manifest_detected(self):
        target = self._build()
        anchor = target / "anchor-manifest.json"
        doc = json.loads(anchor.read_text())
        doc["records"] = 999
        anchor.write_text(json.dumps(doc))
        result = verify_archive(target)
        self.assertFalse(result.ok)
        self.assertIn("modified", result.reason)

    def test_missing_file_detected(self):
        target = self._build()
        (target / "anchor-manifest.json").unlink()
        result = verify_archive(target)
        self.assertFalse(result.ok)
        self.assertIn("missing", result.reason)

    def test_missing_manifest_dir(self):
        result = verify_archive(Path(self.tmp.name) / "nope")
        self.assertFalse(result.ok)

    def test_external_anchor_round_trip_offline(self):
        import hashlib as _hl

        seed = _hl.sha256(b"archive-external-test").digest()
        from ed25519 import public_key as ed_public_key
        from ed25519 import sign as ed_sign

        from audit_rekor import PAYLOAD_TYPE, anchor_statement, pae
        import base64

        payload = anchor_statement(
            feed_sha256=_hl.sha256(self.feed_bytes).hexdigest(),
            head_chain_hash="ab" * 32,
            records=4,
            anchored_at="2026-10-03T10:00:00Z",
        )
        fake_anchor = {
            "anchor": "northstar-rekor-anchor/1",
            "rekor_url": "http://127.0.0.1:1",
            "rekor_api": "v1",
            "entry_kind": "dsse",
            "uuid": "0" * 80,
            "log_index": 1,
            "integrated_time": 1791023198,
            "payload_type": PAYLOAD_TYPE,
            "payload": json.loads(payload.decode()),
            "payload_sha256": _hl.sha256(payload).hexdigest(),
            "envelope_sha256": "00" * 32,
            "signature": base64.b64encode(ed_sign(seed, pae(PAYLOAD_TYPE, payload))).decode(),
            "pubkey": ed_public_key(seed).hex(),
        }
        target = self._build(external_anchor=fake_anchor)
        # The fake head won't match the real feed head: offline check must fail loudly.
        result = verify_archive(target)
        self.assertFalse(result.ok)
        self.assertIn("external anchor invalid", result.reason)

    def test_external_anchor_head_must_match(self):
        # Build a *consistent* fake external anchor for the real feed head.
        import base64
        import hashlib as _hl

        feed_path = Path(self.tmp.name) / "feed.ndjson"
        feed_path.write_bytes(self.feed_bytes)
        head = anchor_manifest(feed_path)["head_chain_hash"]
        seed = _hl.sha256(b"archive-external-test-2").digest()
        from ed25519 import public_key as ed_public_key
        from ed25519 import sign as ed_sign

        from audit_rekor import PAYLOAD_TYPE, anchor_statement, pae

        payload = anchor_statement(
            feed_sha256=_hl.sha256(self.feed_bytes).hexdigest(),
            head_chain_hash=head,
            records=4,
            anchored_at="2026-10-03T10:00:00Z",
        )
        fake_anchor = {
            "anchor": "northstar-rekor-anchor/1",
            "rekor_url": "http://127.0.0.1:1",
            "rekor_api": "v1",
            "entry_kind": "dsse",
            "uuid": "0" * 80,
            "log_index": 1,
            "integrated_time": 1791023198,
            "payload_type": PAYLOAD_TYPE,
            "payload": json.loads(payload.decode()),
            "payload_sha256": _hl.sha256(payload).hexdigest(),
            "envelope_sha256": "00" * 32,
            "signature": base64.b64encode(ed_sign(seed, pae(PAYLOAD_TYPE, payload))).decode(),
            "pubkey": ed_public_key(seed).hex(),
        }
        target = self._build(external_anchor=fake_anchor)
        result = verify_archive(target)  # offline: signature + head checks pass
        self.assertTrue(result.ok, result.reason)
        self.assertTrue(result.external_anchor["present"])
        self.assertTrue(result.external_anchor["offline"]["ok"])


if __name__ == "__main__":
    unittest.main()
