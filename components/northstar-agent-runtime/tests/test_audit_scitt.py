"""Tests for ``audit export --scitt`` (SCITT RFC 9943 / COSE Receipts RFC 9942 spike).

The spike emits a JSON-diagnostic model of the RFC 9943 §6.1 / RFC 9942 §4
CDDL — the tests pin the integer labels to the exact registry values read
from the RFCs (2026-10-03), the iss/sub issuer binding, the receipt mapping
from our Rekor anchor record, and the honest "shape-only / proof-incomplete"
markers. Nothing here tests conformance: the module itself refuses that
claim.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_chain import chain_records
from audit_scitt import (
    COSE_ALG_EDDSA,
    CWT_ISS,
    CWT_SUB,
    LABEL_ALG,
    LABEL_CONTENT_TYPE,
    LABEL_CWT_CLAIMS,
    LABEL_KID,
    LABEL_RECEIPTS,
    LABEL_VDP,
    LABEL_VDS,
    PROOF_INCLUSION,
    SCITT_RECEIPT_MEDIA_TYPE,
    SCITT_SPIKE_LABEL,
    SCITT_STATEMENT_MEDIA_TYPE,
    STATEMENT_PAYLOAD_TYPE,
    VDS_RFC9162_SHA256,
    add_receipts,
    anchor_record_to_receipt,
    build_scitt_bundle,
    build_signed_statement,
    bundle_to_json_bytes,
    verify_statement_signature,
)


def _chained_feed(directory: Path, name: str = "feed.ndjson") -> Path:
    records = [
        {
            "schema_version": "audit.ndjson/1",
            "component": "northstar-agent-runtime",
            "event": "tool_result",
            "ts": "2026-10-03T10:00:01Z",
            "level": "info",
            "payload": {"tool": "shell"},
        },
        {
            "schema_version": "audit.ndjson/1",
            "component": "northstar-agent-runtime",
            "event": "denial",
            "ts": "2026-10-03T10:00:02Z",
            "level": "error",
            "payload": {},
        },
    ]
    chained = chain_records(
        records, component="northstar-agent-runtime", session_id="sess-1", run_id="run-9"
    )
    path = directory / name
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in chained),
        encoding="utf-8",
    )
    return path


def _fake_anchor(log_index: int = 4160000) -> dict:
    return {
        "anchor": "northstar-rekor-anchor/1",
        "rekor_url": "https://rekor.sigstore.dev",
        "rekor_api": "v1",
        "uuid": "0" * 64,
        "log_index": log_index,
        "integrated_time": 1790000000,
        "payload": {
            "anchor": "northstar-rekor-anchor/1",
            "feed_sha256": "a" * 64,
            "head_chain_hash": "b" * 64,
            "records": 2,
        },
        "payload_sha256": "c" * 64,
        "signature": "d" * 128,
        "pubkey": "e" * 64,
    }


class ScittLabelTests(unittest.TestCase):
    """Integer labels pinned to the RFC registry values."""

    def test_header_labels(self):
        self.assertEqual(LABEL_CWT_CLAIMS, 15)
        self.assertEqual(LABEL_ALG, 1)
        self.assertEqual(LABEL_CONTENT_TYPE, 3)
        self.assertEqual(LABEL_KID, 4)
        self.assertEqual(LABEL_RECEIPTS, 394)
        self.assertEqual(LABEL_VDS, 395)
        self.assertEqual(LABEL_VDP, 396)

    def test_cwt_and_crypto_labels(self):
        self.assertEqual((CWT_ISS, CWT_SUB), (1, 2))
        self.assertEqual(COSE_ALG_EDDSA, -8)
        self.assertEqual(VDS_RFC9162_SHA256, 1)  # RFC9162_SHA256
        self.assertEqual(PROOF_INCLUSION, -1)

    def test_media_types(self):
        self.assertEqual(SCITT_STATEMENT_MEDIA_TYPE, "application/scitt-statement+cose")
        self.assertEqual(SCITT_RECEIPT_MEDIA_TYPE, "application/scitt-receipt+cose")


class SignedStatementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_protected_header_shape(self):
        statement = build_signed_statement(self.feed, key_id="key-1")
        protected = statement["protected"]
        # CWT claims: iss + sub present (RFC 9943 §6).
        claims = protected[LABEL_CWT_CLAIMS]
        self.assertIn(str(CWT_ISS), json.dumps(claims))
        self.assertEqual(claims[CWT_ISS], "https://northstar-agent-os/keys/key-1")
        self.assertTrue(claims[CWT_SUB].startswith("audit-feed/sha256:"))
        # alg, cty, kid.
        self.assertEqual(protected[LABEL_ALG], COSE_ALG_EDDSA)
        self.assertEqual(protected[LABEL_CONTENT_TYPE], STATEMENT_PAYLOAD_TYPE)
        self.assertEqual(protected[LABEL_KID], "key-1")

    def test_payload_pins_feed_head(self):
        statement = build_signed_statement(self.feed, key_id="key-1")
        payload = statement["payload"]
        self.assertEqual(payload["records"], 2)
        self.assertRegex(payload["feed_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(payload["head_chain_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(payload["anchor"], "northstar-audit-anchor/1")

    def test_unsigned_by_default(self):
        statement = build_signed_statement(self.feed, key_id="key-1")
        self.assertIsNone(statement["signature"])
        ok, note = verify_statement_signature(statement)
        self.assertFalse(ok)
        self.assertIn("unsigned", note)

    def test_sign_and_verify_json_level(self):
        seed = bytes.fromhex("11" * 32)
        statement = build_signed_statement(self.feed, key_id="key-1", seed=seed)
        signature = statement["signature"]
        self.assertIsNotNone(signature)
        # Honest scope: JSON-level, not COSE_Sign1.
        self.assertIn("NOT a COSE_Sign1", signature["note"])
        ok, _note = verify_statement_signature(statement)
        self.assertTrue(ok)
        # Tamper with the payload: verification must fail.
        statement["payload"]["records"] = 999
        ok, note = verify_statement_signature(statement)
        self.assertFalse(ok)

    def test_unchained_feed_fails_loudly(self):
        raw = self.dir / "raw.ndjson"
        raw.write_text('{"schema_version": "audit.ndjson/1"}\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            build_signed_statement(raw, key_id="key-1")

    def test_key_id_required(self):
        with self.assertRaises(ValueError):
            build_signed_statement(self.feed, key_id="")


class ReceiptMappingTests(unittest.TestCase):
    def test_anchor_to_receipt_shape(self):
        receipt = anchor_record_to_receipt(_fake_anchor(log_index=4160000))
        protected = receipt["protected"]
        self.assertEqual(protected[LABEL_ALG], COSE_ALG_EDDSA)
        self.assertEqual(protected[LABEL_VDS], VDS_RFC9162_SHA256)
        claims = protected[LABEL_CWT_CLAIMS]
        self.assertEqual(claims[CWT_ISS], "https://rekor.sigstore.dev")
        self.assertTrue(claims[CWT_SUB].startswith("rekor-entry:"))
        proofs = receipt["unprotected"][LABEL_VDP][PROOF_INCLUSION]
        self.assertEqual(len(proofs), 1)
        tree_size, leaf_index, path = proofs[0]
        self.assertEqual(leaf_index, 4160000)
        self.assertEqual(tree_size, 4160001)
        self.assertEqual(path, [])

    def test_receipt_honesty_markers(self):
        receipt = anchor_record_to_receipt(_fake_anchor())
        self.assertEqual(receipt["receipt_status"], "shape-only")
        self.assertEqual(receipt["proof"], "incomplete")
        self.assertIsNone(receipt["signature"])  # no TS signature exists
        self.assertIsNone(receipt["payload"])  # detached, per RFC 9942 profiles
        notes = " ".join(receipt["mapping_notes"])
        self.assertIn("no Merkle", notes)
        self.assertIn("COSE_Sign1 signed by the TS", notes)

    def test_bad_anchor_rejected(self):
        with self.assertRaises(ValueError):
            anchor_record_to_receipt({"anchor": "nope"})
        with self.assertRaises(ValueError):
            anchor_record_to_receipt({"anchor": "northstar-rekor-anchor/1"})


class TransparentStatementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_receipts_under_label_394(self):
        statement = build_signed_statement(self.feed, key_id="key-1")
        receipt = anchor_record_to_receipt(_fake_anchor())
        transparent = add_receipts(statement, [receipt])
        self.assertEqual(transparent["unprotected"][LABEL_RECEIPTS], [receipt])
        # The original statement is untouched (no receipt leakage).
        self.assertNotIn(LABEL_RECEIPTS, statement["unprotected"])

    def test_add_receipts_needs_at_least_one(self):
        statement = build_signed_statement(self.feed, key_id="key-1")
        with self.assertRaises(ValueError):
            add_receipts(statement, [])

    def test_bundle_media_type_switches(self):
        lone = build_scitt_bundle(self.feed, key_id="key-1")
        self.assertEqual(lone["media_type"], SCITT_STATEMENT_MEDIA_TYPE)
        self.assertEqual(lone["statement"]["unprotected"], {})
        full = build_scitt_bundle(self.feed, key_id="key-1", rekor_anchor=_fake_anchor())
        self.assertEqual(full["media_type"], SCITT_RECEIPT_MEDIA_TYPE)
        self.assertEqual(len(full["statement"]["unprotected"][LABEL_RECEIPTS]), 1)

    def test_bundle_is_spike_marked_and_deterministic(self):
        first = build_scitt_bundle(
            self.feed, key_id="key-1", exported_at="2026-10-03T12:00:00Z"
        )
        second = build_scitt_bundle(
            self.feed, key_id="key-1", exported_at="2026-10-03T12:00:00Z"
        )
        self.assertEqual(first["scitt"], SCITT_SPIKE_LABEL)
        self.assertEqual(first["encoding"], "json-diagnostic")
        self.assertEqual(bundle_to_json_bytes(first), bundle_to_json_bytes(second))
        self.assertTrue(first["mapping_notes"])


if __name__ == "__main__":
    unittest.main()
