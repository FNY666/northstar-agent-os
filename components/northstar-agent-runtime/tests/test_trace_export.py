"""Tests for ``audit export --trace`` (TRACE v0.2-shaped Trust Records).

Two halves:

1. **JCS cross-validation against the TRACE spec's own conformance
   vectors** (``test_trace_jcs_*``): the spec
   (``spec/trace-v0.2.md`` §3.1.3/§3.2.2) warns that Python ``sorted()``
   gives Unicode code-point order while RFC 8785 sorts object keys by
   UTF-16 code *unit* — the two agree inside the BMP and diverge for
   supplementary-plane characters. The fixture
   ``examples/delegation-link/24-parent-key-supplementary-plane.json``
   is the vector that catches the shortcut: its root record's
   ``cnf.jwk`` carries a BMP private-use key (U+E000) and a
   supplementary-plane key (U+1F600), and the leaf's
   ``parent_record_hash`` is the root's digest under UTF-16 order.
   The root record below is reconstructed from the published fixture
   (explicit escapes, no ambiguity); the expected digest is the value
   the specification publishes, so a match validates both the
   reconstruction and Northstar's hand-written JCS implementation.

2. **Export shape tests** (``test_export_*``): the Trust Record shape,
   honesty defaults, signing, and loud failures.
"""
import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_chain import chain_records, jcs_canonical_json
from trace_export import (
    TRACE_EAT_PROFILE,
    build_trace_record,
    record_to_json_bytes,
    verify_trace_signature,
)


def _trace_spec_root_record():
    """Root record of TRACE-DELEG-024 (supplementary-plane key order).

    Reconstructed from the published fixture with explicit escapes; the
    digest assertion below is what proves the reconstruction faithful.
    """
    return {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": 1785000000,
        "subject": "spiffe://acme.example/agent/orchestrator",
        "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
        "runtime": {
            "platform": "software-only",
            "measurement": "sha256:" + "0" * 64,
        },
        "policy": {
            "bundle_hash": "sha256:" + "a" * 64,
            "enforcement_mode": "enforce",
        },
        "data_class": "restricted",
        "build_provenance": {
            "slsa_level": 0,
            "digest": "sha256:" + "b" * 64,
        },
        "appraisal": {
            "status": "affirming",
            "verifier": "https://verifier.example/v1",
        },
        "cnf": {
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "pNTZUXlAITEWbtVbHk6zGRwVD73s0BEakqkKKaFQyZ4",
                "\ue000": "bmp-private-use",
                "\U0001F600": "supplementary-plane",
            }
        },
        "signature": (
            "ozc4srGxEI1VCqR5VmlMr82GwvZUrp6dbKoB8P5BiMuUf829rZF31rvtJ3K5kxg-"
            "Shats2qMxJgPDWDL9sI1DQ"
        ),
    }


#: Published in the fixture as the leaf's ``parent_record_hash``: the
#: root's digest under RFC 8785 UTF-16 code-unit key order.
TRACE_DELEG_024_DIGEST = (
    "04e312eb2af4b55b8b7b138e8f1c9e077c6066b401ec9bc33702374454375ccd"
)


class TraceJcsVectorTests(unittest.TestCase):
    def test_supplementary_plane_digest_matches_spec(self):
        """Northstar JCS reproduces the spec's published chain digest."""
        digest = hashlib.sha256(
            jcs_canonical_json(_trace_spec_root_record())
        ).hexdigest()
        self.assertEqual(digest, TRACE_DELEG_024_DIGEST)

    def test_codepoint_order_gives_different_digest(self):
        """The fixture actually discriminates: code-point sort diverges."""
        wrong = hashlib.sha256(
            json.dumps(
                _trace_spec_root_record(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertNotEqual(wrong, TRACE_DELEG_024_DIGEST)

    def test_jcs_sorts_by_utf16_code_unit(self):
        """U+1F600 (D83D DE00) sorts before U+E000, unlike code points."""
        self.assertEqual(
            jcs_canonical_json({"\ue000": 1, "\U0001F600": 2}).decode("utf-8"),
            '{"\U0001F600":2,"\ue000":1}',
        )
        # Sanity: the shortcut order really is the other way round.
        self.assertEqual(
            json.dumps({"\ue000": 1, "\U0001F600": 2}, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            '{"\ue000":1,"\U0001F600":2}',
        )


def _write_chained_feed(directory: Path, name: str = "feed.ndjson") -> Path:
    """A small chained audit feed (chain v2) for export tests."""
    records = [
        {
            "schema_version": "audit.ndjson/1",
            "component": "northstar-agent-runtime",
            "event": "session_start",
            "ts": "2026-10-03T10:00:00Z",
            "level": "info",
            "payload": {},
        },
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


class TraceExportShapeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_export_shape_fields(self):
        feed = _write_chained_feed(self.dir)
        record = build_trace_record(feed)
        self.assertEqual(record["eat_profile"], TRACE_EAT_PROFILE)
        self.assertEqual(record["runtime"]["platform"], "software-only")
        self.assertEqual(record["origin"]["kind"], "log-import")
        self.assertEqual(record["origin"]["producer"], "northstar-audit-export")
        self.assertEqual(record["policy"]["enforcement_mode"], "enforce")
        self.assertNotIn("bundle_hash", record["policy"])  # unknown: omitted, not faked
        self.assertNotIn("model", record)  # unknown: omitted, not faked
        self.assertNotIn("signature", record)
        self.assertNotIn("cnf", record)
        # The record commits the chain head by hash (§3.3.2).
        head = json.loads(feed.read_text(encoding="utf-8").splitlines()[-1])["chain_hash"]
        self.assertEqual(record["tool_transcript"]["hash"], "sha256:" + head)
        self.assertEqual(record["tool_transcript"]["call_count"], 1)
        # behavior-trace reference points at the feed by digest.
        (ref,) = record["references"]
        self.assertEqual(ref["rel"], "behavior-trace")
        self.assertEqual(
            ref["digest"], "sha256:" + hashlib.sha256(feed.read_bytes()).hexdigest()
        )
        self.assertEqual(ref["resolver"], "northstar-audit-export")
        # Subject defaults to the run the genesis anchor names.
        self.assertEqual(record["subject"], "did:northstar:run/run-9")
        # Output bytes are the JCS canonical form (the digest form).
        self.assertEqual(record_to_json_bytes(record), jcs_canonical_json(record))

    def test_export_optional_fields(self):
        feed = _write_chained_feed(self.dir)
        record = build_trace_record(
            feed,
            policy_bundle_hash="sha256:" + "c" * 64,
            data_class="confidential",
            subject="did:example:custom",
            model_provider="anthropic",
            model_id="claude-opus-4-6",
        )
        self.assertEqual(record["policy"]["bundle_hash"], "sha256:" + "c" * 64)
        self.assertEqual(record["data_class"], "confidential")
        self.assertEqual(record["subject"], "did:example:custom")
        self.assertEqual(
            record["model"], {"provider": "anthropic", "model_id": "claude-opus-4-6"}
        )

    def test_export_signed_record_verifies(self):
        from ed25519 import public_key

        feed = _write_chained_feed(self.dir)
        seed = bytes(range(32))
        record = build_trace_record(feed, seed=seed)
        self.assertIn("signature", record)
        jwk = record["cnf"]["jwk"]
        self.assertEqual((jwk["kty"], jwk["crv"]), ("OKP", "Ed25519"))
        # Canonical base64url, no padding (§3.2.2).
        self.assertNotIn("=", record["signature"])
        base64.urlsafe_b64decode(record["signature"] + "==")
        self.assertTrue(verify_trace_signature(record, public_key(seed)))
        # Tampering breaks the signature.
        tampered = dict(record)
        tampered["data_class"] = "public"
        self.assertFalse(verify_trace_signature(tampered, public_key(seed)))
        # Unsigned records simply have nothing to check.
        unsigned = build_trace_record(feed)
        self.assertFalse(verify_trace_signature(unsigned, public_key(seed)))

    def test_export_refuses_unprotected_feed(self):
        feed = self.dir / "plain.ndjson"
        feed.write_text(
            json.dumps(
                {
                    "schema_version": "audit.ndjson/1",
                    "component": "northstar-agent-runtime",
                    "event": "session_start",
                    "ts": "2026-10-03T10:00:00Z",
                    "level": "info",
                    "payload": {},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "UNPROTECTED"):
            build_trace_record(feed)

    def test_export_refuses_broken_feed(self):
        feed = _write_chained_feed(self.dir)
        lines = feed.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[-1])
        tampered["payload"] = {"evil": True}
        lines[-1] = json.dumps(tampered)
        feed.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "BROKEN"):
            build_trace_record(feed)

    def test_export_refuses_missing_feed(self):
        with self.assertRaisesRegex(ValueError, "cannot read"):
            build_trace_record(self.dir / "nope.ndjson")

    def test_export_bad_option_values(self):
        feed = _write_chained_feed(self.dir)
        with self.assertRaisesRegex(ValueError, "sha256"):
            build_trace_record(feed, policy_bundle_hash="nope")
        with self.assertRaisesRegex(ValueError, "data-class"):
            build_trace_record(feed, data_class="topsecret")
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            build_trace_record(feed, seed=b"short")


class TraceExportCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _args(self, feed: Path, **overrides):
        import argparse

        args = argparse.Namespace(
            audit_command="export",
            feed=str(feed),
            trace=True,
            out="",
            seed_hex="",
            subject="",
            policy_bundle_hash="",
            data_class="",
            model_provider="",
            model_id="",
        )
        for key, value in overrides.items():
            setattr(args, key, value)
        return args

    def test_cli_export_writes_jcs_record(self):
        from audit_cli import run_audit

        feed = _write_chained_feed(self.dir)
        out = self.dir / "record.json"
        rc = run_audit(self._args(feed, out=str(out)))
        self.assertEqual(rc, 0)
        record = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(record["eat_profile"], TRACE_EAT_PROFILE)
        self.assertEqual(record["origin"]["kind"], "log-import")

    def test_cli_export_unprotected_exits_2(self):
        from audit_cli import run_audit

        feed = self.dir / "plain.ndjson"
        feed.write_text('{"a": 1}\n', encoding="utf-8")
        rc = run_audit(self._args(feed))
        self.assertEqual(rc, 2)

    def test_cli_export_missing_feed_is_usage_error(self):
        from audit_cli import run_audit

        rc = run_audit(self._args(self.dir / "missing.ndjson"))
        self.assertEqual(rc, 64)

    def test_cli_export_bad_seed_hex_is_usage_error(self):
        from audit_cli import run_audit

        feed = _write_chained_feed(self.dir)
        rc = run_audit(self._args(feed, seed_hex="zz"))
        self.assertEqual(rc, 64)


if __name__ == "__main__":
    unittest.main()
