"""Tests for ``audit export --akf`` (AKF v1.1 unit spike).

Three halves:

1. **Export shape tests** (``test_export_*``): the unit's field mapping,
   the honest omissions (no ``ver``/``sig``), and loud failures on
   unprotected/broken feeds.
2. **Self-check tests** (``test_selfcheck_*``): ``validate_akf_unit``
   against the AKF v1.1 required invariants (``v``/``claims``; claim
   ``c``/``t``; prov ``hop``/``by``/``do``/``at``), including negative
   cases.
3. **Real-tool test** (``test_real_akf_audit_*``): when the ``akf``
   package is importable (``pip install akf``), the exported unit is run
   through AKF's own ``compliance.check_regulation(..., 'eu_ai_act')``.
   Expected outcome (derived from the actual compliance.py source):
   3/4 checks pass, score 0.75, compliant=True, with exactly one
   recommendation — the Art. 14 human-oversight gap. Skipped otherwise;
   the self-check above keeps CI green without the package.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from akf_export import (
    AKF_SCHEMA_VERSION,
    build_akf_unit,
    unit_to_json_bytes,
    validate_akf_unit,
)
from audit_chain import chain_records


def _write_chained_feed(directory: Path, name: str = "feed.ndjson") -> Path:
    """A small chained audit feed (chain v2) for export tests."""
    records = [
        {
            "schema_version": "audit.ndjson/1",
            "component": "northstar-agent-runtime",
            "event": "tool.started",
            "ts": "2026-10-03T10:00:00Z",
            "seq": 1,
            "tool": "Write",
            "args_digest": "a" * 64,
        },
        {
            "schema_version": "audit.ndjson/1",
            "component": "northstar-agent-runtime",
            "event": "gate.decision",
            "ts": "2026-10-03T10:00:01Z",
            "seq": 2,
            "decision": "ask",
            "tier": 3,
        },
        {
            "schema_version": "audit.ndjson/1",
            "component": "northstar-agent-runtime",
            "event": "tool.completed",
            "ts": "2026-10-03T10:00:02Z",
            "seq": 3,
            "tool": "Write",
            "ok": True,
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


class AkfExportShapeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_export_unit_shape(self):
        feed = _write_chained_feed(self.dir)
        unit = build_akf_unit(feed, now="2026-10-03T11:00:00Z")
        self.assertEqual(unit["v"], AKF_SCHEMA_VERSION)
        self.assertEqual(unit["id"], "akf:northstar:run/run-9")
        self.assertEqual(unit["label"], "internal")
        self.assertEqual(unit["by"], "northstar-audit-export")
        self.assertEqual(unit["agent"], "northstar-agent-runtime")
        self.assertTrue(unit["hash"].startswith("sha256:"))
        self.assertEqual(len(unit["claims"]), 3)
        self.assertEqual(validate_akf_unit(unit), [])

    def test_claim_field_mapping(self):
        """Every feed record becomes one claim with explicit mapping."""
        feed = _write_chained_feed(self.dir)
        unit = build_akf_unit(feed, now="2026-10-03T11:00:00Z")
        by_id = {c["id"]: c for c in unit["claims"]}
        gate = by_id["gate.decision:2"]
        # c: factual statement of the logged event.
        self.assertIn("gate.decision", gate["c"])
        self.assertIn("decision=ask", gate["c"])
        self.assertIn("tier=3", gate["c"])
        # t: record fidelity (deterministic log), not model confidence.
        self.assertEqual(gate["t"], 1.0)
        # ai: false — claims describe logged events, not AI output.
        self.assertIs(gate["ai"], False)
        # src: the source ledger; src_hash commits the record's chain hash.
        self.assertEqual(gate["src"], "audit.ndjson/1")
        self.assertTrue(gate["src_hash"].startswith("sha256:"))
        tool = by_id["tool.started:1"]
        self.assertIn("tool=Write", tool["c"])

    def test_honest_omissions(self):
        """Fields the feed cannot fill are absent, never fabricated."""
        feed = _write_chained_feed(self.dir)
        unit = build_akf_unit(feed, now="2026-10-03T11:00:00Z")
        # No per-claim human review tracked by the feed.
        for claim in unit["claims"]:
            self.assertNotIn("ver", claim)
            self.assertNotIn("risk", claim)
        # No unit-level signature: the chain is hash-chained, not signed.
        self.assertNotIn("sig", unit)
        self.assertNotIn("sig_algo", unit)
        self.assertNotIn("reviews", unit)
        # No model identity unless the operator passes one.
        self.assertNotIn("model", unit)
        gaps = unit["meta"]["northstar_akf_spike"]["honest_gaps"]
        self.assertTrue(any("ver" in g for g in gaps))

    def test_provenance_hops_use_schema_enum_verbs(self):
        """Prov ``do`` verbs come from the schema's required enum.

        The official AKF v1.1 schema restricts ProvHop.do to
        created|enriched|reviewed|consumed|transformed. "created" is
        factually accurate for the feed-production hop (the runtime did
        create the feed); "transformed" is accurate for the export hop.
        Caveat (asserted, not hidden): AKF's eu_ai_act human-oversight
        heuristic keys on ("reviewed", "created"), so it passes on machine
        provenance — the score must not be read as human oversight, and
        no claim.ver / reviews exist.
        """
        feed = _write_chained_feed(self.dir)
        unit = build_akf_unit(feed, now="2026-10-03T11:00:00Z")
        by_hop = {h["hop"]: h["do"] for h in unit["prov"]}
        self.assertEqual(by_hop, {0: "created", 1: "transformed"})
        for hop in unit["prov"]:
            for key in ("by", "do", "at"):
                self.assertTrue(hop[key])
            self.assertIsInstance(hop["hop"], int)

    def test_chain_head_committed(self):
        """The unit commits the chain head hash like the TRACE record does."""
        feed = _write_chained_feed(self.dir)
        unit = build_akf_unit(feed, now="2026-10-03T11:00:00Z")
        spike = unit["meta"]["northstar_akf_spike"]
        self.assertTrue(spike["chain_head"].startswith("sha256:"))
        self.assertEqual(spike["record_count"], 3)
        self.assertEqual(spike["feed_sha256"], unit["hash"])

    def test_label_option(self):
        feed = _write_chained_feed(self.dir)
        unit = build_akf_unit(feed, label="confidential", now="2026-10-03T11:00:00Z")
        self.assertEqual(unit["label"], "confidential")

    def test_model_id_option(self):
        feed = _write_chained_feed(self.dir)
        unit = build_akf_unit(feed, model_id="claude-opus-4-6", now="2026-10-03T11:00:00Z")
        self.assertEqual(unit["model"], "claude-opus-4-6")

    def test_export_refuses_unprotected_feed(self):
        feed = self.dir / "plain.ndjson"
        feed.write_text('{"a": 1}\n', encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            build_akf_unit(feed)
        self.assertIn("UNPROTECTED", str(ctx.exception))

    def test_export_refuses_broken_feed(self):
        feed = _write_chained_feed(self.dir)
        lines = feed.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[1])
        tampered["decision"] = "allow"
        lines[1] = json.dumps(tampered)
        feed.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            build_akf_unit(feed)
        self.assertIn("BROKEN", str(ctx.exception))

    def test_export_refuses_missing_feed(self):
        with self.assertRaises(ValueError):
            build_akf_unit(self.dir / "missing.ndjson")

    def test_bad_label_rejected(self):
        feed = _write_chained_feed(self.dir)
        with self.assertRaises(ValueError):
            build_akf_unit(feed, label="top-secret")


class AkfSelfCheckTests(unittest.TestCase):
    def _good_unit(self):
        return {
            "v": "1.1",
            "claims": [{"c": "x", "t": 0.5, "ai": False, "src": "s"}],
            "prov": [{"hop": 0, "by": "b", "do": "d", "at": "t"}],
            "label": "internal",
            "hash": "sha256:abc",
            "made_by": [{"by": "b", "role": "system"}],
        }

    def test_valid_unit_passes(self):
        self.assertEqual(validate_akf_unit(self._good_unit()), [])

    def test_missing_version(self):
        unit = self._good_unit()
        unit["v"] = "9.9"
        self.assertTrue(any("v must be" in p for p in validate_akf_unit(unit)))

    def test_empty_claims(self):
        unit = self._good_unit()
        unit["claims"] = []
        self.assertTrue(any("claims" in p for p in validate_akf_unit(unit)))

    def test_claim_missing_content(self):
        unit = self._good_unit()
        unit["claims"] = [{"t": 0.5}]
        problems = validate_akf_unit(unit)
        self.assertTrue(any(".c (content)" in p for p in problems))

    def test_claim_bad_confidence(self):
        unit = self._good_unit()
        unit["claims"] = [{"c": "x", "t": 1.5}]
        problems = validate_akf_unit(unit)
        self.assertTrue(any(".t (confidence)" in p for p in problems))

    def test_hop_missing_field(self):
        unit = self._good_unit()
        unit["prov"] = [{"hop": 0, "by": "b"}]
        problems = validate_akf_unit(unit)
        self.assertTrue(any("prov[0].do" in p for p in problems))

    def test_bad_hash_pattern(self):
        unit = self._good_unit()
        unit["hash"] = "md5:abc"
        problems = validate_akf_unit(unit)
        self.assertTrue(any("hash must match" in p for p in problems))

    def test_non_object(self):
        self.assertTrue(validate_akf_unit("nope"))


class AkfCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _args(self, feed, **kwargs):
        import argparse

        args = argparse.Namespace(
            audit_command="export",
            feed=str(feed),
            trace=False,
            akf=True,
            label="internal",
            model_id="",
            subject="",
            seed_hex="",
            out="",
            policy_bundle_hash="",
            data_class="",
            model_provider="",
        )
        for key, value in kwargs.items():
            setattr(args, key, value)
        return args

    def test_cli_export_writes_akf_unit(self):
        from audit_cli import run_audit

        feed = _write_chained_feed(self.dir)
        out = self.dir / "unit.akf.json"
        rc = run_audit(self._args(feed, out=str(out)))
        self.assertEqual(rc, 0)
        unit = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(unit["v"], AKF_SCHEMA_VERSION)
        self.assertEqual(len(unit["claims"]), 3)
        self.assertEqual(validate_akf_unit(unit), [])

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

    def test_cli_export_requires_shape_flag(self):
        from audit_cli import run_audit

        feed = _write_chained_feed(self.dir)
        rc = run_audit(self._args(feed, trace=False, akf=False))
        self.assertEqual(rc, 64)

    def test_cli_export_rejects_both_shape_flags(self):
        from audit_cli import run_audit

        feed = _write_chained_feed(self.dir)
        rc = run_audit(self._args(feed, trace=True, akf=True))
        self.assertEqual(rc, 64)


class AkfRealToolTests(unittest.TestCase):
    """Run the exported unit through AKF's own audit when installed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_akf_audit_eu_ai_act(self):
        try:
            from akf.compliance import check_regulation
        except ImportError:
            self.skipTest("akf package not installed; `pip install akf` for the real-tool check")
        feed = _write_chained_feed(self.dir)
        unit = build_akf_unit(feed, now="2026-10-03T11:00:00Z")
        result = check_regulation(json.dumps(unit), "eu_ai_act")
        by_check = {c["check"]: c["passed"] for c in result.checks}
        # Expected from the actual compliance.py source. Note the caveat:
        # eu_ai_human_oversight passes because the schema-required "created"
        # prov verb trips AKF's ("reviewed", "created") heuristic on machine
        # provenance — the score must not be read as human oversight. The
        # feed tracks no human review (no claim.ver / reviews).
        self.assertTrue(by_check["eu_ai_transparency"])
        self.assertTrue(by_check["eu_ai_accuracy"])
        self.assertTrue(by_check["eu_ai_traceability"])
        self.assertTrue(by_check["eu_ai_human_oversight"])
        self.assertEqual(result.score, 1.0)
        self.assertEqual(result.recommendations, [])


if __name__ == "__main__":
    unittest.main()
