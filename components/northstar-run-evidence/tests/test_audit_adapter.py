"""audit_adapter + evidence_cli: sealing the runtime's audit feed."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from audit_adapter import (
    parse_audit_feed,
    seal_audit_feed,
    verify_audit_seal,
)
from evidence_cli import main as cli_main
from evidence_store import HmacTestSigner


def _record(seq, event="tool_result", ts="2026-10-03T01:00:00.123Z"):
    return {
        "schema_version": "audit.ndjson/1",
        "component": "northstar-agent-runtime",
        "event": event,
        "seq": seq,
        "ts": ts,
        "level": "info",
        "payload": {"tool": "Shell"},
        "session_id": "session-1",
    }


def _feed(*records):
    return "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)


def _signer():
    return HmacTestSigner("test-key-1", b"test-secret-0123456789")


class AuditAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.store = str(Path(self.tmpdir.name) / "audit.evidence.jsonl")

    def test_seal_feed_produces_verifiable_manifest(self):
        signer = _signer()
        records = parse_audit_feed(_feed(_record(0), _record(1, event="denial")))
        manifest = seal_audit_feed(records, store_path=self.store, run_id="run-9", signer=signer)
        self.assertEqual(manifest["run_id"], "run-9")
        self.assertEqual(manifest["entry_count"], 2)
        result = verify_audit_seal(
            self.store, "run-9", manifest, {signer.key_id: signer.verifier()}
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.authenticity, "verified")

    def test_reseal_same_feed_is_idempotent(self):
        signer = _signer()
        feed = _feed(_record(0), _record(1))
        first = seal_audit_feed(parse_audit_feed(feed), store_path=self.store,
                                run_id="run-9", signer=signer)
        second = seal_audit_feed(parse_audit_feed(feed), store_path=self.store,
                                 run_id="run-9", signer=signer, sealed_at=1_800_000_099)
        self.assertEqual(first["head_digest"], second["head_digest"])
        self.assertEqual(second["entry_count"], 2)

    def test_new_records_extend_the_chain(self):
        signer = _signer()
        seal_audit_feed(parse_audit_feed(_feed(_record(0))), store_path=self.store,
                         run_id="run-9", signer=signer)
        manifest = seal_audit_feed(
            parse_audit_feed(_feed(_record(0), _record(1), _record(2))),
            store_path=self.store, run_id="run-9", signer=signer,
        )
        self.assertEqual(manifest["entry_count"], 3)

    def test_bad_timestamp_is_refused_not_guessed(self):
        records = parse_audit_feed(_feed(_record(0, ts="yesterday-ish")))
        with self.assertRaises(ValueError) as caught:
            seal_audit_feed(records, store_path=self.store, run_id="run-9", signer=_signer())
        self.assertIn("not strict RFC 3339", str(caught.exception))

    def test_wrong_schema_version_is_refused(self):
        record = _record(0)
        record["schema_version"] = "audit.ndjson/999"
        with self.assertRaises(ValueError):
            parse_audit_feed(_feed(record))

    def test_malformed_line_fails_the_whole_feed(self):
        with self.assertRaises(ValueError):
            parse_audit_feed(_feed(_record(0)) + "not json\n")

    def test_tampered_store_fails_verify(self):
        signer = _signer()
        manifest = seal_audit_feed(
            parse_audit_feed(_feed(_record(0))), store_path=self.store,
            run_id="run-9", signer=signer,
        )
        raw = bytearray(Path(self.store).read_bytes())
        raw[200] ^= 0x01
        Path(self.store).write_bytes(bytes(raw))
        with self.assertRaises(ValueError):
            verify_audit_seal(self.store, "run-9", manifest,
                              {signer.key_id: signer.verifier()})

    def test_empty_feed_is_refused(self):
        with self.assertRaises(ValueError):
            seal_audit_feed([], store_path=self.store, run_id="run-9", signer=_signer())


class EvidenceCliTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        (self.root / "feed.ndjson").write_text(
            _feed(_record(0), _record(1, event="denial")), encoding="utf-8"
        )
        (self.root / "key.bin").write_bytes(b"test-secret-0123456789")
        self.store = str(self.root / "audit.evidence.jsonl")
        self.manifest_path = str(self.root / "manifest.json")

    def base_args(self, command):
        args = [command, "--store", self.store, "--run-id", "run-9",
                "--key-file", str(self.root / "key.bin"), "--key-id", "test-key-1"]
        if command == "seal":
            args += ["--audit-feed", str(self.root / "feed.ndjson"),
                     "--manifest-out", self.manifest_path]
        else:
            args += ["--manifest", self.manifest_path]
        return args

    def test_cli_seal_then_verify_round_trip(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli_main(self.base_args("seal"))
        self.assertEqual(code, 0)
        manifest = json.loads(Path(self.manifest_path).read_text(encoding="utf-8"))
        self.assertEqual(manifest["entry_count"], 2)

        out = io.StringIO()
        with redirect_stdout(out):
            code = cli_main(self.base_args("verify"))
        self.assertEqual(code, 0)
        result = json.loads(out.getvalue())
        self.assertTrue(result["ok"])
        self.assertEqual(result["authenticity"], "verified")

    def test_cli_verify_with_wrong_key_fails(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli_main(self.base_args("seal")), 0)
        (self.root / "other-key.bin").write_bytes(b"other-secret-0123456789")
        args = self.base_args("verify")
        args[args.index("--key-file") + 1] = str(self.root / "other-key.bin")
        with redirect_stdout(io.StringIO()):
            code = cli_main(args)
        self.assertEqual(code, 1)

    def test_cli_seal_with_bad_feed_exits_2(self):
        (self.root / "feed.ndjson").write_text("garbage\n", encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            code = cli_main(self.base_args("seal"))
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
