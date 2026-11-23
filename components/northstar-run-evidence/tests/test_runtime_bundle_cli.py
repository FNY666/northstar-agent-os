"""Runtime bundle inspect/pack commands and cross-component ledger compatibility."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from evidence_cli import main
from evidence_store import EvidenceStore


class RuntimeBundleCommandsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="run-evidence-bundle-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir(mode=0o700)
        self.store = EvidenceStore(self.bundle / "ledger.jsonl", "run-001")
        self.store.append(
            source="runtime",
            kind="runtime.started",
            occurred_at=1_800_000_000,
            subject={"session_id": "session-1"},
            source_id="runtime-started",
        )
        terminal = self.store.append(
            source="runtime",
            kind="runtime.completed",
            occurred_at=1_800_000_001,
            subject={"subtype": "success"},
            source_id="result-terminal",
        )
        manifest = {
            "schema_version": "northstar.runtime-evidence-manifest.v1",
            "run_id": "run-001",
            "ledger": {
                "entry_count": 2,
                "head_digest": terminal.entry_digest,
            },
            "completion": {
                "evidence_entry_digest": terminal.entry_digest,
            },
        }
        (self.bundle / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )

    def invoke(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(list(argv))
        return code, out.getvalue()

    def test_inspect_verifies_and_summarizes(self):
        code, output = self.invoke("inspect", str(self.bundle), "--json")
        self.assertEqual(code, 0)
        result = json.loads(output)
        self.assertTrue(result["ok"])
        self.assertTrue(result["manifest_matches_ledger"])
        self.assertEqual(result["ledger"]["entries_checked"], 2)
        self.assertEqual(result["entry_kinds"]["runtime.completed"], 1)

    def test_inspect_detects_tampering(self):
        ledger = self.bundle / "ledger.jsonl"
        raw = bytearray(ledger.read_bytes())
        raw[110] ^= 1
        ledger.write_bytes(raw)
        code, output = self.invoke("inspect", str(self.bundle))
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(output)["ok"])

    def test_pack_copies_only_regular_bundle_artifacts_and_refuses_overwrite(self):
        output_dir = self.root / "copy"
        code, output = self.invoke("pack", str(self.bundle), "--output", str(output_dir))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["output"], str(output_dir.resolve()))
        self.assertTrue((output_dir / "ledger.jsonl").is_file())
        self.assertTrue((output_dir / "manifest.json").is_file())
        self.assertEqual(oct(output_dir.stat().st_mode & 0o777), oct(0o700))
        code, _ = self.invoke("pack", str(self.bundle), "--output", str(output_dir))
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
