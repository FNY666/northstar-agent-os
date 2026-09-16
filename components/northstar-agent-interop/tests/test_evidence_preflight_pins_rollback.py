"""Rollback and high-water-mark tests for the preflight pin store."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from plan_evidence_decision import derive_plan_id
from evidence_preflight_pins import (
    PreflightPinStore,
    verify_pin_resolution,
)
from test_evidence_preflight_pins import D, make_preflight

STORE_SCHEMA = "northstar.evidence-preflight-pins.v1"


class PinRollbackTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = self.root / "pins"
        self.store = PreflightPinStore(self.path)
        self.log = self.path / "pins.jsonl"
        self.plan = derive_plan_id(D("d"))
        self.meta = self.path / "pins.meta.json"

    def _pin(self, plan, seed="a"):
        preflight = make_preflight(decision_digest=D(seed))
        return self.store.pin_preflight(
            derive_plan_id(preflight.manifest_digest), preflight, now=1000
        )

    def _lines(self):
        return self.log.read_text(encoding="utf-8").splitlines(True)

    def _write_meta(self, sequence, head_digest):
        self.meta.write_text(
            json.dumps(
                {
                    "schema_version": STORE_SCHEMA,
                    "high_water": {
                        "sequence": sequence,
                        "head_digest": head_digest,
                    },
                }
            ),
            encoding="utf-8",
        )

    def _reasons(self, resolution):
        return " ".join(resolution.reasons)

    def test_truncated_prefix_is_rejected_not_current(self):
        self._pin("plan-a", "a")
        self._pin("plan-a", "b")
        self.log.write_text("".join(self._lines()[:1]), encoding="utf-8")
        resolved = self.store.resolve(self.plan)
        self.assertEqual(resolved.state, "pins-unverifiable")
        self.assertIn("truncat", self._reasons(resolved))

    def test_empty_log_with_high_water_is_rejected(self):
        self._pin("plan-a", "a")
        self._pin("plan-a", "b")
        self.log.write_text("", encoding="utf-8")
        resolved = self.store.resolve(self.plan)
        self.assertEqual(resolved.state, "pins-unverifiable")

    def test_crash_window_is_repaired_forward(self):
        first = self._pin("plan-a", "a")
        self._pin("plan-a", "b")
        self._write_meta(1, first.record_digest)
        resolved = self.store.resolve(self.plan)
        self.assertEqual(resolved.state, "pins-current")
        self.assertIn("repaired", self._reasons(resolved))
        self.assertEqual(resolved.decision_digest, D("b"))
        again = self.store.resolve(self.plan)
        self.assertEqual(again.state, "pins-current")
        self.assertNotIn("repaired", self._reasons(again))

    def test_high_water_ahead_of_log_is_rejected(self):
        self._pin("plan-a", "a")
        self._write_meta(9, D("a"))
        self.assertEqual(self.store.resolve(self.plan).state, "pins-unverifiable")

    def test_tampered_high_water_head_is_rejected(self):
        self._pin("plan-a", "a")
        self._pin("plan-a", "b")
        self._write_meta(2, D("f"))
        self.assertEqual(self.store.resolve(self.plan).state, "pins-unverifiable")

    def test_missing_high_water_with_existing_log_is_rejected(self):
        self._pin("plan-a", "a")
        self.meta.unlink()
        resolved = self.store.resolve(self.plan)
        self.assertEqual(resolved.state, "pins-unverifiable")
        self.assertIn("high-water", self._reasons(resolved))

    def test_whole_store_removal_reads_as_unrecorded(self):
        self._pin("plan-a", "a")
        self.log.unlink()
        self.meta.unlink()
        resolved = self.store.resolve(self.plan)
        self.assertEqual(resolved.state, "pins-unrecorded")
        self.assertFalse(resolved.execution_authorized)

    def test_pin_after_repair_stays_contiguous(self):
        first = self._pin("plan-a", "a")
        self._pin("plan-a", "b")
        self._write_meta(1, first.record_digest)
        self.assertEqual(self.store.resolve(self.plan).state, "pins-current")
        third = self.store.pin_preflight(
            self.plan, make_preflight(decision_digest=D("c")), now=1010
        )
        self.assertEqual(third.sequence, 3)
        self.assertEqual(third.prev_digest, self._pin_record_digest(2))
        resolved = self.store.resolve(self.plan)
        verdict = verify_pin_resolution(
            resolved,
            self.store,
            expected_chain_head_digest=resolved.chain_head_digest,
            expected_chain_sequence=resolved.chain_sequence,
        )
        self.assertEqual(verdict.state, "pins-current")
        self.assertFalse(verdict.execution_authorized)

    def _pin_record_digest(self, sequence):
        for line in self._lines():
            record = json.loads(line)
            if record["sequence"] == sequence:
                return record["record_digest"]
        self.fail(f"no record with sequence {sequence}")

    def test_repaired_resolution_never_authorizes(self):
        first = self._pin("plan-a", "a")
        self._pin("plan-a", "b")
        self._write_meta(1, first.record_digest)
        resolved = self.store.resolve(self.plan)
        self.assertFalse(resolved.execution_authorized)
        self.assertTrue(resolved.witness_replayable is False)


if __name__ == "__main__":
    unittest.main()
