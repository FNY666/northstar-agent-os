"""Tests for re-judging an integrity check from the logs of a finished run.

Re-running fifty tasks takes days. When the rules change, the verdicts have
to be brought up to date from what the run already recorded. These tests
make sure the re-judgement uses that record and changes nothing else.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from rejudge_integrity import rejudge  # noqa: E402
from swe_bench_integrity import CheckStore, InstanceIntegrity  # noqa: E402


def _log(root: Path, probe: str, instance: str, exit_code: int) -> None:
    base = root / "logs" / "run_evaluation" / "run1" / probe / instance
    base.mkdir(parents=True, exist_ok=True)
    (base / "test_output.txt").write_text(
        f"+ SWEBENCH_TEST_EXIT_CODE={exit_code}\n", encoding="utf-8"
    )


def _report(resolved: bool, f2p_failed: list[str], f2p_passed: list[str]) -> dict:
    return {
        "resolved": resolved,
        "tests_status": {
            "FAIL_TO_PASS": {"failure": f2p_failed, "success": f2p_passed},
            "PASS_TO_PASS": {"failure": [], "success": []},
        },
    }


class RejudgeTests(unittest.TestCase):
    def test_a_run_that_broke_is_inconclusive_not_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            check = root / "check.json"
            store = CheckStore(check)
            store.add(
                InstanceIntegrity(
                    instance_id="x",
                    verdict="gold_patch_rejected",
                    gold_outcome="RESOLVED_NO",
                    empty_outcome="RESOLVED_NO",
                ),
                {"gold": {"resolved": False}, "empty": {"resolved": False}},
            )
            store.flush()
            _log(root, "integrity-gold", "x", 139)
            _log(root, "integrity-empty", "x", 139)

            report = rejudge(check, root, "run1")
            self.assertEqual(report.instances[0].verdict, "inconclusive")
            self.assertIn("Segmentation fault", report.instances[0].detail)

    def test_a_run_that_did_not_break_keeps_its_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            check = root / "check.json"
            store = CheckStore(check)
            store.add(
                InstanceIntegrity(
                    instance_id="a",
                    verdict="trustworthy",
                    gold_outcome="RESOLVED_FULL",
                    empty_outcome="RESOLVED_NO",
                ),
                {
                    "gold": _report(True, ["t::a"], ["t::b"]),
                    "empty": _report(False, ["t::a"], ["t::b"]),
                },
            )
            store.flush()
            _log(root, "integrity-gold", "a", 0)
            _log(root, "integrity-empty", "a", 1)

            report = rejudge(check, root, "run1")
            self.assertEqual(report.instances[0].verdict, "trustworthy")

    def test_the_rejudgement_uses_the_test_lists_it_kept(self):
        # The shape seen in the real run: both probes end in the same
        # partial resolution, and the fail-to-pass tests already pass with
        # no patch at all. The task cannot tell a fix from a no-op, and the
        # re-judgement has to find that in the reports the check kept.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            check = root / "check.json"
            store = CheckStore(check)
            store.add(
                InstanceIntegrity(
                    instance_id="a",
                    verdict="trustworthy",
                    gold_outcome="RESOLVED_PARTIAL",
                    empty_outcome="RESOLVED_PARTIAL",
                ),
                {
                    "gold": _report(False, ["t::c"], ["t::a", "t::b"]),
                    "empty": _report(False, ["t::c"], ["t::a", "t::b"]),
                },
            )
            store.flush()
            _log(root, "integrity-gold", "a", 1)
            _log(root, "integrity-empty", "a", 1)

            report = rejudge(check, root, "run1")
            self.assertEqual(report.instances[0].verdict, "empty_patch_accepted")
            self.assertIn("t::a", report.instances[0].fail_to_pass_passing_when_empty)

    def test_the_summary_counts_the_recomputed_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            check = root / "check.json"
            store = CheckStore(check)
            store.add(InstanceIntegrity(instance_id="a", verdict="trustworthy"))
            store.flush()

            report = rejudge(check, root, "run1")
            self.assertEqual(report.summary()["instances"], 1)

    def test_the_rejudgement_does_not_change_the_original_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            check = root / "check.json"
            store = CheckStore(check)
            store.add(InstanceIntegrity(instance_id="a", verdict="trustworthy"))
            store.flush()
            before = check.read_text(encoding="utf-8")

            rejudge(check, root, "run1")
            self.assertEqual(check.read_text(encoding="utf-8"), before)


if __name__ == "__main__":
    unittest.main()
