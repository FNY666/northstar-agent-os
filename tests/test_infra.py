"""Tests for telling a broken task from a machine that broke.

A probe that dies of a segmentation fault says nothing about the task. The
evaluation images are built for one architecture and run under emulation on
another one, where numpy and pandas crash the test process. Treating that
as a rejected reference patch condemns a sound task.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from swe_bench_infra import INFRA_EXIT_CODES, infra_failure  # noqa: E402
from swe_bench_integrity import INCONCLUSIVE, TRUSTWORTHY, judge_instance  # noqa: E402


def _write_log(root: Path, probe: str, instance: str, name: str, text: str) -> None:
    base = root / "logs" / "run_evaluation" / "run1" / probe / instance
    base.mkdir(parents=True, exist_ok=True)
    (base / name).write_text(text, encoding="utf-8")


class InfraTests(unittest.TestCase):
    def test_a_segmentation_fault_is_an_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_log(
                root, "integrity-gold", "x", "test_output.txt",
                "+ SWEBENCH_TEST_EXIT_CODE=139\n",
            )
            self.assertEqual(infra_failure(root, "run1", "integrity-gold", "x"),
                             "Segmentation fault")

    def test_the_other_fatal_exit_statuses_are_recognised(self):
        for code, reason in INFRA_EXIT_CODES.items():
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                _write_log(
                    root, "integrity-gold", "x", "test_output.txt",
                    f"+ SWEBENCH_TEST_EXIT_CODE={code}\n",
                )
                self.assertEqual(
                    infra_failure(root, "run1", "integrity-gold", "x"), reason
                )

    def test_a_normal_exit_status_is_not_an_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_log(
                root, "integrity-gold", "x", "test_output.txt",
                "+ SWEBENCH_TEST_EXIT_CODE=1\n",
            )
            self.assertEqual(infra_failure(root, "run1", "integrity-gold", "x"), "")

    def test_a_test_that_only_prints_the_word_is_not_an_infrastructure_failure(self):
        # A text match alone would fire here; the exit status is the exact
        # signal, so a test that merely says "Killed" is not a dead run.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_log(
                root, "integrity-gold", "x", "test_output.txt",
                "assert 'Killed' in message\n+ SWEBENCH_TEST_EXIT_CODE=1\n",
            )
            self.assertEqual(infra_failure(root, "run1", "integrity-gold", "x"), "")

    def test_a_missing_log_is_not_an_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(infra_failure(Path(tmp), "run1", "integrity-gold", "x"), "")

    def test_a_probe_with_no_verdict_is_inconclusive_not_rejected(self):
        # This is the judgement that matters: a broken run must not be
        # counted as a task whose reference patch was refused.
        item = judge_instance("x", None, None)
        self.assertEqual(item.verdict, INCONCLUSIVE)
        self.assertFalse(item.is_trustworthy)

    def test_the_probe_breaks_are_told_apart_from_a_rejected_patch(self):
        broken = judge_instance("x", None, None)
        rejected = judge_instance("x", "RESOLVED_NO", "RESOLVED_NO")
        self.assertNotEqual(broken.verdict, rejected.verdict)
        self.assertNotEqual(broken.verdict, TRUSTWORTHY)


if __name__ == "__main__":
    unittest.main()
