"""Test-only coverage audit for archived completion replay declarations."""
from __future__ import annotations
import contextlib
import io

import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "replay" / "archive-replay-spec.json"

from completion_batch_replay import (  # noqa: E402
    default_context,
    load_spec,
)
from completion_coverage import (  # noqa: E402
    audit,
    fixture_requirements,
    main,
    summarize,
)


def _context(archive_root):
    return default_context(archive_root, ROOT / "completion_contract_v2.py")


def _coverage_by_task(coverage):
    return {(item.run, item.task_id): item for item in coverage}


CONTEXT = _context(Path("/var/minis/shared/northstar-live-runs"))


class CompletionCoverageTest(unittest.TestCase):
    def test_fixture_requirements_come_from_the_fixture_not_the_spec(self):
        for run in load_spec(SPEC):
            for spec in run.tasks:
                fixture = json.loads(
                    (CONTEXT.archive_root / run.run / spec.fixture).read_text(encoding="utf-8")
                )
                values = fixture_requirements(fixture)
                self.assertTrue(values)
                declared = [
                    item for item in fixture.get("expect", [])
                    if isinstance(item, dict) and isinstance(item.get("contains"), list)
                ]
                self.assertEqual(len(values), sum(len(item["contains"]) for item in declared))

    def test_measured_tasks_are_fully_bound_and_gaps_are_named(self):
        coverage = _coverage_by_task(audit(CONTEXT, load_spec(SPEC)))
        self.assertTrue(coverage[("2026-09-11-action-failure-recovery", "live-transient-write-recovery-v1")].complete)
        self.assertTrue(coverage[("2026-09-11-multi-task", "live-column-report-v2")].complete)
        self.assertTrue(coverage[("2026-09-11-multi-task", "live-score-audit-v2")].complete)

        release = coverage[("2026-09-11-multi-task", "live-release-note-v2")]
        self.assertFalse(release.complete)
        self.assertEqual(len(release.uncovered), 3)
        self.assertEqual(release.declared_field_count, 0)

        first = coverage[("2026-09-10-first-live-run", "live-column-report")]
        self.assertFalse(first.complete)
        self.assertEqual(first.uncovered, ("4",))
    def test_weakening_a_declaration_shows_up_as_unbound_requirements(self):
        weakened = json.loads(SPEC.read_text(encoding="utf-8"))
        for run in weakened["runs"]:
            for task in run["tasks"]:
                for fields in task.get("semantic_fields", {}).values():
                    for field in fields:
                        if field[0] == "columns":
                            field[1] = "name"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "spec.json"
            path.write_text(json.dumps(weakened), encoding="utf-8")
            coverage = _coverage_by_task(audit(CONTEXT, load_spec(path)))
        item = coverage[("2026-09-11-multi-task", "live-column-report-v2")]
        self.assertFalse(item.complete)
        self.assertEqual(item.uncovered, ("score", "city"))

    def test_strict_gate_fails_while_any_fixture_requirement_is_unbound(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "coverage.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(
                [
                    "--spec",
                    str(SPEC),
                    "--archive-root",
                    str(CONTEXT.archive_root),
                    "--json-out",
                    str(report),
                    "--strict",
                ]
            )
            payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(code, 1)
        self.assertFalse(payload["all_bound"])
        self.assertTrue(payload["gaps"])
        self.assertTrue(all(entry["uncovered"] for entry in payload["gaps"]))

    def test_summary_counts_every_requirement_once(self):
        coverage = audit(CONTEXT, load_spec(SPEC))
        summary = summarize(coverage)
        self.assertEqual(summary["task_count"], len(coverage))
        self.assertEqual(
            summary["requirement_count"],
            sum(len(item.requirements) for item in coverage),
        )
        self.assertEqual(summary["bound"] + summary["unbound"], summary["requirement_count"])
        self.assertEqual(len(summary["tasks"]), len(coverage))
        empty = summarize(())
        self.assertEqual(empty["task_count"], 0)
        self.assertEqual(empty["requirement_count"], 0)
        self.assertEqual(empty["bound"], 0)
        self.assertEqual(empty["unbound"], 0)
        self.assertTrue(empty["all_bound"])
