"""Guards on the read-only completion advisory attached to real runs.

The advisory exists to collect a difference distribution, not to decide
anything. These tests pin the properties that make that safe: a fixture without
a shadow contract produces an unchanged report, a failing or unavailable
advisory never changes ``ok`` or the process exit code, and no advisory form can
authorize execution. The end-to-end cases drive the real driver, the real
workspace, and the real evidence journal with a scripted planner, so the exit
code assertion is about production wiring rather than a stand-in.
"""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
for _path in (
    COMPONENT_ROOT,
    COMPONENT_ROOT.parent / "northstar-run-contract",
    COMPONENT_ROOT.parent / "northstar-host",
    Path(__file__).resolve().parent,
):
    sys.path.insert(0, str(_path))

import live_run  # noqa: E402
from agent_entry import LIST_ACTION, READ_ACTION, WRITE_ACTION  # noqa: E402
from completion_advisory import (  # noqa: E402
    DriverAdvisory,
    contract_from_spec,
    evaluate_driver_advisory,
)
from completion_contract_v2 import (  # noqa: E402
    CompletionResult,
    Provenance,
    WorkspaceSnapshot,
)
from completion_live_shadow import production_result_from_host_check  # noqa: E402
from completion_shadow import compose_shadow  # noqa: E402
from live_run import build_shadow_advisory  # noqa: E402
from planner_adapter import PlannerModelResponse  # noqa: E402
from test_agent_entry import step_value  # noqa: E402

SHADOW = COMPONENT_ROOT / "live" / "shadow"
COMPLIANT = "number_of_data_rows: 4\ncolumns: name, score, city\ntop_scorer: carol\n"
NEGATED = (
    "number_of_data_rows: 4\n"
    "columns: name, score, city\n"
    "top_scorer: carol, NOT verified by source\n"
)


def provenance() -> Provenance:
    return Provenance.from_dict(
        {
            "contract_revision": "live-run-advisory-1",
            "evaluator_digest": "sha256:" + "e" * 64,
            "fixture_digest": "sha256:" + "f" * 64,
            "benchmark_commit": "0" * 40,
            "environment_digest": "sha256:" + "n" * 64,
            "model_id": "fixture-model",
            "model_revision": "rev-1",
            "reasoning_effort": "off",
            "max_output_tokens": 1024,
            "seed": "fixture",
            "trial_id": "fixture-trial",
        }
    )


def snapshot(files: dict[str, str]) -> WorkspaceSnapshot:
    return WorkspaceSnapshot.from_files(files)


class _HostCheck:
    """Stand-in for the driver's own host verification result."""

    def __init__(self, verdict: str, checked=("out/report.md",), failures=()):
        self.verdict = verdict
        self.checked = tuple(checked)
        self.failures = tuple(failures)


class _Written:
    def __init__(self, path: str, content: str):
        self.path = path
        self.content = content


def plan_from_context(context: dict, steps: list[dict]) -> dict:
    """Echo the identity the harness published; admission still re-checks it."""
    return {
        "schema_version": "northstar.agent-plan.v1",
        "plan_id": "plan-advisory-1",
        "plan_version": 1,
        "task_id": context["task_id"],
        "thread_id": context["thread_id"],
        "run_id": context["run_id"],
        "actor_id": context["actor_id"],
        "workspace_id": context["workspace_id"],
        "policy_revision": context["policy_revision"],
        "trace_id": context["trace_id"],
        "steps": steps,
    }


class _ContextCaller:
    """Deterministic planner: builds the plan from published context, no network."""

    def __init__(self, written: _Written, contents: list[str] | None = None):
        self.written = written
        self.contents = contents
        self.calls = 0

    def _content(self) -> str:
        if self.contents is None:
            return self.written.content
        index = min(self.calls - 1, len(self.contents) - 1)
        return self.contents[index]

    def __call__(self, *, goal, context, repair_error, attempt):
        self.calls += 1
        deadline = context["deadline_at"]

        def step(step_id, action_id, payload, postcondition):
            value = step_value(step_id, action_id, payload, [postcondition])
            value["deadline_at"] = deadline
            return value

        steps = [
            step("list-1", LIST_ACTION, {"prefix": "data", "max_depth": 1, "max_entries": 8}, "listing_ok"),
            step("read-1", READ_ACTION, {"path": "data/records.csv", "max_bytes": 4096}, "read_ok"),
            step(
                "write-1",
                WRITE_ACTION,
                {"path": self.written.path, "content": self._content()},
                "content_matches_payload",
            ),
        ]
        return PlannerModelResponse(
            json.dumps({"plan": plan_from_context(context, steps)}),
            "scripted-planner",
            "fixture",
            "rev-1",
        )


class AdvisoryShapeTest(unittest.TestCase):
    def advisory(self, *, production="verified", contract="verified") -> DriverAdvisory:
        journal = Path(tempfile.mkdtemp()) / "round-1.evidence.jsonl"
        journal.write_text("", encoding="utf-8")
        host_check = production_result_from_host_check(
            verdict=production,
            failures=(),
            checked=(),
            run_status="finished",
            after=snapshot({"out/report.md": "x\n"}),
        )
        contract_result = CompletionResult(contract, (), ())
        return DriverAdvisory(
            production=host_check,
            contract=contract_result,
            layered=compose_shadow(host_check, contract_result),
            evidence_path=journal,
        )

    def test_report_dict_is_non_authorizing_and_digested(self):
        payload = self.advisory().as_report_dict()
        self.assertFalse(payload["authoritative"])
        self.assertFalse(payload["affects_task_outcome"])
        self.assertFalse(payload["execution_authorized"])
        self.assertTrue(payload["advisory_digest"].startswith("sha256:"))
        self.assertEqual(payload["layered_verdict"], "verified")

    def test_digest_changes_when_the_layered_verdict_changes(self):
        verified = self.advisory().as_report_dict()
        failed = self.advisory(contract="failed").as_report_dict()
        self.assertNotEqual(verified["advisory_digest"], failed["advisory_digest"])

    def test_contract_from_spec_restricts_mutations_to_declared_artifacts(self):
        spec = json.loads((SHADOW / "01-column-report-shadow.json").read_text(encoding="utf-8"))[
            "shadow_contract"
        ]
        contract = contract_from_spec(spec, provenance())
        self.assertEqual(
            tuple(item.path for item in contract.required_artifacts), ("out/report.md",)
        )
        self.assertEqual(tuple(contract.allowed_mutations), ("out/report.md",))


class DriverSemanticsTest(unittest.TestCase):
    """The advisory re-expresses the host check; it never trusts a boolean."""

    def test_cancelled_run_is_a_failure_and_never_authorizes(self):
        journal = Path(tempfile.mkdtemp()) / "round-1.evidence.jsonl"
        journal.write_text("", encoding="utf-8")
        spec = json.loads((SHADOW / "01-column-report-shadow.json").read_text(encoding="utf-8"))[
            "shadow_contract"
        ]
        advisory = evaluate_driver_advisory(
            contract=contract_from_spec(spec, provenance()),
            provenance=provenance(),
            verification=_HostCheck("verified"),
            run_status="cancelled",
            before=snapshot({"README.md": "seed\n"}),
            after=snapshot({"README.md": "seed\n", "out/report.md": COMPLIANT}),
            evidence_path=journal,
        )
        self.assertEqual(advisory.production.verdict, "failed")
        self.assertFalse(advisory.layered.execution_authorized)

    def test_unfinished_run_is_unknown_not_verified(self):
        journal = Path(tempfile.mkdtemp()) / "round-1.evidence.jsonl"
        journal.write_text("", encoding="utf-8")
        spec = json.loads((SHADOW / "01-column-report-shadow.json").read_text(encoding="utf-8"))[
            "shadow_contract"
        ]
        advisory = evaluate_driver_advisory(
            contract=contract_from_spec(spec, provenance()),
            provenance=provenance(),
            verification=_HostCheck("verified"),
            run_status="paused_unknown",
            before=snapshot({"README.md": "seed\n"}),
            after=snapshot({"README.md": "seed\n", "out/report.md": COMPLIANT}),
            evidence_path=journal,
        )
        self.assertEqual(advisory.production.verdict, "unknown")
        self.assertEqual(advisory.layered.verdict, "unknown")


class LiveRunWiringTest(unittest.TestCase):
    """The advisory is recorded beside the run and never consulted by it."""

    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self):
        self._temporary.cleanup()

    def run_live(self, fixture_name: str, written: _Written) -> tuple[int, dict]:
        return self.run_fixture(
            json.loads((SHADOW / fixture_name).read_text(encoding="utf-8")), written
        )

    def run_fixture(
        self,
        fixture: dict,
        written: _Written,
        contents: list[str] | None = None,
        tag: str = "run",
    ) -> tuple[int, dict, Path]:
        """Run the real production path offline by scripting the planner."""
        fixture_path = self.root / f"{tag}-fixture.json"
        fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
        sandbox = self.root / f"{tag}-sandbox"
        report_path = self.root / f"{tag}-report.json"
        stdout = io.StringIO()
        with patch.object(
            live_run,
            "OpenAICompatiblePlannerCaller",
            lambda config: _ContextCaller(written, contents),
        ), contextlib.redirect_stdout(stdout):
            code = live_run.main(
                [
                    "--fixture", str(fixture_path),
                    "--endpoint", "https://planner.example/v1/chat/completions",
                    "--key-env", "TEST_PLANNER_API_KEY",
                    "--model", "fixture/model",
                    "--sandbox", str(sandbox),
                    "--report", str(report_path),
                ]
            )
        return code, json.loads(report_path.read_text(encoding="utf-8")), sandbox

    def test_fixture_without_shadow_contract_leaves_the_report_unchanged(self):
        fixture = json.loads((SHADOW / "01-column-report-shadow.json").read_text(encoding="utf-8"))
        fixture.pop("shadow_contract")
        code, report, _ = self.run_fixture(
            fixture, _Written("out/report.md", COMPLIANT), tag="plain"
        )
        self.assertEqual(code, 0)
        self.assertNotIn("shadow_advisory", report)

    def test_contract_failure_does_not_change_ok_or_exit_code(self):
        code, report, _ = self.run_live(
            "03-semantic-negation-shadow.json", _Written("out/report.md", NEGATED)
        )
        self.assertTrue(report["ok"])
        self.assertEqual(code, 0)
        advisory = report["shadow_advisory"]
        self.assertTrue(advisory["available"])
        self.assertEqual(advisory["production_verdict"], "verified")
        self.assertEqual(advisory["contract_verdict"], "failed")
        self.assertEqual(advisory["layered_verdict"], "failed")
        self.assertFalse(advisory["affects_task_outcome"])
        self.assertFalse(advisory["execution_authorized"])

    def test_compliant_run_reports_a_verified_layered_advisory(self):
        code, report, _ = self.run_live(
            "01-column-report-shadow.json", _Written("out/report.md", COMPLIANT)
        )
        self.assertTrue(report["ok"])
        self.assertEqual(code, 0)
        advisory = report["shadow_advisory"]
        self.assertTrue(advisory["available"])
        self.assertEqual(advisory["layered_verdict"], "verified")

    def test_malformed_shadow_contract_is_recorded_without_breaking_the_run(self):
        fixture = json.loads((SHADOW / "01-column-report-shadow.json").read_text(encoding="utf-8"))
        fixture["shadow_contract"] = {"milestones": ["list"]}
        code, report, _ = self.run_fixture(
            fixture, _Written("out/report.md", COMPLIANT), tag="malformed"
        )
        self.assertTrue(report["ok"])
        self.assertEqual(code, 0)
        advisory = report["shadow_advisory"]
        self.assertFalse(advisory["available"])
        self.assertEqual(advisory["reason"], "advisory_error:KeyError")
        self.assertFalse(advisory["execution_authorized"])

    def test_two_round_run_binds_the_final_round_evidence(self):
        fixture = {
            "schema_version": "northstar.live-task.v1",
            "task_id": "advisory-two-round-001",
            "goal": "Write out/report.md.",
            "seed": {"README.md": "seed\n", "data/records.csv": "name,score\ncarol,23\n"},
            "expect": [{"path": "out/report.md", "contains": ["final"]}],
            "shadow_contract": {
                "artifacts": [
                    {
                        "path": "out/report.md",
                        "semantic_fields": [{"name": "status", "value": "done"}],
                    }
                ],
                "milestones": ["list", "read", "write"],
                "milestone_edges": [["list", "read"], ["read", "write"]],
                "milestone_action_map": {
                    "workspace.list": "list",
                    "repo.read": "read",
                    "workspace.write": "write",
                },
            },
        }
        code, report, sandbox = self.run_fixture(
            fixture,
            _Written("out/report.md", ""),
            contents=["status: done\n", "status: done\nfinal: yes\n"],
            tag="two-round",
        )
        self.assertEqual(len(report["rounds"]), 2)
        self.assertTrue(report["ok"])
        self.assertEqual(code, 0)
        advisory = report["shadow_advisory"]
        self.assertTrue(advisory["available"])
        self.assertEqual(advisory["layered_verdict"], "verified")
        self.assertTrue(advisory["evidence_journal"].endswith("round-2.evidence.jsonl"))
        self.assertTrue((sandbox / "evidence" / "round-2.evidence.jsonl").exists())

    def test_the_verdict_follows_the_journal_it_is_given(self):
        """Discriminating twin: same inputs, only the terminal journal differs."""
        fixture = {
            "schema_version": "northstar.live-task.v1",
            "task_id": "advisory-binding-001",
            "goal": "Write out/report.md.",
            "seed": {"README.md": "seed\n", "data/records.csv": "name,score\ncarol,23\n"},
            "expect": [{"path": "out/report.md", "contains": ["final"]}],
            "shadow_contract": {
                "artifacts": [
                    {
                        "path": "out/report.md",
                        "semantic_fields": [{"name": "status", "value": "done"}],
                    }
                ],
                "milestones": ["list", "read", "write"],
                "milestone_edges": [["list", "read"], ["read", "write"]],
                "milestone_action_map": {
                    "workspace.list": "list",
                    "repo.read": "read",
                    "workspace.write": "write",
                },
            },
        }
        code, report, sandbox = self.run_fixture(
            fixture,
            _Written("out/report.md", "status: done\nfinal: yes\n"),
            tag="binding",
        )
        self.assertEqual(code, 0)
        stripped = self.root / "stripped-sandbox"
        (stripped / "evidence").mkdir(parents=True, exist_ok=True)
        shutil.copy(
            sandbox / "evidence" / "round-1.evidence.jsonl",
            stripped / "evidence" / "round-1.evidence.jsonl",
        )
        (stripped / "evidence" / "round-1.evidence.jsonl").write_text("", encoding="utf-8")

        def advisory_for(root: Path) -> dict:
            outcome = SimpleNamespace(
                rounds=[
                    SimpleNamespace(
                        round_index=1,
                        status="finished",
                        steps=[
                            {"action_id": action}
                            for action in ("workspace.list", "repo.read", "workspace.write")
                        ],
                    )
                ],
                verification=SimpleNamespace(verdict="verified", failures=(), checked=()),
            )
            return build_shadow_advisory(
                fixture=fixture,
                fixture_path=SHADOW / "01-column-report-shadow.json",
                outcome=outcome,
                sandbox=root,
                before=snapshot({"README.md": "seed\n"}),
                after=snapshot({"README.md": "seed\n", "out/report.md": "status: done\nfinal: yes\n"}),
                model_id="fixture/model",
                model_revision="fixture-rev",
                reasoning_effort="off",
                max_output_tokens=1024,
            )

        with_journal = advisory_for(sandbox)
        without_journal = advisory_for(stripped)
        self.assertTrue(with_journal["available"], with_journal)
        self.assertTrue(without_journal["available"], without_journal)
        self.assertEqual(with_journal["layered_verdict"], "verified", with_journal)
        self.assertNotEqual(without_journal["layered_verdict"], "verified", without_journal)


if __name__ == "__main__":
    unittest.main()
