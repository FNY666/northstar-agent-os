import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "northstar-run-contract"))
sys.path.insert(0, str(ROOT.parent / "northstar-host"))

from agent_driver import AgentDriver, DriverBudget  # noqa: E402
from agent_entry import ExpectedArtifact  # noqa: E402
from planner_adapter import PlannerModelResponse, TypedPlannerAdapter  # noqa: E402

WRITE = "workspace.write"
READ = "repo.read"
LIST = "workspace.list"


def plan_from_context(context, steps, *, plan_id="plan-live"):
    """Build a plan the way a real caller must: from published host identity."""
    return {
        "schema_version": "northstar.agent-plan.v1",
        "plan_id": plan_id,
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


def read_step(context, path, *, step_id=None, max_bytes=4096):
    step_id = step_id or f"read-{path.replace('/', '-')}"
    return {
        "schema_version": "northstar.agent-plan-step.v1",
        "step_id": step_id,
        "action_id": READ,
        "input_payload": {"path": path, "max_bytes": max_bytes},
        "scope_snapshot": ["workspace:read"],
        "expected_postconditions": ["read_ok"],
        "idempotency_key": f"{step_id}-{context['run_id']}",
        "max_attempts": 1,
        "deadline_at": context["deadline_at"] - 10,
    }


def list_step(context, prefix="", *, step_id="list-workspace"):
    return {
        "schema_version": "northstar.agent-plan-step.v1",
        "step_id": step_id,
        "action_id": LIST,
        "input_payload": {"prefix": prefix, "max_depth": 3, "max_entries": 16},
        "scope_snapshot": ["workspace:read"],
        "expected_postconditions": ["listing_ok"],
        "idempotency_key": f"{step_id}-{context['run_id']}",
        "max_attempts": 1,
        "deadline_at": context["deadline_at"] - 10,
    }


def write_step(context, path, content, *, step_id="write-report", attempts=1):
    return {
        "schema_version": "northstar.agent-plan-step.v1",
        "step_id": step_id,
        "action_id": WRITE,
        "input_payload": {"path": path, "content": content},
        "scope_snapshot": ["workspace:write"],
        "expected_postconditions": ["content_matches_payload"],
        "idempotency_key": f"{step_id}-{context['run_id']}",
        "max_attempts": attempts,
        "deadline_at": context["deadline_at"] - 10,
    }


class ReplanningCaller:
    """Round 1 guesses; later rounds must use the host's observations."""

    def __init__(self, decide):
        self.decide = decide
        self.contexts = []

    def __call__(self, *, goal, context, repair_error, attempt):
        self.contexts.append(context)
        steps = self.decide(context)
        return PlannerModelResponse(
            {"plan": plan_from_context(context, steps)}, "scripted-replanner", "fixture", "rev-1"
        )


class BrokenCaller:
    def __call__(self, *, goal, context, repair_error, attempt):
        return PlannerModelResponse("not json", "scripted-replanner", "fixture", "rev-1")


class AgentDriverTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        (self.workspace / "README.md").write_text(
            "Write out/report.md naming the columns of data/records.csv\n", encoding="utf-8"
        )
        (self.workspace / "data").mkdir()
        (self.workspace / "data" / "records.csv").write_text(
            "name,score,city\nalice,1,paris\nbob,2,rome\n", encoding="utf-8"
        )
        self.expectations = [ExpectedArtifact("out/report.md", contains=("name", "score", "city"))]

    def tearDown(self):
        self.tempdir.cleanup()

    def driver(self, **kwargs):
        return AgentDriver(
            workspace_root=self.workspace,
            evidence_dir=self.root / "evidence",
            expectations=self.expectations,
            clock=lambda: 100,
            **kwargs,
        )

    def test_driver_replans_from_host_observations_until_the_deliverable_verifies(self):
        def decide(context):
            if context["round"] == 1:
                return [
                    read_step(context, "README.md"),
                    read_step(context, "data/records.csv"),
                ]
            observed = context["observations"].get("data/records.csv", {})
            self.assertIn("name,score,city", observed.get("content", ""))
            return [write_step(context, "out/report.md", "columns: name, score, city\n")]

        caller = ReplanningCaller(decide)
        outcome = self.driver().run("driver-001", "Write the column report", TypedPlannerAdapter(caller))

        self.assertTrue(outcome.ok)
        self.assertEqual(len(outcome.rounds), 2)
        self.assertEqual(outcome.model_calls, 2)
        self.assertEqual(outcome.verification.verdict, "verified")
        self.assertEqual(
            (self.workspace / "out" / "report.md").read_text(encoding="utf-8"),
            "columns: name, score, city\n",
        )
        self.assertEqual([record.status for record in outcome.rounds], ["finished", "finished"])
        self.assertEqual(
            sorted(outcome.rounds[0].observed), ["README.md", "data/records.csv"]
        )
        self.assertEqual(sorted(outcome.rounds[1].observed), ["out/report.md"])

    def test_round_one_cannot_see_what_it_has_not_read_yet(self):
        seen = []

        def decide(context):
            seen.append(dict(context["observations"]))
            return [write_step(context, "out/report.md", "columns: guess\n")]

        outcome = self.driver(budget=DriverBudget(max_rounds=1)).run(
            "driver-002", "Write the column report", TypedPlannerAdapter(ReplanningCaller(decide))
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(seen, [{}])
        self.assertEqual(outcome.verification.verdict, "failed")

    def test_driver_stops_at_the_budget_and_says_so(self):
        def decide(context):
            return [write_step(context, "out/report.md", "columns: still wrong\n")]

        outcome = self.driver(budget=DriverBudget(max_rounds=2)).run(
            "driver-003", "Write the column report", TypedPlannerAdapter(ReplanningCaller(decide))
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(len(outcome.rounds), 2)
        self.assertEqual(outcome.model_calls, 2)
        self.assertEqual(outcome.verification.verdict, "failed")

    def test_a_refused_round_stops_the_driver_instead_of_retrying(self):
        def decide(context):
            return [write_step(context, "../escape.txt", "nope\n")]

        outcome = self.driver().run(
            "driver-004", "Escape the workspace", TypedPlannerAdapter(ReplanningCaller(decide))
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(len(outcome.rounds), 1)
        self.assertNotEqual(outcome.rounds[0].status, "finished")
        self.assertEqual(outcome.rounds[0].blocked, "step.action_denied")
        self.assertFalse((self.root / "escape.txt").exists())

    def test_a_proven_absent_round_is_replanned_instead_of_abandoning_the_task(self):
        """No file at the guessed path is a solvable mistake, not a refusal."""

        def decide(context):
            if context["round"] == 1:
                return [read_step(context, "data/missing.csv")]
            if context["round"] == 2:
                names = [entry["path"] for entry in context["workspace_files"]]
                self.assertIn("data/records.csv", names)
                return [read_step(context, "data/records.csv")]
            return [write_step(context, "out/report.md", "columns: name, score, city\n")]

        outcome = self.driver().run(
            "driver-008", "Write the column report", TypedPlannerAdapter(ReplanningCaller(decide))
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(len(outcome.rounds), 3)
        self.assertIsNone(outcome.rounds[0].blocked)
        self.assertEqual(outcome.verification.verdict, "verified")

    def test_observation_file_budget_is_strictly_bounded(self):
        def decide(context):
            return [
                read_step(context, "README.md", step_id="read-readme"),
                read_step(context, "data/records.csv", step_id="read-csv"),
            ]

        outcome = self.driver(
            budget=DriverBudget(max_rounds=1, max_observed_files=1)
        ).run("driver-011", "Inspect files", TypedPlannerAdapter(ReplanningCaller(decide)))
        self.assertFalse(outcome.ok)
        self.assertEqual(len(outcome.observations), 1)

    def test_directory_listing_observation_is_metadata_only_until_an_explicit_read(self):
        def decide(context):
            if context["round"] == 1:
                return [list_step(context)]
            if context["round"] == 2:
                listing = context["observations"]["listing:."]
                self.assertEqual(listing["action_id"], LIST)
                self.assertIn("README.md", [item["path"] for item in listing["entries"]])
                self.assertNotIn("content", listing)
                return [read_step(context, "README.md")]
            readback = context["observations"]["README.md"]
            self.assertIn("data/records.csv", readback["content"])
            return [write_step(context, "out/report.md", "columns: name, score, city\n")]

        outcome = self.driver().run(
            "driver-010", "Inspect then write", TypedPlannerAdapter(ReplanningCaller(decide))
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(len(outcome.rounds), 3)
        self.assertEqual(outcome.rounds[0].observed, ("listing:.",))

    def test_a_round_never_reuses_another_runs_evidence_file(self):
        """Stale evidence must fail loudly, not silently mismatch plan digests."""
        driver = self.driver()
        driver._harness("driver-009", 1)
        (self.root / "evidence" / "round-1.evidence.jsonl").write_text("", encoding="utf-8")
        with self.assertRaises(ValueError):
            driver._harness("driver-009", 1)

    def test_a_broken_planner_stops_the_driver_without_crashing(self):
        outcome = self.driver().run("driver-005", "Anything", TypedPlannerAdapter(BrokenCaller()))
        self.assertFalse(outcome.ok)
        self.assertEqual(len(outcome.rounds), 1)
        self.assertEqual(outcome.rounds[0].status, "round_failed")
        self.assertEqual(outcome.rounds[0].error, "ValueError")

    def test_observations_never_expose_written_content_as_evidence(self):
        def decide(context):
            return [write_step(context, "out/report.md", "columns: name, score, city\n")]

        outcome = self.driver().run(
            "driver-006", "Write the column report", TypedPlannerAdapter(ReplanningCaller(decide))
        )
        observation = outcome.observations["out/report.md"]
        self.assertNotIn("content", observation)
        self.assertEqual(observation["action_id"], WRITE)
        self.assertTrue(observation["digest"].startswith("sha256:"))

    def test_each_round_is_a_separate_governed_run_with_its_own_evidence(self):
        def decide(context):
            return [write_step(context, "out/report.md", "columns: still wrong\n")]

        outcome = self.driver(budget=DriverBudget(max_rounds=2)).run(
            "driver-007", "Write the column report", TypedPlannerAdapter(ReplanningCaller(decide))
        )
        run_ids = [record.run_id for record in outcome.rounds]
        self.assertEqual(len(set(run_ids)), 2)
        evidence = sorted((self.root / "evidence").glob("round-*.evidence.jsonl"))
        self.assertEqual(len(evidence), 2)
        for path in evidence:
            self.assertTrue(path.read_text(encoding="utf-8").strip())


if __name__ == "__main__":
    unittest.main()
