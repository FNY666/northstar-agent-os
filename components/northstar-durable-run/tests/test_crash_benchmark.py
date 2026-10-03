"""Crash-benchmark regression suite: scripted baseline + kill at every site.

Baseline: 3 steps x 2 ledger tool calls each + per-step checkpoints, all
deterministic (fixed logical timestamps, no I/O beyond temp files). For every
instrumented crash site (4 per tool call + 2 checkpoint sites), one subtest
kills the run at that site with SimulatedCrash (the kill -9 stand-in), then
resumes with a fresh runner and asserts:

- the recovered outputs are byte-identical (canonical JSON) to the golden run,
- every completed tool call ran its raw effect exactly once (zero re-runs),
- the terminal marker (run.finished) appears exactly once.

Single-process: SimulatedCrash models kill -9 in-process. The real kill -9
cross-process test lives in test_supervisor.py.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
if str(COMPONENT_ROOT) not in sys.path:
    sys.path.insert(0, str(COMPONENT_ROOT))

from durable_contract import RunContract
from event_store import EventStore
from runner import DurableRunner, SimulatedCrash, StepPlan
from tool_ledger import InMemoryDedupReceiver


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _make_run(run_id="run-ledger-001", deadline_at=2000):
    return RunContract.from_dict(
        {
            "schema_version": "northstar.durable-run.v1",
            "task_id": "task-001",
            "thread_id": "thread-001",
            "run_id": run_id,
            "parent_run_id": None,
            "status": "planned",
            "deadline_at": deadline_at,
            "scope_snapshot": ["workspace:read", "workspace:write"],
            "trace_id": "trace-001",
        }
    )


STEP_IDS = ("s1", "s2", "s3")
TOOL_IDS = ("s1a", "s1b", "s2a", "s2b", "s3a", "s3b")


def _plan(step_id, action):
    return StepPlan(
        step_id=step_id,
        input_payload={"step": step_id},
        scope_snapshot=["workspace:write"],
        expected_postconditions=[f"{step_id}_done"],
        action=action,
    )
TOOL_SITES = [
    f"{phase}:{tid}"
    for tid in TOOL_IDS
    for phase in (
        "before-tool-started",
        "after-tool-started",
        "before-tool-completed",
        "after-tool-completed",
    )
]
SITES = TOOL_SITES + ["before-checkpoint", "after-checkpoint"]


class _Bench:
    """One scripted run: 3 steps x 2 tool calls, shared counters across resume."""

    def __init__(self, run_id):
        self.tempdir = tempfile.TemporaryDirectory()
        self.base = Path(self.tempdir.name)
        self.store = EventStore(self.base / "events.jsonl")
        self.run_id = run_id
        self.raw_calls = {}
        self.outputs = {}
        self.receiver = InMemoryDedupReceiver()

    def cleanup(self):
        self.tempdir.cleanup()

    def make_runner(self, crash_site=None):
        def hook(site):
            if site == crash_site:
                raise SimulatedCrash(f"benchmark kill at {site}")

        return DurableRunner(
            _make_run(self.run_id),
            self.store,
            lease_path=self.base / "run.lease.json",
            lease_ttl_seconds=20,
            crash_hook=hook if crash_site is not None else None,
        )

    def effect(self, tool_call_id):
        bench = self

        def _fn(key):
            bench.raw_calls[tool_call_id] = bench.raw_calls.get(tool_call_id, 0) + 1
            return bench.receiver.execute(key, lambda: {"tool": tool_call_id})

        return _fn

    def plans(self, now):
        bench = self

        def make_action(step_id, tids):
            def _action(key):
                results = [
                    bench.runner.run_tool(
                        step_id=step_id,
                        tool_call_id=tid,
                        fn=bench.effect(tid),
                        now=now,
                        receiver=bench.receiver,
                    )
                    for tid in tids
                ]
                output = {"step": step_id, "tools": results}
                bench.outputs[step_id] = output
                return output

            return _action

        return [
            _plan(step_id, make_action(step_id, (f"{step_id}a", f"{step_id}b")))
            for step_id in STEP_IDS
        ]

    def event_types(self):
        return [event.event_type for event in self.store.read_history(self.run_id)]


class CrashBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bench = _Bench("run-bench-golden")
        cls.addClassCleanup(bench.cleanup)
        bench.runner = bench.make_runner()
        state = bench.runner.execute(bench.plans(now=100), owner_id="w", now=100)
        assert state["status"] == "finished"
        cls.golden_outputs = _canonical(bench.outputs)
        cls.golden_raw_calls = dict(bench.raw_calls)
        assert cls.golden_raw_calls == {tid: 1 for tid in TOOL_IDS}
        assert set(bench.outputs) == set(STEP_IDS)

    def test_golden_baseline_shape(self):
        self.assertEqual(
            self.golden_raw_calls, {tid: 1 for tid in TOOL_IDS}
        )

    def test_crash_at_every_site_recovers_identically(self):
        for site in SITES:
            with self.subTest(site=site):
                bench = _Bench(f"run-bench-{site.replace(':', '-')}")
                self.addCleanup(bench.cleanup)
                # Run 1: killed at the site.
                bench.runner = bench.make_runner(crash_site=site)
                with self.assertRaises(SimulatedCrash):
                    bench.runner.execute(bench.plans(now=100), owner_id="w", now=100)
                # Run 2: fresh runner, no hook, resumes from the event log.
                bench.runner = bench.make_runner()
                state = bench.runner.execute(
                    bench.plans(now=200), owner_id="w2", now=200
                )
                self.assertEqual(state["status"], "finished")
                # Byte-identical outputs.
                self.assertEqual(_canonical(bench.outputs), self.golden_outputs)
                # Zero re-runs of completed tool calls: every raw effect ran
                # exactly once across the crash and the resume.
                self.assertEqual(bench.raw_calls, {tid: 1 for tid in TOOL_IDS})
                # Terminal marker exactly once (the webhook analog).
                types = bench.event_types()
                self.assertEqual(types.count("run.finished"), 1)
                self.assertEqual(types.count("step.finished"), 3)
                # Every tool call completed exactly once in the ledger.
                for tid in TOOL_IDS:
                    completed = [
                        event
                        for event in bench.store.read_history(bench.run_id)
                        if event.event_type == "tool.completed"
                        and event.idempotency_key.startswith(f"tool:{tid}:")
                    ]
                    self.assertEqual(len(completed), 1, tid)


if __name__ == "__main__":
    unittest.main()
