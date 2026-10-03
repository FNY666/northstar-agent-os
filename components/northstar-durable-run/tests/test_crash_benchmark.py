"""Crash-benchmark regression suite: scripted baseline + kill at every site.

Baseline: 3 steps x 2 ledger tool calls each + per-step checkpoints, all
deterministic (fixed logical timestamps, no I/O beyond temp files). For every
instrumented crash site (4 per tool call + 2 checkpoint sites), one subtest
kills the run at that site with SimulatedCrash (the kill -9 stand-in), then
resumes with a fresh runner and asserts:

- the recovered outputs are byte-identical (canonical JSON) to the golden run,
- every completed tool call ran its raw effect exactly once (zero re-runs),
- the terminal marker (run.finished) appears exactly once.

Two receiver models:

- *Surviving receiver* (``CrashBenchmarkTests``): the dedup store outlives
  the crash (e.g. a database-backed receiver). In-flight tool calls are
  adopted from the store; nothing re-executes.
- *Non-surviving receiver* (``CrashInflightMetricsTests``): the dedup store
  dies with the process — the honest model for an in-memory receiver under a
  real ``kill -9`` (``InMemoryDedupReceiver`` is documented as
  single-process/tests-only for exactly this reason). A tool call whose raw
  effect executed before the crash but never completed MUST re-execute on
  resume: without surviving dedup state, "ran but unrecorded" is
  indistinguishable from "never ran". The suite measures this in-flight
  re-execution rate per crash site.

Methodology ("in-flight necessarily re-executes"): end-to-end exactly-once
holds iff the receiver deduplicates on the idempotency key. DCP-2.0
(sdageltc/agent-durability-bench, physical OS SIGKILL fault injection)
independently reports the same finding: in-flight steps necessarily
re-execute, ~1.4-2.8% token waste. In this scripted benchmark the rate is
exact per site: 1 of 6 tool calls re-executes at ``before-tool-completed``
sites (the only sites where the effect ran but completion was never
recorded), 0 elsewhere; 6 duplicate executions across the 26-site sweep
(6/156 slots = 3.85%).

``CrashRealKillTests`` repeats three representative sites with a real forked
child killed by the OS (``SIGKILL``), proving the SimulatedCrash conclusions
hold under a true kill -9.
"""

import json
import multiprocessing
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
from collections import Counter
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


def _tool_call_id_of(event):
    """Parse the tool_call_id out of a ledger idempotency key.

    Keys look like ``tool:<tool_call_id>:attempt-<n>:<phase>``.
    """
    parts = event.idempotency_key.split(":")
    if len(parts) >= 2 and parts[0] == "tool":
        return parts[1]
    return None


def _in_flight_tool_calls(store, run_id):
    """Tool calls with tool.started but no tool.completed in the log."""
    started, completed = set(), set()
    for event in store.read_history(run_id):
        tid = _tool_call_id_of(event)
        if tid is None:
            continue
        if event.event_type == "tool.started":
            started.add(tid)
        elif event.event_type == "tool.completed":
            completed.add(tid)
    return started - completed


def _poll_for(path, timeout_seconds=30):
    deadline = time.time() + timeout_seconds
    while not path.exists():
        if time.time() > deadline:
            raise AssertionError(f"timed out waiting for {path}")
        time.sleep(0.02)
    return True


class _Bench:
    """One scripted run: 3 steps x 2 tool calls, shared counters across resume."""

    def __init__(self, run_id, base_dir=None, log_path=None, step_outputs_dir=None):
        if base_dir is None:
            self.tempdir = tempfile.TemporaryDirectory()
            self.base = Path(self.tempdir.name)
        else:
            # Shared directory (e.g. across a forked child): no ownership.
            self.tempdir = None
            self.base = Path(base_dir)
            self.base.mkdir(parents=True, exist_ok=True)
        self.store = EventStore(self.base / "events.jsonl")
        self.run_id = run_id
        self.raw_calls = {}
        self.outputs = {}
        self.receiver = InMemoryDedupReceiver()
        self.log_path = Path(log_path) if log_path is not None else None
        # Optional cross-process step-output sink: after each step action
        # completes, its canonical output is fsync'd to
        # <dir>/<step_id>.json. Lets a parent process merge outputs across a
        # SIGKILL boundary (the child's in-memory dict dies with it).
        self.step_outputs_dir = (
            Path(step_outputs_dir) if step_outputs_dir is not None else None
        )
        if self.step_outputs_dir is not None:
            self.step_outputs_dir.mkdir(parents=True, exist_ok=True)

    def cleanup(self):
        if self.tempdir is not None:
            self.tempdir.cleanup()

    def make_runner(self, crash_site=None, hook=None):
        if hook is not None:
            crash_hook = hook
        elif crash_site is not None:
            def crash_hook(site):
                if site == crash_site:
                    raise SimulatedCrash(f"benchmark kill at {site}")
        else:
            crash_hook = None

        return DurableRunner(
            _make_run(self.run_id),
            self.store,
            lease_path=self.base / "run.lease.json",
            lease_ttl_seconds=20,
            crash_hook=crash_hook,
        )

    def effect(self, tool_call_id):
        bench = self

        def _fn(key):
            bench.raw_calls[tool_call_id] = bench.raw_calls.get(tool_call_id, 0) + 1
            if bench.log_path is not None:
                # Cross-process execution counter: the child may be SIGKILLed,
                # so flush + fsync every line.
                with open(bench.log_path, "a", encoding="utf-8") as fh:
                    fh.write(tool_call_id + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
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
                if bench.step_outputs_dir is not None:
                    out_path = bench.step_outputs_dir / f"{step_id}.json"
                    with open(out_path, "w", encoding="utf-8") as fh:
                        fh.write(_canonical(output))
                        fh.flush()
                        os.fsync(fh.fileno())
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


class CrashInflightMetricsTests(unittest.TestCase):
    """In-flight re-execution rate with a non-surviving (in-memory) receiver.

    Models the honest kill -9 case: the dedup store dies with the process, so
    the resume gets a fresh receiver. A tool call whose raw effect executed
    before the crash but never completed MUST re-execute — "ran but
    unrecorded" is indistinguishable from "never ran". Completed tool calls
    must never re-execute.
    """

    @classmethod
    def setUpClass(cls):
        bench = _Bench("run-bench-golden-inflight")
        cls.addClassCleanup(bench.cleanup)
        bench.runner = bench.make_runner()
        state = bench.runner.execute(bench.plans(now=100), owner_id="w", now=100)
        assert state["status"] == "finished"
        cls.golden_outputs = _canonical(bench.outputs)

        cls.site_results = {}
        for site in SITES:
            b = _Bench(f"run-bench-inflight-{site.replace(':', '-')}")
            cls.addClassCleanup(b.cleanup)
            b.runner = b.make_runner(crash_site=site)
            try:
                b.runner.execute(b.plans(now=100), owner_id="w", now=100)
            except SimulatedCrash:
                pass
            else:
                raise AssertionError(f"crash site {site} did not crash")
            in_flight = _in_flight_tool_calls(b.store, b.run_id)
            # The in-memory dedup store died with the killed process.
            b.receiver = InMemoryDedupReceiver()
            b.runner = b.make_runner()
            state = b.runner.execute(b.plans(now=200), owner_id="w2", now=200)
            assert state["status"] == "finished"
            re_executed = {tid for tid, n in b.raw_calls.items() if n > 1}
            cls.site_results[site] = {
                "in_flight": in_flight,
                "re_executed": re_executed,
                "raw_calls": dict(b.raw_calls),
                "outputs": _canonical(b.outputs),
                "types": b.event_types(),
            }

    def test_completed_tool_calls_never_reexecute(self):
        # The core safety property, per site: only in-flight calls may ever
        # re-execute. A completed tool call re-running its raw effect would
        # be a double application.
        for site, res in self.site_results.items():
            with self.subTest(site=site):
                self.assertLessEqual(
                    res["re_executed"],
                    res["in_flight"],
                    f"site {site}: completed call re-executed: "
                    f"{res['re_executed'] - res['in_flight']}",
                )

    def test_inflight_reexecution_is_exact_per_site(self):
        # Deterministic benchmark: the re-executed set is exactly the tool
        # calls whose effect ran but never completed before the crash.
        for site, res in self.site_results.items():
            with self.subTest(site=site):
                phase = site.split(":")[0]
                tid = site.split(":")[1] if ":" in site else None
                if phase == "before-tool-completed":
                    # Effect executed, completion never recorded: the resume
                    # cannot tell it apart from never-run -> must re-execute.
                    self.assertEqual(res["in_flight"], {tid}, site)
                    self.assertEqual(res["re_executed"], {tid}, site)
                elif phase == "after-tool-started":
                    # Started but the effect never ran: reconcile re-issues
                    # exactly once, no duplicate execution.
                    self.assertEqual(res["in_flight"], {tid}, site)
                    self.assertEqual(res["re_executed"], set(), site)
                else:
                    self.assertEqual(res["in_flight"], set(), site)
                    self.assertEqual(res["re_executed"], set(), site)
                # Every tool call ran at least once; none ran more than twice.
                for call_tid in TOOL_IDS:
                    self.assertIn(call_tid, res["raw_calls"], (site, call_tid))
                    self.assertLessEqual(res["raw_calls"][call_tid], 2, (site, call_tid))

    def test_recovery_correct_with_fresh_receiver(self):
        # Even with dedup state lost, recovery is correct: byte-identical
        # outputs, terminal markers exactly once.
        for site, res in self.site_results.items():
            with self.subTest(site=site):
                self.assertEqual(res["outputs"], self.golden_outputs, site)
                self.assertEqual(res["types"].count("run.finished"), 1, site)
                self.assertEqual(res["types"].count("step.finished"), 3, site)

    def test_inflight_reexecution_aggregate_rate(self):
        total_dupes = sum(len(res["re_executed"]) for res in self.site_results.values())
        slots = len(SITES) * len(TOOL_IDS)
        # Exactly the 6 before-tool-completed sites re-execute one call each.
        self.assertEqual(total_dupes, 6)
        rate = total_dupes / slots
        self.assertAlmostEqual(rate, 6 / 156)
        print(
            "\ncrash-benchmark in-flight metrics (fresh receiver model):\n"
            f"  crash sites swept            : {len(SITES)}\n"
            f"  tool-call slots              : {slots}\n"
            f"  duplicate raw executions     : {total_dupes}\n"
            f"  in-flight re-execution rate  : {rate:.2%}\n"
            "  per-site: 1/6 re-execute at before-tool-completed sites,\n"
            "            0 elsewhere (completed calls never re-execute).\n"
            "  Methodology: in-flight necessarily re-executes without a\n"
            "  surviving dedup store; DCP-2.0 independently reports\n"
            "  ~1.4-2.8% token waste from in-flight re-execution."
        )


def _realkill_worker(
    events_path, lease_path, log_path, ready_path, run_id, target_site, step_outputs_dir
):
    """Child-process entry: run the benchmark, block at target_site for SIGKILL.

    The crash hook signals readiness through ``ready_path`` and then blocks
    forever; the parent SIGKILLs the child at that point. Raw effect
    executions are counted in ``log_path`` (fsync'd per line) and completed
    step outputs in ``step_outputs_dir`` because the child's memory dies
    with it.
    """
    bench = _Bench(
        run_id,
        base_dir=str(Path(events_path).parent),
        log_path=log_path,
        step_outputs_dir=step_outputs_dir,
    )

    def hook(site):
        if site == target_site:
            Path(ready_path).write_text(site, encoding="utf-8")
            threading.Event().wait()  # block until the parent SIGKILLs us

    bench.runner = bench.make_runner(hook=hook)
    bench.runner.execute(bench.plans(now=100), owner_id="w", now=100)


class CrashRealKillTests(unittest.TestCase):
    """True OS SIGKILL at representative crash sites.

    Proves the SimulatedCrash conclusions hold under a real kill -9: the
    child process dies mid-site, the parent resumes with a fresh runner and
    a fresh (non-surviving) receiver, and the in-flight re-execution counts
    match the simulated model exactly.
    """

    # (site, tool calls expected to re-execute their raw effect)
    REAL_KILL_SITES = (
        ("before-tool-completed:s2a", {"s2a"}),  # in-flight, effect executed
        ("after-tool-started:s2b", set()),  # in-flight, effect never ran
        ("after-tool-completed:s1b", set()),  # completed -> replay
    )

    @classmethod
    def setUpClass(cls):
        bench = _Bench("run-bench-golden-realkill")
        cls.addClassCleanup(bench.cleanup)
        bench.runner = bench.make_runner()
        state = bench.runner.execute(bench.plans(now=100), owner_id="w", now=100)
        assert state["status"] == "finished"
        cls.golden_outputs = _canonical(bench.outputs)

    def test_real_sigkill_matches_simulated_crash(self):
        for site, expected_dupes in self.REAL_KILL_SITES:
            with self.subTest(site=site):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                base = Path(tmp.name)
                run_id = f"run-bench-realkill-{site.replace(':', '-')}"
                ready_path = base / "ready"
                log_path = base / "effect.log"
                step_outputs_dir = base / "step_outputs"

                proc = multiprocessing.Process(
                    target=_realkill_worker,
                    args=(
                        str(base / "events.jsonl"),
                        str(base / "run.lease.json"),
                        str(log_path),
                        str(ready_path),
                        run_id,
                        site,
                        str(step_outputs_dir),
                    ),
                )
                proc.start()
                try:
                    self.assertTrue(_poll_for(ready_path, timeout_seconds=30))
                    self.assertEqual(ready_path.read_text(encoding="utf-8"), site)
                    self.assertTrue(proc.is_alive())
                    os.kill(proc.pid, signal.SIGKILL)
                    proc.join(timeout=10)
                    self.assertEqual(proc.exitcode, -signal.SIGKILL)
                finally:
                    if proc.is_alive():
                        proc.terminate()
                        proc.join(timeout=5)

                # Resume in the parent: fresh runner, fresh receiver (the
                # child's in-memory dedup store died with it).
                bench = _Bench(
                    run_id,
                    base_dir=str(base),
                    log_path=str(log_path),
                    step_outputs_dir=str(step_outputs_dir),
                )
                bench.runner = bench.make_runner()
                state = bench.runner.execute(
                    bench.plans(now=200), owner_id="w2", now=200
                )
                self.assertEqual(state["status"], "finished")
                # Byte-identical outputs across the kill boundary: merge the
                # child's completed step outputs with the parent's.
                merged = {
                    sid: json.loads(
                        (step_outputs_dir / f"{sid}.json").read_text(encoding="utf-8")
                    )
                    for sid in STEP_IDS
                }
                self.assertEqual(_canonical(merged), self.golden_outputs)
                counts = Counter(
                    line for line in log_path.read_text(encoding="utf-8").split() if line
                )
                for tid in TOOL_IDS:
                    expected = 2 if tid in expected_dupes else 1
                    self.assertEqual(counts[tid], expected, (site, tid))
                types = bench.event_types()
                self.assertEqual(types.count("run.finished"), 1)
                self.assertEqual(types.count("step.finished"), 3)


if __name__ == "__main__":
    unittest.main()
