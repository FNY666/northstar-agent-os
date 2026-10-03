"""Tests for RunSupervisor: orchestrator-held execution leases and crash takeover.

The unit tests use a fake clock so heartbeat/expiry behavior is exact, not
timing-dependent. The fault-injection test at the bottom kills a real worker
process with SIGKILL and asserts a healthy worker takes over without
re-running finished steps.
"""

import multiprocessing
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
if str(COMPONENT_ROOT) not in sys.path:
    sys.path.insert(0, str(COMPONENT_ROOT))

from durable_contract import RunContract
from event_store import EventStore
from runner import DurableRunner, FencingError, RunSupervisor, StepPlan


def _make_run(run_id="run-ledger-001", deadline_at=10_000_000_000):
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


def _plan(step_id, action):
    return StepPlan(
        step_id=step_id,
        input_payload={"step": step_id},
        scope_snapshot=["workspace:write"],
        expected_postconditions=[f"{step_id}_done"],
        action=action,
    )

class _FakeClock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


class _FakeProc:
    """Minimal process double: is_alive()/join()/exitcode."""

    def __init__(self, exitcode):
        self.exitcode = exitcode
        self._alive = True

    def is_alive(self):
        return self._alive

    def join(self, timeout=None):
        self._alive = False


class RunSupervisorUnitTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.lease_path = Path(self.tempdir.name) / "sup.lease.json"
        self.clock = _FakeClock(100)
        self.sup = RunSupervisor(
            self.lease_path, lease_ttl_seconds=60, clock=self.clock
        )

    def test_acquire_and_heartbeat_extend_the_lease(self):
        first = self.sup.acquire(owner_id="sup", now=100)
        self.assertEqual(first["fencing_token"], 1)
        self.assertEqual(first["expires_at"], 160)
        renewed = self.sup.heartbeat(owner_id="sup", token=1, now=150)
        self.assertEqual(renewed["fencing_token"], 1)
        self.assertEqual(renewed["expires_at"], 210)

    def test_heartbeat_with_wrong_token_is_refused(self):
        self.sup.acquire(owner_id="sup", now=100)
        with self.assertRaises(FencingError):
            self.sup.heartbeat(owner_id="sup", token=999, now=120)

    def test_start_heartbeat_keeps_lease_alive_then_stop_lets_it_expire(self):
        sup = RunSupervisor(
            self.lease_path, lease_ttl_seconds=10, clock=self.clock
        )
        lease = sup.acquire(owner_id="sup", now=100)  # expires 110
        stop = sup.start_heartbeat(
            owner_id="sup", token=lease["fencing_token"], interval_seconds=0.02
        )
        try:
            # Advance in small steps (each < ttl): every heartbeat extends
            # the expiry, so the lease survives well past its original 110.
            for now in (103, 106, 109, 112, 115):
                self.clock.now = now
                time.sleep(0.1)
            renewed = sup.lease.assert_valid("sup", now=115)
            self.assertGreater(renewed["expires_at"], 115)
        finally:
            stop()
        # After stop(), no more heartbeats: the lease expires for real.
        with self.assertRaises(ValueError):
            sup.lease.assert_valid("sup", now=10_000)

    def test_stop_reraises_a_lost_lease(self):
        sup = RunSupervisor(
            self.lease_path, lease_ttl_seconds=10, clock=self.clock
        )
        lease = sup.acquire(owner_id="sup", now=100)
        stop = sup.start_heartbeat(
            owner_id="sup", token=lease["fencing_token"], interval_seconds=0.02
        )
        # A foreign owner takes over out of band; the heartbeat loop must
        # notice and stop() must surface it.
        self.clock.now = 500
        sup.lease.acquire("intruder", now=500, ttl_seconds=10)
        time.sleep(0.15)
        with self.assertRaises((FencingError, ValueError)):
            stop()

    def test_supervise_completed_path(self):
        def spawn(owner_id, token):
            self.assertEqual(owner_id, "sup")
            self.assertEqual(token, 1)
            return _FakeProc(exitcode=0)

        self.assertEqual(
            self.sup.supervise(
                owner_id="sup", now=100, spawn_worker=spawn, poll_interval_seconds=0.01
            ),
            "completed",
        )

    def test_supervise_worker_died_path_stops_heartbeating(self):
        def spawn(owner_id, token):
            return _FakeProc(exitcode=-signal.SIGKILL)

        self.assertEqual(
            self.sup.supervise(
                owner_id="sup", now=100, spawn_worker=spawn, poll_interval_seconds=0.01
            ),
            "worker-died",
        )
        # The heartbeat stopped with the worker: the lease now expires on its
        # own, which is exactly what lets a healthy worker take over.
        with self.assertRaises(ValueError):
            self.sup.lease.assert_valid("sup", now=10_000)


class AdoptLeaseTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.lease_path = Path(self.tempdir.name) / "adopt.lease.json"
        self.events_path = Path(self.tempdir.name) / "events.jsonl"
        self.clock = _FakeClock(100)
        self.sup = RunSupervisor(
            self.lease_path, lease_ttl_seconds=60, clock=self.clock
        )

    def _runner(self, adopt):
        store = EventStore(self.events_path)
        return DurableRunner(
            _make_run(), store, lease_path=self.lease_path, adopt_lease=adopt
        )

    def test_adopt_wrong_owner_is_refused(self):
        lease = self.sup.acquire(owner_id="sup", now=100)
        runner = self._runner(("sup", lease["fencing_token"]))
        with self.assertRaises(FencingError):
            runner.execute([], owner_id="intruder", now=100)

    def test_adopt_wrong_token_is_refused(self):
        self.sup.acquire(owner_id="sup", now=100)
        runner = self._runner(("sup", 999))
        with self.assertRaises(FencingError):
            runner.execute([], owner_id="sup", now=100)

    def test_adopt_expired_lease_is_refused(self):
        lease = self.sup.acquire(owner_id="sup", now=100)
        runner = self._runner(("sup", lease["fencing_token"]))
        with self.assertRaises(ValueError):
            runner.execute([], owner_id="sup", now=10_000)

    def test_adopted_worker_never_releases(self):
        lease = self.sup.acquire(owner_id="sup", now=100)
        runner = self._runner(("sup", lease["fencing_token"]))
        state = runner.execute([], owner_id="sup", now=100)
        self.assertEqual(state["status"], "finished")
        # The worker must not release a lease it does not own: the supervisor
        # can still heartbeat afterwards.
        renewed = self.sup.heartbeat(
            owner_id="sup", token=lease["fencing_token"], now=120
        )
        self.assertEqual(renewed["expires_at"], 180)


# ---------------------------------------------------------------------------
# Fault injection: real SIGKILL of a real worker process.
# ---------------------------------------------------------------------------


def _poll_for(path_str, timeout_seconds=20):
    deadline = time.time() + timeout_seconds
    path = Path(path_str)
    while not path.exists():
        if time.time() > deadline:
            raise AssertionError(f"timed out waiting for {path}")
        time.sleep(0.02)


def _kill_test_plans(log_path_str, started_path_str, proceed_path_str):
    """Three steps; step-2 blocks on a proceed-marker file (no IPC)."""

    def _log(step_id):
        with open(log_path_str, "a") as handle:
            handle.write(step_id + "\n")

    def _wait_for_proceed():
        _poll_for(proceed_path_str, timeout_seconds=60)

    def _fast(step_id):
        def action(key):
            _log(step_id)
            return {"step": step_id}

        return action

    def _blocking(key):
        _log("step-2")
        Path(started_path_str).touch()
        _wait_for_proceed()
        return {"step": "step-2"}

    return [
        _plan("step-1", _fast("step-1")),
        _plan("step-2", _blocking),
        _plan("step-3", _fast("step-3")),
    ]


def _kill_test_worker(
    events_path_str,
    lease_path_str,
    log_path_str,
    started_path_str,
    proceed_path_str,
    owner_id,
    token,
    now,
):
    # Re-import inside the child so this also works under spawn, not just fork.
    from event_store import EventStore
    from runner import DurableRunner

    store = EventStore(events_path_str)
    runner = DurableRunner(
        _make_run(),
        store,
        lease_path=lease_path_str,
        lease_ttl_seconds=2,
        adopt_lease=(owner_id, token),
    )
    runner.execute(
        _kill_test_plans(log_path_str, started_path_str, proceed_path_str),
        owner_id=owner_id,
        now=now,
    )


@unittest.skipUnless(hasattr(os, "fork"), "fork required for kill -9 test")
class SupervisorKill9Tests(unittest.TestCase):
    """Kill -9 the worker mid-step; a healthy worker must take over.

    The worker holds no lease of its own: the supervisor acquired it and the
    worker adopted it. Logical time: lease acquired at T0 with ttl=2, the
    takeover runs at T0+10, so the lease is unambiguously expired.
    """

    def test_kill9_worker_then_takeover_finishes_without_rerunning_finished_steps(
        self,
    ):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        base = Path(tempdir.name)
        events_path = base / "events.jsonl"
        lease_path = base / "run.lease.json"
        log_path = base / "action.log"
        started_path = base / "step2.started"
        proceed_path = base / "proceed"

        t0 = 1_000_000
        sup = RunSupervisor(lease_path, lease_ttl_seconds=2)
        lease = sup.acquire(owner_id="supervisor", now=t0)
        token = lease["fencing_token"]
        self.assertEqual(lease["expires_at"], t0 + 2)

        worker = multiprocessing.Process(
            target=_kill_test_worker,
            args=(
                str(events_path),
                str(lease_path),
                str(log_path),
                str(started_path),
                str(proceed_path),
                "supervisor",
                token,
                t0,
            ),
        )
        worker.start()
        try:
            # Step-1 finished, step-2's action started and is blocked.
            _poll_for(str(started_path), timeout_seconds=20)
            self.assertTrue(worker.is_alive())
            os.kill(worker.pid, signal.SIGKILL)
            worker.join(timeout=10)
            self.assertEqual(worker.exitcode, -signal.SIGKILL)
        finally:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=5)

        # Let any waiter proceed; the takeover worker runs here in the parent.
        proceed_path.touch()
        store = EventStore(events_path)
        runner = DurableRunner(
            _make_run(), store, lease_path=lease_path, lease_ttl_seconds=60
        )
        plans = _kill_test_plans(
            str(log_path), str(started_path), str(proceed_path)
        )
        state = runner.execute(plans, owner_id="worker-b", now=t0 + 10)

        self.assertEqual(state["status"], "finished")
        lines = log_path.read_text().strip().split("\n")
        # Step-1 ran exactly once (never re-run). Step-2 ran twice: the killed
        # attempt plus the retry. Step-3 ran once.
        self.assertEqual(lines.count("step-1"), 1, lines)
        self.assertEqual(lines.count("step-2"), 2, lines)
        self.assertEqual(lines.count("step-3"), 1, lines)
        types = [event.event_type for event in store.read_history("run-ledger-001")]
        self.assertIn("run.fenced", types)
        self.assertEqual(types.count("run.finished"), 1)
        self.assertEqual(types.count("step.finished"), 3)
        self.assertEqual(types.count("step.started"), 3)
        # The takeover used a fresh fencing epoch: the marker names the fenced
        # prior epoch (supervisor, token 1) in its idempotency key.
        fenced = [
            event
            for event in store.read_history("run-ledger-001")
            if event.event_type == "run.fenced"
        ]
        self.assertEqual(len(fenced), 1)
        self.assertEqual(
            fenced[0].idempotency_key, "run-ledger-001-fenced-supervisor-1"
        )


if __name__ == "__main__":
    unittest.main()
