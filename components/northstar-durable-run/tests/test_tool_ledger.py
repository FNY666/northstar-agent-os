"""Tests for the tool-effect three-state ledger (tool_ledger.py).

Each tool effect records (run_id, tool_call_id) started/completed/failed.
Recovery reconciles before re-running: completed effects replay their cached
result (zero re-execution), started-but-never-completed effects consult the
receiver's dedup state and either adopt, re-issue, or fail closed.

Exactly-once holds iff the receiver dedups on the idempotency key; these
tests pin that contract, not the assumption.
"""

import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
if str(COMPONENT_ROOT) not in sys.path:
    sys.path.insert(0, str(COMPONENT_ROOT))
if str(CONTRACT_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTRACT_ROOT))

import durable_audit
from durable_contract import EventContract, RunContract
from event_store import EventStore
from runner import DurableRunner, SimulatedCrash, StepPlan
from tool_ledger import InMemoryDedupReceiver, ToolEffectLedger


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


def _plan(step_id, action):
    return StepPlan(
        step_id=step_id,
        input_payload={"step": step_id},
        scope_snapshot=["workspace:write"],
        expected_postconditions=[f"{step_id}_done"],
        action=action,
    )

class _Harness:
    """Fresh store + runner per test, with a counting receiver-backed effect."""

    def __init__(self, test, run_id="run-ledger-001"):
        self.test = test
        self.tempdir = tempfile.TemporaryDirectory()
        test.addCleanup(self.tempdir.cleanup)
        self.events_path = Path(self.tempdir.name) / "events.jsonl"
        self.lease_path = Path(self.tempdir.name) / "run.lease.json"
        self.ledger_path = Path(self.tempdir.name) / "events.jsonl.ledger.json"
        self.store = EventStore(self.events_path)
        self.run = _make_run(run_id=run_id)
        self.run_id = run_id
        self.raw_calls = {}  # tool_call_id -> number of raw effect executions
        self.receiver = InMemoryDedupReceiver()
        self.runner = DurableRunner(
            self.run, self.store, lease_path=self.lease_path, lease_ttl_seconds=20
        )

    def with_crash_hook(self, hook):
        self.runner = DurableRunner(
            self.run,
            self.store,
            lease_path=self.lease_path,
            lease_ttl_seconds=20,
            crash_hook=hook,
        )
        return self.runner

    def effect(self, tool_call_id, result=None):
        """A raw effect routed through the receiver under the ledger's key."""
        harness = self

        def _fn(key):
            harness.raw_calls[tool_call_id] = harness.raw_calls.get(tool_call_id, 0) + 1
            value = (
                {"tool": tool_call_id, "n": harness.raw_calls[tool_call_id]}
                if result is None
                else result
            )
            return harness.receiver.execute(key, lambda: value)

        return _fn

    def action(self, tool_call_id, result=None, now=100, crash_after=False):
        harness = self

        def _action(key):
            value = harness.runner.run_tool(
                step_id="s1",
                tool_call_id=tool_call_id,
                fn=harness.effect(tool_call_id, result),
                now=now,
                receiver=harness.receiver,
            )
            if crash_after:
                raise SimulatedCrash(f"after {tool_call_id}")
            return {"result": value}

        return _action

    def plan(self, action):
        return [_plan("s1", action)]

    def tool_types(self):
        return [
            event.event_type
            for event in self.store.read_history(self.run_id)
            if event.event_type.startswith("tool.")
        ]

    def standalone_ledger(self, ledger_name="lost.ledger.json", crash_hook=None):
        """A ledger over the same events with a fresh (empty) sidecar."""

        def append(*, event_type, status, step_id, idempotency_key, now, payload):
            history = self.store.read_history(self.run_id)
            self.store.append_event(
                EventContract.from_dict(
                    {
                        "schema_version": "northstar.durable-event.v1",
                        "event_id": f"event-{len(history) + 1:06d}",
                        "task_id": self.run.task_id,
                        "thread_id": self.run.thread_id,
                        "run_id": self.run_id,
                        "step_id": step_id,
                        "sequence": len(history) + 1,
                        "event_type": event_type,
                        "status": status,
                        "occurred_at": now,
                        "idempotency_key": idempotency_key,
                        "trace_id": self.run.trace_id,
                        "payload_digest": "sha256:" + "0" * 64,
                    }
                )
            )

        return ToolEffectLedger(
            self.store,
            run_id=self.run_id,
            ledger_path=Path(self.tempdir.name) / ledger_name,
            append=append,
            crash_hook=crash_hook,
        )


class LedgerHappyPathTests(unittest.TestCase):
    def test_completed_tool_replays_without_reexecution(self):
        h = _Harness(self)
        with self.assertRaises(SimulatedCrash):
            h.runner.execute(h.plan(h.action("t1", now=100, crash_after=True)),
                             owner_id="w", now=100)
        self.assertEqual(h.raw_calls, {"t1": 1})
        self.assertEqual(h.runner.tool_ledger.state_of("t1"), "completed")

        # Resume with a fresh runner: the completed effect replays from the
        # sidecar cache, never re-running the raw effect.
        h.with_crash_hook(None)
        returned = {}

        def capturing(key):
            value = h.runner.run_tool(
                step_id="s1",
                tool_call_id="t1",
                fn=h.effect("t1"),
                now=101,
                receiver=h.receiver,
            )
            returned["value"] = value
            return {"result": value}

        state = h.runner.execute(
            [_plan("s1", capturing)],
            owner_id="w2",
            now=101,
        )
        self.assertEqual(state["status"], "finished")
        self.assertEqual(h.raw_calls, {"t1": 1})  # zero re-execution
        self.assertEqual(returned["value"], {"tool": "t1", "n": 1})

    def test_tool_events_are_first_class_in_audit(self):
        h = _Harness(self)
        h.runner.execute(h.plan(h.action("t1", now=100)), owner_id="w", now=100)
        tool_events = [
            event
            for event in h.store.read_history(h.run_id)
            if event.event_type in durable_audit.TOOL_EVENT_TYPES
        ]
        self.assertEqual(
            [event.event_type for event in tool_events],
            ["tool.started", "tool.completed"],
        )
        records = [durable_audit.event_to_audit(event.to_dict()) for event in tool_events]
        self.assertEqual(
            [record["event"] for record in records],
            ["tool.started", "tool.completed"],
        )
        self.assertEqual(records[0]["component"], "northstar-durable-run")
        self.assertEqual(
            [event.idempotency_key for event in tool_events],
            ["tool:t1:attempt-1:started", "tool:t1:attempt-1:completed"],
        )
        self.assertTrue(all(event.step_id == "s1" for event in tool_events))


class LedgerReconcileTests(unittest.TestCase):
    def test_started_without_completed_adopts_on_receiver_hit(self):
        # Crash lands after the raw effect ran (the receiver holds it under
        # the attempt's key) but before tool.completed was appended: recovery
        # must adopt, not re-run.
        h = _Harness(self)

        def hook(site):
            if site == "before-tool-completed:t1":
                raise SimulatedCrash("injected")

        h.with_crash_hook(hook)
        with self.assertRaises(SimulatedCrash):
            h.runner.execute(h.plan(h.action("t1", now=100)), owner_id="w", now=100)
        self.assertEqual(h.raw_calls, {"t1": 1})
        self.assertEqual(h.runner.tool_ledger.state_of("t1"), "started")

        # Same receiver object survives the in-process crash: the query hits.
        h.with_crash_hook(None)
        returned = {}

        def capturing(key):
            value = h.runner.run_tool(
                step_id="s1",
                tool_call_id="t1",
                fn=h.effect("t1"),
                now=101,
                receiver=h.receiver,
            )
            returned["value"] = value
            return {"result": value}

        state = h.runner.execute(
            [_plan("s1", capturing)],
            owner_id="w2",
            now=101,
        )
        self.assertEqual(state["status"], "finished")
        self.assertEqual(h.raw_calls, {"t1": 1})  # adopted: no re-execution
        self.assertEqual(returned["value"], {"tool": "t1", "n": 1})
        adopted = [
            event
            for event in h.store.read_history(h.run_id)
            if event.event_type == "tool.completed"
        ]
        self.assertEqual(len(adopted), 1)
        # Adopted under the reconcile attempt (attempt-2): the raw effect ran
        # once (attempt-1), the completed marker converges the trail.
        self.assertEqual(adopted[0].idempotency_key, "tool:t1:attempt-2:completed")

    def test_started_without_completed_reissues_on_receiver_miss(self):
        # Crash lands before the raw effect ran: a fresh receiver knows
        # nothing, so recovery re-issues under the same idempotency key.
        h = _Harness(self)

        def hook(site):
            if site == "after-tool-started:t1":
                raise SimulatedCrash("injected")

        h.with_crash_hook(hook)
        with self.assertRaises(SimulatedCrash):
            h.runner.execute(h.plan(h.action("t1", now=100)), owner_id="w", now=100)
        self.assertEqual(h.raw_calls, {})  # the effect never ran

        h.receiver = InMemoryDedupReceiver()  # a genuinely new receiver
        h.with_crash_hook(None)
        state = h.runner.execute(
            h.plan(h.action("t1", now=101)), owner_id="w2", now=101
        )
        self.assertEqual(state["status"], "finished")
        self.assertEqual(h.raw_calls, {"t1": 1})  # exactly one execution total
        self.assertEqual(h.tool_types().count("tool.started"), 2)
        self.assertEqual(h.tool_types().count("tool.completed"), 1)

    def test_started_without_receiver_fails_closed(self):
        h = _Harness(self)

        def hook(site):
            if site == "after-tool-started:t1":
                raise SimulatedCrash("injected")

        h.with_crash_hook(hook)
        with self.assertRaises(SimulatedCrash):
            h.runner.execute(h.plan(h.action("t1", now=100)), owner_id="w", now=100)

        # No receiver: the ambiguous effect cannot be reconciled. The ledger
        # refuses to re-run the raw effect; execute() records the refusal
        # honestly as step.failed/run.failed instead of guessing.
        h.with_crash_hook(None)

        def no_receiver_action(key):
            return h.runner.run_tool(
                step_id="s1",
                tool_call_id="t1",
                fn=h.effect("t1"),
                now=101,
                receiver=None,
            )

        state = h.runner.execute(
            [_plan("s1", no_receiver_action)],
            owner_id="w2",
            now=101,
        )
        self.assertEqual(state["status"], "failed")
        self.assertEqual(h.raw_calls, {})  # the raw effect never re-ran
        self.assertEqual(h.tool_types().count("tool.started"), 1)

    def test_started_without_receiver_raises_at_ledger_level(self):
        h = _Harness(self)

        def hook(site):
            if site == "after-tool-started:t1":
                raise SimulatedCrash("injected")

        ledger = h.standalone_ledger("ambiguous.ledger.json", crash_hook=hook)
        with self.assertRaises(SimulatedCrash):
            ledger.run_tool(
                step_id="s1", tool_call_id="t1", fn=lambda key: {"v": 1},
                now=100, receiver=h.receiver,
            )
        self.assertEqual(ledger.state_of("t1"), "started")
        with self.assertRaisesRegex(ValueError, "without a DedupReceiver"):
            ledger.run_tool(
                step_id="s1", tool_call_id="t1", fn=lambda key: {"v": 1},
                now=101, receiver=None,
            )

    def test_failed_tool_is_retried_fresh(self):
        # The runner refuses to re-run a failed *step*; the ledger itself
        # retries a failed *tool effect* under a fresh attempt. Tested at the
        # ledger level.
        h = _Harness(self)
        ledger = h.standalone_ledger()
        attempts = {"n": 0}

        def flaky(key):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise RuntimeError("tool blew up")
            return {"ok": True}

        with self.assertRaises(RuntimeError):
            ledger.run_tool(
                step_id="s1", tool_call_id="t1", fn=flaky, now=100,
                receiver=h.receiver,
            )
        self.assertEqual(ledger.state_of("t1"), "failed")
        result = ledger.run_tool(
            step_id="s1", tool_call_id="t1", fn=flaky, now=101,
            receiver=h.receiver,
        )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(attempts["n"], 2)
        self.assertEqual(
            h.tool_types(),
            ["tool.started", "tool.failed", "tool.started", "tool.completed"],
        )

    def test_large_result_replays_via_receiver_query(self):
        # Result exceeds the inline cap: the sidecar is digest-only. With the
        # sidecar lost, recovery falls back to the receiver's dedup store.
        h = _Harness(self)
        big = {"blob": "y" * 9000}
        h.runner.execute(
            h.plan(h.action("t1", result=big, now=100)), owner_id="w", now=100
        )
        completed = [
            event
            for event in h.store.read_history(h.run_id)
            if event.event_type == "tool.completed"
        ]
        self.assertEqual(len(completed), 1)

        ledger = h.standalone_ledger()  # fresh, empty sidecar
        found, cached = ledger.replay_result("t1")
        self.assertFalse(found)
        # The receiver still holds the result under the attempt's key.
        result = ledger.run_tool(
            step_id="s1",
            tool_call_id="t1",
            fn=lambda key: (_ for _ in ()).throw(AssertionError("must not run")),
            now=101,
            receiver=h.receiver,
        )
        self.assertEqual(result, big)
        self.assertEqual(h.raw_calls, {"t1": 1})

    def test_large_result_without_receiver_is_unrecoverable(self):
        h = _Harness(self)
        big = {"blob": "x" * 9000}
        h.runner.execute(
            h.plan(h.action("t1", result=big, now=100)), owner_id="w", now=100
        )
        ledger = h.standalone_ledger()
        found, _ = ledger.replay_result("t1")
        self.assertFalse(found)
        with self.assertRaisesRegex(ValueError, "unrecoverable"):
            ledger.run_tool(
                step_id="s1",
                tool_call_id="t1",
                fn=lambda key: {"never": "runs"},
                now=101,
                receiver=None,
            )
        self.assertEqual(h.raw_calls, {"t1": 1})


class LedgerStateTests(unittest.TestCase):
    def test_state_of_tracks_last_event(self):
        h = _Harness(self)
        ledger = h.runner.tool_ledger
        self.assertIsNone(ledger.state_of("t1"))
        h.runner.execute(h.plan(h.action("t1", now=100)), owner_id="w", now=100)
        self.assertEqual(ledger.state_of("t1"), "completed")

    def test_tool_call_id_must_be_sane(self):
        h = _Harness(self)
        ledger = h.runner.tool_ledger
        for bad in ["", "a:b", "x" * 129, "has space"]:
            with self.assertRaises(ValueError, msg=bad):
                ledger.state_of(bad)


if __name__ == "__main__":
    unittest.main()
