"""Durable checkpoints, retry-clears-writes, and an explicit resume command.

The properties this file exists to pin down:

- **state and pending writes are two ordered records** -- a checkpoint holds
  the committed state; the writes a step declared hang off it in order;
- **a checkpoint without a run id is refused** -- it cannot be stored, found,
  or resumed from;
- **a retry clears the uncommitted writes first** -- the effect happens once,
  proved by a counter, not by a promise;
- **the retry predicate retries throttling and 5xx, and refuses auth and
  permission failures**;
- **an exhausted retry budget fails loudly** -- it never passes silently;
- **an interrupt without a checkpointer is an error**;
- **a resume is an explicit command** -- re-sending the prompt is refused;
- **resume values match the step's interrupts in order**, and belong to that
  task only;
- **an unwound (interrupted) call's writes are dropped**, never replayed as
  successes;
- **a checkpoint whose digest no longer matches fails closed**;
- and the whole sequence, driven end to end: **kill -> retry -> resume**.
"""
from __future__ import annotations

import json
import sys
import unittest

import support  # noqa: F401  (bootstraps sys.path)
from support import RuntimeTestCase

from durable_resume import (
    Command,
    DurableCheckpoint,
    DurableRunner,
    DurableStore,
    DurableStoreError,
    GraphInterrupt,
    Interrupt,
    InterruptRequiresCheckpointError,
    MissingRunIdError,
    PendingWrite,
    RetryExhaustedError,
    RetryPolicy,
    ResumeRequiresCommandError,
    ResumeValueMismatchError,
    CheckpointIntegrityError,
    default_retry_on,
    drop_unwound_writes,
    checkpoint_from_verified,
    verify_verified_checkpoint,
    state_digest,
)
from providers.base import ProviderError
from sessions import SessionStore


class _StatusError(ProviderError):
    """A provider error carrying an HTTP status, the way a real SDK does."""


class _Throttle(_StatusError):
    pass


def _write(task_id: str = "t1", idx: int = 0, effect_key: str = "tool:1", channel: str = "files") -> PendingWrite:
    return PendingWrite(
        task_id=task_id,
        idx=idx,
        channel=channel,
        value={"path": f"/tmp/{effect_key}"},
        effect_key=effect_key,
        task_path=task_id,
    )


def _assistant_with_tool_use(call_id: str, name: str):
    from providers.base import AssistantMessage, ToolUseBlock

    return AssistantMessage(content=[ToolUseBlock(id=call_id, name=name, input={"path": "/tmp/x"})])


def _transcript_with_pending_call() -> list:
    """A transcript whose only tool_use never got a result."""
    from providers.base import UserMessage

    return [_assistant_with_tool_use("call-1", "write_file"), UserMessage.text_block("do the thing")]


class DurableCheckpointTests(RuntimeTestCase):
    """The checkpoint record: state, pending writes, and the run id."""

    def test_state_and_pending_writes_are_two_ordered_records(self) -> None:
        store = DurableStore()
        checkpoint = store.put_checkpoint(run_id="run-1", state={"turns": 3})
        store.put_writes(checkpoint.checkpoint_id, [_write("t1", 0, "tool:a"), _write("t1", 1, "tool:b")])

        # The state is one record and the writes are another, under the
        # checkpoint -- not a second copy of the writes inside the state.
        self.assertEqual(checkpoint.state, {"turns": 3})
        self.assertNotIn("tool:a", str(checkpoint.state))
        pending = store.pending_writes(checkpoint.checkpoint_id)
        self.assertEqual([write.effect_key for write in pending], ["tool:a", "tool:b"])
        self.assertEqual([write.idx for write in pending], [0, 1])

    def test_writes_are_ordered_by_task_path_task_id_and_index(self) -> None:
        store = DurableStore()
        checkpoint = store.put_checkpoint(run_id="run-1", state={})
        store.put_writes(
            checkpoint.checkpoint_id,
            [
                _write("t2", 0, "tool:late"),
                _write("t1", 1, "tool:second"),
                _write("t1", 0, "tool:first"),
            ],
        )
        ordered = [write.effect_key for write in store.pending_writes(checkpoint.checkpoint_id)]
        self.assertEqual(ordered, ["tool:first", "tool:second", "tool:late"])

    def test_a_checkpoint_without_a_run_id_fails_closed(self) -> None:
        store = DurableStore()
        with self.assertRaises(MissingRunIdError):
            store.put_checkpoint(run_id="", state={"turns": 1})
        with self.assertRaises(MissingRunIdError):
            store.latest_checkpoint("")
        with self.assertRaises(MissingRunIdError):
            DurableCheckpoint(run_id="", checkpoint_id="ck-1", seq=1, state={})

    def test_a_checkpoint_of_another_run_cannot_be_read_back(self) -> None:
        store = DurableStore()
        checkpoint = store.put_checkpoint(run_id="run-A", state={"turns": 1})
        # The run id is the primary key: the same checkpoint id under another
        # run is not the same checkpoint.
        self.assertIsNone(store.get_checkpoint("run-B", checkpoint.checkpoint_id))
        self.assertEqual(store.list_checkpoints("run-B"), ())
        self.assertEqual(len(store.list_checkpoints("run-A")), 1)

    def test_a_checkpoint_whose_state_was_edited_fails_closed(self) -> None:
        store = DurableStore()
        checkpoint = store.put_checkpoint(run_id="run-1", state={"turns": 3})
        self.assertTrue(store.verify(checkpoint))

        # A checkpoint whose state does not hash to its own digest is refused
        # at construction: the record cannot claim to describe a history it
        # does not describe.
        with self.assertRaises(CheckpointIntegrityError):
            DurableCheckpoint(
                run_id=checkpoint.run_id,
                checkpoint_id=checkpoint.checkpoint_id,
                seq=checkpoint.seq,
                state={"turns": 99},
                state_digest=checkpoint.state_digest,
            )

        # And a state edited under a live checkpoint is caught by the store's
        # own verification, so a resume cannot inherit it.
        edited = DurableCheckpoint(
            run_id=checkpoint.run_id,
            checkpoint_id=checkpoint.checkpoint_id,
            seq=checkpoint.seq,
            state={"turns": 3},
        )
        object.__setattr__(edited, "state", {"turns": 99})
        self.assertFalse(store.verify(edited))

    def test_pending_and_cleared_writes_are_kept_apart_from_committed_ones(self) -> None:
        store = DurableStore()
        checkpoint = store.put_checkpoint(run_id="run-1", state={})
        store.put_writes(checkpoint.checkpoint_id, [_write("t1", 0, "tool:a"), _write("t1", 1, "tool:b")])
        store.clear_writes(checkpoint.checkpoint_id, reason="dropped", effect_keys=frozenset({"tool:a"}))

        self.assertEqual([w.effect_key for w in store.pending_writes(checkpoint.checkpoint_id)], ["tool:b"])
        self.assertEqual([w.effect_key for w in store.cleared_writes(checkpoint.checkpoint_id)], ["tool:a"])
        self.assertEqual(store.committed_writes(checkpoint.checkpoint_id), ())


class RetryClearsWritesTests(RuntimeTestCase):
    """The retry rule: clear the uncommitted writes, then try again."""

    def test_a_retry_clears_the_pending_writes_so_the_effect_lands_once(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store, policy=RetryPolicy(max_attempts=3, jitter=False), sleep=lambda _s: None)
        effects: list[str] = []
        attempts: list[int] = []

        def step() -> str:
            attempts.append(len(attempts) + 1)
            runner.declare(_write("t1", 0, "tool:only-once"))
            if len(attempts) < 2:
                raise _Throttle("too many requests", status_code=429)
            return "done"

        result = runner.run(
            task_id="t1",
            step=step,
            state={"turns": 1},
            run_id="run-1",
            applier=lambda write: effects.append(write.effect_key or ""),
        )

        # The effect landed exactly once, even though the step declared it twice.
        self.assertEqual(effects, ["tool:only-once"])
        self.assertEqual(result.attempt_count, 2)
        # And the first attempt's declaration was dropped, not committed.
        checkpoint = store.latest_checkpoint("run-1")
        self.assertEqual(len(store.committed_writes(checkpoint.checkpoint_id)), 1)
        self.assertEqual(len(store.cleared_writes(checkpoint.checkpoint_id)), 1)

    def test_a_retry_that_never_succeeds_leaves_no_committed_effect(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store, policy=RetryPolicy(max_attempts=3, jitter=False), sleep=lambda _s: None)
        effects: list[str] = []

        def step() -> str:
            runner.declare(_write("t1", 0, "tool:never"))
            raise _Throttle("too many requests", status_code=429)

        with self.assertRaises(RetryExhaustedError):
            runner.run(
                task_id="t1",
                step=step,
                state={},
                run_id="run-1",
                applier=lambda write: effects.append(write.effect_key or ""),
            )
        self.assertEqual(effects, [])
        checkpoint = store.latest_checkpoint("run-1")
        self.assertEqual(store.committed_writes(checkpoint.checkpoint_id), ())
        self.assertEqual(len(store.cleared_writes(checkpoint.checkpoint_id)), 3)

    def test_the_retry_predicate_retries_throttling_and_server_errors(self) -> None:
        self.assertTrue(default_retry_on(_Throttle("slow down", status_code=429)))
        self.assertTrue(default_retry_on(_StatusError("server blew up", status_code=500)))
        self.assertTrue(default_retry_on(_StatusError("bad gateway", status_code=502)))
        self.assertTrue(default_retry_on(_StatusError("unavailable", status_code=503)))
        self.assertTrue(default_retry_on(ConnectionRefusedError("no listener")))

    def test_the_retry_predicate_refuses_auth_and_permission_failures(self) -> None:
        self.assertFalse(default_retry_on(_StatusError("bad key", status_code=401)))
        self.assertFalse(default_retry_on(_StatusError("forbidden", status_code=403)))
        self.assertFalse(default_retry_on(_StatusError("bad request", status_code=400)))
        # A post-write drop is not retried either: the peer may already have
        # executed it, which is retry_contract's rule and this one agrees.
        self.assertFalse(default_retry_on(ConnectionResetError("dropped")))

    def test_an_auth_failure_is_not_retried_at_all(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store, policy=RetryPolicy(max_attempts=5, jitter=False), sleep=lambda _s: None)
        calls: list[int] = []

        def step() -> str:
            calls.append(1)
            raise _StatusError("bad key", status_code=401)

        with self.assertRaises(_StatusError):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")
        self.assertEqual(len(calls), 1)

    def test_an_exhausted_retry_budget_fails_loudly_and_never_passes(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store, policy=RetryPolicy(max_attempts=2, jitter=False), sleep=lambda _s: None)
        calls: list[int] = []

        def step() -> str:
            calls.append(1)
            raise _Throttle("too many requests", status_code=429)

        with self.assertRaises(RetryExhaustedError):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")
        self.assertEqual(len(calls), 2)

    def test_the_retry_policy_schedule_is_bounded_and_jitterable(self) -> None:
        policy = RetryPolicy(initial_interval=0.5, backoff_factor=2.0, max_interval=128.0, jitter=False)
        self.assertEqual(policy.delay(1), 0.5)
        self.assertEqual(policy.delay(2), 1.0)
        self.assertEqual(policy.delay(3), 2.0)
        self.assertEqual(policy.delay(20), 128.0)

        jittered = RetryPolicy(initial_interval=1.0, backoff_factor=2.0, jitter=True)
        self.assertEqual(jittered.delay(1, lambda: 0.25), 1.25)
        self.assertEqual(jittered.delay(1, lambda: 0.0), 1.0)


class InterruptAndResumeTests(RuntimeTestCase):
    """Interrupt, explicit resume, and the values that go with them."""

    def test_an_interrupt_without_a_checkpointer_is_an_error(self) -> None:
        runner = DurableRunner(store=None)
        with self.assertRaises(InterruptRequiresCheckpointError):
            runner.interrupt("need an answer")

    def test_an_interrupt_records_the_value_against_a_checkpoint(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store)

        def step() -> str:
            answer = runner.interrupt("what now?")
            return f"got {answer}"

        with self.assertRaises(GraphInterrupt):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")

        checkpoint = store.latest_checkpoint("run-1")
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint.interrupted_task, "t1")
        self.assertEqual(checkpoint.interrupt_value, "what now?")

    def test_a_resume_must_be_an_explicit_command_and_a_prompt_is_refused(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store)

        def step() -> str:
            runner.declare(_write("t1", 0, "tool:interrupted"))
            answer = runner.interrupt("what now?")
            return f"got {answer}"

        with self.assertRaises(GraphInterrupt):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")

        # A re-sent prompt is not a resume.
        with self.assertRaises(ResumeRequiresCommandError):
            runner.resume(
                "please continue",
                task_id="t1",
                step=step,
                state={},
                run_id="run-1",
            )
        with self.assertRaises(ResumeRequiresCommandError):
            runner.resume(None, task_id="t1", step=step, state={}, run_id="run-1")

        # And the refusal is real: the run did not continue. The step is still
        # paused, the pending writes are still pending, and no effect landed.
        checkpoint = store.latest_checkpoint("run-1")
        self.assertEqual(len(store.pending_writes(checkpoint.checkpoint_id)), 1)
        self.assertEqual(store.committed_writes(checkpoint.checkpoint_id), ())
        self.assertEqual(store.cleared_writes(checkpoint.checkpoint_id), ())

        # Only the explicit command lets it through.
        result = runner.resume(
            Command(resume="green light"),
            task_id="t1",
            step=step,
            state={},
            run_id="run-1",
        )
        self.assertEqual(result.value, "got green light")

    def test_a_resume_re_enters_the_step_from_its_start(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store)
        entries: list[str] = []

        def step() -> str:
            entries.append("before")
            answer = runner.interrupt("what now?")
            entries.append("after")
            return f"got {answer}"

        with self.assertRaises(GraphInterrupt):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")

        result = runner.resume(
            Command(resume="green light"),
            task_id="t1",
            step=step,
            state={},
            run_id="run-1",
        )

        # The step restarted: "before" ran twice.
        self.assertEqual(entries.count("before"), 2)
        self.assertEqual(result.value, "got green light")

    def test_a_resume_replays_only_the_committed_writes(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store)
        effects: list[str] = []

        def step() -> str:
            runner.declare(_write("t1", 0, "tool:committed"))
            runner.declare(_write("t1", 1, "tool:pending"))
            answer = runner.interrupt("what now?")
            return f"got {answer}"

        with self.assertRaises(GraphInterrupt):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")
        checkpoint = store.latest_checkpoint("run-1")
        self.assertEqual(len(store.pending_writes(checkpoint.checkpoint_id)), 2)

        result = runner.resume(
            Command(resume="go"),
            task_id="t1",
            step=step,
            state={},
            run_id="run-1",
            applier=lambda write: effects.append(write.effect_key or ""),
        )

        # The interrupted attempt's writes were dropped; the re-run's
        # declarations are the ones that committed -- and the effect landed
        # once per distinct effect key, not once per declaration.
        self.assertEqual(sorted(set(effects)), ["tool:committed", "tool:pending"])
        self.assertEqual(len(effects), 2)
        self.assertTrue(result.succeeded)

    def test_resume_values_match_the_interrupts_in_order(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store)
        seen: list[object] = []

        def step() -> str:
            first = runner.interrupt("first question")
            seen.append(first)
            second = runner.interrupt("second question")
            seen.append(second)
            return "done"

        with self.assertRaises(GraphInterrupt):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")

        # A sequence answers the interrupts in order.
        runner.resume(
            Command(resume=["answer-one", "answer-two"]),
            task_id="t1",
            step=step,
            state={},
            run_id="run-1",
        )
        self.assertEqual(seen[:2], ["answer-one", "answer-two"])

    def test_a_resume_value_belonging_to_another_task_is_refused(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store)

        def step() -> str:
            answer = runner.interrupt("what now?")
            return f"got {answer}"

        with self.assertRaises(GraphInterrupt):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")

        with self.assertRaises(ResumeValueMismatchError):
            runner.resume(
                Command(resume={"other-task#0": "value"}),
                task_id="t1",
                step=step,
                state={},
                run_id="run-1",
            )

    def test_a_resume_of_a_tampered_checkpoint_fails_closed(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store)

        def step() -> str:
            answer = runner.interrupt("what now?")
            return f"got {answer}"

        with self.assertRaises(GraphInterrupt):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")

        # The checkpoint's state is edited under it.
        checkpoint = store.latest_checkpoint("run-1")
        object.__setattr__(checkpoint, "state", {"turns": 999})

        with self.assertRaises(CheckpointIntegrityError):
            runner.resume(
                Command(resume="go"),
                task_id="t1",
                step=step,
                state={},
                run_id="run-1",
            )

    def test_a_resume_clears_the_interrupted_attempts_writes_before_re_entering(self) -> None:
        store = DurableStore()
        runner = DurableRunner(store=store)

        def step() -> str:
            runner.declare(_write("t1", 0, "tool:interrupted"))
            answer = runner.interrupt("what now?")
            return f"got {answer}"

        with self.assertRaises(GraphInterrupt):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")
        checkpoint = store.latest_checkpoint("run-1")
        self.assertEqual(len(store.pending_writes(checkpoint.checkpoint_id)), 1)

        runner.resume(
            Command(resume="go"),
            task_id="t1",
            step=step,
            state={},
            run_id="run-1",
        )

        # The interrupted attempt's declaration was dropped, and the re-run's
        # declaration is what is pending now -- the clear happened before the
        # re-entry, not after it.
        self.assertEqual(len(store.cleared_writes(checkpoint.checkpoint_id)), 1)
        self.assertEqual(
            [write.effect_key for write in store.cleared_writes(checkpoint.checkpoint_id)],
            ["tool:interrupted"],
        )


class UnwoundWritesTests(RuntimeTestCase):
    """The seam with sessions.py: an interrupted call never landed."""

    def test_an_unwound_calls_writes_are_dropped_and_never_replayed_as_successes(self) -> None:
        from providers.base import UserMessage

        root = self.temp_dir()
        session = SessionStore(directory=str(root), session_id="sess-1")
        session.record_user(UserMessage.text_block("do the thing"))
        # A tool_use with no tool_result is the signature of a killed turn.
        session.record_assistant(_assistant_with_tool_use("call-1", "write_file"))

        unwound = session.unwound_calls("sess-1")
        self.assertEqual(unwound, (("call-1", "write_file"),))

        store = DurableStore()
        checkpoint = store.put_checkpoint(run_id="sess-1", state={})
        store.put_writes(
            checkpoint.checkpoint_id,
            [_write("t1", 0, "tool:call-1"), _write("t1", 1, "tool:other")],
        )

        dropped = drop_unwound_writes(store, checkpoint.checkpoint_id, [])
        # Nothing matched because the transcript was not passed; with the
        # session's verdict the interrupted call's write is the one dropped.
        self.assertEqual(dropped, ())

        from durable_resume import unwind_effect_keys

        keys = unwind_effect_keys(_transcript_with_pending_call())
        self.assertEqual(keys, frozenset({"tool:call-1"}))
        dropped = drop_unwound_writes(store, checkpoint.checkpoint_id, _transcript_with_pending_call())
        self.assertEqual([write.effect_key for write in dropped], ["tool:call-1"])
        self.assertEqual(
            [write.effect_key for write in store.pending_writes(checkpoint.checkpoint_id)],
            ["tool:other"],
        )


class KillRetryResumeTests(RuntimeTestCase):
    """The whole sequence, driven: kill -> retry -> resume -> landed."""

    def test_kill_then_retry_then_explicit_resume_lands_the_run_once(self) -> None:
        store = DurableStore()
        effects: list[str] = []
        runner = DurableRunner(
            store=store,
            policy=RetryPolicy(max_attempts=3, jitter=False),
            sleep=lambda _s: None,
        )

        phase = {"name": "kill"}
        attempts: list[str] = []

        def step() -> str:
            attempts.append(phase["name"])
            # The step declares its effect *before* it finishes, so a kill
            # leaves the effect declared but not committed.
            runner.declare(_write("t1", 0, "tool:side-effect"))
            if phase["name"] == "kill":
                # The run is killed mid-step: the write stays pending, nothing
                # was applied, and the process never came back on its own.
                raise KeyboardInterrupt("the process was killed mid-step")
            if phase["name"] == "retry":
                # The retry's first attempt fails transiently, so the policy
                # retries it -- and the retry clears the pending writes first.
                raise _Throttle("too many requests", status_code=429)
            answer = runner.interrupt("the operator must approve this")
            return f"approved: {answer}"

        # -- phase 1: the kill ------------------------------------------
        with self.assertRaises(KeyboardInterrupt):
            runner.run(
                task_id="t1",
                step=step,
                state={"phase": "kill"},
                run_id="run-1",
                applier=lambda write: effects.append(write.effect_key or ""),
            )
        killed = store.latest_checkpoint("run-1")
        self.assertEqual(len(store.pending_writes(killed.checkpoint_id)), 1)
        self.assertEqual(effects, [])
        self.assertEqual(store.committed_writes(killed.checkpoint_id), ())

        # -- phase 2: the retry ------------------------------------------
        phase["name"] = "retry"
        with self.assertRaises(RetryExhaustedError):
            # The retry itself fails transiently twice, so the budget runs out.
            runner.run(
                task_id="t1",
                step=step,
                state={"phase": "retry"},
                run_id="run-1",
                applier=lambda write: effects.append(write.effect_key or ""),
            )
        retried = store.latest_checkpoint("run-1")
        # Every attempt's declaration was cleared, so the effect never landed.
        self.assertEqual(effects, [])
        self.assertEqual(store.committed_writes(retried.checkpoint_id), ())
        self.assertEqual(len(store.cleared_writes(retried.checkpoint_id)), 3)

        # -- phase 3: the explicit resume --------------------------------
        phase["name"] = "resume"
        result = runner.resume(
            Command(resume="approved"),
            task_id="t1",
            step=step,
            state={"phase": "resume"},
            run_id="run-1",
            applier=lambda write: effects.append(write.effect_key or ""),
        )

        # The run landed, and the effect landed exactly once -- across the
        # kill, the retries, and the resume.
        self.assertEqual(result.value, "approved: approved")
        self.assertEqual(effects, ["tool:side-effect"])
        landed = store.latest_checkpoint("run-1")
        self.assertEqual(len(store.committed_writes(landed.checkpoint_id)), 1)

        # The attempt sequence proves all three phases actually ran.
        self.assertEqual(attempts[0], "kill")
        self.assertIn("retry", attempts)
        self.assertEqual(attempts[-1], "resume")

    def test_a_resume_of_a_clean_run_replays_the_committed_writes_and_nothing_else(self) -> None:
        store = DurableStore()
        effects: list[str] = []
        runner = DurableRunner(store=store)

        def step() -> str:
            runner.declare(_write("t1", 0, "tool:landed"))
            return "ok"

        runner.run(
            task_id="t1",
            step=step,
            state={},
            run_id="run-1",
            applier=lambda write: effects.append(write.effect_key or ""),
        )
        checkpoint = store.latest_checkpoint("run-1")
        self.assertEqual(effects, ["tool:landed"])

        # Re-entering the same checkpoint must not apply the effect again.
        runner.resume(
            Command(resume="again"),
            task_id="t1",
            step=step,
            state={},
            run_id="run-1",
            checkpoint_id=checkpoint.checkpoint_id,
            applier=lambda write: effects.append(write.effect_key or ""),
        )
        self.assertEqual(effects, ["tool:landed"])


class LongHorizonDurableCheckpointTests(RuntimeTestCase):
    """The seam with long_horizon.py: only verified progress reaches a checkpoint."""

    def test_only_auditor_verified_progress_reaches_a_durable_checkpoint(self) -> None:
        from long_horizon import (
            AuditorBackend,
            ExecutorBackend,
            LongHorizonLoop,
            ManagerBackend,
            StepPlan,
        )

        workspace = self.workspace({"result.txt": "verified\n"})
        durable = DurableStore()
        loop = LongHorizonLoop(
            objective="produce result.txt",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=workspace),
            auditor=AuditorBackend(workspace=workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("result.txt",)),
            checks=(),
            max_rounds=1,
            session_id="horizon-1",
            durable_store=durable,
        )
        result = loop.run()

        checkpoints = durable.list_checkpoints("horizon-1")
        self.assertEqual(len(checkpoints), 1)
        state = checkpoints[0].state
        # The state carries the verified progress, and nothing that only the
        # executor said.
        self.assertEqual(state["objective"], "produce result.txt")
        self.assertTrue(state["verified_progress"])
        self.assertTrue(verify_verified_checkpoint(durable, checkpoints[0], expected_round_index=0))

    def test_a_checkpoint_state_built_from_verified_progress_needs_verified_progress(self) -> None:
        with self.assertRaises(DurableStoreError):
            checkpoint_from_verified(
                run_id="run-1",
                round_index=0,
                objective="do the thing",
                verified_progress=(),
                context_digest="sha256:x",
            )

    def test_an_executors_claim_cannot_reach_the_durable_checkpoint(self) -> None:
        from long_horizon import (
            AuditorBackend,
            ExecutorBackend,
            LongHorizonLoop,
            ManagerBackend,
            StepPlan,
        )

        workspace = self.workspace({"result.txt": "verified\n"})
        durable = DurableStore()
        # The executor's summary is a word it chose; the auditor's is the
        # wording of what was verified.
        loop = LongHorizonLoop(
            objective="produce result.txt",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=workspace),
            auditor=AuditorBackend(workspace=workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("result.txt",)),
            checks=(),
            max_rounds=1,
            session_id="horizon-2",
            durable_store=durable,
        )
        loop.run()

        checkpoint = durable.list_checkpoints("horizon-2")[0]
        state = checkpoint.state
        # The state's progress entries carry the auditor's wording, and there
        # is nowhere in the state for the executor's own claim.
        self.assertNotIn("executor_summary", state)
        self.assertNotIn("executor_claim", state)
        for entry in state["verified_progress"]:
            self.assertIn("summary", entry)
            self.assertIn("evidence", entry)


class DurableStateSeamTests(RuntimeTestCase):
    """The join with checkpoints.py: committed state only, no pending writes."""

    def test_the_durable_state_carries_the_committed_boundary_and_no_writes(self) -> None:
        from checkpoints import Checkpoint, durable_state

        checkpoint = Checkpoint(
            session_id="sess-1",
            record_index=7,
            transcript_len=12,
            transcript_digest="a" * 64,
            turns=4,
            tool_calls=9,
            cost_usd=0.25,
            usage={"input_tokens": 10},
            model="m",
            provider="p",
            permission_mode="default",
        )
        state = durable_state(checkpoint)
        self.assertEqual(state["turns"], 4)
        self.assertEqual(state["transcript_len"], 12)
        self.assertEqual(state["cost_usd"], 0.25)

        # The pending writes are not in the state: a write that has not landed
        # cannot travel inside the state as if it had.
        self.assertNotIn("writes", state)
        self.assertNotIn("pending_writes", state)

    def test_the_durable_state_digest_is_a_sha256_pin_in_the_ledger_shape(self) -> None:
        digest = state_digest({"turns": 1})
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), len("sha256:") + 64)

    def test_the_store_writes_its_records_to_disk(self) -> None:
        root = self.temp_dir()
        log = root / "durable.jsonl"
        store = DurableStore(path=log)
        checkpoint = store.put_checkpoint(run_id="run-1", state={"turns": 1})
        store.put_writes(checkpoint.checkpoint_id, [_write("t1", 0, "tool:a")])
        store.commit_writes(checkpoint.checkpoint_id)

        # The records are on disk, one JSON object per line, in order.
        lines = [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
        kinds = [json.loads(line)["kind"] for line in lines]
        self.assertEqual(kinds, ["checkpoint", "pending_writes", "committed_writes"])

    def test_two_runs_in_one_store_may_use_the_same_effect_key(self) -> None:
        store = DurableStore()
        effects: list[tuple[str, str]] = []
        for run in ("run-A", "run-B"):
            checkpoint = store.put_checkpoint(run_id=run, state={})
            store.put_writes(checkpoint.checkpoint_id, [_write("t1", 0, "tool:1")])
            store.commit_writes(
                checkpoint.checkpoint_id,
                applier=lambda write: effects.append((run, write.effect_key or "")),
            )

        # The exactly-once guard is scoped per run: run-B's effect is not
        # silently dropped because run-A committed an effect with the same
        # key.
        self.assertEqual(effects, [("run-A", "tool:1"), ("run-B", "tool:1")])
        run_b = store.list_checkpoints("run-B")[0]
        self.assertEqual(len(store.committed_writes(run_b.checkpoint_id)), 1)


class DurableResumeSecondHalfTests(RuntimeTestCase):
    """The SECOND half of each guard in ``durable_resume``.

    A planted-fault probe over ``durable_resume.py`` reported these
    survivors.  Each one is one arm of a two-armed guard, or one half of
    a conjunction, that the first half of the suite drove but never the
    other side.  The technique for each is named in the method's own
    docstring, so the next person does not have to re-derive it.

    The list:

      or@164   the "not a string" half of the text guard
      or@203   the "not an int" half of the idx guard
      or@229   the "task_path is absent" half of the write reader
      or@287   the "interrupt_answers is absent" half of the checkpoint reader
      or@294   the "state is absent" half of the checkpoint reader
      or@295   the "state_digest is absent" half of the checkpoint reader
      or@299   the "task_path is absent" half of the checkpoint reader
      retT@507 the "keep a write of another task" answer in ``clear_writes``
      eq@566   the checkpoint's own run lookup
      lt@659   the status band's upper bound, on the exception itself
      lt@663   the status band's upper bound, on the response object
      lt@701   an EQUIVALENT mutant, recorded (see the class docstring)
      retF@703 the "we could not place it" answer
      lt@735   the "initial_interval may be zero" bound
      lt@737   the "backoff_factor may be one" bound
      lt@739   the "max_interval may equal initial_interval" bound
      lt@741   the "max_attempts may be one" bound
      or@741   the "max_attempts is not a bool" half
      and@804  the "the last attempt failed" half of ``succeeded``
      and@884  the "there is a checkpoint to hang the write under" half
      and@892  the "there is a checkpoint to clear under" half
      or@919   the "run_id or task_id" fallback when no run id is given
      or@920   the "state or {}" fallback when no state is given
      or@1011  the "run_id or task_id" fallback on the resumed run
      or@1034  the "state or {}" fallback on the interrupt record
      retF@1179 the "the checkpoint does not verify" answer
      retF@1182 the "the round index does not match" answer

    Every one of these is driven by feeding the guard the *other* kind of
    bad input -- a wrong type where the guard checks emptiness, an empty
    value where the guard checks type -- or, where the two arms mask
    each other, by reaching the arm the public API cannot otherwise
    reach.
    """

    # -- or@164: the "not a string" half of the text guard ---------------
    def test_a_write_with_a_non_string_task_id_is_refused(self) -> None:
        """`or@164`: the wrong TYPE, not the empty string.

        The guard is ``not isinstance(value, str) or not value.strip()``.
        Under the mutant (``or`` -> ``and``) the wrong-type half no
        longer refuses on its own: the guard goes on to call ``.strip()``
        on a value that is not a string, so the refusal is replaced by
        an ``AttributeError`` from the wrong place.
        """
        with self.assertRaises(DurableStoreError):
            PendingWrite(task_id=None, idx=0, channel="files")  # type: ignore[arg-type]

    def test_a_write_with_an_empty_task_id_is_refused(self) -> None:
        """`or@164`: the other half, as the control.

        An empty string IS a string, so only the emptiness half refuses
        it.  Under the mutant the guard accepts it, and a write with no
        task is written into the durable log.
        """
        with self.assertRaises(DurableStoreError):
            PendingWrite(task_id="", idx=0, channel="files")

    def test_a_write_with_an_empty_channel_is_refused(self) -> None:
        """`or@164`: the same guard, on the other field."""
        with self.assertRaises(DurableStoreError):
            PendingWrite(task_id="t1", idx=0, channel="")

    def test_a_checkpoint_with_a_non_string_id_is_refused(self) -> None:
        """`or@164`: the guard is shared by the checkpoint's id."""
        with self.assertRaises(DurableStoreError):
            DurableCheckpoint(run_id="run-1", checkpoint_id=None, seq=1, state={})  # type: ignore[arg-type]

    # -- or@203: the "not an int" half of the idx guard -------------------
    def test_a_write_with_a_boolean_index_is_refused(self) -> None:
        """`or@203`: **a bool IS an int in Python**.

        The guard is ``isinstance(self.idx, bool) or not isinstance(self.idx, int) or self.idx < 0``.
        ``isinstance(True, int)`` is True, so the "not an int" half
        never refuses a bool -- only the explicit ``bool`` half does.
        Under the mutant (``or`` -> ``and``) a boolean index is accepted
        and used as the integer 1.
        """
        with self.assertRaises(DurableStoreError):
            PendingWrite(task_id="t1", idx=True, channel="files")  # type: ignore[arg-type]

    def test_a_write_with_a_float_index_is_refused(self) -> None:
        """`or@203`: the other half, as the control.

        A float is not an int and not a bool, so the "not an int" half
        refuses it.  Under the mutant the index would be accepted and
        then truncated by the record's own ``int(...)`` cast.
        """
        with self.assertRaises(DurableStoreError):
            PendingWrite(task_id="t1", idx=1.5, channel="files")  # type: ignore[arg-type]

    def test_a_write_with_a_negative_index_is_refused(self) -> None:
        """`or@203`: the third arm, for completeness."""
        with self.assertRaises(DurableStoreError):
            PendingWrite(task_id="t1", idx=-1, channel="files")

    # -- or@229 / or@299: the "task_path is absent" half -----------------
    def test_a_read_write_keeps_its_task_path(self) -> None:
        """`or@229`: the read side of a pending write.

        The line is ``task_path=str(value.get("task_path", "") or "")``.
        Under the mutant (``or`` -> ``and``) a task path that IS present
        is replaced by the empty string, so the write loses the path
        that orders it against its siblings.
        """
        write = PendingWrite.from_dict(
            {
                "task_id": "t1",
                "idx": 0,
                "channel": "files",
                "value": 1,
                "effect_key": "tool:a",
                "task_path": "nested",
            }
        )
        self.assertEqual(write.task_path, "nested")

    def test_a_read_write_without_a_task_path_reads_as_empty(self) -> None:
        """`or@229`: the other half, as the control.

        An absent task path reads as the empty string either way -- the
        difference is only visible when the path is present.
        """
        write = PendingWrite.from_dict({"task_id": "t1", "idx": 0, "channel": "files"})
        self.assertEqual(write.task_path, "")

    def test_a_read_checkpoint_keeps_its_task_path(self) -> None:
        """`or@299`: the same reader, on the checkpoint.

        ``task_path=str(value.get("task_path", "") or "")`` -- under the
        mutant the checkpoint's own task path is dropped on the way in.
        """
        store = DurableStore()
        record = store.put_checkpoint(run_id="run-1", state={}, task_path="nested").as_dict()
        self.assertEqual(DurableCheckpoint.from_dict(record).task_path, "nested")

    # -- or@287: the "interrupt_answers is absent" half -------------------
    def test_a_read_checkpoint_keeps_its_interrupt_answers(self) -> None:
        """`or@287`: the answers are the resume's whole memory.

        The line is ``answers = value.get("interrupt_answers") or {}``.
        Under the mutant (``or`` -> ``and``) a non-empty mapping is
        replaced by the empty one, so every answer the interrupted
        attempt was given is forgotten.
        """
        store = DurableStore()
        record = store.put_checkpoint(run_id="run-1", state={}).as_dict()
        record["interrupt_answers"] = {"t1#0": "green light"}
        self.assertEqual(
            DurableCheckpoint.from_dict(record).interrupt_answers,
            {"t1#0": "green light"},
        )

    def test_a_read_checkpoint_without_answers_reads_as_empty(self) -> None:
        """`or@287`: the other half, as the control.

        An absent answers mapping reads as ``{}`` under the original
        guard.  Under the mutant the absent key leaves ``None`` in its
        place, and the reader refuses a checkpoint it just wrote.
        """
        store = DurableStore()
        record = store.put_checkpoint(run_id="run-1", state={}).as_dict()
        del record["interrupt_answers"]
        self.assertEqual(DurableCheckpoint.from_dict(record).interrupt_answers, {})

    # -- or@294: the "state is absent" half -------------------------------
    def test_a_read_checkpoint_keeps_its_state(self) -> None:
        """`or@294`: the committed state is the checkpoint's payload.

        The line is ``state=dict(value.get("state") or {})``.  Under the
        mutant (``or`` -> ``and``) a state that IS present is replaced
        by the empty dict, so the checkpoint resumes onto nothing.
        """
        store = DurableStore()
        record = store.put_checkpoint(run_id="run-1", state={"turns": 3}).as_dict()
        self.assertEqual(DurableCheckpoint.from_dict(record).state, {"turns": 3})

    def test_a_read_checkpoint_without_state_reads_as_empty(self) -> None:
        """`or@294`: the other half, as the control.

        An absent state reads as ``{}`` under the original guard.  Under
        the mutant the absent key leaves ``None`` in its place and the
        reader raises a ``TypeError`` from the wrong place.  The digest
        goes with it: a record with no state has no digest to match.
        """
        store = DurableStore()
        record = store.put_checkpoint(run_id="run-1", state={"turns": 3}).as_dict()
        del record["state"]
        del record["state_digest"]
        self.assertEqual(DurableCheckpoint.from_dict(record).state, {})

    # -- or@295: the "state_digest is absent" half ------------------------
    def test_a_read_checkpoint_without_a_digest_recomputes_it(self) -> None:
        """`or@295`: a record with no digest is still a record.

        The line is ``state_digest=str(value.get("state_digest") or "")``.
        Under the mutant (``or`` -> ``and``) an absent digest becomes
        the string ``"None"`` instead of the empty string, and the
        checkpoint refuses its own state as a mismatch.
        """
        store = DurableStore()
        record = store.put_checkpoint(run_id="run-1", state={"turns": 3}).as_dict()
        del record["state_digest"]
        restored = DurableCheckpoint.from_dict(record)
        self.assertEqual(restored.state, {"turns": 3})
        self.assertEqual(restored.state_digest, state_digest({"turns": 3}))

    # -- retT@507: the "keep a write of another task" answer -------------
    def test_clearing_one_task_leaves_another_tasks_write_alone(self) -> None:
        """`retT@507`: the *keep* answer, not the *drop* one.

        ``clear_writes`` answers "keep" for a write that belongs to
        another task, so that narrowing the clear to one task does not
        throw away the other task's declaration.  Under the mutant
        (``return True`` -> ``return False``) the other task's write is
        dropped as well -- the clear takes more than it was asked for.
        """
        store = DurableStore()
        checkpoint = store.put_checkpoint(run_id="run-1", state={})
        store.put_writes(
            checkpoint.checkpoint_id,
            [_write("t1", 0, "tool:mine"), _write("t2", 0, "tool:theirs")],
        )
        dropped = store.clear_writes(checkpoint.checkpoint_id, reason="one task only", task_id="t1")
        self.assertEqual([write.effect_key for write in dropped], ["tool:mine"])
        self.assertEqual(
            [write.effect_key for write in store.pending_writes(checkpoint.checkpoint_id)],
            ["tool:theirs"],
        )

    # -- eq@566: the checkpoint's own run lookup --------------------------
    def test_an_effect_key_is_scoped_to_the_run_that_declared_it(self) -> None:
        """`eq@566`: the run lookup that the exactly-once guard rests on.

        ``_run_of`` walks the checkpoints and returns the run of the one
        whose id MATCHES.  Under the mutant (``==`` -> ``!=``) it returns
        the run of the first checkpoint that does NOT match -- so two
        different runs can be made to share one exactly-once scope, and
        the second run's effect is silently dropped because the first
        run committed an effect with the same key.

        Three runs are needed: with two, the mutant merely swaps the two
        runs' scopes and the swap cancels out.
        """
        store = DurableStore()
        effects: list[str] = []
        checkpoints = {
            run: store.put_checkpoint(run_id=run, state={}).checkpoint_id
            for run in ("run-A", "run-B", "run-C")
        }
        for run in ("run-A", "run-B", "run-C"):
            store.put_writes(checkpoints[run], [_write("t1", 0, "tool:1")])
            store.commit_writes(
                checkpoints[run],
                applier=lambda write: effects.append(write.effect_key or ""),
            )

        # Every run's own effect lands: the same key in three different
        # runs is three different effects.
        self.assertEqual(effects, ["tool:1", "tool:1", "tool:1"])
        for run in ("run-A", "run-B", "run-C"):
            self.assertEqual(len(store.committed_writes(checkpoints[run])), 1)

    # -- lt@659 / lt@663: the status band's upper bound -------------------
    def test_a_status_just_past_the_band_is_not_believed(self) -> None:
        """`lt@659`: the band is ``100 <= status < 600``.

        A status outside the band is not a status at all, so the
        predicate falls through to the failure's own classification.
        Under the mutant (``<`` -> ``<=``) 600 is inside the band, and
        the classification is never consulted -- so a connection failure
        that happens to carry an out-of-range status stops being
        retried.
        """
        error = _RefusedWithStatus("no listener", 600)
        self.assertTrue(default_retry_on(error))

    def test_a_status_inside_the_band_is_believed(self) -> None:
        """`lt@659`: the control -- 599 is inside the band."""
        error = _RefusedWithStatus("no listener", 599)
        self.assertFalse(default_retry_on(error))

    def test_a_response_status_just_past_the_band_is_not_believed(self) -> None:
        """`lt@663`: the same band, read off the response object.

        The second copy of the guard reads ``response.status_code`` when
        the exception itself carries no status.  Under the mutant
        (``<`` -> ``<=``) the same out-of-range status is believed, and
        the failure's own classification is skipped.
        """
        error = _RefusedWithResponse("no listener", 600)
        self.assertTrue(default_retry_on(error))

    def test_a_response_status_inside_the_band_is_believed(self) -> None:
        """`lt@663`: the control."""
        error = _RefusedWithResponse("no listener", 599)
        self.assertFalse(default_retry_on(error))

    # -- lt@701: an EQUIVALENT mutant, recorded ---------------------------
    def test_the_four_hundred_band_boundary_is_unreachable(self) -> None:
        """`lt@701`: the boundary, and why the mutant is equivalent.

        The line is ``if 400 <= status < 500: return False``.  The
        planted fault turns it into ``400 <= status <= 500``.  The two
        differ at exactly one status: 500.  But 500 is in
        ``SERVER_ERROR_STATUSES``, so the earlier branch answers it
        first and the 4xx band is never consulted at 500.  The mutated
        condition is therefore unreachable at the only value that could
        distinguish it: an EQUIVALENT mutant, not a gap in the suite.

        The proof is a DIFFERENTIAL test over the module's OWN source.
        Two copies are built from it -- one with the strict bound, one
        with the mutated bound -- and the two predicates are compared
        over every status the predicate can be handed.  They must agree
        everywhere.

        A POSITIVE CONTROL keeps the differential test from passing
        vacuously: with the server-error branch emptied, the two
        variants must then DIFFER at 500 -- the only status the fault
        touches.  If the control finds no difference, the fault was
        never really applied and the agreement above would have meant
        nothing.

        This mutant is therefore EXPECTED TO SURVIVE the probe.  It is
        recorded here so the next person does not spend a round looking
        for a killer that cannot exist.
        """
        strict = _variant_default_retry_on("<")
        mutated = _variant_default_retry_on("<=")
        self.assertIsNotNone(strict, "the strict variant could not be built")
        self.assertIsNotNone(mutated, "the mutated variant could not be built")
        for status in range(100, 601):
            error = _StatusError("x", status_code=status)
            self.assertEqual(
                strict(error),
                mutated(error),
                f"status {status} behaves differently under the mutant",
            )

        # -- the positive control: the fault really is in there ---------
        import sys

        module = sys.modules["durable_resume_mutated_le"]
        saved = module.SERVER_ERROR_STATUSES
        module.SERVER_ERROR_STATUSES = frozenset(status for status in saved if status != 500)
        try:
            error = _StatusError("x", status_code=500)
            self.assertTrue(strict(error), "the control: 500 is a server error")
            self.assertFalse(
                mutated(error),
                "the control: with the server-error branch emptied the fault "
                "must show -- otherwise the differential test above was "
                "comparing two identical functions",
            )
        finally:
            module.SERVER_ERROR_STATUSES = saved

    def test_the_shipped_predicate_agrees_with_the_strict_band(self) -> None:
        """`lt@701`: the shipped predicate, pinned.

        The predicate as shipped answers the same as the strict-bound
        variant at every status -- which is the property the mutant
        also has, and the reason the mutant is equivalent rather than
        merely untested.
        """
        strict = _variant_default_retry_on("<")
        self.assertIsNotNone(strict)
        for status in range(100, 601):
            error = _StatusError("x", status_code=status)
            self.assertEqual(
                default_retry_on(error),
                strict(error),
                f"status {status} behaves differently from the strict band",
            )

    def test_a_server_error_status_is_retried(self) -> None:
        """`lt@701`: the value that makes the equivalence hold.

        500 is the one status the mutated bound would treat differently,
        and it is answered by the server-error branch before the band
        is reached.
        """
        self.assertTrue(default_retry_on(_StatusError("server blew up", status_code=500)))

    def test_a_client_error_status_is_not_retried(self) -> None:
        """`lt@701`: the band still answers for the statuses in it."""
        self.assertFalse(default_retry_on(_StatusError("bad request", status_code=400)))
        self.assertFalse(default_retry_on(_StatusError("bad request", status_code=499)))

    # -- retF@703: the "we could not place it" answer ---------------------
    def test_a_status_the_predicate_cannot_place_is_not_retried(self) -> None:
        """`retF@703`: the last answer, the one that gives up.

        A status the predicate cannot place -- neither throttling, nor a
        listed server error, nor a 4xx, nor a redirect -- is NOT
        retried: "we could not tell" is not "transient".  Under the
        mutant (``return False`` -> ``return True``) it becomes the
        opposite, and every unplaceable failure turns into a request
        storm against the thing that is already failing.
        """
        self.assertFalse(default_retry_on(_StatusError("not implemented", status_code=501)))
        self.assertFalse(default_retry_on(_StatusError("moved", status_code=302)))

    # -- lt@735 / lt@737 / lt@739 / lt@741: the bounds --------------------
    def test_a_zero_initial_interval_is_allowed(self) -> None:
        """`lt@735`: waiting zero seconds is waiting.

        The guard is ``if self.initial_interval < 0``.  Under the mutant
        (``<`` -> ``<=``) a zero initial interval is refused, so a
        policy that wants to retry immediately cannot be built.
        """
        policy = RetryPolicy(initial_interval=0.0, jitter=False)
        self.assertEqual(policy.delay(1), 0.0)

    def test_a_backoff_factor_of_one_is_allowed(self) -> None:
        """`lt@737`: a factor of one means "no growth".

        The guard is ``if self.backoff_factor < 1.0``.  Under the
        mutant (``<`` -> ``<=``) a flat schedule is refused.
        """
        policy = RetryPolicy(initial_interval=1.0, backoff_factor=1.0, jitter=False)
        self.assertEqual(policy.delay(1), 1.0)
        self.assertEqual(policy.delay(3), 1.0)

    def test_a_max_interval_equal_to_the_initial_interval_is_allowed(self) -> None:
        """`lt@739`: the ceiling may sit exactly on the floor.

        The guard is ``if self.max_interval < self.initial_interval``.
        Under the mutant (``<`` -> ``<=``) a policy whose ceiling equals
        its first wait is refused.
        """
        policy = RetryPolicy(initial_interval=5.0, max_interval=5.0, jitter=False)
        self.assertEqual(policy.delay(1), 5.0)

    def test_a_max_attempts_of_one_is_allowed(self) -> None:
        """`lt@741`: one attempt means "no retry", not "no policy".

        The guard is ``... or self.max_attempts < 1``.  Under the
        mutant (``<`` -> ``<=``) a policy that allows exactly one
        attempt is refused, so a step that must not be retried cannot
        be run at all.
        """
        policy = RetryPolicy(max_attempts=1)
        self.assertEqual(policy.as_dict()["max_attempts"], 1)

    def test_a_boolean_max_attempts_is_refused(self) -> None:
        """`or@741`: the "not a bool" half.

        The guard is ``isinstance(self.max_attempts, bool) or not
        isinstance(self.max_attempts, int) or self.max_attempts < 1``.
        ``isinstance(True, int)`` is True, so only the explicit ``bool``
        half refuses a boolean.  Under the mutant (``or`` -> ``and``) a
        boolean attempt count is accepted and used as the integer 1.
        """
        with self.assertRaises(DurableStoreError):
            RetryPolicy(max_attempts=True)  # type: ignore[arg-type]

    def test_a_float_max_attempts_is_refused(self) -> None:
        """`or@741`: the other half, as the control."""
        with self.assertRaises(DurableStoreError):
            RetryPolicy(max_attempts=2.5)  # type: ignore[arg-type]

    # -- and@804: the "the last attempt failed" half ----------------------
    def test_a_result_whose_last_attempt_failed_did_not_succeed(self) -> None:
        """`and@804`: the "the last attempt failed" half.

        ``succeeded`` is ``bool(self.attempts) and self.attempts[-1].error is None``.
        Under the mutant (``and`` -> ``or``) a result whose last attempt
        FAILED reads as succeeded, because the first half is already
        true.  The runner never hands out such a result -- it raises
        instead -- so the property is pinned directly on the record.
        """
        from durable_resume import Attempt, StepResult

        failed = StepResult(
            value=None,
            attempts=(Attempt(index=1, error=RuntimeError("boom")),),
        )
        self.assertFalse(failed.succeeded)

    def test_a_result_with_no_attempts_did_not_succeed(self) -> None:
        """`and@804`: the other half, as the control.

        A result with no attempts at all has not succeeded either.  Under
        the mutant the second half is evaluated on an empty tuple, so
        the property raises instead of answering.
        """
        from durable_resume import StepResult

        self.assertFalse(StepResult().succeeded)

    # -- and@884: the "there is a checkpoint to hang it under" half -------
    def test_a_write_declared_before_a_checkpoint_exists_is_kept_in_memory(self) -> None:
        """`and@884`: the "there is a checkpoint" half.

        ``declare`` hangs the write under the current checkpoint, but
        only if there IS one.  Under the mutant (``and`` -> ``or``) the
        store is consulted whenever the store exists at all, and a
        declaration made before the first checkpoint is refused with
        "no checkpoint None to hang writes under".
        """
        store = DurableStore()
        runner = DurableRunner(store=store)
        write = _write("t1", 0, "tool:early")
        self.assertIs(runner.declare(write), write)
        # Nothing was hung under anything: there is no checkpoint yet.
        self.assertEqual(store.pending_writes("ck-000001"), ())

    # -- and@892: the "there is a checkpoint to clear under" half ----------
    def test_a_failure_without_a_store_does_not_reach_the_store(self) -> None:
        """`and@892`: the "there is a checkpoint" half.

        ``_clear_pending`` clears the store's pending writes, but only
        if there is a store AND a checkpoint to clear under.  Under the
        mutant (``and`` -> ``or``) the store is consulted whenever
        either half is true, so a runner whose store has been detached
        crashes with an ``AttributeError`` on the failure path -- and
        the failure the caller was told about is lost behind it.

        The store is detached through its public attribute; the
        checkpoint id stays behind, so the mutant's second arm is true
        while the first is false.
        """
        store = DurableStore()
        runner = DurableRunner(
            store=store,
            policy=RetryPolicy(max_attempts=3, jitter=False),
            sleep=lambda _s: None,
        )
        runner.run(task_id="t1", step=lambda: "ok", state={}, run_id="run-1")
        runner.store = None

        def failing() -> str:
            raise _StatusError("bad key", status_code=401)

        # The caller still sees the failure the step raised.
        with self.assertRaises(_StatusError):
            runner.run(task_id="t1", step=failing, state={}, run_id="run-1")

    # -- and@946: the "there is a checkpoint to commit under" half -------
    def test_a_success_without_a_store_commits_nothing_and_still_returns(self) -> None:
        """`and@946`: the "there is a checkpoint" half.

        The runner commits the pending writes only if there is a store
        AND a checkpoint to commit under.  Under the mutant (``and`` ->
        ``or``) the store is consulted whenever either half is true, so
        a runner whose store has been detached crashes with an
        ``AttributeError`` on the SUCCESS path -- and the step's value
        is lost behind it.

        The store is detached through its public attribute; the
        checkpoint id stays behind from the earlier run, so the
        mutant's second arm is true while the first is false.
        """
        store = DurableStore()
        runner = DurableRunner(store=store)
        runner.run(task_id="t1", step=lambda: "ok", state={}, run_id="run-1")
        runner.store = None

        result = runner.run(task_id="t1", step=lambda: "still ok", state={}, run_id="run-1")
        self.assertEqual(result.value, "still ok")
        self.assertEqual(result.committed, ())

    # -- or@919 / or@920: the run's own fallbacks -------------------------
    def test_a_run_without_a_run_id_falls_back_to_the_task_id(self) -> None:
        """`or@919`: the fallback, and why it is not a fallback to nothing.

        ``run_id=run_id or task_id`` -- a run with no run id of its own
        is stored under its task's id.  Under the mutant (``or`` ->
        ``and``) the fallback becomes ``None``, and the store refuses
        the checkpoint with a ``MissingRunIdError``.
        """
        store = DurableStore()
        runner = DurableRunner(store=store)
        result = runner.run(task_id="t1", step=lambda: "ok", state={})
        self.assertEqual(result.value, "ok")
        self.assertEqual(len(store.list_checkpoints("t1")), 1)

    def test_a_run_without_a_state_starts_from_an_empty_state(self) -> None:
        """`or@920`: the same fallback, on the state.

        ``state=dict(state or {})`` -- a run with no state starts from
        the empty state.  Under the mutant (``or`` -> ``and``) the
        fallback becomes ``None``, and the store refuses the state with
        a ``TypeError``.
        """
        store = DurableStore()
        runner = DurableRunner(store=store)
        result = runner.run(task_id="t1", step=lambda: "ok", state=None, run_id="run-1")
        self.assertEqual(result.value, "ok")
        self.assertEqual(store.list_checkpoints("run-1")[0].state, {})

    # -- or@1011: the resumed run's own run id ---------------------------
    def test_a_second_interrupt_on_resume_is_recorded_under_the_runs_id(self) -> None:
        """`or@1011`: the run id the resumed run carries.

        The resume re-enters the step with ``run_id=run_id or task_id``.
        Under the mutant (``or`` -> ``and``) a resume that NAMED a run
        falls back to the task's id instead, and the second interrupt's
        checkpoint is filed under the task rather than under the run --
        so the run's own history loses a boundary.

        The step is made to interrupt again by answering an interrupt it
        does not ask for: the answers are keyed by index, so answering
        ``t1#1`` leaves the step's own ``t1#0`` question open.
        """
        store = DurableStore()
        runner = DurableRunner(store=store)

        def step() -> str:
            return runner.interrupt("what now?")

        with self.assertRaises(GraphInterrupt):
            runner.run(task_id="t1", step=step, state={}, run_id="run-1")

        with self.assertRaises(GraphInterrupt):
            runner.resume(
                Command(resume={"t1#1": "answer"}),
                task_id="t1",
                step=step,
                state={},
                run_id="run-1",
            )

        # Every checkpoint of the sequence belongs to the run the caller
        # named -- and none of them belongs to the task.
        self.assertEqual(len(store.list_checkpoints("run-1")), 3)
        self.assertEqual(store.list_checkpoints("t1"), ())

    # -- or@1034: the interrupt record's own state -----------------------
    def test_an_interrupt_recorded_with_no_state_reads_as_empty(self) -> None:
        """`or@1034`: the same fallback, on the interrupt's record.

        ``_record_interrupt`` stores ``dict(state or {})``.  Under the
        mutant (``or`` -> ``and``) the fallback becomes ``None`` and the
        interrupt's checkpoint is refused with a ``TypeError`` -- the
        pause nobody can leave, raised at the wrong moment.
        """
        store = DurableStore()
        runner = DurableRunner(store=store)

        def step() -> str:
            return runner.interrupt("what now?")

        with self.assertRaises(GraphInterrupt):
            runner.run(task_id="t1", step=step, state=None, run_id="run-1")
        checkpoint = store.latest_checkpoint("run-1")
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint.state, {})

    # -- retF@1179 / retF@1182: the verified checkpoint's answers --------
    def test_a_checkpoint_whose_digest_no_longer_matches_is_refused(self) -> None:
        """`retF@1179`: the "the checkpoint does not verify" answer.

        ``verify_verified_checkpoint`` answers False for a checkpoint
        whose state was edited under it.  Under the mutant (``return
        False`` -> ``return True``) an edited checkpoint reads as
        verified, and a resume would inherit counters describing a
        different history.
        """
        store = DurableStore()
        checkpoint = store.put_checkpoint(run_id="run-1", state={"round_index": 0})
        object.__setattr__(checkpoint, "state", {"round_index": 0, "verified_progress": [{"summary": "s"}]})
        self.assertFalse(
            verify_verified_checkpoint(store, checkpoint, expected_round_index=0)
        )

    def test_a_checkpoint_of_another_round_is_refused(self) -> None:
        """`retF@1182`: the "the round index does not match" answer.

        Under the mutant (``return False`` -> ``return True``) a
        checkpoint from a different round reads as the one asked for, so
        a loop would resume onto the wrong round's counters.
        """
        store = DurableStore()
        checkpoint = store.put_checkpoint(
            run_id="run-1",
            state={"round_index": 5, "verified_progress": [{"summary": "s"}]},
        )
        self.assertFalse(
            verify_verified_checkpoint(store, checkpoint, expected_round_index=0)
        )

    def test_the_matching_round_is_verified(self) -> None:
        """`retF@1179` / `retF@1182`: the control, the other side."""
        store = DurableStore()
        checkpoint = store.put_checkpoint(
            run_id="run-1",
            state={"round_index": 0, "verified_progress": [{"summary": "s"}]},
        )
        self.assertTrue(
            verify_verified_checkpoint(store, checkpoint, expected_round_index=0)
        )


class _RefusedWithStatus(ConnectionRefusedError):
    """A connection failure that also carries an HTTP status.

    ``ConnectionRefusedError`` is the runtime's own example of a failure
    raised *before* the connection was established, so it is retried.
    The status here is deliberately out of the valid band, so the status
    must be ignored and the failure's own classification must decide.
    """

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class _RefusedWithResponse(ConnectionRefusedError):
    """A connection failure whose status lives on a response object."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.response = _Response(status_code)


class _Response:
    """The shape an SDK's response object has."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def _variant_default_retry_on(bound: str):
    """``default_retry_on`` with the 4xx band's upper bound as given.

    The module's own source is read and the band's upper bound is
    replaced with ``bound`` (``"<"`` for the shipped, strict form;
    ``"<="`` for the planted fault); the variant is then executed under
    a private name.  The predicate it exposes is the module's own
    behaviour with that bound in place -- not a hand-written copy of
    it, which could drift from the code it is about.

    The band is matched in EITHER form, so the helper still works when
    the source it reads already carries the planted fault -- the
    equivalence must be provable against the shipped code and against
    the mutated code alike, and that is what lets the mutant be shown
    to be equivalent rather than merely untested.

    Returns ``None`` when the variant cannot be built, so the caller can
    say so rather than silently comparing a function with itself.
    """
    import importlib.util
    import re
    import shutil
    import sys
    import tempfile
    from pathlib import Path

    import durable_resume

    source_path = Path(durable_resume.__file__)
    lines = source_path.read_text(encoding="utf-8").splitlines(keepends=True)
    pattern = re.compile(r"400 <= status <=? 500")
    target = None
    for index, line in enumerate(lines):
        if pattern.search(line):
            target = index
            break
    if target is None:
        return None
    mutated_line = pattern.sub(f"400 <= status {bound} 500", lines[target], count=1)
    wanted = f"400 <= status {bound} 500"
    if wanted not in mutated_line:
        return None
    lines[target] = mutated_line

    root = Path(tempfile.mkdtemp(prefix="durable-resume-mutant-"))
    try:
        name = f"durable_resume_mutated_{'le' if bound == '<=' else 'lt'}"
        (root / f"{name}.py").write_text("".join(lines), encoding="utf-8")
        spec = importlib.util.spec_from_file_location(name, root / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module.default_retry_on
    finally:
        shutil.rmtree(root, ignore_errors=True)


class DurableResumeRecordRoundTripTests(RuntimeTestCase):
    """The record round trip: what the store writes is what it reads.

    The first half of this file proved the guards of
    ``durable_resume.py``; this class proves the records themselves --
    that a checkpoint and a pending write survive the trip through
    ``as_dict`` / ``from_dict`` and through the durable log on disk
    without losing a field, changing one, or gaining one.

    These are the properties a resumed run depends on: the resume
    re-enters a step from a checkpoint that was read back off the
    disk, so a field that does not survive the trip is a field the
    resume cannot use.
    """

    def test_a_checkpoint_survives_its_own_round_trip(self) -> None:
        """Every field of a checkpoint is preserved by the round trip."""
        store = DurableStore()
        original = store.put_checkpoint(
            run_id="run-1",
            state={"turns": 3, "cost_usd": 0.25},
            parent_checkpoint_id="ck-000001",
            interrupted_task="t1",
            interrupt_value="what now?",
            task_path="nested/path",
            interrupt_answers={"t1#0": "green light"},
        )
        restored = DurableCheckpoint.from_dict(original.as_dict())

        self.assertEqual(restored.run_id, original.run_id)
        self.assertEqual(restored.checkpoint_id, original.checkpoint_id)
        self.assertEqual(restored.seq, original.seq)
        self.assertEqual(restored.state, original.state)
        self.assertEqual(restored.state_digest, original.state_digest)
        self.assertEqual(restored.parent_checkpoint_id, original.parent_checkpoint_id)
        self.assertEqual(restored.interrupted_task, original.interrupted_task)
        self.assertEqual(restored.interrupt_value, original.interrupt_value)
        self.assertEqual(restored.task_path, original.task_path)
        self.assertEqual(restored.interrupt_answers, original.interrupt_answers)

    def test_a_write_survives_its_own_round_trip(self) -> None:
        """Every field of a pending write is preserved too."""
        original = PendingWrite(
            task_id="t1",
            idx=3,
            channel="files",
            value={"path": "/tmp/x", "nested": [1, 2]},
            effect_key="tool:a",
            task_path="nested/path",
        )
        restored = PendingWrite.from_dict(original.as_dict())
        self.assertEqual(restored, original)

    def test_a_checkpoint_read_back_from_the_disk_log_is_usable(self) -> None:
        """The log on disk is the store's own record, not a copy of it.

        Every record the store appends names its kind, and the kinds
        appear in the order the run produced them: the checkpoint
        first, then the pending writes, then the committed writes.
        """
        root = self.temp_dir()
        log = root / "durable.jsonl"
        store = DurableStore(path=log)
        checkpoint = store.put_checkpoint(run_id="run-1", state={"turns": 1})
        store.put_writes(checkpoint.checkpoint_id, [_write("t1", 0, "tool:a")])
        store.commit_writes(checkpoint.checkpoint_id)

        records = [
            json.loads(line)
            for line in log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(
            [record["kind"] for record in records],
            ["checkpoint", "pending_writes", "committed_writes"],
        )
        # The checkpoint record carries the schema pin, and its own state.
        self.assertEqual(records[0]["schema"], "northstar.durable-resume.v1")
        self.assertEqual(records[0]["state"], {"turns": 1})
        # And the write records name the checkpoint they hang under.
        self.assertEqual(records[1]["checkpoint_id"], checkpoint.checkpoint_id)
        self.assertEqual(records[2]["checkpoint_id"], checkpoint.checkpoint_id)

    def test_a_cleared_write_is_recorded_as_cleared_and_never_committed(self) -> None:
        """The log tells the two apart: dropped, and landed.

        A write that was dropped appears under the cleared-writes kind
        and never under the committed-writes kind, so "the write was
        dropped" and "the write never happened" stay distinguishable
        after the fact.
        """
        root = self.temp_dir()
        log = root / "durable.jsonl"
        store = DurableStore(path=log)
        checkpoint = store.put_checkpoint(run_id="run-1", state={})
        store.put_writes(checkpoint.checkpoint_id, [_write("t1", 0, "tool:a")])
        store.clear_writes(checkpoint.checkpoint_id, reason="the step failed")

        records = [
            json.loads(line)
            for line in log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        kinds = [record["kind"] for record in records]
        self.assertIn("cleared_writes", kinds)
        self.assertNotIn("committed_writes", kinds)
        cleared = next(record for record in records if record["kind"] == "cleared_writes")
        self.assertEqual(cleared["reason"], "the step failed")
        self.assertEqual([w["effect_key"] for w in cleared["writes"]], ["tool:a"])

    def test_a_checkpoint_with_an_unknown_schema_is_refused(self) -> None:
        """A record from another schema is not read as this one.

        The schema pin is what makes the log's records readable at all;
        a record that does not carry it is refused rather than
        interpreted.
        """
        store = DurableStore()
        record = store.put_checkpoint(run_id="run-1", state={}).as_dict()
        record["schema"] = "northstar.some-other-schema.v1"
        with self.assertRaises(DurableStoreError):
            DurableCheckpoint.from_dict(record)

    def test_a_checkpoint_with_non_mapping_answers_is_refused(self) -> None:
        """The answers must be a mapping, not a list of pairs."""
        store = DurableStore()
        record = store.put_checkpoint(run_id="run-1", state={}).as_dict()
        record["interrupt_answers"] = ["t1#0", "green light"]
        with self.assertRaises(DurableStoreError):
            DurableCheckpoint.from_dict(record)

    def test_a_run_of_one_cannot_see_another_runs_checkpoints(self) -> None:
        """The run id is the primary key on the reading side too.

        ``list_checkpoints`` and ``latest_checkpoint`` are both scoped
        to a run, so a run's history cannot be read as another run's --
        and the newest checkpoint of a run is that run's own newest,
        not the store's.
        """
        store = DurableStore()
        store.put_checkpoint(run_id="run-A", state={"n": 1})
        store.put_checkpoint(run_id="run-B", state={"n": 2})
        store.put_checkpoint(run_id="run-A", state={"n": 3})

        self.assertEqual(len(store.list_checkpoints("run-A")), 2)
        self.assertEqual(len(store.list_checkpoints("run-B")), 1)
        self.assertEqual(store.latest_checkpoint("run-A").state, {"n": 3})
        self.assertEqual(store.latest_checkpoint("run-B").state, {"n": 2})

    def test_deleting_a_thread_forgets_that_run_only(self) -> None:
        """``delete_thread`` takes one run and leaves the others alone.

        The effect keys of the deleted run go with it, so a later run
        that reuses the key starts clean.
        """
        store = DurableStore()
        effects: list[str] = []
        kept = store.put_checkpoint(run_id="run-B", state={})
        gone = store.put_checkpoint(run_id="run-A", state={})
        store.put_writes(kept.checkpoint_id, [_write("t1", 0, "tool:1")])
        store.put_writes(gone.checkpoint_id, [_write("t1", 0, "tool:1")])
        store.commit_writes(kept.checkpoint_id, applier=lambda w: effects.append("kept"))

        store.delete_thread("run-A")

        self.assertEqual(store.list_checkpoints("run-A"), ())
        self.assertEqual(len(store.list_checkpoints("run-B")), 1)
        self.assertEqual(store.pending_writes(gone.checkpoint_id), ())
        # And run-A's effect key is free again.
        store.put_checkpoint(run_id="run-A", state={})
        self.assertEqual(len(store.list_checkpoints("run-A")), 1)

    def test_a_write_hung_under_an_unknown_checkpoint_is_refused(self) -> None:
        """A write with nowhere to hang is refused, not silently kept.

        ``put_writes`` names the checkpoint the writes hang under; a
        checkpoint that does not exist cannot hold them, and the store
        says so instead of keeping them in memory where no resume can
        find them.
        """
        store = DurableStore()
        with self.assertRaises(DurableStoreError):
            store.put_writes("ck-999999", [_write("t1", 0, "tool:a")])

    def test_the_writes_of_a_checkpoint_keep_their_declaration_order(self) -> None:
        """The order a step declared its writes in is the order kept.

        Two calls to ``put_writes`` under one checkpoint append: the
        first declaration stays first, so the second call's write is
        not applied before the first one.
        """
        store = DurableStore()
        checkpoint = store.put_checkpoint(run_id="run-1", state={})
        store.put_writes(checkpoint.checkpoint_id, [_write("t1", 0, "tool:first")])
        store.put_writes(checkpoint.checkpoint_id, [_write("t1", 1, "tool:second")])
        self.assertEqual(
            [write.effect_key for write in store.pending_writes(checkpoint.checkpoint_id)],
            ["tool:first", "tool:second"],
        )

    def test_moving_a_writes_record_re_parents_it_and_leaves_a_trace(self) -> None:
        """Re-parenting the writes leaves the old record empty.

        The move is an append, so the log shows both what was pending
        when the step started and what was pending when it paused; the
        live view shows the writes under their new checkpoint only.
        """
        store = DurableStore()
        first = store.put_checkpoint(run_id="run-1", state={})
        store.put_writes(first.checkpoint_id, [_write("t1", 0, "tool:inflight")])
        second = store.put_checkpoint(run_id="run-1", state={}, parent_checkpoint_id=first.checkpoint_id)

        moved = store.move_writes(first.checkpoint_id, second.checkpoint_id)
        self.assertEqual([write.effect_key for write in moved], ["tool:inflight"])
        self.assertEqual(store.pending_writes(first.checkpoint_id), ())
        self.assertEqual(
            [write.effect_key for write in store.pending_writes(second.checkpoint_id)],
            ["tool:inflight"],
        )

    def test_moving_the_writes_of_a_checkpoint_with_none_is_a_no_op(self) -> None:
        """There is nothing to move, so nothing is moved."""
        store = DurableStore()
        first = store.put_checkpoint(run_id="run-1", state={})
        second = store.put_checkpoint(run_id="run-1", state={})
        self.assertEqual(store.move_writes(first.checkpoint_id, second.checkpoint_id), ())
        self.assertEqual(store.pending_writes(second.checkpoint_id), ())
