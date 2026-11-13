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

import sys
import unittest

import support  # noqa: F401  (bootstraps sys.path)
from support import RuntimeTestCase

from durable_resume import (
    Command,
    DurableCheckpoint,
    DurableRunner,
    DurableStore,
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
        with self.assertRaises(Exception):
            checkpoint_from_verified(
                run_id="run-1",
                round_index=0,
                objective="do the thing",
                verified_progress=(),
                context_digest="sha256:x",
            )


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
