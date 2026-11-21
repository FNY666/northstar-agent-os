"""Tests for checkpoint durability modes: *when* a checkpoint reaches disk.

The rules under test, one class each:

* **mode validation** -- an unknown mode is refused (fail closed); the three
  known modes are accepted;
* **write timing and checkpoint counts** -- a fifty-step run writes one
  checkpoint under ``exit`` and fifty-two under ``async`` and ``sync``;
* **interrupt semantics** -- every mode saves the checkpoint a resume needs;
* **crash windows** -- what each mode loses when the process dies mid-run;
* **the first checkpoint of a new thread** -- how each mode admits a thread;
* **receipts** -- every write carries its mode, id, timing and settled flag;
* **the three real paths** -- driven end to end.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from checkpoint_durability import (
    CrashWindow,
    DurabilityController,
    DurabilityError,
    DurabilityInterrupt,
    DurabilityMode,
    DurabilityPolicy,
    DurabilityReceipt,
    DurabilityStateError,
    DurableStoreSink,
    FileSink,
    InvalidDurabilityModeError,
    MemorySink,
    RunOutcome,
    SimulatedCrash,
    StepCost,
    WriteTiming,
    state_digest,
)

ALL_MODES = (DurabilityMode.EXIT, DurabilityMode.ASYNC, DurabilityMode.SYNC)


def _steps(count: int):
    """``count`` trivial super-steps, each returning its own state."""
    return [lambda index=index: {"n": index + 1} for index in range(count)]


class ModeValidationTests(unittest.TestCase):
    """An unknown durability mode is refused, never guessed."""

    def test_the_three_known_modes_parse(self):
        self.assertIs(DurabilityMode.parse("exit"), DurabilityMode.EXIT)
        self.assertIs(DurabilityMode.parse("async"), DurabilityMode.ASYNC)
        self.assertIs(DurabilityMode.parse("sync"), DurabilityMode.SYNC)

    def test_a_mode_object_parses_to_itself(self):
        self.assertIs(DurabilityMode.parse(DurabilityMode.SYNC), DurabilityMode.SYNC)

    def test_an_unknown_mode_is_refused(self):
        for value in ("durable", "SYNC", "sync ", "", "exit-mode", "none"):
            with self.subTest(value=value):
                with self.assertRaises(InvalidDurabilityModeError):
                    DurabilityMode.parse(value)

    def test_a_non_string_mode_is_refused(self):
        for value in (None, 1, 1.5, True, object(), ["sync"]):
            with self.subTest(value=value):
                with self.assertRaises(InvalidDurabilityModeError):
                    DurabilityMode.parse(value)

    def test_the_refusal_names_the_three_modes(self):
        with self.assertRaises(InvalidDurabilityModeError) as caught:
            DurabilityMode.parse("durable")
        message = str(caught.exception)
        for mode in ("exit", "async", "sync"):
            self.assertIn(mode, message)

    def test_a_controller_refuses_an_unknown_mode(self):
        with self.assertRaises(InvalidDurabilityModeError):
            DurabilityController(sink=MemorySink(), mode="durable")

    def test_a_policy_refuses_an_unknown_mode(self):
        with self.assertRaises(InvalidDurabilityModeError):
            DurabilityPolicy(mode="durable")

    def test_a_policy_accepts_the_three_modes(self):
        for mode in ALL_MODES:
            with self.subTest(mode=mode):
                self.assertIs(DurabilityPolicy(mode=mode).mode, mode)

    def test_a_policy_parses_a_mode_name(self):
        self.assertIs(DurabilityPolicy.parse("sync").mode, DurabilityMode.SYNC)


class PolicyShapeTests(unittest.TestCase):
    """The policy says when a write happens, per mode."""

    def test_exit_writes_only_on_exit(self):
        self.assertIs(
            DurabilityPolicy(mode=DurabilityMode.EXIT).write_timing(),
            WriteTiming.ON_EXIT,
        )

    def test_async_writes_in_the_background(self):
        self.assertIs(
            DurabilityPolicy(mode=DurabilityMode.ASYNC).write_timing(),
            WriteTiming.BACKGROUND,
        )

    def test_sync_awaits_the_write(self):
        self.assertIs(
            DurabilityPolicy(mode=DurabilityMode.SYNC).write_timing(),
            WriteTiming.AWAITED,
        )

    def test_only_sync_awaits_before_the_next_step(self):
        self.assertFalse(DurabilityPolicy(mode=DurabilityMode.EXIT).awaits_writes())
        self.assertFalse(DurabilityPolicy(mode=DurabilityMode.ASYNC).awaits_writes())
        self.assertTrue(DurabilityPolicy(mode=DurabilityMode.SYNC).awaits_writes())

    def test_the_crash_window_of_each_mode(self):
        window = DurabilityPolicy(mode=DurabilityMode.EXIT).crash_window()
        self.assertTrue(window.loses_all_progress)
        self.assertFalse(window.preserves_completed_steps)

        window = DurabilityPolicy(mode=DurabilityMode.ASYNC).crash_window()
        self.assertFalse(window.loses_all_progress)
        self.assertTrue(window.may_lose_last_checkpoint)

        window = DurabilityPolicy(mode=DurabilityMode.SYNC).crash_window()
        self.assertFalse(window.loses_all_progress)
        self.assertFalse(window.may_lose_last_checkpoint)
        self.assertTrue(window.preserves_completed_steps)

    def test_the_recommended_mode_follows_the_step_cost(self):
        self.assertIs(
            DurabilityPolicy.recommend(StepCost.SIDE_EFFECTING), DurabilityMode.SYNC
        )
        self.assertIs(
            DurabilityPolicy.recommend(StepCost.RECOMPUTABLE), DurabilityMode.EXIT
        )
        self.assertIs(DurabilityPolicy.recommend(None), DurabilityMode.ASYNC)

    def test_a_recommendation_accepts_a_cost_name(self):
        self.assertIs(
            DurabilityPolicy.recommend("side_effecting"), DurabilityMode.SYNC
        )


class WriteTimingAndCountTests(unittest.TestCase):
    """Fifty steps, three modes: how many checkpoints, and written when.

    The counts come from the source's measurement of a fifty-node graph on
    langgraph 1.2.11: ``exit`` wrote one checkpoint, ``async`` and ``sync``
    each wrote fifty-two -- "one per super-step plus the input".
    """

    def test_a_fifty_step_run_under_exit_writes_one_checkpoint(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.EXIT)
        outcome = controller.run(_steps(50), initial_state={"n": 0})
        self.assertEqual(outcome.status, "completed")
        self.assertEqual(outcome.checkpoint_count, 1)
        self.assertEqual(len(sink.ids()), 1)

    def test_a_fifty_step_run_under_async_writes_fifty_two_checkpoints(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.ASYNC)
        outcome = controller.run(_steps(50), initial_state={"n": 0})
        self.assertEqual(outcome.checkpoint_count, 52)
        self.assertEqual(len(sink.ids()), 52)

    def test_a_fifty_step_run_under_sync_writes_fifty_two_checkpoints(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        outcome = controller.run(_steps(50), initial_state={"n": 0})
        self.assertEqual(outcome.checkpoint_count, 52)
        self.assertEqual(len(sink.ids()), 52)

    def test_all_three_modes_reach_the_same_final_state(self):
        # The source's measurement: "All three modes produced the same
        # terminal state value of 50."
        finals = {}
        for mode in ALL_MODES:
            controller = DurabilityController(sink=MemorySink(), mode=mode)
            outcome = controller.run(_steps(50), initial_state={"n": 0})
            finals[mode.value] = outcome.final_state
        self.assertEqual(finals["exit"], {"n": 50})
        self.assertEqual(finals["async"], {"n": 50})
        self.assertEqual(finals["sync"], {"n": 50})

    def test_the_input_checkpoint_is_the_first_one_written(self):
        # "one per super-step plus the input" -- the input comes first.
        for mode in (DurabilityMode.ASYNC, DurabilityMode.SYNC):
            with self.subTest(mode=mode):
                sink = MemorySink()
                controller = DurabilityController(sink=sink, mode=mode)
                controller.run(_steps(50), initial_state={"n": 0})
                first = sink.load(sink.ids()[0])
                self.assertEqual(first["kind"], "input")

    def test_exit_writes_nothing_until_the_run_exits(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.EXIT)
        controller.start({"n": 0})
        self.assertEqual(len(sink.ids()), 0)
        for index in range(5):
            controller.step(index, {"n": index + 1})
            self.assertEqual(len(sink.ids()), 0)
        controller.finish(reason="completed", state={"n": 5})
        self.assertEqual(len(sink.ids()), 1)

    def test_async_leaves_a_write_in_flight_when_the_run_returns(self):
        # The run does not wait for the background write: the last write is
        # still outstanding when the run's work is done.
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.ASYNC)
        outcome = controller.run(_steps(50), initial_state={"n": 0})
        self.assertGreater(outcome.outstanding_at_return, 0)

    def test_sync_leaves_nothing_outstanding_when_the_run_returns(self):
        # "the run does not return until pending writes have settled".
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        outcome = controller.run(_steps(50), initial_state={"n": 0})
        self.assertEqual(outcome.outstanding_at_return, 0)

    def test_exit_leaves_nothing_outstanding_when_the_run_returns(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.EXIT)
        outcome = controller.run(_steps(50), initial_state={"n": 0})
        self.assertEqual(outcome.outstanding_at_return, 0)

    def test_an_async_write_lands_while_the_next_step_runs(self):
        # The background write for step N is on disk by the time step N+1 has
        # finished -- it lands *during* the next step, not before it.
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.ASYNC)
        seen: list[int] = []

        def step(index):
            seen.append(len(sink.ids()))
            return {"n": index + 1}

        controller.run([lambda index=index: step(index) for index in range(4)])
        # The input and start writes land before the first user node runs, so
        # step 0 sees 2 checkpoints.  Step 1 starts with step 0's write *not
        # yet landed* -- the background write lands while step 1 runs -- so
        # step 1 also sees 2.  Step 2 then sees 3, step 3 sees 4.
        self.assertEqual(seen, [2, 2, 3, 4])

    def test_a_sync_write_is_on_disk_before_the_next_step_starts(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        seen: list[int] = []

        def step(index):
            seen.append(len(sink.ids()))
            return {"n": index + 1}

        controller.run([lambda index=index: step(index) for index in range(4)])
        # Every step starts with the previous step's checkpoint already on
        # disk: 2 (input + start) then 3, 4, 5.
        self.assertEqual(seen, [2, 3, 4, 5])

    def test_sync_and_async_differ_in_whether_the_next_step_waits(self):
        # The source's distinction, made observable: "async writes while the
        # next step runs" versus "sync writes before the next step starts".
        observed = {}
        for mode in (DurabilityMode.ASYNC, DurabilityMode.SYNC):
            sink = MemorySink()
            controller = DurabilityController(sink=sink, mode=mode)
            seen: list[int] = []

            def step(index):
                seen.append(len(sink.ids()))
                return {"n": index + 1}

            controller.run([lambda index=index: step(index) for index in range(4)])
            observed[mode.value] = seen
        self.assertEqual(observed["async"], [2, 2, 3, 4])
        self.assertEqual(observed["sync"], [2, 3, 4, 5])

    def test_the_write_timings_agree_with_the_mode(self):
        timings = {}
        for mode in ALL_MODES:
            sink = MemorySink()
            controller = DurabilityController(sink=sink, mode=mode)
            controller.run(_steps(3), initial_state={"n": 0})
            step_receipts = [
                receipt for receipt in controller.receipts if receipt.kind == "step"
            ]
            timings[mode.value] = {receipt.timing for receipt in step_receipts}
        self.assertEqual(timings["exit"], set())
        self.assertEqual(timings["async"], {WriteTiming.BACKGROUND})
        self.assertEqual(timings["sync"], {WriteTiming.AWAITED})


class InterruptSemanticsTests(unittest.TestCase):
    """Every mode saves the checkpoint a resume needs.

    The source says interrupts work in all three modes because the run saves
    a checkpoint when it pauses.  Northstar makes that an *awaited* barrier
    even under ``async``: the run is going nowhere until the human answers,
    so there is no performance reason to leave the write in flight.
    """

    def test_every_mode_saves_a_checkpoint_at_the_interrupt(self):
        for mode in ALL_MODES:
            with self.subTest(mode=mode):
                sink = MemorySink()
                controller = DurabilityController(sink=sink, mode=mode)

                def asking():
                    raise DurabilityInterrupt("need-approval")

                outcome = controller.run(
                    [asking, lambda: {"n": 2}], initial_state={"n": 0}
                )
                self.assertEqual(outcome.status, "interrupted")
                self.assertIsNotNone(outcome.interrupt_checkpoint_id)
                self.assertTrue(sink.exists(outcome.interrupt_checkpoint_id))

    def test_the_interrupt_checkpoint_is_settled_in_every_mode(self):
        for mode in ALL_MODES:
            with self.subTest(mode=mode):
                sink = MemorySink()
                controller = DurabilityController(sink=sink, mode=mode)

                def asking():
                    raise DurabilityInterrupt("need-approval")

                outcome = controller.run([asking], initial_state={"n": 0})
                receipt = outcome.receipt_for(outcome.interrupt_checkpoint_id)
                self.assertTrue(receipt.settled)
                self.assertTrue(receipt.awaited)
                self.assertEqual(receipt.kind, "interrupt")

    def test_the_interrupt_checkpoint_carries_the_requested_value(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)

        def asking():
            raise DurabilityInterrupt("need-approval")

        outcome = controller.run([asking], initial_state={"n": 0})
        self.assertEqual(outcome.interrupt_value, "need-approval")

    def test_a_resume_continues_from_the_interrupt_point(self):
        for mode in ALL_MODES:
            with self.subTest(mode=mode):
                sink = MemorySink()
                controller = DurabilityController(sink=sink, mode=mode)
                executed: list[int] = []

                def asking():
                    executed.append(0)
                    raise DurabilityInterrupt("need-approval")

                def after(index):
                    executed.append(index)
                    return {"n": index + 1}

                outcome = controller.run(
                    [asking, lambda: after(1)], initial_state={"n": 0}
                )
                self.assertEqual(outcome.status, "interrupted")

                # The resume re-enters at the interrupt point and runs the
                # steps that had not finished.
                resumed = controller.resume(
                    [lambda: after(1)],
                    from_checkpoint_id=outcome.interrupt_checkpoint_id,
                    initial_state={"n": 0},
                )
                self.assertEqual(resumed.status, "completed")
                self.assertEqual(executed, [0, 1])

    def test_a_resume_does_not_write_a_second_input_checkpoint(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)

        def asking():
            raise DurabilityInterrupt("need-approval")

        outcome = controller.run([asking], initial_state={"n": 0})
        before = len(controller.receipts)
        controller.resume(
            [lambda: {"n": 2}],
            from_checkpoint_id=outcome.interrupt_checkpoint_id,
            initial_state={"n": 0},
        )
        after_receipts = controller.receipts[before:]
        self.assertEqual([receipt.kind for receipt in after_receipts], ["step"])

    def test_a_resume_needs_the_checkpoint_it_continues_from(self):
        controller = DurabilityController(sink=MemorySink(), mode=DurabilityMode.SYNC)
        with self.assertRaises(DurabilityError):
            controller.resume([lambda: {"n": 2}], from_checkpoint_id="")

    def test_an_interrupt_under_exit_still_writes_one_checkpoint(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.EXIT)

        def asking():
            raise DurabilityInterrupt("need-approval")

        outcome = controller.run([asking], initial_state={"n": 0})
        self.assertEqual(outcome.status, "interrupted")
        self.assertEqual(len(sink.ids()), 1)


class CrashWindowTests(unittest.TestCase):
    """What a mid-run crash costs, per mode.

    The crash is *simulated* with an injected hook -- no process is killed --
    and the loss window is measured from what actually reached the sink.
    """

    def _crash_run(self, mode, *, point: str, index: int, steps: int = 50):
        sink = MemorySink()

        def hook(hit_point, hit_index):
            if hit_point == point and hit_index == index:
                raise SimulatedCrash("the process died")

        controller = DurabilityController(sink=sink, mode=mode, crash_hook=hook)
        with self.assertRaises(SimulatedCrash):
            controller.run(_steps(steps), initial_state={"n": 0})
        return sink, controller

    def test_a_crash_under_exit_loses_every_intermediate_checkpoint(self):
        sink, controller = self._crash_run(DurabilityMode.EXIT, point="after_step", index=25)
        # Nothing was written: the run never exited, so there is nothing to
        # resume from.
        self.assertEqual(len(sink.ids()), 0)
        self.assertEqual(controller.outstanding, 0)

    def test_a_crash_under_async_may_lose_the_last_checkpoint(self):
        sink, controller = self._crash_run(
            DurabilityMode.ASYNC, point="after_step", index=25
        )
        # The write for the step that was in flight is lost; the ones before
        # it are on disk.
        self.assertGreater(len(sink.ids()), 0)
        self.assertLess(len(sink.ids()), 52)

    def test_a_crash_under_sync_loses_no_completed_step(self):
        sink, controller = self._crash_run(
            DurabilityMode.SYNC, point="after_step", index=25
        )
        # Every step that finished has its checkpoint on disk: the input and
        # start writes, plus one per step that completed before the crash.
        landed = len(sink.ids())
        self.assertEqual(landed, 28)  # input + start + 26 completed steps
        self.assertEqual(controller.outstanding, 0)

    def test_the_crash_window_windows_narrow_from_exit_to_sync(self):
        exit_sink, _ = self._crash_run(DurabilityMode.EXIT, point="after_step", index=25)
        async_sink, _ = self._crash_run(DurabilityMode.ASYNC, point="after_step", index=25)
        sync_sink, _ = self._crash_run(DurabilityMode.SYNC, point="after_step", index=25)
        self.assertLess(len(exit_sink.ids()), len(async_sink.ids()))
        self.assertLessEqual(len(async_sink.ids()), len(sync_sink.ids()))

    def test_a_crash_before_the_first_step_loses_nothing_under_sync(self):
        sink, _ = self._crash_run(DurabilityMode.SYNC, point="before_step", index=0)
        # The input and start writes were scheduled during the early ticks
        # and landed before the first node ran.
        self.assertEqual(len(sink.ids()), 2)

    def test_a_crash_before_the_first_step_loses_the_thread_under_exit(self):
        sink, _ = self._crash_run(DurabilityMode.EXIT, point="before_step", index=0)
        # "A crash during the run leaves no record of the thread."
        self.assertEqual(len(sink.ids()), 0)

    def test_the_declared_crash_window_matches_the_measured_one(self):
        # The declared window must not promise more than the run delivers.
        window = DurabilityPolicy(mode=DurabilityMode.SYNC).crash_window()
        sink, _ = self._crash_run(DurabilityMode.SYNC, point="after_step", index=25)
        if window.preserves_completed_steps:
            self.assertGreater(len(sink.ids()), 0)

        window = DurabilityPolicy(mode=DurabilityMode.EXIT).crash_window()
        sink, _ = self._crash_run(DurabilityMode.EXIT, point="after_step", index=25)
        if window.loses_all_progress:
            self.assertEqual(len(sink.ids()), 0)

    def test_a_crash_aborts_the_writes_that_were_in_flight(self):
        sink, controller = self._crash_run(
            DurabilityMode.ASYNC, point="after_step", index=25
        )
        # No write is left dangling in the buffer after the crash.
        self.assertEqual(controller.outstanding, 0)
        for receipt in controller.receipts:
            if not receipt.settled:
                self.assertIsNotNone(receipt.error)


class NewThreadFirstCheckpointTests(unittest.TestCase):
    """How each mode admits a brand-new thread.

    The source's per-mode description of a new thread: the internal
    ``__start__`` superstep runs first and step ``0`` is the loop checkpoint
    written after it.
    """

    def test_under_exit_no_checkpoint_exists_before_the_run_ends(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.EXIT)
        controller.start({"n": 0})
        self.assertEqual(len(sink.ids()), 0)
        self.assertEqual(controller.receipts, ())

    def test_under_async_the_input_write_starts_before_the_first_user_node(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.ASYNC)
        controller.start({"n": 0})
        # The write is *scheduled* -- issued but not yet landed.
        self.assertEqual(len(controller.receipts), 2)
        self.assertEqual(controller.receipts[0].kind, "input")
        self.assertEqual(controller.receipts[0].timing, WriteTiming.BACKGROUND)
        self.assertFalse(controller.receipts[0].settled)

    def test_under_async_the_first_user_node_need_not_wait_for_the_write(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.ASYNC)
        seen: list[int] = []

        def step(index):
            seen.append(len(sink.ids()))
            return {"n": index + 1}

        controller.run([lambda index=index: step(index) for index in range(2)])
        # The first user node ran; the background write lands around it.
        self.assertEqual(seen[0], 2)

    def test_under_sync_the_input_and_step_zero_writes_are_scheduled_early(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        controller.start({"n": 0})
        kinds = [receipt.kind for receipt in controller.receipts]
        self.assertEqual(kinds, ["input", "start"])
        # Scheduled, not awaited: the source notes that admission visibility
        # at this boundary matches ``async``.
        self.assertFalse(any(receipt.awaited for receipt in controller.receipts))

    def test_the_start_checkpoint_is_step_zero(self):
        for mode in (DurabilityMode.ASYNC, DurabilityMode.SYNC):
            with self.subTest(mode=mode):
                sink = MemorySink()
                controller = DurabilityController(sink=sink, mode=mode)
                controller.start({"n": 0})
                start_receipt = [
                    receipt for receipt in controller.receipts if receipt.kind == "start"
                ]
                self.assertEqual(len(start_receipt), 1)
                self.assertEqual(start_receipt[0].step_index, 0)

    def test_a_thread_that_already_has_a_checkpoint_gets_no_new_input(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.ASYNC)
        controller.start({"n": 0})
        first = len(controller.receipts)
        resumed = DurabilityController(
            sink=sink, mode=DurabilityMode.ASYNC, new_thread=False
        )
        resumed.start({"n": 0})
        self.assertEqual(len(resumed.receipts), 0)
        self.assertGreater(first, 0)


class ReceiptTests(unittest.TestCase):
    """Every write produces a receipt, and the receipt has all its fields."""

    def test_a_receipt_carries_the_four_required_fields(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        controller.run(_steps(3), initial_state={"n": 0})
        self.assertTrue(controller.receipts)
        for receipt in controller.receipts:
            self.assertIsInstance(receipt.mode, DurabilityMode)
            self.assertIsInstance(receipt.checkpoint_id, str)
            self.assertTrue(receipt.checkpoint_id)
            self.assertIsInstance(receipt.timing, WriteTiming)
            self.assertIsInstance(receipt.settled, bool)

    def test_the_receipt_mode_matches_the_runs_mode(self):
        for mode in ALL_MODES:
            with self.subTest(mode=mode):
                sink = MemorySink()
                controller = DurabilityController(sink=sink, mode=mode)
                controller.run(_steps(3), initial_state={"n": 0})
                for receipt in controller.receipts:
                    self.assertIs(receipt.mode, mode)

    def test_a_receipt_names_the_checkpoint_it_carries(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        controller.run(_steps(3), initial_state={"n": 0})
        for receipt in controller.receipts:
            self.assertTrue(sink.exists(receipt.checkpoint_id))

    def test_a_receipt_records_whether_the_write_settled(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        controller.run(_steps(3), initial_state={"n": 0})
        for receipt in controller.receipts:
            self.assertTrue(receipt.settled)

    def test_a_background_receipt_records_that_the_run_did_not_wait(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.ASYNC)
        controller.run(_steps(3), initial_state={"n": 0})
        step_receipts = [r for r in controller.receipts if r.kind == "step"]
        self.assertTrue(step_receipts)
        for receipt in step_receipts:
            self.assertFalse(receipt.awaited)
            self.assertIs(receipt.timing, WriteTiming.BACKGROUND)

    def test_an_awaited_receipt_records_that_the_run_waited(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        controller.run(_steps(3), initial_state={"n": 0})
        step_receipts = [r for r in controller.receipts if r.kind == "step"]
        self.assertTrue(step_receipts)
        for receipt in step_receipts:
            self.assertTrue(receipt.awaited)
            self.assertIs(receipt.timing, WriteTiming.AWAITED)

    def test_a_receipt_serialises_to_a_mapping(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        controller.run(_steps(3), initial_state={"n": 0})
        payload = controller.receipts[0].as_dict()
        for field in ("mode", "checkpoint_id", "timing", "settled"):
            self.assertIn(field, payload)
        self.assertIn(payload["mode"], ("exit", "async", "sync"))
        self.assertIn(payload["timing"], ("on_exit", "background", "awaited"))

    def test_a_receipt_carries_the_thread_and_step(self):
        sink = MemorySink()
        controller = DurabilityController(
            sink=sink, mode=DurabilityMode.SYNC, thread_id="thread-42"
        )
        controller.run(_steps(3), initial_state={"n": 0})
        for receipt in controller.receipts:
            self.assertEqual(receipt.thread_id, "thread-42")
        step_receipts = [r for r in controller.receipts if r.kind == "step"]
        self.assertEqual([r.step_index for r in step_receipts], [0, 1, 2])

    def test_the_exit_receipt_records_why_the_run_ended(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.EXIT)
        controller.run(_steps(2), initial_state={"n": 0})
        exit_receipts = [r for r in controller.receipts if r.kind == "exit"]
        self.assertEqual(len(exit_receipts), 1)
        self.assertEqual(exit_receipts[0].reason, "completed")
        self.assertIs(exit_receipts[0].timing, WriteTiming.ON_EXIT)


class ErrorPathTests(unittest.TestCase):
    """A run that fails still ends with a checkpoint under ``exit``."""

    def test_a_failing_run_under_exit_writes_one_checkpoint(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.EXIT)

        def boom():
            raise RuntimeError("the step failed")

        outcome = controller.run([lambda: {"n": 1}, boom], initial_state={"n": 0})
        self.assertEqual(outcome.status, "error")
        self.assertIsInstance(outcome.error, RuntimeError)
        self.assertEqual(len(sink.ids()), 1)

    def test_the_error_receipt_records_the_failure(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.EXIT)

        def boom():
            raise RuntimeError("the step failed")

        controller.run([boom], initial_state={"n": 0})
        exit_receipts = [r for r in controller.receipts if r.kind == "exit"]
        self.assertEqual(len(exit_receipts), 1)
        self.assertEqual(exit_receipts[0].reason, "error")

    def test_a_failing_run_under_sync_settles_its_writes(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)

        def boom():
            raise RuntimeError("the step failed")

        outcome = controller.run([lambda: {"n": 1}, boom], initial_state={"n": 0})
        self.assertEqual(outcome.status, "error")
        self.assertEqual(controller.outstanding, 0)
        for receipt in controller.receipts:
            self.assertTrue(receipt.settled)

    def test_a_run_cannot_be_started_twice(self):
        controller = DurabilityController(sink=MemorySink(), mode=DurabilityMode.SYNC)
        controller.start({"n": 0})
        with self.assertRaises(DurabilityStateError):
            controller.start({"n": 0})

    def test_a_step_before_the_run_starts_is_refused(self):
        controller = DurabilityController(sink=MemorySink(), mode=DurabilityMode.SYNC)
        with self.assertRaises(DurabilityStateError):
            controller.step(0, {"n": 1})


class RealPathIntegrationTests(unittest.TestCase):
    """The policy applied to Northstar's own stores, not a mock."""

    def test_the_file_sink_writes_onto_a_real_checkpoint_store(self):
        from checkpoint_store import FileCheckpointStorage

        with tempfile.TemporaryDirectory() as directory:
            storage = FileCheckpointStorage(Path(directory) / "checkpoints")
            sink = FileSink(storage)
            controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
            outcome = controller.run(_steps(5), initial_state={"n": 0})
            self.assertEqual(outcome.checkpoint_count, 7)
            stored = storage.list_ids()
            self.assertEqual(len(stored), 7)
            # The payload is the real checkpoint payload shape.
            payload = storage.load(sorted(stored)[0])
            self.assertEqual(payload["mode"], "sync")
            self.assertIn("state", payload)
            self.assertIn("state_digest", payload)

    def test_the_file_sink_under_exit_writes_one_file(self):
        from checkpoint_store import FileCheckpointStorage

        with tempfile.TemporaryDirectory() as directory:
            storage = FileCheckpointStorage(Path(directory) / "checkpoints")
            sink = FileSink(storage)
            controller = DurabilityController(sink=sink, mode=DurabilityMode.EXIT)
            controller.run(_steps(50), initial_state={"n": 0})
            self.assertEqual(len(storage.list_ids()), 1)

    def test_the_durable_store_sink_writes_onto_the_durable_log(self):
        from durable_resume import DurableStore

        store = DurableStore()
        sink = DurableStoreSink(store, run_id="run-1")
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        outcome = controller.run(_steps(4), initial_state={"n": 0})
        # Four steps plus the input and start writes.
        self.assertEqual(outcome.checkpoint_count, 6)
        self.assertEqual(len(store.list_checkpoints("run-1")), 6)
        # The store's own ids are reported back on the receipts.
        externals = [
            receipt.external_checkpoint_id
            for receipt in controller.receipts
            if receipt.external_checkpoint_id
        ]
        self.assertEqual(len(externals), 6)

    def test_the_durable_store_sink_survives_a_verification(self):
        from durable_resume import DurableStore

        store = DurableStore()
        sink = DurableStoreSink(store, run_id="run-1")
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        controller.run(_steps(3), initial_state={"n": 0})
        for checkpoint in store.list_checkpoints("run-1"):
            self.assertTrue(store.verify(checkpoint))

    def test_the_state_digest_is_canonical(self):
        first = state_digest({"b": 2, "a": 1})
        second = state_digest({"a": 1, "b": 2})
        self.assertEqual(first, second)


class RealPathDrillTests(unittest.TestCase):
    """The three real paths, driven end to end."""

    def test_path_a_the_fifty_step_run_under_every_mode(self):
        # The source's measured path: fifty nodes, one run per mode.
        counts = {}
        for mode in ALL_MODES:
            sink = MemorySink()
            controller = DurabilityController(sink=sink, mode=mode)
            outcome = controller.run(_steps(50), initial_state={"n": 0})
            counts[mode.value] = outcome.checkpoint_count
            self.assertEqual(outcome.status, "completed")
            self.assertEqual(outcome.final_state, {"n": 50})
        self.assertEqual(counts, {"exit": 1, "async": 52, "sync": 52})

    def test_path_b_the_interrupt_and_resume_path_under_every_mode(self):
        for mode in ALL_MODES:
            with self.subTest(mode=mode):
                sink = MemorySink()
                controller = DurabilityController(sink=sink, mode=mode)
                state = {"n": 0}

                def first():
                    raise DurabilityInterrupt("approve?")

                outcome = controller.run(
                    [first, lambda: {"n": 2}], initial_state=dict(state)
                )
                self.assertEqual(outcome.status, "interrupted")
                checkpoint_id = outcome.interrupt_checkpoint_id
                self.assertTrue(sink.exists(checkpoint_id))

                # The resume finds that checkpoint and carries on.
                resumed = controller.resume(
                    [lambda: {"n": 2}],
                    from_checkpoint_id=checkpoint_id,
                    initial_state=dict(state),
                )
                self.assertEqual(resumed.status, "completed")
                self.assertEqual(resumed.final_state, {"n": 2})

    def test_path_c_the_crash_window_path_under_every_mode(self):
        measured = {}
        for mode in ALL_MODES:
            sink = MemorySink()

            def hook(point, index):
                if point == "after_step" and index == 25:
                    raise SimulatedCrash("the process died")

            controller = DurabilityController(sink=sink, mode=mode, crash_hook=hook)
            with self.assertRaises(SimulatedCrash):
                controller.run(_steps(50), initial_state={"n": 0})
            measured[mode.value] = len(sink.ids())

        # exit loses everything; async keeps the writes that had landed;
        # sync keeps every completed step.
        self.assertEqual(measured["exit"], 0)
        self.assertGreater(measured["async"], 0)
        self.assertLess(measured["async"], measured["sync"])
        self.assertEqual(measured["sync"], 28)


class PublicSurfaceTests(unittest.TestCase):
    """The rest of the public surface, covered directly."""

    def test_landed_ids_names_the_checkpoints_that_reached_the_sink(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        controller.run(_steps(3), initial_state={"n": 0})
        # input + start + one per step.
        self.assertEqual(len(controller.landed_ids), 5)
        self.assertEqual(controller.landed_ids, sink.ids())

    def test_await_pending_lands_the_outstanding_writes(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.ASYNC)
        controller.start({"n": 0})
        self.assertGreater(controller.outstanding, 0)
        receipts = controller.await_pending()
        self.assertEqual(len(receipts), controller.receipts.__len__())
        self.assertEqual(controller.outstanding, 0)
        for receipt in receipts:
            self.assertTrue(receipt.settled)

    def test_crash_at_fires_the_hook_directly(self):
        seen: list[tuple[str, int]] = []

        def hook(point, index):
            seen.append((point, index))

        controller = DurabilityController(
            sink=MemorySink(), mode=DurabilityMode.SYNC, crash_hook=hook
        )
        controller.crash_at("before_step", 3)
        self.assertEqual(seen, [("before_step", 3)])

    def test_the_durable_store_sink_reports_the_store_s_own_id(self):
        from durable_resume import DurableStore

        store = DurableStore()
        sink = DurableStoreSink(store, run_id="run-1")
        controller = DurabilityController(sink=sink, mode=DurabilityMode.SYNC)
        controller.run(_steps(2), initial_state={"n": 0})
        first = controller.receipts[0]
        self.assertIsNotNone(sink.external_id(first.checkpoint_id))
        self.assertEqual(sink.external_id(first.checkpoint_id), first.external_checkpoint_id)
        self.assertTrue(sink.exists(first.checkpoint_id))

    def test_a_receipt_is_a_dataclass_with_the_four_named_fields(self):
        receipt = DurabilityReceipt(
            mode=DurabilityMode.SYNC,
            checkpoint_id="ck-000001",
            timing=WriteTiming.AWAITED,
            settled=True,
        )
        self.assertIs(receipt.mode, DurabilityMode.SYNC)
        self.assertEqual(receipt.checkpoint_id, "ck-000001")
        self.assertIs(receipt.timing, WriteTiming.AWAITED)
        self.assertTrue(receipt.settled)

    def test_the_crash_window_dataclass_carries_its_facts(self):
        window = CrashWindow(
            mode=DurabilityMode.ASYNC,
            loses_all_progress=False,
            may_lose_last_checkpoint=True,
            preserves_completed_steps=False,
            summary="a crash may lose the last checkpoint",
        )
        self.assertIs(window.mode, DurabilityMode.ASYNC)
        self.assertTrue(window.may_lose_last_checkpoint)
        self.assertIn("last checkpoint", window.summary)

    def test_a_run_outcome_reports_its_checkpoint_count(self):
        sink = MemorySink()
        controller = DurabilityController(sink=sink, mode=DurabilityMode.EXIT)
        outcome = controller.run(_steps(2), initial_state={"n": 0})
        self.assertIsInstance(outcome, RunOutcome)
        self.assertEqual(outcome.checkpoint_count, 1)
        self.assertIsNone(outcome.receipt_for("ck-999999"))


class SecondHalfGuardTests(unittest.TestCase):
    """The second half of every guard in the durability controller.

    Seven planted faults survived this suite.  They fall into three
    shapes, and each one is a PAIR of conditions joined by ``or`` or
    ``and`` where the suite drove only one half:

    * a "the payload is a mapping" half joined to a "the key is
      present" half;
    * a "there is a stored id" half joined to a "the store still has
      it" half;
    * a "the caller gave a state" half joined to a "the builder made
      one" half.
    """

    # -- the FileSink's existence probe ---------------------------------

    def test_a_file_sink_says_a_checkpoint_that_is_there_exists(self):
        """`retF@382`: the "it IS there" half of the existence probe.

        ``exists()`` loads the checkpoint and returns False only when
        the load RAISES.  Under the mutant the successful path returns
        False -- so every checkpoint the sink actually stored is
        reported as absent, and a run that wrote five checkpoints
        believes it wrote none.
        """
        from checkpoint_store import FileCheckpointStorage

        with tempfile.TemporaryDirectory() as directory:
            storage = FileCheckpointStorage(Path(directory) / "checkpoints")
            sink = FileSink(storage)
            sink.write("ck-1", {"state": {"n": 1}})
            self.assertTrue(sink.exists("ck-1"))

    def test_a_file_sink_says_a_checkpoint_that_is_not_there_does_not_exist(self):
        """`retF@382`: the control -- the absent case."""
        from checkpoint_store import FileCheckpointStorage

        with tempfile.TemporaryDirectory() as directory:
            storage = FileCheckpointStorage(Path(directory) / "checkpoints")
            sink = FileSink(storage)
            self.assertFalse(sink.exists("ck-999"))

    # -- the durable-store sink's task path -----------------------------

    def test_the_durable_store_sink_keeps_a_declared_task_path(self):
        """`or@420`: the "the payload has a task path" half.

        The task path is read as ``payload.get("task_path", "") or ""``.
        Under the mutant (``or`` -> ``and``) the expression becomes
        ``payload.get("task_path", "") and ""``: a DECLARED task path is
        truthy, so the ``and`` yields ``""`` and the path is dropped.

        The discriminating input is a payload that DOES declare a task
        path.  The real code carries it through to the durable store;
        the mutant stores an empty one -- so the checkpoint a resume
        reads no longer says which task it interrupted.
        """
        from durable_resume import DurableStore

        store = DurableStore()
        sink = DurableStoreSink(store, run_id="run-1")
        sink.write("ck-1", {"state": {"n": 1}, "task_path": "fetch > summarise"})
        checkpoint = store.list_checkpoints("run-1")[0]
        self.assertEqual(checkpoint.task_path, "fetch > summarise")

    def test_the_durable_store_sink_keeps_an_empty_task_path_empty(self):
        """`or@420`: the other half, as the control.

        A payload with NO task path must store an empty one.
        """
        from durable_resume import DurableStore

        store = DurableStore()
        sink = DurableStoreSink(store, run_id="run-1")
        sink.write("ck-1", {"state": {"n": 1}})
        checkpoint = store.list_checkpoints("run-1")[0]
        self.assertEqual(checkpoint.task_path, "")

    def test_the_durable_store_sink_accepts_a_payload_that_is_not_a_mapping(self):
        """`or@420`: the mapping guard, as the control.

        A payload that is not a mapping at all must still be written,
        with an empty state and an empty task path.
        """
        from durable_resume import DurableStore

        store = DurableStore()
        sink = DurableStoreSink(store, run_id="run-1")
        sink.write("ck-1", "not a mapping")
        checkpoint = store.list_checkpoints("run-1")[0]
        self.assertEqual(checkpoint.task_path, "")
        self.assertEqual(dict(checkpoint.state), {})

    # -- the durable-store sink's existence probe ------------------------

    def test_the_durable_store_sink_says_a_checkpoint_that_is_there_exists(self):
        """`retF@431`: the "the store still has it" half.

        ``exists()`` returns False when the sink has no mapping for
        the id, and otherwise asks the store whether the checkpoint is
        still there.  Under the mutant (``return False`` -> ``return
        True``) the second branch is unreachable -- the sink reports
        every checkpoint it knows about as present, including the ones
        the store has since dropped.
        """
        from durable_resume import DurableStore

        store = DurableStore()
        sink = DurableStoreSink(store, run_id="run-1")
        sink.write("ck-1", {"state": {"n": 1}})
        self.assertTrue(sink.exists("ck-1"))

    def test_the_durable_store_sink_says_an_unknown_checkpoint_does_not_exist(self):
        """`retF@431`: the control -- the absent case."""
        from durable_resume import DurableStore

        store = DurableStore()
        sink = DurableStoreSink(store, run_id="run-1")
        self.assertFalse(sink.exists("ck-999"))

    # -- the controller's run id -----------------------------------------

    def test_a_controller_with_no_run_id_falls_back_to_its_thread_id(self):
        """`or@521`: the "the caller gave a run id" half.

        ``self.run_id = run_id or thread_id`` -- the caller's run id,
        or the thread id when there is none.  Under the mutant
        (``or`` -> ``and``) a controller with no run id gets a run id
        of ``None``, and every checkpoint it writes lands under no run
        at all -- a checkpoint nobody can find again is not a
        checkpoint.

        The discriminating input is a controller built with a run id
        and a DIFFERENT thread id: the real code keeps the run id.
        """
        sink = MemorySink()
        controller = DurabilityController(
            sink=sink, mode=DurabilityMode.SYNC, thread_id="thread-1"
        )
        self.assertEqual(controller.run_id, "thread-1")

        sink = MemorySink()
        controller = DurabilityController(
            sink=sink,
            mode=DurabilityMode.SYNC,
            thread_id="thread-1",
            run_id="run-9",
        )
        self.assertEqual(controller.run_id, "run-9")

    def test_a_written_checkpoint_carries_the_run_id(self):
        """`or@521`: the control -- the run id reaches the payload."""
        sink = MemorySink()
        controller = DurabilityController(
            sink=sink,
            mode=DurabilityMode.SYNC,
            thread_id="thread-1",
            run_id="run-9",
        )
        controller.run(_steps(2), initial_state={"n": 0})
        for checkpoint_id in sink.ids():
            self.assertEqual(sink.load(checkpoint_id)["run_id"], "run-9")

    # -- the interrupt and exit state -------------------------------------

    def test_an_interrupt_with_no_state_uses_the_state_builder(self):
        """`or@773`: the "the caller gave a state" half.

        ``dict(state or self._state_for(index))`` -- the caller's
        state, or the one the builder makes.  Under the mutant
        (``or`` -> ``and``) a caller that DID give a state gets
        ``{}`` instead, so the interrupt checkpoint carries no state
        and a resume that reads it finds nothing.

        The discriminating input is a caller that DID give a state.
        """
        sink = MemorySink()
        controller = DurabilityController(
            sink=sink,
            mode=DurabilityMode.SYNC,
            state_builder=lambda index: {"built": index},
        )
        controller.start({"n": 0})
        receipt = controller.interrupt(1, value="need a human", state={"asked": True})
        self.assertIsNotNone(receipt)
        payload = sink.load(receipt.checkpoint_id)
        self.assertEqual(payload["state"], {"asked": True})

    def test_an_interrupt_with_no_state_still_builds_one(self):
        """`or@773`: the other half, as the control."""
        sink = MemorySink()
        controller = DurabilityController(
            sink=sink,
            mode=DurabilityMode.SYNC,
            state_builder=lambda index: {"built": index},
        )
        controller.start({"n": 0})
        receipt = controller.interrupt(1, value="need a human")
        self.assertIsNotNone(receipt)
        payload = sink.load(receipt.checkpoint_id)
        self.assertEqual(payload["state"], {"built": 1})

    def test_the_exit_checkpoint_with_no_state_uses_the_state_builder(self):
        """`or@795`: the "the caller gave a state" half, on the exit write.

        The exit write has its own copy of the same chain, and it is
        the one checkpoint a run leaves behind under ``EXIT`` -- so a
        dropped state here loses the whole run.

        The discriminating input is a caller that DID give a state.
        """
        sink = MemorySink()
        controller = DurabilityController(
            sink=sink,
            mode=DurabilityMode.EXIT,
            state_builder=lambda index: {"built": index},
        )
        controller.start({"n": 0})
        receipt = controller.finish(reason="completed", state={"final": True})
        self.assertIsNotNone(receipt)
        payload = sink.load(receipt.checkpoint_id)
        self.assertEqual(payload["state"], {"final": True})

    def test_the_exit_checkpoint_with_no_state_still_builds_one(self):
        """`or@795`: the other half, as the control."""
        sink = MemorySink()
        controller = DurabilityController(
            sink=sink,
            mode=DurabilityMode.EXIT,
            state_builder=lambda index: {"built": index},
        )
        controller.start({"n": 0})
        receipt = controller.finish(reason="completed")
        self.assertIsNotNone(receipt)
        payload = sink.load(receipt.checkpoint_id)
        self.assertEqual(payload["state"], {"built": -1})
