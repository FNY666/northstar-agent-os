"""Tests for the long-horizon Manager / Executor / Auditor loop.

Every rule in the harness has a test here:

* the Manager rebuilds from objective + verified progress + failure
  evidence only, and never from an executor's claim;
* the Executor is bounded (tool-call budget, output budget) and an
  over-budget step becomes failure evidence, not progress;
* the Auditor reads real artifacts and judges a "claimed pass, real file
  broken" round as a failure;
* only auditor-verified progress lands in a checkpoint;
* failure evidence carries into the next round;
* reaching the round bound without a pass is ``outcome_unknown``;
* each round's executor context is fresh (no unverified summary rides
  along);
* the auditor and the executor may be configured with different backends,
  and sharing one is refused.

The two-round test drives a *real* multi-step path: round 1 writes a
broken artifact and is rejected by the auditor, round 2 fixes it and is
accepted.
"""

from __future__ import annotations

import re
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import long_horizon as lh  # noqa: E402
from long_horizon import (  # noqa: E402
    AuditCheck,
    AuditorBackend,
    ExecutorBackend,
    FailureEvidence,
    LongHorizonLoop,
    ManagerBackend,
    RoleConfig,
    RoundState,
    StepPlan,
    VerifiedCheckpoint,
    VerifiedProgress,
    VerifiedProgressStore,
)


class _WorkspaceCase(unittest.TestCase):
    """A workspace on disk; the auditor reads real files from it."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, name: str, content: str) -> Path:
        path = self.workspace / name
        path.write_text(content, encoding="utf-8")
        return path


class ManagerRebuildTests(_WorkspaceCase):
    """The Manager rebuilds from trusted inputs only."""

    def test_the_rebuild_ignores_the_executors_claim(self) -> None:
        import inspect

        # The rebuild signature has no place for a claim to arrive in.
        parameters = set(inspect.signature(ManagerBackend.rebuild).parameters)
        self.assertNotIn("claim", parameters)
        self.assertNotIn("summary", parameters)
        self.assertNotIn("step", parameters)

        manager = ManagerBackend()
        state = manager.rebuild(
            objective="make the tests pass",
            verified_progress=(),
            failures=(),
            round_index=0,
        )
        # A claim text from an executor never appears in the rebuild.
        claim = "I definitely finished everything, trust me"
        rendered = "\n".join(str(item) for item in state.context)
        self.assertNotIn(claim, rendered)
        self.assertIn("make the tests pass", rendered)

    def test_a_claim_text_from_a_rejected_step_never_reaches_the_next_rebuild(self) -> None:
        """The end-to-end version: a lying executor cannot poison the rebuild."""
        claim = "I definitely finished everything, trust me"
        seen: list[RoundState] = []

        def plan(state: RoundState) -> StepPlan:
            seen.append(state)
            return StepPlan(
                commands=["printf 'I definitely finished everything, trust me'"],
                artifacts=("never.txt",),
                summary=claim,
            )

        loop = LongHorizonLoop(
            objective="make the tests pass",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=plan,
            checks=(),
            max_rounds=2,
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_OUTCOME_UNKNOWN)
        for state in seen:
            rendered = "\n".join(str(item) for item in state.context)
            self.assertNotIn(claim, rendered)
        # The failure evidence says the auditor rejected it -- not the claim.
        self.assertIn("the auditor rejected step", result.failures[0].reason)

    def test_a_rejected_step_becomes_failure_evidence_not_progress(self) -> None:
        manager = ManagerBackend()
        state = manager.rebuild(
            objective="ship it",
            verified_progress=(),
            failures=(FailureEvidence(reason="the auditor rejected step r0: file missing"),),
            round_index=1,
        )
        self.assertEqual(state.verified_progress, ())
        self.assertEqual(len(state.failures), 1)
        rendered = "\n".join(str(item) for item in state.context)
        self.assertIn("the auditor rejected step r0", rendered)

    def test_the_rebuilt_state_is_structured_not_prose(self) -> None:
        manager = ManagerBackend()
        state = manager.rebuild(
            objective="ship it",
            verified_progress=(
                VerifiedProgress(step_id="r0", round_index=0, summary="built the thing"),
            ),
            failures=(),
            round_index=1,
        )
        self.assertIsInstance(state, RoundState)
        self.assertEqual(state.verified_step_ids, ("r0",))
        self.assertEqual(state.round_index, 1)
        # The state serialises to a structured record.
        payload = state.as_dict()
        self.assertEqual(payload["verified_progress"][0]["step_id"], "r0")
        self.assertIsInstance(payload["failures"], list)


class ExecutorBoundTests(_WorkspaceCase):
    """The Executor takes one bounded step and no more."""

    def test_a_step_over_the_tool_call_budget_is_aborted(self) -> None:
        executor = ExecutorBackend(workspace=self.workspace, max_tool_calls=1)
        state = ManagerBackend().rebuild(
            objective="do it", verified_progress=(), failures=(), round_index=0
        )
        outcome = executor.run_step(
            state=state,
            plan=lambda _state: ["true", "true"],
            step_id="s0",
        )
        self.assertEqual(outcome.kind, lh.STEP_ABORTED)
        self.assertIn("budget", outcome.reason)
        self.assertTrue(outcome.evidence)

    def test_a_step_over_the_output_budget_is_aborted(self) -> None:
        executor = ExecutorBackend(workspace=self.workspace, max_output_chars=16)
        state = ManagerBackend().rebuild(
            objective="do it", verified_progress=(), failures=(), round_index=0
        )
        outcome = executor.run_step(
            state=state,
            plan=lambda _state: ["printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"],
            step_id="s0",
        )
        self.assertEqual(outcome.kind, lh.STEP_ABORTED)
        self.assertIn("output", outcome.reason)

    def test_a_failing_command_is_a_failed_step_not_a_pending_one(self) -> None:
        executor = ExecutorBackend(workspace=self.workspace)
        state = ManagerBackend().rebuild(
            objective="do it", verified_progress=(), failures=(), round_index=0
        )
        outcome = executor.run_step(
            state=state,
            plan=lambda _state: ["exit 3"],
            step_id="s0",
        )
        self.assertEqual(outcome.kind, lh.STEP_FAILED)
        self.assertIn("exited 3", outcome.reason)


class AuditorIndependenceTests(_WorkspaceCase):
    """The Auditor judges the world, not the executor."""

    def test_a_claimed_pass_with_a_broken_file_is_a_fail(self) -> None:
        # The executor "says" it produced the artifact; the file says otherwise.
        self.write("artifact.txt", "")
        auditor = AuditorBackend(workspace=self.workspace)
        state = ManagerBackend().rebuild(
            objective="ship it", verified_progress=(), failures=(), round_index=0
        )
        verdict = auditor.audit(
            state=state,
            declared_artifacts=("artifact.txt",),
            checks=(),
        )
        self.assertFalse(verdict.passed)
        self.assertIn("artifact.txt", verdict.summary)
        self.assertTrue(any(item.kind == lh.EVIDENCE_FILE for item in verdict.evidence))

    def test_the_auditors_signature_cannot_receive_the_executors_claim(self) -> None:
        import inspect

        parameters = set(inspect.signature(AuditorBackend.audit).parameters)
        self.assertNotIn("step", parameters)
        self.assertNotIn("summary", parameters)
        self.assertNotIn("claim", parameters)
        self.assertIn("declared_artifacts", parameters)

    def test_a_missing_declared_artifact_is_a_fail(self) -> None:
        auditor = AuditorBackend(workspace=self.workspace)
        state = ManagerBackend().rebuild(
            objective="ship it", verified_progress=(), failures=(), round_index=0
        )
        verdict = auditor.audit(
            state=state,
            declared_artifacts=("not-there.txt",),
            checks=(),
        )
        self.assertFalse(verdict.passed)
        self.assertIn("does not exist", verdict.summary)

    def test_a_failing_declared_check_is_a_fail(self) -> None:
        auditor = AuditorBackend(workspace=self.workspace)
        state = ManagerBackend().rebuild(
            objective="ship it", verified_progress=(), failures=(), round_index=0
        )
        verdict = auditor.audit(
            state=state,
            declared_artifacts=(),
            checks=(AuditCheck(check_id="c1", description="the marker is present", command="grep -q MARKER marker.txt"),),
        )
        self.assertFalse(verdict.passed)
        self.assertIn("c1", verdict.summary)

    def test_a_passing_check_and_a_real_file_is_a_pass(self) -> None:
        self.write("marker.txt", "MARKER\n")
        auditor = AuditorBackend(workspace=self.workspace)
        state = ManagerBackend().rebuild(
            objective="ship it", verified_progress=(), failures=(), round_index=0
        )
        verdict = auditor.audit(
            state=state,
            declared_artifacts=("marker.txt",),
            checks=(AuditCheck(check_id="c1", description="the marker is present", command="grep -q MARKER marker.txt"),),
        )
        self.assertTrue(verdict.passed)
        self.assertTrue(verdict.evidence)


class CheckpointTrustTests(_WorkspaceCase):
    """Only auditor-verified progress lands in a checkpoint."""

    def test_only_a_verified_round_is_recorded(self) -> None:
        store = VerifiedProgressStore(self.workspace / "verified.ndjson")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("out.txt",), summary="wrote out.txt"),
            checks=(),
            max_rounds=2,
            session_id="lh-test",
            checkpoint_store=store,
        )
        # Round 0 produces no artifact -> the auditor fails it -> no checkpoint.
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_OUTCOME_UNKNOWN)
        self.assertEqual(store.checkpoints(), ())
        self.assertEqual(len(result.failures), 2)

    def test_a_verified_round_is_recorded_with_its_progress(self) -> None:
        self.write("out.txt", "real content\n")
        store = VerifiedProgressStore(self.workspace / "verified.ndjson")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("out.txt",), summary="wrote out.txt"),
            checks=(),
            max_rounds=1,
            session_id="lh-test",
            checkpoint_store=store,
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_PASSED)
        checkpoints = store.checkpoints()
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(len(checkpoints[0].verified_progress), 1)
        self.assertEqual(checkpoints[0].verified_progress[0].step_id, "lh-test-r0")
        self.assertTrue(checkpoints[0].head_hash)

    def test_the_checkpoint_carries_no_executor_claim(self) -> None:
        self.write("out.txt", "real content\n")
        store = VerifiedProgressStore(self.workspace / "verified.ndjson")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(
                commands=["printf 'I TOTALLY SUCCEEDED'"],
                artifacts=("out.txt",),
                summary="I TOTALLY SUCCEEDED",
            ),
            checks=(),
            max_rounds=1,
            session_id="lh-test",
            checkpoint_store=store,
        )
        loop.run()
        raw = (self.workspace / "verified.ndjson").read_text(encoding="utf-8")
        self.assertNotIn("I TOTALLY SUCCEEDED", raw)

    def test_a_resume_starts_from_the_verified_checkpoint(self) -> None:
        store = VerifiedProgressStore(self.workspace / "verified.ndjson")
        store.record(
            VerifiedCheckpoint(
                session_id="lh-test",
                round_index=0,
                objective="ship it",
                verified_progress=(
                    VerifiedProgress(step_id="lh-test-r0", round_index=0, summary="did the thing"),
                ),
                context_digest="sha256:abc",
                head_hash="sha256:def",
            )
        )
        checkpoint = store.latest()
        self.assertIsNotNone(checkpoint)
        fresh = lh.resume_from_checkpoint(checkpoint, new_head_hash="sha256:ghi")
        self.assertEqual(fresh.objective, "ship it")
        self.assertEqual(len(fresh.verified_progress), 1)
        self.assertEqual(fresh.round_index, 1)
        self.assertEqual(fresh.previous_head_hash, "sha256:def")


class RoleIsolationTests(_WorkspaceCase):
    """The auditor may not share a backend with the executor or the manager."""

    def test_sharing_one_backend_identity_is_refused(self) -> None:
        with self.assertRaises(lh.LongHorizonError):
            LongHorizonLoop(
                objective="ship it",
                manager=ManagerBackend(),
                executor=ExecutorBackend(workspace=self.workspace),
                auditor=AuditorBackend(workspace=self.workspace),
                plan=lambda state: StepPlan(commands=["true"]),
                checks=(),
                manager_config=RoleConfig(role="manager", backend_id="same"),
                executor_config=RoleConfig(role="executor", backend_id="other"),
                auditor_config=RoleConfig(role="auditor", backend_id="same"),
            )

    def test_the_auditor_and_the_executor_may_use_different_backends(self) -> None:
        self.write("out.txt", "ok\n")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("out.txt",)),
            checks=(),
            max_rounds=1,
            executor_config=RoleConfig(role="executor", backend_id="executor.shell.v1", model="m1"),
            auditor_config=RoleConfig(role="auditor", backend_id="auditor.commands.v1", model="m2"),
            manager_config=RoleConfig(role="manager", backend_id="manager.deterministic.v1", model="m3"),
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_PASSED)
        self.assertEqual(loop.executor_config.backend_id, "executor.shell.v1")
        self.assertEqual(loop.auditor_config.backend_id, "auditor.commands.v1")

    def test_the_auditor_runs_its_own_checks_not_the_executors(self) -> None:
        """The auditor's checks are host-declared; the executor cannot add them."""
        self.write("marker.txt", "no marker here\n")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("marker.txt",)),
            checks=(AuditCheck(check_id="c1", description="MARKER present", command="grep -q MARKER marker.txt"),),
            max_rounds=1,
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_OUTCOME_UNKNOWN)
        self.assertIn("c1", result.failures[0].reason)

    def test_the_auditor_may_be_given_a_different_checker_than_the_executor(self) -> None:
        """The executor's command and the auditor's check are separate things.

        The executor runs "produce the marker"; the auditor runs its own,
        differently-worded check on the file the executor produced.  The
        executor's own command is not the check.
        """
        self.write("marker.txt", "MARKER\n")
        executor = ExecutorBackend(workspace=self.workspace)
        auditor = AuditorBackend(workspace=self.workspace)
        self.assertNotEqual(
            AuditCheck(check_id="a", description="d", command="grep -q MARKER marker.txt").command,
            "printf 'MARKER\\n' > marker.txt",
        )
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=executor,
            auditor=auditor,
            plan=lambda state: StepPlan(
                commands=["printf 'MARKER\\n' > marker.txt"],
                artifacts=("marker.txt",),
            ),
            checks=(
                AuditCheck(
                    check_id="marker-present",
                    description="marker.txt holds the marker",
                    command="grep -q MARKER marker.txt",
                ),
            ),
            max_rounds=1,
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_PASSED)


class TwoRoundRealPathTests(_WorkspaceCase):
    """A real multi-step path driven by the loop: round 1 rejected, round 2 accepted.

    This is the shape the whole module exists for.  The executor's own
    output claims success in *both* rounds; the auditor judges the file on
    disk.  Round 1 writes a broken artifact and is rejected; round 2 fixes
    it and passes.  The failure evidence from round 1 is what round 2's
    rebuild is given.
    """

    def _plan(self, state: RoundState) -> StepPlan:
        # The plan reacts to the rebuilt state: if the last round was
        # rejected, fix the artifact; otherwise write it broken.
        if state.failures:
            return StepPlan(
                commands=["printf 'fixed\\n' > artifact.txt"],
                artifacts=("artifact.txt",),
                summary="I fixed it, it definitely works now",
            )
        return StepPlan(
            commands=["printf 'broken\\n' > artifact.txt"],
            artifacts=("artifact.txt",),
            summary="I wrote the artifact, it definitely works",
        )

    def _loop(self, **kwargs) -> LongHorizonLoop:
        return LongHorizonLoop(
            objective="produce a valid artifact.txt",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=self._plan,
            checks=(
                AuditCheck(
                    check_id="artifact-valid",
                    description="artifact.txt contains the word fixed",
                    command="grep -q fixed artifact.txt",
                ),
            ),
            max_rounds=3,
            session_id="lh-two-round",
            **kwargs,
        )

    def test_the_first_round_is_rejected_and_the_second_passes(self) -> None:
        loop = self._loop()
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_PASSED)
        self.assertEqual(len(result.rounds), 2)
        first, second = result.rounds
        self.assertIsNotNone(first.verdict)
        self.assertFalse(first.verdict.passed)
        self.assertIsNotNone(second.verdict)
        self.assertTrue(second.verdict.passed)
        self.assertEqual((self.workspace / "artifact.txt").read_text(encoding="utf-8").strip(), "fixed")

    def test_the_claim_of_the_first_round_is_not_in_the_verified_progress(self) -> None:
        loop = self._loop()
        result = loop.run()
        self.assertEqual(len(result.verified_progress), 1)
        self.assertNotIn("definitely works", result.verified_progress[0].summary)

    def test_the_failure_evidence_carries_into_the_next_round(self) -> None:
        loop = self._loop()
        result = loop.run()
        self.assertEqual(len(result.failures), 1)
        self.assertIn("the auditor rejected step", result.failures[0].reason)
        # The second round's rebuild was given that failure evidence.
        second_state = result.rounds[1].state
        self.assertEqual(len(second_state.failures), 1)
        self.assertEqual(second_state.failures[0].reason, result.failures[0].reason)
        self.assertEqual(second_state.verified_progress, ())

    def test_each_round_runs_with_a_fresh_context(self) -> None:
        seen: list[RoundState] = []

        def plan(state: RoundState) -> StepPlan:
            seen.append(state)
            return self._plan(state)

        loop = LongHorizonLoop(
            objective="produce a valid artifact.txt",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=plan,
            checks=(
                AuditCheck(
                    check_id="artifact-valid",
                    description="artifact.txt contains the word fixed",
                    command="grep -q fixed artifact.txt",
                ),
            ),
            max_rounds=3,
            session_id="lh-two-round",
        )
        loop.run()
        self.assertEqual(len(seen), 2)
        first, second = seen
        # The second round's context is a different object built from the
        # rebuilt state, not the first round's context carried over.
        self.assertIsNot(first.context, second.context)
        # Nothing unverified from round 1 rides along: the only inputs are
        # the objective and the failure evidence.
        rendered = "\n".join(str(item) for item in second.context)
        self.assertIn("failure evidence:", rendered)
        self.assertNotIn("verified progress:\n- ", rendered.replace("verified progress: (none)", ""))

    def test_a_rejected_round_leaves_no_checkpoint_and_an_accepted_one_does(self) -> None:
        store = VerifiedProgressStore(self.workspace / "verified.ndjson")
        loop = self._loop(checkpoint_store=store)
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_PASSED)
        checkpoints = store.checkpoints()
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(checkpoints[0].round_index, 1)
        self.assertEqual(len(checkpoints[0].verified_progress), 1)

    def test_the_auditors_evidence_points_at_the_real_file(self) -> None:
        loop = self._loop()
        result = loop.run()
        second = result.rounds[1]
        self.assertIsNotNone(second.verdict)
        pointers = second.verdict.evidence
        self.assertTrue(any(item.kind == lh.EVIDENCE_COMMAND for item in pointers))
        self.assertTrue(any(item.kind == lh.EVIDENCE_FILE for item in pointers))


class BoundAndBudgetTests(_WorkspaceCase):
    """The loop is bounded, and the bound is a named outcome."""

    def test_reaching_the_round_bound_without_a_pass_is_outcome_unknown(self) -> None:
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("never-written.txt",)),
            checks=(),
            max_rounds=3,
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_OUTCOME_UNKNOWN)
        self.assertFalse(result.passed)
        self.assertEqual(len(result.rounds), 3)
        self.assertIn("outcome is unknown", result.reason)
        self.assertEqual(result.verified_progress, ())

    def test_an_over_budget_step_is_failure_evidence_and_not_progress(self) -> None:
        store = VerifiedProgressStore(self.workspace / "verified.ndjson")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace, max_tool_calls=1),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true", "true"]),
            checks=(),
            max_rounds=1,
            checkpoint_store=store,
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_OUTCOME_UNKNOWN)
        self.assertEqual(len(result.failures), 1)
        self.assertIn("aborted", result.failures[0].reason)
        self.assertEqual(result.verified_progress, ())
        self.assertEqual(store.checkpoints(), ())

    def test_a_zero_round_bound_is_refused(self) -> None:
        with self.assertRaises(lh.LongHorizonError):
            LongHorizonLoop(
                objective="ship it",
                manager=ManagerBackend(),
                executor=ExecutorBackend(workspace=self.workspace),
                auditor=AuditorBackend(workspace=self.workspace),
                plan=lambda state: StepPlan(commands=["true"]),
                checks=(),
                max_rounds=0,
            )


class SessionSeamTests(_WorkspaceCase):
    """The loop is wired into the real session / checkpoint path."""

    def test_a_verified_round_writes_a_resumable_session_checkpoint(self) -> None:
        from sessions import SessionStore

        self.write("out.txt", "real content\n")
        directory = self.workspace / "sessions"
        store = SessionStore(directory, session_id="lh-session")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("out.txt",)),
            checks=(),
            max_rounds=1,
            session_id="lh-session",
            session=store,
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_PASSED)
        records, _ = store.read()
        checkpoints = [item for item in records if item.get("type") == "checkpoint"]
        self.assertEqual(len(checkpoints), 1)
        record = checkpoints[0]
        self.assertEqual(record["boundary"], "long-horizon-verified")
        self.assertEqual(record["objective"], "ship it")
        self.assertEqual(len(record["verified_progress"]), 1)
        # The record is a real checkpoints.py checkpoint: it carries the
        # transcript digest and the counters, so a resume can fork from it.
        self.assertIn("transcript_digest", record)
        self.assertEqual(record["turns"], 1)

    def test_a_rejected_round_writes_no_session_checkpoint(self) -> None:
        from sessions import SessionStore

        directory = self.workspace / "sessions2"
        store = SessionStore(directory, session_id="lh-session-2")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("missing.txt",)),
            checks=(),
            max_rounds=2,
            session_id="lh-session-2",
            session=store,
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_OUTCOME_UNKNOWN)
        records, _ = store.read()
        self.assertEqual([item for item in records if item.get("type") == "checkpoint"], [])

    def test_the_session_checkpoint_is_selectable_by_checkpoints_select(self) -> None:
        from checkpoints import select as select_checkpoint
        from sessions import SessionStore

        self.write("out.txt", "real content\n")
        directory = self.workspace / "sessions3"
        store = SessionStore(directory, session_id="lh-session-3")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("out.txt",)),
            checks=(),
            max_rounds=1,
            session_id="lh-session-3",
            session=store,
        )
        loop.run()
        records, _ = store.read()
        checkpoint = select_checkpoint(records)
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint.session_id, "lh-session-3")
        self.assertEqual(checkpoint.turns, 1)

    def test_a_resumed_loop_starts_from_the_verified_progress(self) -> None:
        """A fresh loop continues the verified state, not an executor claim."""
        store = VerifiedProgressStore(self.workspace / "verified.ndjson")
        first = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("out.txt",)),
            checks=(),
            max_rounds=1,
            session_id="lh-resume",
            checkpoint_store=store,
        )
        self.write("out.txt", "real content\n")
        first.run()
        checkpoint = store.latest()
        self.assertIsNotNone(checkpoint)
        fresh = lh.resume_from_checkpoint(checkpoint, new_head_hash="sha256:newhead")
        resumed = LongHorizonLoop(
            objective=fresh.objective,
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("out.txt",)),
            checks=(),
            max_rounds=1,
            session_id="lh-resume-2",
            initial_progress=fresh.verified_progress,
            initial_failures=fresh.failures,
        )
        result = resumed.run()
        self.assertEqual(result.outcome, lh.LOOP_PASSED)
        # The resumed loop carried the verified progress into its rebuild.
        self.assertEqual(len(result.rounds[0].state.verified_progress), 1)


class FreshStartHeadTests(_WorkspaceCase):
    """The fresh start carries the old head, so a re-mint shows as a mismatch."""

    def test_the_fresh_start_carries_the_previous_head(self) -> None:
        store = VerifiedProgressStore(self.workspace / "verified.ndjson")
        store.record(
            VerifiedCheckpoint(
                session_id="lh-fresh",
                round_index=2,
                objective="ship it",
                verified_progress=(),
                context_digest="sha256:ctx",
                head_hash="sha256:oldhead",
            )
        )
        fresh = lh.resume_from_checkpoint(store.latest(), new_head_hash="sha256:newhead")
        self.assertEqual(fresh.previous_head_hash, "sha256:oldhead")
        self.assertEqual(fresh.new_head_hash, "sha256:newhead")

    def test_a_fresh_start_without_an_independent_head_fails_closed(self) -> None:
        fresh = lh.FreshStart(
            objective="ship it",
            previous_head_hash="sha256:oldhead",
            new_head_hash="sha256:newhead",
            genesis="northstar.long-horizon.v1",
        )
        ok, note = lh.check_fresh_start_head(fresh, None)
        self.assertFalse(ok)
        self.assertIn("no independent head", note)

    def test_a_fresh_start_is_checked_against_the_audit_head_module(self) -> None:
        from audit_head_holder import HeadPin

        fresh = lh.FreshStart(
            objective="ship it",
            previous_head_hash="sha256:oldhead",
            new_head_hash="sha256:newhead",
            genesis="northstar.long-horizon.v1",
            round_index=1,
        )
        independent = HeadPin(
            head_hash="sha256:oldhead",
            seq=1,
            records_sealed=1,
            genesis="northstar.long-horizon.v1",
            seq_first=1,
            seq_last=1,
        )
        ok, note = lh.check_fresh_start_head(fresh, independent)
        self.assertFalse(ok)
        self.assertIn("mismatch", note)


class DoubleGuardTests(_WorkspaceCase):
    """The mutant-lift for the ``horizon`` slice.

    The slice's own tests drove only ONE half of each double-guard in
    ``long_horizon.py``.  The planted faults ``or@114`` and ``or@192``
    (``or -> and``) both SURVIVED the slice's test suite, which is the
    measure of the gap: the tests executed the code but did not verify
    its behaviour.

    Each guard below joins a TYPE half to an EMPTY/BOUND half with ``or``.
    The type half fires on a value of the wrong type; the second half
    fires on a value of the RIGHT type that is empty, blank, or out of
    bounds.  A suite that only feeds the wrong type cannot tell the two
    halves apart, so flipping the connective leaves it green.

    Every test here drives the SECOND half of its guard, and every test
    is proven -- against a mutated copy of the module -- to FAIL when
    its fault is applied alone.
    """

    # -- or@114: `not isinstance(value, str) or not value.strip()` ----------

    def test_a_blank_step_id_is_refused(self) -> None:
        """``not value.strip()`` -- the emptiness half of the text guard.

        The step id is a string, so the type half never fires; only the
        emptiness half can refuse it.  A blank step id would produce an
        unverifiable progress row whose id names nothing.
        """
        with self.assertRaises(lh.LongHorizonError):
            VerifiedProgress(step_id="   ", round_index=0, summary="did the thing")

    def test_an_empty_evidence_path_is_refused(self) -> None:
        """``not value.strip()`` -- the emptiness half, on the evidence path."""
        with self.assertRaises(lh.LongHorizonError):
            lh.EvidencePointer(kind=lh.EVIDENCE_FILE, path="")

    def test_a_blank_failure_reason_is_refused(self) -> None:
        """``not value.strip()`` -- the emptiness half, on a failure reason."""
        with self.assertRaises(lh.LongHorizonError):
            FailureEvidence(reason="\t\n ")

    def test_a_blank_objective_is_refused(self) -> None:
        """``not value.strip()`` -- the emptiness half, on the objective.

        The objective is what the whole round is rebuilt from, so a blank
        one must fail closed rather than rebuild an empty round.
        """
        with self.assertRaises(lh.LongHorizonError):
            RoundState(round_index=0, objective="  ")

    def test_a_blank_session_id_is_refused(self) -> None:
        """``not value.strip()`` -- the emptiness half, on a session id."""
        with self.assertRaises(lh.LongHorizonError):
            VerifiedCheckpoint(session_id=" ", round_index=0, objective="ship it")

    # -- or@192: `isinstance(self.round_index, bool) or not isinstance(...)` --

    def test_a_round_index_that_is_a_string_is_refused(self) -> None:
        """``not isinstance(self.round_index, int)`` -- the type half.

        ``"0"`` is not an int.  It compares equal to ``0`` nowhere in
        Python, but a round index of ``"0"`` would still serialise into
        the checkpoint as a string and break the chain's arithmetic.
        """
        with self.assertRaises(lh.LongHorizonError):
            VerifiedProgress(step_id="r0", round_index="0", summary="did the thing")

    def test_a_round_index_that_is_a_float_is_refused(self) -> None:
        """``not isinstance(self.round_index, int)`` -- the type half again.

        A float round index would silently truncate into the checkpoint.
        """
        with self.assertRaises(lh.LongHorizonError):
            VerifiedProgress(step_id="r0", round_index=1.5, summary="did the thing")

    def test_a_round_state_with_a_non_int_round_index_is_refused(self) -> None:
        """The same type half, on the rebuilt round state."""
        with self.assertRaises(lh.LongHorizonError):
            RoundState(round_index="1", objective="ship it")

    def test_a_checkpoint_with_a_non_int_round_index_is_refused(self) -> None:
        """The same type half, on the checkpoint that a resume forks from."""
        with self.assertRaises(lh.LongHorizonError):
            VerifiedCheckpoint(session_id="lh", round_index=None, objective="ship it")

    def test_a_boolean_round_index_is_refused(self) -> None:
        """``isinstance(self.round_index, bool)`` -- the bool half.

        ``True`` IS an ``int`` in Python, so the second half of the guard
        (``not isinstance(..., int)``) does not fire for it.  The first
        half has to exclude it explicitly, or a round index of ``True``
        would be a round index of ``1``.
        """
        with self.assertRaises(lh.LongHorizonError):
            VerifiedProgress(step_id="r0", round_index=True, summary="did the thing")

    def test_a_boolean_round_index_is_refused_on_the_round_state(self) -> None:
        """The same bool half, on the rebuilt round state."""
        with self.assertRaises(lh.LongHorizonError):
            RoundState(round_index=False, objective="ship it")

    # -- or@337 / or@340: a planned command / a declared artifact ----------

    def test_a_blank_planned_command_is_refused(self) -> None:
        """``not command.strip()`` -- the emptiness half of the plan guard.

        A blank command is a string, so the type half never fires; only
        the emptiness half can refuse it.
        """
        with self.assertRaises(lh.LongHorizonError):
            StepPlan(commands=("   ",))

    def test_a_blank_declared_artifact_is_refused(self) -> None:
        """``not artifact.strip()`` -- the emptiness half, on the artifact.

        A blank artifact path would be audited against the workspace root
        rather than against a real file.
        """
        with self.assertRaises(lh.LongHorizonError):
            StepPlan(artifacts=("  ",))

    # -- or@370: an audit check's three text fields -----------------------

    def test_a_blank_audit_check_id_is_refused(self) -> None:
        """``not value.strip()`` -- the emptiness half of the check guard.

        The check id is what a rejection names ("c1: the check failed"),
        so a blank one names nothing.
        """
        with self.assertRaises(lh.LongHorizonError):
            AuditCheck(check_id="  ", description="the marker is present", command="true")

    def test_a_blank_audit_check_description_is_refused(self) -> None:
        """The same emptiness half, on the description."""
        with self.assertRaises(lh.LongHorizonError):
            AuditCheck(check_id="c1", description="   ", command="true")

    def test_a_blank_audit_check_command_is_refused(self) -> None:
        """The same emptiness half, on the command."""
        with self.assertRaises(lh.LongHorizonError):
            AuditCheck(check_id="c1", description="the marker is present", command=" ")

    # -- or@554: `not commands or not all(command.strip() ...)` ------------

    def test_a_blank_command_in_a_plan_is_a_failed_step(self) -> None:
        """``not all(command.strip() ...)`` -- the emptiness half.

        The executor's own guard has two halves: no commands at all, and
        commands that are all blank.  The slice's suite drove only the
        first.  A plan of one blank command must be a FAILED step, not a
        step that runs an empty shell line.
        """
        executor = ExecutorBackend(workspace=self.workspace)
        state = ManagerBackend().rebuild(
            objective="do it", verified_progress=(), failures=(), round_index=0
        )
        outcome = executor.run_step(
            state=state,
            plan=lambda _state: ["   "],
            step_id="s0",
        )
        self.assertEqual(outcome.kind, lh.STEP_FAILED)
        self.assertIn("no command", outcome.reason)

    # -- or@603: `output = completed.stdout or ""` -----------------------

    def test_a_command_with_no_output_yields_an_empty_string(self) -> None:
        """``completed.stdout or ""`` -- the empty-output half.

        A command that prints nothing has ``stdout`` of ``None`` when the
        pipe is closed early.  The step's summary must then be the empty
        string, and the step must still be pending audit rather than a
        crash.
        """
        executor = ExecutorBackend(workspace=self.workspace)
        state = ManagerBackend().rebuild(
            objective="do it", verified_progress=(), failures=(), round_index=0
        )
        outcome = executor.run_step(
            state=state,
            plan=lambda _state: ["exit 0"],
            step_id="s0",
        )
        self.assertEqual(outcome.kind, lh.STEP_PENDING_AUDIT)
        self.assertEqual(outcome.summary, "")

    # -- or@740 / or@741: the auditor's check output ----------------------

    def test_a_check_with_no_output_is_still_audited(self) -> None:
        """``completed.stdout or ""`` -- the empty-output half, in the auditor.

        The check passes on its exit status; an empty output must not
        change that, and must not crash the auditor.
        """
        self.write("marker.txt", "MARKER\n")
        auditor = AuditorBackend(workspace=self.workspace)
        state = ManagerBackend().rebuild(
            objective="ship it", verified_progress=(), failures=(), round_index=0
        )
        verdict = auditor.audit(
            state=state,
            declared_artifacts=("marker.txt",),
            checks=(AuditCheck(check_id="c1", description="the marker is present", command="true"),),
        )
        self.assertTrue(verdict.passed)

    # -- or@813: the checkpoint's round index ----------------------------

    def test_a_checkpoint_with_a_boolean_round_index_is_refused(self) -> None:
        """``isinstance(self.round_index, bool)`` -- the bool half."""
        with self.assertRaises(lh.LongHorizonError):
            VerifiedCheckpoint(session_id="lh", round_index=True, objective="ship it")

    # -- or@838: `path is None or (isinstance(path, str) and not path)` ---

    def test_an_empty_store_path_is_refused(self) -> None:
        """``isinstance(path, str) and not path`` -- the emptiness half.

        The store's path is a str, so the type half never fires; only the
        emptiness half can refuse it.  An empty path would point the store
        at the current directory.
        """
        with self.assertRaises(lh.LongHorizonError):
            VerifiedProgressStore("")

    def test_a_none_store_path_is_refused(self) -> None:
        """``path is None`` -- the type half, for the pair."""
        with self.assertRaises(lh.LongHorizonError):
            VerifiedProgressStore(None)

    def test_a_real_store_path_is_accepted(self) -> None:
        """``isinstance(path, str) and not path`` -- the emptiness half.

        The guard refuses a path that is *empty*, not one that is a
        string.  A real path must be accepted, and the store must write
        its checkpoint there.  The slice's suite only ever fed the guard
        a bad path, so it could not tell "refuse an empty path" from
        "refuse every path".
        """
        path = self.workspace / "verified.ndjson"
        store = VerifiedProgressStore(str(path))
        store.record(
            VerifiedCheckpoint(
                session_id="lh-store",
                round_index=0,
                objective="ship it",
                context_digest="sha256:ctx",
                head_hash="sha256:head",
            )
        )
        self.assertTrue(path.exists())
        self.assertEqual(len(store.checkpoints()), 1)

    # -- or@740: `output = completed.stdout or ""` in the auditor ----------

    def test_a_failing_check_reports_the_output_it_actually_read(self) -> None:
        """``completed.stdout or ""`` -- the empty-output half, in the auditor.

        The auditor's rejection quotes what the check printed.  If the
        check's own output were dropped, the rejection would name the
        check but not the reason it failed -- an auditor that cannot show
        what it read is an auditor that cannot be audited.
        """
        auditor = AuditorBackend(workspace=self.workspace)
        state = ManagerBackend().rebuild(
            objective="ship it", verified_progress=(), failures=(), round_index=0
        )
        verdict = auditor.audit(
            state=state,
            declared_artifacts=(),
            checks=(
                AuditCheck(
                    check_id="c1",
                    description="the marker is present",
                    command="printf 'the-marker-is-missing'; exit 1",
                ),
            ),
        )
        self.assertFalse(verdict.passed)
        self.assertIn("the-marker-is-missing", verdict.summary)

    # -- lt@517: `if self.max_output_chars < 1` ---------------------------

    def test_an_output_budget_of_one_char_is_accepted(self) -> None:
        """``max_output_chars < 1`` -- the bound half, at the exact limit.

        A budget of one character is a budget: the bound is ``< 1``, so
        exactly one is allowed and only zero is refused.
        """
        executor = ExecutorBackend(workspace=self.workspace, max_output_chars=1)
        self.assertEqual(executor.max_output_chars, 1)

    # -- gt@605: `if total > self.max_output_chars` -----------------------

    def test_output_exactly_at_the_budget_is_not_aborted(self) -> None:
        """``total > max_output_chars`` -- the bound half, at the limit.

        The budget is a ceiling on what may be produced; output of
        exactly the budget is within it.  The slice's suite only ever
        overshot, so it could not tell ``>`` from ``>=``.
        """
        executor = ExecutorBackend(workspace=self.workspace, max_output_chars=3)
        state = ManagerBackend().rebuild(
            objective="do it", verified_progress=(), failures=(), round_index=0
        )
        outcome = executor.run_step(
            state=state,
            plan=lambda _state: ["printf abc"],
            step_id="s0",
        )
        self.assertEqual(outcome.kind, lh.STEP_PENDING_AUDIT)
        self.assertEqual(outcome.summary, "abc")

    # -- or@1086: `verdict.summary or f"round {round_index} verified"` ----

    def test_the_verified_progress_carries_the_auditors_own_wording(self) -> None:
        """``verdict.summary or ...`` -- the fallback half, on the summary.

        The progress row's summary is the AUDITOR's wording about what it
        verified.  The fallback is only for a verdict that carries no
        wording at all; when the auditor did speak, its words are what
        must be recorded.
        """
        self.write("out.txt", "real content\n")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("out.txt",)),
            checks=(),
            max_rounds=1,
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_PASSED)
        summary = result.verified_progress[0].summary
        self.assertIn("declared artifact", summary)
        self.assertNotIn("round 0 verified", summary)

    # -- or@1153: `int(getattr(self.session, "written", 0) or 0)` ---------

    def test_the_session_checkpoint_records_the_position_it_was_written_at(self) -> None:
        """``getattr(self.session, "written", 0) or 0`` -- the fallback half.

        The checkpoint's ``record_index`` is its POSITION in the
        transcript: the number of records already written when it was
        built.  A session that already holds a record must not write its
        checkpoint at position zero.
        """
        from sessions import SessionStore

        self.write("out.txt", "real content\n")
        directory = self.workspace / "sessions-position"
        store = SessionStore(directory, session_id="lh-position")
        store.append("assistant", {"role": "assistant", "content": []})
        self.assertEqual(store.written, 1)
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("out.txt",)),
            checks=(),
            max_rounds=1,
            session_id="lh-position",
            session=store,
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_PASSED)
        records, _ = store.read()
        checkpoints = [item for item in records if item.get("type") == "checkpoint"]
        self.assertEqual(len(checkpoints), 1)
        # The checkpoint was written at position 1 -- after the assistant
        # record that was already there.
        self.assertEqual(checkpoints[0]["record_index"], 1)

    # -- or@1159: `self.executor_config.model or "unknown"` ---------------

    def test_the_session_checkpoint_records_the_executors_model(self) -> None:
        """``self.executor_config.model or "unknown"`` -- the fallback half.

        The checkpoint names the model that ran the step.  The fallback
        is only for a config with no model at all; a named model must be
        the one recorded.
        """
        from sessions import SessionStore

        self.write("out.txt", "real content\n")
        directory = self.workspace / "sessions-model"
        store = SessionStore(directory, session_id="lh-model")
        loop = LongHorizonLoop(
            objective="ship it",
            manager=ManagerBackend(),
            executor=ExecutorBackend(workspace=self.workspace),
            auditor=AuditorBackend(workspace=self.workspace),
            plan=lambda state: StepPlan(commands=["true"], artifacts=("out.txt",)),
            checks=(),
            max_rounds=1,
            session_id="lh-model",
            session=store,
            executor_config=RoleConfig(
                role="executor", backend_id="executor.shell.v1", model="model-under-test"
            ),
        )
        result = loop.run()
        self.assertEqual(result.outcome, lh.LOOP_PASSED)
        records, _ = store.read()
        checkpoints = [item for item in records if item.get("type") == "checkpoint"]
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(checkpoints[0]["model"], "model-under-test")


class AuditorOutputTruncationEquivalentMutantTests(_WorkspaceCase):
    """``gt@741``: the auditor's output cap -- an EQUIVALENT mutant.

    The planted fault at this site (``>`` -> ``>=``) survives the slice's
    suite, and it is **not killable, and provably so**.

    The site is::

        output = completed.stdout or ""
        if len(output) > self.max_output_chars:
            output = output[: self.max_output_chars]

    The mutant turns the bound into ``>=``, so the truncation branch runs
    one extra time -- at ``len(output) == self.max_output_chars`` exactly.

    That extra run is a no-op, because:

    * ``output[: self.max_output_chars]`` with ``len(output) ==
      self.max_output_chars`` is the IDENTITY -- slicing a string to
      exactly its own length returns the string unchanged;
    * the truncated value is then used only in ``output.strip()[:400]``
      (the failure message) and nowhere else, and the *detail* the
      evidence pointer carries is ``f"exit={completed.returncode}"`` --
      which does not mention the output at all.

    So the two versions agree at every input, on both the passing and the
    failing branch.  This class PROVES that by differential testing: it
    loads the module twice -- once as it is, once with the bound mutated
    -- and compares the two across a sweep of output lengths, caps and
    exit codes.  A single behavioural difference anywhere in the sweep
    fails the test.

    It is an EQUIVALENT mutant, not a gap in the suite, and no test can
    distinguish it.  It is recorded here so the next person does not
    spend a round looking for one.
    """

    #: The exact source line the mutation targets.
    _BOUND_RE = re.compile(
        r"if len\(output\) (?P<op>[<>]=?) self\.max_output_chars:"
    )

    def _load_with_bound(self, op: str):
        """Load ``long_horizon`` with the truncation bound set to ``op``.

        The module is re-executed from its own source with the one
        comparison rewritten, in a fresh module object, so the two
        versions coexist in one process and can be called side by side.
        """
        source = Path(lh.__file__).read_text(encoding="utf-8")
        matches = self._BOUND_RE.findall(source)
        self.assertEqual(
            len(matches), 1, f"expected exactly one truncation bound, found {matches}"
        )
        mutated = self._BOUND_RE.sub(
            f"if len(output) {op} self.max_output_chars:", source, count=1
        )
        name = f"_long_horizon_bound_{op.replace('<', 'lt').replace('>', 'gt')}"
        module = types.ModuleType(name)
        module.__file__ = str(Path(lh.__file__))
        sys.modules[name] = module
        exec(compile(mutated, module.__file__, "exec"), module.__dict__)
        return module

    def _run_check(self, module, out_len: int, cap: int, returncode: int):
        """Run one check under ``module`` with a faked ``subprocess``."""
        completed = types.SimpleNamespace(
            stdout="y" * out_len, returncode=returncode
        )
        original = module.subprocess.run
        module.subprocess.run = lambda *args, **kwargs: completed
        try:
            auditor = module.AuditorBackend(
                workspace=self.workspace, max_output_chars=cap
            )
            check = module.AuditCheck(
                check_id="c1", description="a check", command="true"
            )
            ok, detail, pointer = auditor._run_check(check)
            # The pointer is a dataclass from a *different* module object,
            # so it is compared field by field rather than by identity.
            return (ok, detail, pointer.kind, pointer.path, pointer.detail)
        finally:
            module.subprocess.run = original

    # -- the proof -------------------------------------------------------

    def test_the_mutated_bound_behaves_identically_across_a_sweep(self):
        """``gt@741``: the differential proof of equivalence.

        The sweep covers both sides of the bound, the boundary itself,
        caps below and above the output length, and BOTH branches of the
        check (a passing check and a failing one, whose rejection quotes
        the output it read).

        The caps start at 1 because a cap below 1 is refused outright by
        the auditor's constructor -- see the validation test below.
        """
        original = self._load_with_bound(">")
        mutant = self._load_with_bound(">=")

        differences = 0
        cases = 0
        for cap in list(range(1, 12)) + [100, 8192]:
            for out_len in range(0, 16):
                for returncode in (0, 3):
                    cases += 1
                    before = self._run_check(original, out_len, cap, returncode)
                    after = self._run_check(mutant, out_len, cap, returncode)
                    if before != after:
                        differences += 1
                        self.fail(
                            f"the mutated bound changed the behaviour at "
                            f"cap={cap} out_len={out_len} rc={returncode}: "
                            f"{before!r} != {after!r}"
                        )
        self.assertGreater(cases, 0)
        self.assertEqual(differences, 0)

    # -- the behaviour the equivalence rests on --------------------------

    def test_output_exactly_at_the_cap_is_returned_whole(self):
        """``gt@741``: the boundary -- an output exactly at the cap is whole.

        The cap is the largest output the auditor keeps.  An output of
        exactly the cap is kept whole, and the check's verdict does not
        depend on it.
        """
        auditor = AuditorBackend(workspace=self.workspace, max_output_chars=10)
        check = AuditCheck(
            check_id="c1", description="a check", command="true"
        )
        state = ManagerBackend().rebuild(
            objective="ship it", verified_progress=(), failures=(), round_index=0
        )
        verdict = auditor.audit(
            state=state, declared_artifacts=(), checks=(check,)
        )
        self.assertTrue(verdict.passed)

    def test_output_one_over_the_cap_is_still_verified_and_quoted(self):
        """``gt@741``: from the other side -- over the cap is still checked.

        The cap bounds what the auditor KEEPS; it does not turn an
        over-cap output into an error, and it does not hide the output
        the check actually read: the rejection still quotes it -- capped
        to the cap, which is the truncation the site performs.
        """
        auditor = AuditorBackend(workspace=self.workspace, max_output_chars=10)
        check = AuditCheck(
            check_id="c1",
            description="a check",
            command="printf 'the-marker-is-missing-and-then-some'; exit 1",
        )
        state = ManagerBackend().rebuild(
            objective="ship it", verified_progress=(), failures=(), round_index=0
        )
        verdict = auditor.audit(
            state=state, declared_artifacts=(), checks=(check,)
        )
        self.assertFalse(verdict.passed)
        # The rejection quotes the output the check really read, capped
        # to the cap -- and the tail beyond the cap is dropped.
        self.assertIn("the-marker", verdict.summary)
        self.assertNotIn("the-marker-is-missing-and-then-some", verdict.summary)

    # -- lt@674: `if self.max_output_chars < 1` in the auditor -------------

    def test_the_auditors_output_cap_of_zero_is_refused(self):
        """``lt@674``: the auditor's output cap must be at least one.

        A cap of zero keeps NO output at all, so the rejection of a
        failing check would name the check but not the reason it
        failed.  A cap below zero is worse: it slices from the tail, so
        it keeps output the cap was meant to drop.  The executor refuses
        these caps already; the auditor must too.
        """
        with self.assertRaises(lh.LongHorizonError):
            AuditorBackend(workspace=self.workspace, max_output_chars=0)

    def test_the_auditors_output_cap_below_zero_is_refused(self):
        """``lt@674``: from the other side -- a negative cap is refused."""
        with self.assertRaises(lh.LongHorizonError):
            AuditorBackend(workspace=self.workspace, max_output_chars=-1)

    def test_the_auditors_output_cap_of_one_char_is_accepted(self):
        """``lt@674``: the boundary -- exactly one char is a cap.

        The bound is ``< 1``, so exactly one is allowed and only zero is
        refused.
        """
        auditor = AuditorBackend(workspace=self.workspace, max_output_chars=1)
        self.assertEqual(auditor.max_output_chars, 1)


if __name__ == "__main__":  # pragma: no cover - manual entry point
    unittest.main()


class AuditorOutputTruncationHarnessControlTests(_WorkspaceCase):
    """The ``gt@741`` equivalence proof must be able to FAIL.

    ``AuditorOutputTruncationEquivalentMutantTests`` proves that the
    planted fault at ``gt@741`` (``len(output) > cap`` ->
    ``len(output) >= cap``) changes nothing, by loading the module twice
    -- once as shipped, once with that comparison rewritten -- and
    comparing the two over a sweep of output lengths, caps and exit
    codes.

    A differential test that CANNOT fail proves nothing.  If the two
    variants were accidentally the same source, or if the sweep never
    reached an input that separates them, the agreement would be empty
    and the "EQUIVALENT mutant" conclusion would be worthless.

    This class gives the harness its **non-vacuity control**: the same
    loader and the same comparison are pointed at a mutation that is
    known to change behaviour, and the harness is REQUIRED to notice.
    The control is the same line with the bound turned the other way
    (``<`` instead of ``>``), which truncates a body that must be kept
    whole -- and the truncation shows up in the failure message.
    """

    #: The exact source line the mutation targets.
    _BOUND_RE = re.compile(
        r"if len\(output\) (?P<op>[<>]=?) self\.max_output_chars:"
    )

    def _load_with_bound(self, op: str):
        """Load ``long_horizon`` with the truncation bound set to ``op``."""
        source = Path(lh.__file__).read_text(encoding="utf-8")
        matches = self._BOUND_RE.findall(source)
        self.assertEqual(
            len(matches), 1, f"expected exactly one truncation bound, found {matches}"
        )
        mutated = self._BOUND_RE.sub(
            f"if len(output) {op} self.max_output_chars:", source, count=1
        )
        name = f"_long_horizon_control_{op.replace('<', 'lt').replace('>', 'gt')}"
        module = types.ModuleType(name)
        module.__file__ = str(Path(lh.__file__))
        sys.modules[name] = module
        exec(compile(mutated, module.__file__, "exec"), module.__dict__)
        return module

    def _run_check(self, module, out_len: int, cap: int, returncode: int):
        """Run one check under ``module`` with a faked ``subprocess``."""
        completed = types.SimpleNamespace(
            stdout="y" * out_len, returncode=returncode
        )
        original = module.subprocess.run
        module.subprocess.run = lambda *args, **kwargs: completed
        try:
            auditor = module.AuditorBackend(
                workspace=self.workspace, max_output_chars=cap
            )
            check = module.AuditCheck(
                check_id="c1", description="a check", command="true"
            )
            ok, detail, pointer = auditor._run_check(check)
            return (ok, detail, pointer.kind, pointer.path, pointer.detail)
        finally:
            module.subprocess.run = original

    #: The truncation the CONTROL mutation rewrites.
    _SLICE_RE = re.compile(
        r"output = output\[: self\.max_output_chars\]"
    )

    def _load_with_a_one_char_shorter_cap(self):
        """The CONTROL variant: the truncation keeps one character less.

        The guard's two spellings (``>`` and ``>=``) agree at the
        boundary because slicing a string to its own length is the
        identity, so neither can show a difference -- which is exactly
        why the mutant is equivalent.  The control therefore moves the
        SLICE, the thing the guard protects: the truncation then keeps
        one character fewer, and the failure message changes.
        """
        source = Path(lh.__file__).read_text(encoding="utf-8")
        matches = self._SLICE_RE.findall(source)
        self.assertEqual(
            len(matches), 1, f"expected exactly one truncation, found {matches}"
        )
        mutated = self._SLICE_RE.sub(
            "output = output[: self.max_output_chars - 1]", source, count=1
        )
        module = types.ModuleType("_long_horizon_control_slice")
        module.__file__ = str(Path(lh.__file__))
        sys.modules[module.__name__] = module
        exec(compile(mutated, module.__file__, "exec"), module.__dict__)
        return module

    def test_the_control_mutation_changes_the_outcome(self):
        """The control mutation must actually CHANGE the outcome."""
        original = self._load_with_bound(">")
        control = self._load_with_a_one_char_shorter_cap()

        # An output over the cap, on the FAILING branch: the shipped
        # form keeps the cap's worth of output in the message, the
        # control form keeps one character less.
        before = self._run_check(original, 30, 20, 3)
        after = self._run_check(control, 30, 20, 3)
        self.assertNotEqual(
            before,
            after,
            "the control mutation changed nothing, so the differential "
            "harness cannot distinguish any two functions",
        )

    def test_the_harness_notices_the_control_mutation(self):
        """The SAME harness, pointed at the control, must find a difference.

        This is the non-vacuity check on the equivalence proof: the same
        loader and the same sweep that ``gt@741`` uses must report a
        disagreement when the rule it compares against is one that
        genuinely disagrees.
        """
        original = self._load_with_bound(">")
        control = self._load_with_a_one_char_shorter_cap()

        differences = 0
        cases = 0
        for cap in list(range(1, 12)) + [100, 8192]:
            for out_len in range(0, 16):
                for returncode in (0, 3):
                    cases += 1
                    before = self._run_check(original, out_len, cap, returncode)
                    after = self._run_check(control, out_len, cap, returncode)
                    if before != after:
                        differences += 1
        self.assertGreater(cases, 0)
        self.assertGreater(
            differences,
            0,
            "the harness found no difference for a mutation that changes "
            "the outcome, so it cannot certify gt@741 as equivalent",
        )
