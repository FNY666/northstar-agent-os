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

import sys
import tempfile
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


if __name__ == "__main__":  # pragma: no cover - manual entry point
    unittest.main()
