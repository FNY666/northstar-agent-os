"""Tests for ``revision_checked_tool_results``.

Three real paths are driven end to end, not just isolated assertions:

* **(a) the normal write-back** -- a result read at revision 41 is
  committed while the state is at revision 41; state updates and a new
  revision is allocated.
* **(b) the late overwrite** -- a result read at revision 41 is rejected
  once the state has moved to revision 42; state is untouched, the old
  result is retained verbatim as evidence, and reconciliation records the
  tool call id, both revisions, and the applicability verdict.
* **(c) the interleaving** -- two commits race; the second is rejected
  after the first has advanced the revision, rather than both succeeding
  or the later one silently overwriting the earlier one.

Source: Moltbook ``neo_konsi_s2bw``, "the last tool to finish has no
right to own agent state" (post 87f799a1-245a-4d13-9fcc-5cd7cca53e31).
"""

from __future__ import annotations

import threading
import unittest

from revision_checked_tool_results import (
    CommitOutcome,
    EvidenceSlot,
    InvalidRevisionError,
    InvalidToolCallIdError,
    MissingReadRevisionError,
    Reconciliation,
    RevisionCheckedResult,
    RevisionCheckedToolResults,
    RevisionCheckedToolResultsError,
)


class ResultConstructionTests(unittest.TestCase):
    """A result must name the revision it read, or it is refused."""

    def test_missing_read_revision_is_refused_fail_closed(self):
        """read_revision is required -- there is no default to fall back on."""
        with self.assertRaises(TypeError):
            RevisionCheckedResult(tool_call_id="call-a", payload={"x": 1})
        with self.assertRaises(TypeError):
            RevisionCheckedResult(payload={"x": 1})

    def test_empty_read_revision_is_refused_fail_closed(self):
        """None is not a revision; a result without one cannot write back."""
        with self.assertRaises(MissingReadRevisionError):
            RevisionCheckedResult(
                tool_call_id="call-a", read_revision=None, payload={"x": 1}
            )

    def test_non_integer_read_revision_is_refused(self):
        """Revisions are integer seqs, not wall clocks and not strings."""
        for bad in ("41", 41.0, True):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidRevisionError):
                    RevisionCheckedResult(
                        tool_call_id="call-a", read_revision=bad
                    )

    def test_negative_read_revision_is_refused(self):
        """A negative revision is not a state revision."""
        with self.assertRaises(InvalidRevisionError):
            RevisionCheckedResult(tool_call_id="call-a", read_revision=-1)

    def test_empty_tool_call_id_is_refused(self):
        """An unnamable result cannot be reconciled or evidenced."""
        with self.assertRaises(InvalidToolCallIdError):
            RevisionCheckedResult(tool_call_id="", read_revision=41)

    def test_result_carries_read_revision_and_payload_verbatim(self):
        """The result holds exactly what the caller gave it."""
        payload = {"rows": [1, 2, 3], "note": "verbatim"}
        result = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload=payload
        )
        self.assertEqual(result.tool_call_id, "call-a")
        self.assertEqual(result.read_revision, 41)
        self.assertIs(result.payload, payload)
        self.assertIsNone(result.result_revision)

    def test_result_as_dict_carries_the_schema_pin(self):
        """The JSON-safe record names the schema and both revisions."""
        result = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={"x": 1}
        )
        record = result.as_dict()
        self.assertEqual(record["schema"], "northstar.revision-checked-tool-results.v1")
        self.assertEqual(record["tool_call_id"], "call-a")
        self.assertEqual(record["read_revision"], 41)
        self.assertIsNone(record["result_revision"])

    def test_with_result_revision_returns_a_copy_and_leaves_the_original(self):
        """Assigning a revision does not mutate the result that was read."""
        result = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={"x": 1}
        )
        assigned = result.with_result_revision(42)
        self.assertEqual(assigned.result_revision, 42)
        self.assertEqual(assigned.read_revision, 41)
        self.assertIs(assigned.payload, result.payload)
        # The original is untouched.
        self.assertIsNone(result.result_revision)

    def test_with_result_revision_validates_its_argument(self):
        """A revision is an integer; nothing else is accepted."""
        result = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={}
        )
        with self.assertRaises(InvalidRevisionError):
            result.with_result_revision("42")
        with self.assertRaises(InvalidRevisionError):
            result.with_result_revision(-1)


class CommitPathTests(unittest.TestCase):
    """Path (a): the result matches the current revision."""

    def test_matching_revision_commits_updates_state_and_allocates_revision(self):
        """The whole normal path, driven end to end."""
        ledger = RevisionCheckedToolResults(current_revision=41)
        state = {"goal": "old"}
        result = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={"goal": "new"}
        )

        outcome = ledger.commit(
            result, 41, lambda res: state.update(goal=res.payload["goal"])
        )

        self.assertTrue(outcome.committed)
        self.assertFalse(outcome.rejected)
        self.assertEqual(outcome.tool_call_id, "call-a")
        self.assertEqual(outcome.read_revision, 41)
        self.assertEqual(outcome.result_revision, 42)
        self.assertEqual(outcome.reason, "committed")
        # The state was actually updated, not merely recorded as updated.
        self.assertEqual(state, {"goal": "new"})
        # The ledger advanced to the newly allocated revision.
        self.assertEqual(ledger.current_revision, 42)
        # Nothing was retained as evidence on a clean commit.
        self.assertEqual(len(ledger.evidence_slot), 0)


class StaleResultPathTests(unittest.TestCase):
    """Path (b): the result was read at an older revision than the state."""

    def _stale_ledger(self):
        """A ledger already at revision 42, with a result read at 41."""
        ledger = RevisionCheckedToolResults(current_revision=42)
        state = {"goal": "user's newer goal"}
        stale = RevisionCheckedResult(
            tool_call_id="call-late",
            read_revision=41,
            payload={"goal": "yesterday's goal"},
        )
        return ledger, state, stale

    def test_mismatched_revision_is_rejected_and_state_is_untouched(self):
        """A result read at 41 must not overwrite a state at 42."""
        ledger, state, stale = self._stale_ledger()

        outcome = ledger.commit(
            stale, 42, lambda res: state.update(goal=res.payload["goal"])
        )

        self.assertTrue(outcome.rejected)
        self.assertFalse(outcome.committed)
        self.assertEqual(outcome.reason, "revision_mismatch")
        # The state still holds the newer goal -- the old result never landed.
        self.assertEqual(state, {"goal": "user's newer goal"})
        # No revision was allocated for a rejected commit.
        self.assertIsNone(outcome.result_revision)
        self.assertEqual(ledger.current_revision, 42)

    def test_apply_is_not_even_called_on_a_rejected_commit(self):
        """The write must not run at all, not run and then be undone."""
        ledger, state, stale = self._stale_ledger()
        calls = []

        def apply(res):
            calls.append(res)
            state.update(goal=res.payload["goal"])

        ledger.commit(stale, 42, apply)
        self.assertEqual(calls, [])
        self.assertEqual(state, {"goal": "user's newer goal"})

    def test_rejected_result_is_retained_verbatim_as_evidence(self):
        """The old result is kept, byte for byte, and not discarded."""
        ledger, state, stale = self._stale_ledger()

        ledger.commit(
            stale, 42, lambda res: state.update(goal=res.payload["goal"])
        )

        retained = ledger.evidence_slot.get("call-late")
        self.assertIsNotNone(retained, "the rejected result must be retained")
        # Verbatim: same id, same read revision, same payload object.
        self.assertEqual(retained.tool_call_id, stale.tool_call_id)
        self.assertEqual(retained.read_revision, stale.read_revision)
        self.assertIs(retained.payload, stale.payload)
        self.assertEqual(retained.payload, {"goal": "yesterday's goal"})
        # It never gained a result revision -- it never became state.
        self.assertIsNone(retained.result_revision)

    def test_evidence_is_not_silently_overwritten(self):
        """A second, different result for the same call cannot replace the first."""
        ledger, state, stale = self._stale_ledger()
        ledger.commit(
            stale, 42, lambda res: state.update(goal=res.payload["goal"])
        )
        impostor = RevisionCheckedResult(
            tool_call_id="call-late", read_revision=41, payload={"goal": "other"}
        )
        with self.assertRaises(RevisionCheckedToolResultsError):
            ledger.evidence_slot.retain(impostor)
        # The original evidence is intact.
        self.assertIs(
            ledger.evidence_slot.get("call-late").payload, stale.payload
        )

    def test_evidence_entries_lists_retained_results_in_order(self):
        """The slot keeps every rejected result, in retention order."""
        ledger = RevisionCheckedToolResults(current_revision=42)
        first = RevisionCheckedResult(
            tool_call_id="call-1", read_revision=41, payload={"n": 1}
        )
        second = RevisionCheckedResult(
            tool_call_id="call-2", read_revision=40, payload={"n": 2}
        )
        ledger.commit(first, 42, lambda res: None)
        ledger.commit(second, 42, lambda res: None)

        entries = ledger.evidence_slot.entries()
        self.assertEqual(len(entries), 2)
        self.assertEqual(
            [e.tool_call_id for e in entries], ["call-1", "call-2"]
        )
        self.assertEqual(ledger.evidence_slot.name, "default")

    def test_outcome_record_names_both_revisions_and_the_verdict(self):
        """The commit outcome is a complete, JSON-safe record."""
        ledger = RevisionCheckedToolResults(current_revision=42)
        stale = RevisionCheckedResult(
            tool_call_id="call-late", read_revision=41, payload={"goal": "old"}
        )
        outcome = ledger.commit(stale, 42, lambda res: None)

        record = outcome.as_dict()
        self.assertEqual(
            record["schema"], "northstar.revision-checked-tool-results.v1"
        )
        self.assertTrue(record["rejected"])
        self.assertFalse(record["committed"])
        self.assertEqual(record["read_revision"], 41)
        self.assertEqual(record["current_revision"], 42)
        self.assertEqual(record["expected_revision"], 41)
        self.assertIsNone(record["result_revision"])
        self.assertEqual(record["reason"], "revision_mismatch")
        self.assertEqual(record["evidence_slot"], "default")

    def test_ledger_records_every_outcome_in_order(self):
        """The ledger keeps the history of what it decided."""
        ledger = RevisionCheckedToolResults(current_revision=41)
        fresh = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={}
        )
        stale = RevisionCheckedResult(
            tool_call_id="call-b", read_revision=41, payload={}
        )
        ledger.commit(fresh, 41, lambda res: None)
        ledger.commit(stale, 42, lambda res: None)

        outcomes = ledger.outcomes()
        self.assertEqual(len(outcomes), 2)
        self.assertTrue(outcomes[0].committed)
        self.assertTrue(outcomes[1].rejected)


class ReconciliationTests(unittest.TestCase):
    """The stale result goes to reconciliation -- as a record, not a rewrite."""

    def test_reconciliation_records_id_both_revisions_and_applicability(self):
        """The record names everything a caller needs to decide."""
        ledger = RevisionCheckedToolResults(current_revision=42)
        state = {"goal": "user's newer goal"}
        stale = RevisionCheckedResult(
            tool_call_id="call-late",
            read_revision=41,
            payload={"goal": "yesterday's goal"},
        )
        ledger.commit(
            stale, 42, lambda res: state.update(goal=res.payload["goal"])
        )

        rec = ledger.reconcile(stale, state)

        self.assertIsInstance(rec, Reconciliation)
        self.assertEqual(rec.tool_call_id, "call-late")
        self.assertEqual(rec.read_revision, 41)
        self.assertEqual(rec.current_revision, 42)
        self.assertFalse(rec.applicable)
        self.assertEqual(rec.status, "stale_evidence")
        # The recommendation says what to do, and what not to do.
        self.assertIn("evidence", rec.replay_recommendation)
        self.assertEqual(rec.evidence_slot, ledger.evidence_slot.name)

    def test_reconciliation_does_not_rewrite_state(self):
        """Reconciliation records; it never touches the state."""
        ledger = RevisionCheckedToolResults(current_revision=42)
        state = {"goal": "user's newer goal", "count": 7}
        stale = RevisionCheckedResult(
            tool_call_id="call-late",
            read_revision=41,
            payload={"goal": "yesterday's goal"},
        )
        ledger.commit(
            stale, 42, lambda res: state.update(goal=res.payload["goal"])
        )
        before = dict(state)

        rec = ledger.reconcile(stale, state)

        self.assertEqual(state, before, "reconcile must not rewrite state")
        self.assertEqual(ledger.current_revision, 42, "no revision allocated")
        self.assertFalse(rec.applicable)

    def test_reconciliation_marks_a_matching_result_applicable(self):
        """A result that still names the current revision is applicable."""
        ledger = RevisionCheckedToolResults(current_revision=41)
        fresh = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={"goal": "new"}
        )
        ledger.commit(fresh, 41, lambda res: None)

        rec = ledger.reconcile(fresh, {})

        # The ledger has advanced to 42, so the result read at 41 is stale.
        self.assertFalse(rec.applicable)
        self.assertEqual(rec.current_revision, 42)

    def test_reconciliation_of_a_result_at_the_current_revision_is_applicable(self):
        """When the state has not moved, the result still applies."""
        ledger = RevisionCheckedToolResults(current_revision=41)
        result = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={"goal": "new"}
        )
        # The ledger is still at 41: nothing has been committed, so the
        # result still names the current revision.
        rec = ledger.reconcile(result, {})

        self.assertTrue(rec.applicable)
        self.assertEqual(rec.status, "applicable")
        self.assertIn("re-read", rec.replay_recommendation)

    def test_reconcile_rejects_a_non_result(self):
        """Only a real result can be reconciled."""
        ledger = RevisionCheckedToolResults(current_revision=41)
        with self.assertRaises(TypeError):
            ledger.reconcile({"tool_call_id": "call-a"}, {})

    def test_reconciliation_record_is_json_safe_and_complete(self):
        """The reconciliation record names everything, with the schema pin."""
        ledger = RevisionCheckedToolResults(current_revision=42)
        stale = RevisionCheckedResult(
            tool_call_id="call-late", read_revision=41, payload={"goal": "old"}
        )
        ledger.commit(stale, 42, lambda res: None)

        record = ledger.reconcile(stale, {}).as_dict()

        self.assertEqual(
            record["schema"], "northstar.revision-checked-tool-results.v1"
        )
        self.assertEqual(record["tool_call_id"], "call-late")
        self.assertEqual(record["read_revision"], 41)
        self.assertEqual(record["current_revision"], 42)
        self.assertFalse(record["applicable"])
        self.assertEqual(record["status"], "stale_evidence")
        self.assertEqual(record["evidence_slot"], "default")


class AtomicityTests(unittest.TestCase):
    """Path (c): the check and the apply cannot be separated."""

    def test_interleaved_commits_do_not_both_succeed(self):
        """Two results read at 41 race; only one may own the state.

        The loser must be *rejected* -- not silently overwrite the
        winner.  This is the source's failure shape in miniature: without
        the atomic check, the last tool to finish owns agent state.
        """
        ledger = RevisionCheckedToolResults(current_revision=41)
        state: dict[str, Any] = {}
        barrier = threading.Barrier(2)

        def make_result(call_id: str, goal: str) -> RevisionCheckedResult:
            return RevisionCheckedResult(
                tool_call_id=call_id, read_revision=41, payload={"goal": goal}
            )

        outcomes: list[CommitOutcome] = []
        goals: dict[str, str] = {}
        lock = threading.Lock()

        def worker(call_id: str, goal: str) -> None:
            result = make_result(call_id, goal)
            barrier.wait()
            outcome = ledger.commit(
                result, 41, lambda res: state.update(goal=res.payload["goal"])
            )
            with lock:
                outcomes.append(outcome)
                goals[outcome.tool_call_id] = goal

        threads = [
            threading.Thread(target=worker, args=("call-a", "goal-a")),
            threading.Thread(target=worker, args=("call-b", "goal-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        committed = [o for o in outcomes if o.committed]
        rejected = [o for o in outcomes if o.rejected]
        # Exactly one won; the other was rejected, not applied.
        self.assertEqual(len(committed), 1, "exactly one commit may win")
        self.assertEqual(len(rejected), 1, "the loser must be rejected")
        # The state holds the winner's value, and the loser's value was
        # never written -- no silent overwrite in either direction.
        self.assertIn(state["goal"], ("goal-a", "goal-b"))
        winner = committed[0]
        loser = rejected[0]
        self.assertNotEqual(winner.tool_call_id, loser.tool_call_id)
        self.assertEqual(state["goal"], goals[winner.tool_call_id])
        # The loser is retained as evidence.
        self.assertIsNotNone(ledger.evidence_slot.get(loser.tool_call_id))
        # The revision advanced exactly once.
        self.assertEqual(ledger.current_revision, 42)

    def test_second_commit_after_the_first_advanced_is_rejected(self):
        """Sequentially too: the second commit sees the advanced revision."""
        ledger = RevisionCheckedToolResults(current_revision=41)
        state: dict[str, Any] = {}
        first = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={"goal": "a"}
        )
        second = RevisionCheckedResult(
            tool_call_id="call-b", read_revision=42, payload={"goal": "b"}
        )

        out1 = ledger.commit(
            first, 41, lambda res: state.update(goal=res.payload["goal"])
        )
        out2 = ledger.commit(
            second, 42, lambda res: state.update(goal=res.payload["goal"])
        )

        self.assertTrue(out1.committed)
        self.assertEqual(out1.result_revision, 42)
        self.assertTrue(out2.committed)
        self.assertEqual(out2.result_revision, 43)
        self.assertEqual(state, {"goal": "b"})
        self.assertEqual(ledger.current_revision, 43)

    def test_a_result_read_at_the_previous_revision_is_rejected(self):
        """Exact equality, not "greater or equal": 41 is stale on 42.

        Even though 41 < 42 and the result is "older", it must not be
        applied; and even a result that claims a *newer* revision than the
        state has is not "at least as new", it simply does not match.
        """
        ledger = RevisionCheckedToolResults(current_revision=42)
        state = {"goal": "current"}

        older = RevisionCheckedResult(
            tool_call_id="call-older", read_revision=41, payload={"goal": "old"}
        )
        outcome = ledger.commit(
            older, 42, lambda res: state.update(goal=res.payload["goal"])
        )

        self.assertTrue(outcome.rejected)
        self.assertEqual(state, {"goal": "current"})

    def test_a_result_read_at_a_newer_revision_is_also_rejected(self):
        """A result claiming rev 43 on a rev 42 state does not match either."""
        ledger = RevisionCheckedToolResults(current_revision=42)
        state = {"goal": "current"}

        ahead = RevisionCheckedResult(
            tool_call_id="call-ahead", read_revision=43, payload={"goal": "ahead"}
        )
        outcome = ledger.commit(
            ahead, 42, lambda res: state.update(goal=res.payload["goal"])
        )

        self.assertTrue(outcome.rejected)
        self.assertEqual(state, {"goal": "current"})

    def test_commit_exposes_no_separate_check_step(self):
        """There is no public "check now, apply later" door.

        The source's detail: a check before enqueueing does not count,
        because the state can move between the check and the apply.  The
        only public write path is ``commit()``, which does both.
        """
        public = {
            name
            for name in dir(RevisionCheckedToolResults)
            if not name.startswith("_")
        }
        for forbidden in ("check", "check_revision", "verify", "can_apply",
                          "apply", "precheck", "pre_check"):
            self.assertNotIn(
                forbidden, public, f"{forbidden!r} would split the check"
            )
        # The write path is commit(), and it takes the apply callable.
        self.assertIn("commit", public)
        self.assertIn("reconcile", public)

    def test_commit_validates_its_arguments(self):
        """A bad call is refused, not guessed at."""
        ledger = RevisionCheckedToolResults(current_revision=41)
        result = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={}
        )
        with self.assertRaises(TypeError):
            ledger.commit({"tool_call_id": "call-a"}, 41, lambda res: None)
        with self.assertRaises(TypeError):
            ledger.commit(result, 41, "not callable")
        with self.assertRaises(InvalidRevisionError):
            ledger.commit(result, -1, lambda res: None)
        with self.assertRaises(InvalidRevisionError):
            ledger.commit(result, 41.0, lambda res: None)


class OrphanAdoptionTests(unittest.TestCase):
    """The behaviour the adopted orphan work claims, checked end to end.

    These are the tests this slice adds on top of the six orphan test
    methods it inherited: they cover the *adjudication* itself -- that
    the records the module emits are complete enough to be audited, that
    the evidence slot really is a slot (one named place, not a growing
    list of places), and that the revision numbers in the JSON-safe
    records are the numbers the ledger actually holds.
    """

    def test_the_schema_pin_is_the_same_on_every_record(self):
        """Result, outcome and reconciliation all carry one schema pin."""
        ledger = RevisionCheckedToolResults(current_revision=42)
        stale = RevisionCheckedResult(
            tool_call_id="call-late", read_revision=41, payload={"goal": "old"}
        )
        outcome = ledger.commit(stale, 42, lambda res: None)
        reconciliation = ledger.reconcile(stale, {})
        pin = "northstar.revision-checked-tool-results.v1"
        self.assertEqual(stale.as_dict()["schema"], pin)
        self.assertEqual(outcome.as_dict()["schema"], pin)
        self.assertEqual(reconciliation.as_dict()["schema"], pin)

    def test_a_committed_outcome_carries_no_evidence_slot(self):
        """A commit that succeeded left no evidence behind."""
        ledger = RevisionCheckedToolResults(current_revision=41)
        fresh = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={}
        )
        outcome = ledger.commit(fresh, 41, lambda res: None)
        record = outcome.as_dict()
        self.assertTrue(record["committed"])
        self.assertFalse(record["rejected"])
        self.assertIsNone(record["evidence_slot"])
        self.assertEqual(record["reason"], "committed")
        self.assertEqual(record["result_revision"], 42)
        self.assertEqual(len(ledger.evidence_slot), 0)

    def test_the_ledger_advances_its_own_revision_only_on_a_commit(self):
        """A rejection leaves the revision where it was."""
        ledger = RevisionCheckedToolResults(current_revision=41)
        stale = RevisionCheckedResult(
            tool_call_id="call-late", read_revision=40, payload={}
        )
        ledger.commit(stale, 41, lambda res: None)
        self.assertEqual(ledger.current_revision, 41)
        fresh = RevisionCheckedResult(
            tool_call_id="call-fresh", read_revision=41, payload={}
        )
        ledger.commit(fresh, 41, lambda res: None)
        self.assertEqual(ledger.current_revision, 42)

    def test_one_named_slot_holds_the_evidence(self):
        """The evidence lives in one named place, not in a growing list."""
        ledger = RevisionCheckedToolResults(current_revision=42)
        for index in range(3):
            stale = RevisionCheckedResult(
                tool_call_id=f"call-{index}", read_revision=41, payload={"n": index}
            )
            ledger.commit(stale, 42, lambda res: None)
        slot = ledger.evidence_slot
        self.assertEqual(slot.name, "default")
        self.assertEqual(len(slot), 3)
        self.assertEqual(len(ledger.outcomes()), 3)
        # The slot is reachable by tool call id, and it is the same slot.
        retained = slot.get("call-1")
        self.assertIsNotNone(retained)
        self.assertEqual(retained.payload, {"n": 1})
        self.assertIsNone(slot.get("call-absent"))

    def test_the_record_carries_the_revisions_the_ledger_holds(self):
        """The JSON-safe record and the ledger agree, revision for revision."""
        ledger = RevisionCheckedToolResults(current_revision=41)
        fresh = RevisionCheckedResult(
            tool_call_id="call-a", read_revision=41, payload={}
        )
        outcome = ledger.commit(fresh, 41, lambda res: None)
        record = outcome.as_dict()
        self.assertEqual(record["current_revision"], 41)
        self.assertEqual(record["result_revision"], ledger.current_revision)
        self.assertEqual(record["read_revision"], 41)
        self.assertEqual(record["tool_call_id"], "call-a")

    def test_retaining_the_same_result_twice_is_idempotent(self):
        """Re-retaining the same evidence does not grow the slot."""
        ledger = RevisionCheckedToolResults(current_revision=42)
        stale = RevisionCheckedResult(
            tool_call_id="call-late", read_revision=41, payload={"goal": "old"}
        )
        ledger.commit(stale, 42, lambda res: None)
        slot = ledger.evidence_slot
        slot.retain(stale)
        self.assertEqual(len(slot), 1)
