"""Tool results carry the revision they read; commit checks that revision atomically.

Absorbed from Moltbook ``neo_konsi_s2bw``, "the last tool to finish has no
right to own agent state" (post 87f799a1-245a-4d13-9fcc-5cd7cca53e31,
108 up / 320 comments -- the heat figures are as observed during the
2026-11-14 00:48 sweep, not a measurement).

The failure shape, verbatim from the post:

    "rev 41 的查询最晚返回，覆盖用户在 rev 42 的新目标，单步全成功、整体在
     昨天上工作。"

A query that read revision 41 returned last and overwrote the user's newer
goal at revision 42. Every step succeeded; the run as a whole worked on
yesterday's state.

The mechanism, verbatim from the post:

* every tool result carries the **state revision** it was read at;
* writing to current state must perform an **atomic revision check**;
* on mismatch the result goes to **reconciliation**; the old result is kept
  only as **evidence** and gains no ownership of state.

And the detail that makes it work: a check **before enqueueing does not
count** -- the check and the commit can still be interleaved, so the check
must be atomic (check and commit in one indivisible step).

Northstar's gap (read from the code, not assumed)
-------------------------------------------------
* ``loop.py`` records ``policy_revision`` -- *which policy revision approved
  this run's tool calls* (the field is declared at ``loop.py:315`` and copied
  into the run record at ``loop.py:2252`` and ``loop.py:2919``).  That is
  **attribution**, not a check: it says who approved, never "which revision
  did you read, and is that still the current one?".
* A tool result's write-back happens in ``loop.py`` where the report is
  appended to ``state.tool_reports`` (e.g. ``loop.py:3027``, ``loop.py:3032``,
  ``loop.py:3197``, ``loop.py:3232``).  Nothing there asks the result which
  revision it read.  A late result that read an old revision therefore
  overwrites newer state, and -- exactly as in the post -- every individual
  step reports success.
* ``vector_clock.py`` orders *events* causally (``happens_before`` /
  ``concurrent_with``).  It says nothing about which revision a tool result
  was computed against, and it cannot refuse a write.
* ``state_machine.py`` transitions under a ``threading.RLock`` and its
  guards can block a transition -- but a guard is a *caller-supplied
  predicate*, and no caller supplies a revision guard for tool results.

This module is that missing check.  A tool result carries the revision it
read; ``commit()`` verifies it against the current revision and applies the
write **in the same indivisible step**; a stale result is never applied, is
kept verbatim as evidence, and goes to reconciliation.

Revision representation
-----------------------
A revision is a caller-supplied **integer seq** -- no wall clock, matching
the ledger style used elsewhere in this repository (``vector_clock.py``
counts integer counters; ``state_machine.py`` sequences are integers).
Comparison is **exact equality**, never "greater or equal": a result that
read revision 41 is stale on a revision 42 state *regardless of how new or
old it looks*, because the question is "is this still the state I read?", not
"is this newer than what I have?".

Scope
-----
This module is a self-contained mechanism.  It does **not** modify
``loop.py``, ``sessions.py``, ``state_machine.py`` or any other existing
module -- wiring the runtime's write-back path to it is a separate change.
What it guarantees is the check itself: atomicity, fail-closed construction,
exact-equality staleness, verbatim evidence retention, and reconciliation
that records rather than rewrites.

House style: frozen dataclasses, stdlib-only, fail-closed refusals.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence

#: Version pin for this module's record shapes.
REVISION_CHECKED_TOOL_RESULTS_VERSION = "revision-checked-tool-results.v1"

#: Schema pin for the records this module emits.
SCHEMA_PIN = "northstar.revision-checked-tool-results.v1"

#: Largest revision this module will represent.
_MAX_REVISION = 2**63 - 1


class RevisionCheckedToolResultsError(Exception):
    """Base class for every refusal raised by this module."""


class MissingReadRevisionError(RevisionCheckedToolResultsError):
    """A tool result was created without a usable read revision.

    Fail closed: a result that cannot name the revision it read has no
    standing to write to state.  There is no default and no "assume
    current" fallback.
    """


class InvalidRevisionError(RevisionCheckedToolResultsError):
    """A revision was not a non-negative integer."""


class InvalidToolCallIdError(RevisionCheckedToolResultsError):
    """A tool call id was not a non-empty string."""


def _check_revision(value: object, name: str) -> int:
    """Validate one revision.  Returns it as int, or raises fail-closed."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidRevisionError(
            f"{name} must be int, got {type(value).__name__}"
        )
    if value < 0:
        raise InvalidRevisionError(f"{name} must be non-negative, got {value}")
    if value > _MAX_REVISION:
        raise InvalidRevisionError(f"{name} exceeds {_MAX_REVISION}")
    return value


def _check_tool_call_id(value: object) -> str:
    if not isinstance(value, str):
        raise InvalidToolCallIdError(
            f"tool_call_id must be str, got {type(value).__name__}"
        )
    if not value:
        raise InvalidToolCallIdError("tool_call_id must be non-empty")
    if len(value) > 1024:
        raise InvalidToolCallIdError("tool_call_id exceeds 1024 chars")
    return value


@dataclass(frozen=True)
class RevisionCheckedResult:
    """One tool result, tagged with the state revision it was read at.

    Attributes:
        tool_call_id: the provider's id for the tool call.
        read_revision: the state revision this result was computed
            against.  Required, no default -- a result without it is
            refused at construction (fail closed).
        payload: the result body.  Anything the caller wants to carry
            forward; opaque to this module.
        result_revision: the revision assigned to the state *after* this
            result was written back.  ``None`` until a commit assigns it.
    """

    tool_call_id: str
    read_revision: int
    payload: Any = None
    result_revision: Optional[int] = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "tool_call_id", _check_tool_call_id(self.tool_call_id)
        )
        if self.read_revision is None:
            # Fail closed, with the dedicated error: a result that cannot
            # name the revision it read has no standing to write to state.
            raise MissingReadRevisionError(
                "read_revision is required; a tool result without the "
                "revision it read cannot write back to state"
            )
        object.__setattr__(
            self,
            "read_revision",
            _check_revision(self.read_revision, "read_revision"),
        )
        if self.result_revision is not None:
            object.__setattr__(
                self,
                "result_revision",
                _check_revision(self.result_revision, "result_revision"),
            )

    def with_result_revision(self, revision: int) -> "RevisionCheckedResult":
        """Return a copy of this result carrying ``revision`` as assigned."""
        return RevisionCheckedResult(
            tool_call_id=self.tool_call_id,
            read_revision=self.read_revision,
            payload=self.payload,
            result_revision=_check_revision(revision, "result_revision"),
        )

    def as_dict(self) -> dict:
        """JSON-safe record with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "tool_call_id": self.tool_call_id,
            "read_revision": self.read_revision,
            "result_revision": self.result_revision,
        }


@dataclass(frozen=True)
class CommitOutcome:
    """The result of one ``commit()`` call.

    Exactly one of ``committed`` / ``rejected`` is true.

    Attributes:
        committed: True when the result was applied to state.
        rejected: True when the result was stale and was not applied.
        tool_call_id: the tool call the outcome belongs to.
        read_revision: the revision the result was read at.
        current_revision: the state revision at commit time.
        result_revision: the newly assigned revision, when committed.
        expected_revision: the revision the result would have needed, when
            rejected.
        reason: a short machine-readable reason, e.g. ``"revision_mismatch"``.
        evidence_slot: where the rejected result was retained, when
            rejected.
    """

    committed: bool
    rejected: bool
    tool_call_id: str
    read_revision: int
    current_revision: int
    result_revision: Optional[int] = None
    expected_revision: Optional[int] = None
    reason: str = ""
    evidence_slot: Optional[str] = None

    def as_dict(self) -> dict:
        """JSON-safe record with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "committed": self.committed,
            "rejected": self.rejected,
            "tool_call_id": self.tool_call_id,
            "read_revision": self.read_revision,
            "current_revision": self.current_revision,
            "result_revision": self.result_revision,
            "expected_revision": self.expected_revision,
            "reason": self.reason,
            "evidence_slot": self.evidence_slot,
        }


class EvidenceSlot:
    """A named slot that retains rejected tool results verbatim.

    A rejected result is **evidence**, not garbage: it is kept exactly as
    it was (same tool call id, same read revision, same payload object),
    so a reviewer can see what the stale result wanted to write.  It is
    never discarded and never silently overwritten -- a second rejection
    into the same slot is refused, so the earlier evidence survives.

    The slot does not own state and cannot write to it.
    """

    def __init__(self, name: str) -> None:
        self._name = _check_tool_call_id(name)
        self._entries: list[RevisionCheckedResult] = []
        self._lock = threading.RLock()

    @property
    def name(self) -> str:
        return self._name

    def retain(self, result: RevisionCheckedResult) -> str:
        """Retain ``result`` verbatim.  Returns this slot's name.

        Retaining the *same* result again is idempotent -- the original
        evidence stays.  Retaining a *different* result under a tool call
        id already held here raises: evidence is never overwritten.
        """
        if not isinstance(result, RevisionCheckedResult):
            raise TypeError(
                "retain expects a RevisionCheckedResult, got "
                f"{type(result).__name__}"
            )
        with self._lock:
            for entry in self._entries:
                if entry.tool_call_id != result.tool_call_id:
                    continue
                if entry == result:
                    return self._name
                raise RevisionCheckedToolResultsError(
                    f"evidence slot {self._name!r} already holds a different "
                    f"result for tool call {result.tool_call_id!r}; evidence "
                    "is not overwritten"
                )
            self._entries.append(result)
        return self._name

    def entries(self) -> tuple[RevisionCheckedResult, ...]:
        """Retained results, in retention order."""
        with self._lock:
            return tuple(self._entries)

    def get(self, tool_call_id: str) -> Optional[RevisionCheckedResult]:
        """The retained result for ``tool_call_id``, if any."""
        wanted = _check_tool_call_id(tool_call_id)
        with self._lock:
            for entry in self._entries:
                if entry.tool_call_id == wanted:
                    return entry
        return None

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


@dataclass(frozen=True)
class Reconciliation:
    """A record about a rejected (stale) tool result.

    Reconciliation **records**; it never rewrites state.  Whether the stale
    result should be replayed is the caller's decision.

    Attributes:
        tool_call_id: the tool call whose result was rejected.
        read_revision: the revision that result was read at.
        current_revision: the state revision at rejection time.
        applicable: True when the result may still describe the current
            state (its read revision matches the current revision at
            reconcile time -- e.g. the state was rolled back or the result
            was rejected for a reason other than staleness).  False when
            the result is stale evidence: the state has moved on.
        status: ``"applicable"`` or ``"stale_evidence"``.
        replay_recommendation: what the caller could do, when applicable.
        evidence_slot: where the rejected result is retained.
        reason: the machine-readable reason the result was rejected.
    """

    tool_call_id: str
    read_revision: int
    current_revision: int
    applicable: bool
    status: str
    replay_recommendation: str = ""
    evidence_slot: Optional[str] = None
    reason: str = ""

    def as_dict(self) -> dict:
        """JSON-safe record with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "tool_call_id": self.tool_call_id,
            "read_revision": self.read_revision,
            "current_revision": self.current_revision,
            "applicable": self.applicable,
            "status": self.status,
            "replay_recommendation": self.replay_recommendation,
            "evidence_slot": self.evidence_slot,
            "reason": self.reason,
        }


class RevisionCheckedToolResults:
    """Atomic revision-checked write-back for tool results.

    The whole point of this class is that the revision check and the
    write-back are **one indivisible step**.  There is deliberately no
    public "check" method that a caller could run and then separately
    apply: a pre-check is worthless, because the state can move between
    the check and the apply (the post's own detail -- a check before
    enqueueing does not count).  ``commit()`` is the only way in.

    Attributes:
        current_revision: the revision the state is currently at.
        evidence_slot: where rejected results are retained.
    """

    def __init__(
        self,
        current_revision: int = 0,
        *,
        evidence_slot: Optional[EvidenceSlot] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._current_revision = _check_revision(
            current_revision, "current_revision"
        )
        self._evidence_slot = (
            evidence_slot if evidence_slot is not None else EvidenceSlot("default")
        )
        #: Every outcome this ledger has produced, in order.
        self._outcomes: list[CommitOutcome] = []

    # -- reads ---------------------------------------------------------

    @property
    def current_revision(self) -> int:
        """The revision the state is currently at."""
        with self._lock:
            return self._current_revision

    @property
    def evidence_slot(self) -> EvidenceSlot:
        """The slot where rejected results are retained."""
        return self._evidence_slot

    def outcomes(self) -> tuple[CommitOutcome, ...]:
        """Every commit outcome so far, in order."""
        with self._lock:
            return tuple(self._outcomes)

    # -- the one write path --------------------------------------------

    def commit(
        self,
        result: RevisionCheckedResult,
        current_revision: int,
        apply: Callable[[RevisionCheckedResult], Any],
    ) -> CommitOutcome:
        """Check ``result`` against ``current_revision`` and write it back.

        The check and the apply happen under one lock: no other commit can
        interleave between them.

        * If ``result.read_revision == current_revision`` **and** the
          ledger's own revision is still ``current_revision``: ``apply(result)``
          runs, a new revision is allocated (``current_revision + 1``), and
          a committed outcome is returned.
        * Otherwise: ``apply`` is **not** called, no revision is allocated,
          the result is retained verbatim in the evidence slot, and a
          rejected outcome is returned naming the expected revision, the
          actual revision, and the evidence slot.

        The second condition is what makes the check *atomic* rather than
        advisory.  Checking only the caller's ``current_revision`` would
        let two commits that both read revision 41 both succeed -- the
        second would silently overwrite the first, which is the exact
        failure the source describes.  Requiring the ledger's own revision
        to still agree means the loser of the race is rejected.

        ``current_revision`` is the state revision the caller believes is
        current.  It is validated, and it is compared by **exact
        equality** -- never "greater or equal".
        """
        if not isinstance(result, RevisionCheckedResult):
            raise TypeError(
                "commit expects a RevisionCheckedResult, got "
                f"{type(result).__name__}"
            )
        if not callable(apply):
            raise TypeError("apply must be callable")
        claimed = _check_revision(current_revision, "current_revision")
        with self._lock:
            actual = self._current_revision
            # Exact equality, twice: the result must name the revision it
            # read, and that revision must still be the state's revision.
            # A result read at an older revision is stale even if the state
            # moved *backwards*; there is no ordering test here, only
            # "is this still the state I read?".
            if result.read_revision != claimed or claimed != actual:
                slot_name = self._evidence_slot.retain(result)
                outcome = CommitOutcome(
                    committed=False,
                    rejected=True,
                    tool_call_id=result.tool_call_id,
                    read_revision=result.read_revision,
                    current_revision=actual,
                    result_revision=None,
                    expected_revision=result.read_revision,
                    reason="revision_mismatch",
                    evidence_slot=slot_name,
                )
                self._outcomes.append(outcome)
                return outcome
            # Check passed: apply and allocate the new revision in the
            # same locked step, so no other commit can slip in between.
            apply(result)
            new_revision = actual + 1
            self._current_revision = new_revision
            outcome = CommitOutcome(
                committed=True,
                rejected=False,
                tool_call_id=result.tool_call_id,
                read_revision=result.read_revision,
                current_revision=actual,
                result_revision=new_revision,
                expected_revision=result.read_revision,
                reason="committed",
                evidence_slot=None,
            )
            self._outcomes.append(outcome)
            return outcome

    # -- reconciliation ------------------------------------------------

    def reconcile(
        self,
        rejected_result: RevisionCheckedResult,
        current_state: Any = None,
    ) -> Reconciliation:
        """Build a reconciliation record for a rejected result.

        The record names the old result's tool call id, the revision it
        read, the current revision, and whether the result is still
        applicable.  It **does not** rewrite state and does not replay
        anything -- replay is the caller's decision.
        """
        if not isinstance(rejected_result, RevisionCheckedResult):
            raise TypeError(
                "reconcile expects a RevisionCheckedResult, got "
                f"{type(rejected_result).__name__}"
            )
        with self._lock:
            current = self._current_revision
        applicable = rejected_result.read_revision == current
        if applicable:
            status = "applicable"
            recommendation = (
                "result still describes the current revision; the caller "
                "may re-read the state and re-run the tool"
            )
        else:
            status = "stale_evidence"
            recommendation = (
                "result was computed against an older revision; retain as "
                "evidence and do not replay over the current state"
            )
        slot_name: Optional[str] = None
        retained = self._evidence_slot.get(rejected_result.tool_call_id)
        if retained is not None:
            slot_name = self._evidence_slot.name
        return Reconciliation(
            tool_call_id=rejected_result.tool_call_id,
            read_revision=rejected_result.read_revision,
            current_revision=current,
            applicable=applicable,
            status=status,
            replay_recommendation=recommendation,
            evidence_slot=slot_name,
            reason="revision_mismatch",
        )


def main() -> None:
    """Self-check: the commit path, the stale path, and reconciliation."""
    ledger = RevisionCheckedToolResults(current_revision=41)
    state: dict[str, Any] = {"goal": "old"}

    fresh = RevisionCheckedResult(
        tool_call_id="call-a", read_revision=41, payload={"goal": "new"}
    )
    outcome = ledger.commit(
        fresh, 41, lambda res: state.update(goal=res.payload["goal"])
    )
    assert outcome.committed and not outcome.rejected
    assert outcome.result_revision == 42
    assert state["goal"] == "new"

    late = RevisionCheckedResult(
        tool_call_id="call-b", read_revision=41, payload={"goal": "stale"}
    )
    outcome = ledger.commit(
        late, 42, lambda res: state.update(goal=res.payload["goal"])
    )
    assert outcome.rejected and not outcome.committed
    assert state["goal"] == "new", "a stale result must not be applied"

    rec = ledger.reconcile(late, state)
    assert rec.tool_call_id == "call-b"
    assert rec.read_revision == 41 and rec.current_revision == 42
    assert not rec.applicable and rec.status == "stale_evidence"

    print("revision-checked-tool-results OK: commit, stale rejection, reconcile")


if __name__ == "__main__":
    main()
