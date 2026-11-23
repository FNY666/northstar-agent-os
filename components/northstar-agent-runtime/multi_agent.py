"""Multi-agent run collaboration ledger: spawn / coordinate / merge.

Research motivation: the *mechanism ideas* of the 2026 multi-agent
framework wave (no code or spec text was available; only the ideas are
absorbed):

1. **OpenAI Swarm** (github.com/openai/swarm, MIT) -- agent handoffs:
   one agent declares it is handing the conversation to another agent;
   the framework books who held the turn and what came back.
2. **AutoGen** (microsoft/autogen) -- multi-agent conversations: named
   agent instances take part in a chat round over a task; each round's
   participants and their declared contributions are bookable.
3. **LangGraph** -- state graphs: a run moves through named nodes; a
   node join merges sub-agent state into one state.
4. **CrewAI** -- crews: a crew is a named set of role-playing agents
   (planner / worker / critic); the crew declares tasks and the merged
   crew output.

What this module is: the single-host deterministic *ledger* for that
lifecycle. It spawns no real agents, runs no LLM, and merges no real
outputs: ``MultiAgent`` books declared agent instances
(``spawn()``), declares which agents took part in one coordination
round and over what task pin (``coordinate()``), and books the
declared merged outcome of that round (``merge()``). Task text,
per-agent contributions, and merged output bytes travel as
``sha256:`` digest pins only -- raw text/bytes are banned from
records and from the audit boundary.

Public API:

- ``MultiAgent(run_id)`` -- mutable, RLock-guarded ledger.
  - ``spawn(agent_id, role, seq)`` -> frozen ``AgentRecord``: books
    one agent instance with a pinned role. Duplicate ids refused;
    ids are never recycled.
  - ``coordinate(round_id, agent_ids, seq, task_digest="")`` -> frozen
    ``CoordinationRecord``: declares one coordination round with its
    participant set (sorted for a deterministic pin) and the task pin.
    Every participant must be spawned; the round starts ``open``.
  - ``merge(round_id, outcome_digest, seq)`` -> frozen
    ``MergeRecord``: terminal -- books the declared merged outcome of
    an open round (``round_id -> merged``); a merged round cannot be
    merged again.
  - ``agent(agent_id)`` / ``agent_ids()`` / ``round_ids()`` /
    ``stats()`` / ``audit_log()`` -- pure read views; consume no seq.
- ``multi_agent_audit_event(kind, seq, **detail)`` --
  ``audit.ndjson/1`` records: ``"multi-agent.spawned"``,
  ``"multi-agent.coordinated"``, ``"multi-agent.merged"``,
  ``"multi-agent.rejected"``.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq and book a
``"multi-agent.rejected"`` row; malformed seqs raise bare and consume
nothing), RLock-guarded, fail-closed taxonomy, stdlib-only
(``canonical_json`` sibling helper behind the standard try/except
fallback).

Honest scope:

- This module books *declared* agent instances, declared round
  participants, and declared merged outcomes. It observes no LLM, runs
  no agent code, and cannot prove a booked ``merged`` outcome was
  really produced by the named agents.
- A ``MergeRecord`` proves a ``merge()`` call happened in this ledger;
  the merge logic itself is the host's problem.
- The round's ``open`` -> ``merged`` transition is monotonic:
  ``coordinate`` cannot reopen a merged round.

Version pin: ``multi-agent.v1`` / schema pin
``northstar.multi-agent.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
MULTI_AGENT_VERSION = "multi-agent.v1"

#: Schema pin carried by records and audit events.
MULTI_AGENT_SCHEMA = "northstar.multi-agent.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_SPAWNED = "multi-agent.spawned"
KIND_COORDINATED = "multi-agent.coordinated"
KIND_MERGED = "multi-agent.merged"
KIND_REJECTED = "multi-agent.rejected"

_LEDGER_KINDS = frozenset(
    {KIND_SPAWNED, KIND_COORDINATED, KIND_MERGED, KIND_REJECTED}
)

#: Detail keys that must never cross the audit boundary (raw text/bytes
#: travel as digest pins only; the bytes themselves stay host-side).
_BANNED_DETAIL_KEYS = frozenset(
    {
        "task",
        "task_text",
        "outcome",
        "outcome_text",
        "contribution",
        "payload",
        "result",
        "bytes",
        "value",
        "data",
        "message",
    }
)

#: Digest pins are always ``sha256:`` + 64 lowercase hex characters.
_HEX64 = set("0123456789abcdef")

#: Pinned role vocabulary (CrewAI-flavoured; ``custom`` for the rest).
ROLE_PLANNER = "planner"
ROLE_WORKER = "worker"
ROLE_CRITIC = "critic"
ROLE_COORDINATOR = "coordinator"
ROLE_TOOL_EXECUTOR = "tool-executor"
ROLE_CUSTOM = "custom"
ROLES = frozenset(
    {
        ROLE_PLANNER,
        ROLE_WORKER,
        ROLE_CRITIC,
        ROLE_COORDINATOR,
        ROLE_TOOL_EXECUTOR,
        ROLE_CUSTOM,
    }
)

#: Round lifecycle states.
ROUND_OPEN = "open"
ROUND_MERGED = "merged"
_ROUND_STATES = frozenset({ROUND_OPEN, ROUND_MERGED})

#: Max identifier length.
_MAX_ID_LEN = 128


# --- error taxonomy --------------------------------------------------------


class MultiAgentError(Exception):
    """Base class for every fail-closed refusal in this module."""


class BadRunError(MultiAgentError):
    """Run id shape is malformed."""


class BadAgentError(MultiAgentError):
    """Agent id shape is malformed."""


class DuplicateAgentError(MultiAgentError):
    """Agent id is already booked (ids are never recycled)."""


class UnknownAgentError(MultiAgentError):
    """No such spawned agent."""


class BadRoleError(MultiAgentError):
    """Role is outside the pinned vocabulary."""


class BadRoundError(MultiAgentError):
    """Round id shape is malformed."""


class DuplicateRoundError(MultiAgentError):
    """Round id is already booked (ids are never recycled)."""


class UnknownRoundError(MultiAgentError):
    """No such booked round."""


class BadParticipantsError(MultiAgentError):
    """Participant list is malformed (empty, duplicates, bad ids)."""


class RoundStateError(MultiAgentError):
    """The operation is invalid in the round's current state."""


class BadDigestError(MultiAgentError):
    """A digest pin is not ``sha256:`` + 64 lowercase hex."""


class SeqOrderError(MultiAgentError):
    """Caller seq did not strictly increase."""


class AuditKindError(MultiAgentError):
    """Audit event kind is outside the fixed vocabulary."""


# --- input validation ------------------------------------------------------


def _check_seq(seq: Any, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"{name} must be an int seq, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"{name} must be non-negative, got {seq}")
    return seq


def _check_id(value: Any, name: str, exc: type) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise exc(f"{name} must be a string, got {type(value).__name__}")
    value = value.strip()
    if not value:
        raise exc(f"{name} must be non-empty")
    if len(value) > _MAX_ID_LEN:
        raise exc(f"{name} exceeds {_MAX_ID_LEN} chars")
    return value


def _check_run_id(value: Any) -> str:
    return _check_id(value, "run_id", BadRunError)


def _check_agent_id(value: Any) -> str:
    return _check_id(value, "agent_id", BadAgentError)


def _check_round_id(value: Any) -> str:
    return _check_id(value, "round_id", BadRoundError)


def _check_role(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadRoleError(f"role must be a string, got {type(value).__name__}")
    if value not in ROLES:
        raise BadRoleError(f"role must be one of {sorted(ROLES)}, got {value!r}")
    return value


def _check_digest(value: Any, name: str) -> str:
    """Validate a ``sha256:<64hex>`` pin; empty string means 'absent'."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{name} must be a string, got {type(value).__name__}")
    if value == "":
        return ""
    if len(value) != 7 + 64 or not value.startswith("sha256:"):
        raise BadDigestError(f"{name} must look like 'sha256:' + 64 hex chars")
    if any(c not in _HEX64 for c in value[7:]):
        raise BadDigestError(f"{name} must be lowercase hex")
    return value


def _check_participants(value: Any, known: Mapping[str, Any]) -> Tuple[str, ...]:
    """Validate the participant list; returns sorted ids."""
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise BadParticipantsError("agent_ids must be a sequence of agent ids")
    ids = tuple(_check_agent_id(v) for v in value)
    if not ids:
        raise BadParticipantsError("agent_ids must be non-empty")
    if len(set(ids)) != len(ids):
        raise BadParticipantsError("agent_ids must not contain duplicates")
    unknown = [i for i in ids if i not in known]
    if unknown:
        raise UnknownAgentError(f"unknown agent ids: {unknown!r}")
    return tuple(sorted(ids))


def _pin_bytes(data: bytes) -> str:
    """Convenience digest pin (host-side only; pins enter records)."""
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


def _canonical(obj: Any) -> bytes:
    if _cj is not None:
        dumped = _cj.jcs_dumps(obj)  # type: ignore[attr-defined]
        return dumped.encode("utf-8") if isinstance(dumped, str) else dumped
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_of(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()


# --- audit builder -----------------------------------------------------------


def multi_agent_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the multi-agent ledger."""
    if kind not in _LEDGER_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    banned = _BANNED_DETAIL_KEYS.intersection(detail)
    if banned:
        raise MultiAgentError(
            f"detail carries banned keys: {sorted(banned)}"
        )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "multi-agent",
        "module_version": MULTI_AGENT_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# --- frozen records ----------------------------------------------------------


@dataclass(frozen=True)
class AgentRecord:
    """One spawned agent instance (declared)."""

    run_id: str
    agent_id: str
    role: str
    seq: int
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _digest_of(
                {
                    "run_id": self.run_id,
                    "agent_id": self.agent_id,
                    "role": self.role,
                }
            ),
        )

    def verify(self) -> bool:
        """Recompute the pin; True when untampered."""
        return self.digest == _digest_of(
            {
                "run_id": self.run_id,
                "agent_id": self.agent_id,
                "role": self.role,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "role": self.role,
            "seq": self.seq,
            "digest": self.digest,
            "schema": MULTI_AGENT_SCHEMA,
        }


@dataclass(frozen=True)
class CoordinationRecord:
    """One declared coordination round over a task pin."""

    run_id: str
    round_id: str
    participants: Tuple[str, ...]
    task_digest: str
    seq: int
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _digest_of(
                {
                    "run_id": self.run_id,
                    "round_id": self.round_id,
                    "participants": list(self.participants),
                    "task_digest": self.task_digest,
                }
            ),
        )

    def verify(self) -> bool:
        """Recompute the pin; True when untampered."""
        return self.digest == _digest_of(
            {
                "run_id": self.run_id,
                "round_id": self.round_id,
                "participants": list(self.participants),
                "task_digest": self.task_digest,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "round_id": self.round_id,
            "participants": list(self.participants),
            "task_digest": self.task_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": MULTI_AGENT_SCHEMA,
        }


@dataclass(frozen=True)
class MergeRecord:
    """The declared merged outcome of one coordination round."""

    run_id: str
    round_id: str
    outcome_digest: str
    seq: int
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _digest_of(
                {
                    "run_id": self.run_id,
                    "round_id": self.round_id,
                    "outcome_digest": self.outcome_digest,
                }
            ),
        )

    def verify(self) -> bool:
        """Recompute the pin; True when untampered."""
        return self.digest == _digest_of(
            {
                "run_id": self.run_id,
                "round_id": self.round_id,
                "outcome_digest": self.outcome_digest,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "round_id": self.round_id,
            "outcome_digest": self.outcome_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": MULTI_AGENT_SCHEMA,
        }


# --- ledger -----------------------------------------------------------------


class MultiAgent:
    """A multi-agent run collaboration ledger.

    Books declared agent instances (``spawn``), declared coordination
    rounds with their participant sets and task pins (``coordinate``),
    and declared merged outcomes (``merge``). All mutations take a
    caller-supplied strictly increasing ``seq``; failed mutations
    consume their seq and book a ``"multi-agent.rejected"`` audit row
    (batch discipline). Round merge is terminal: a merged round cannot
    be merged again or reopened. Views consume no seq and write no
    audit rows.
    """

    def __init__(self, run_id: str):
        self._run_id = _check_run_id(run_id)
        self._lock = threading.RLock()
        self._last_seq = -1
        self._agents: Dict[str, AgentRecord] = {}
        self._rounds: Dict[str, CoordinationRecord] = {}
        self._round_state: Dict[str, str] = {}
        self._merges: Dict[str, MergeRecord] = {}
        self._audit: list = []

    # -- seq discipline --------------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)  # malformed seq raises, consumes nothing
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must strictly increase (last={self._last_seq}, got={seq})"
                )
            self._last_seq = seq
        return seq

    def _fail(self, seq: int, exc: MultiAgentError, **detail: Any) -> "None":
        """Book a rejection audit row, then raise the given error."""
        with self._lock:
            self._audit.append(
                multi_agent_audit_event(KIND_REJECTED, seq, reason=str(exc), **detail)
            )
        raise exc

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        with self._lock:
            self._audit.append(multi_agent_audit_event(kind, seq, **detail))

    # -- mutations --------------------------------------------------------------

    def spawn(self, agent_id: str, role: str, seq: int) -> AgentRecord:
        """Book one declared agent instance in this run."""
        seq = self._claim(seq)
        try:
            agent_id = _check_agent_id(agent_id)
            role = _check_role(role)
        except MultiAgentError as exc:
            self._fail(seq, exc)
        with self._lock:
            if agent_id in self._agents:
                self._fail(
                    seq,
                    DuplicateAgentError(f"agent already spawned: {agent_id!r}"),
                    agent_id=agent_id,
                )
            record = AgentRecord(
                run_id=self._run_id, agent_id=agent_id, role=role, seq=seq
            )
            self._agents[agent_id] = record
        self._emit(KIND_SPAWNED, seq, agent_id=agent_id, role=role)
        return record

    def coordinate(
        self,
        round_id: str,
        agent_ids: Sequence[str],
        seq: int,
        task_digest: str = "",
    ) -> CoordinationRecord:
        """Declare one coordination round over a task pin (starts open)."""
        seq = self._claim(seq)
        try:
            round_id = _check_round_id(round_id)
            participants = _check_participants(agent_ids, self._agents)
            task_digest = _check_digest(task_digest, "task_digest")
        except MultiAgentError as exc:
            self._fail(seq, exc)
        with self._lock:
            if round_id in self._rounds:
                self._fail(
                    seq,
                    DuplicateRoundError(f"round already booked: {round_id!r}"),
                    round_id=round_id,
                )
            record = CoordinationRecord(
                run_id=self._run_id,
                round_id=round_id,
                participants=participants,
                task_digest=task_digest,
                seq=seq,
            )
            self._rounds[round_id] = record
            self._round_state[round_id] = ROUND_OPEN
        self._emit(
            KIND_COORDINATED,
            seq,
            round_id=round_id,
            participants=list(participants),
        )
        return record

    def merge(
        self, round_id: str, outcome_digest: str, seq: int
    ) -> MergeRecord:
        """Book the declared merged outcome of an open round (terminal)."""
        seq = self._claim(seq)
        try:
            round_id = _check_round_id(round_id)
            outcome_digest = _check_digest(outcome_digest, "outcome_digest")
        except MultiAgentError as exc:
            self._fail(seq, exc)
        with self._lock:
            if round_id not in self._rounds:
                self._fail(
                    seq,
                    UnknownRoundError(f"no such round: {round_id!r}"),
                    round_id=round_id,
                )
            if self._round_state[round_id] != ROUND_OPEN:
                self._fail(
                    seq,
                    RoundStateError(
                        f"round {round_id!r} is already merged; cannot re-merge"
                    ),
                    round_id=round_id,
                )
            record = MergeRecord(
                run_id=self._run_id,
                round_id=round_id,
                outcome_digest=outcome_digest,
                seq=seq,
            )
            self._merges[round_id] = record
            self._round_state[round_id] = ROUND_MERGED
        self._emit(KIND_MERGED, seq, round_id=round_id)
        return record

    # -- views -----------------------------------------------------------------

    def agent(self, agent_id: str) -> Optional[AgentRecord]:
        """Pure read view of one spawned agent (None when unknown)."""
        agent_id = _check_agent_id(agent_id)
        with self._lock:
            return self._agents.get(agent_id)

    def agent_ids(self) -> Tuple[str, ...]:
        """Sorted ids of spawned agents; pure read."""
        with self._lock:
            return tuple(sorted(self._agents))

    def round(self, round_id: str) -> Optional[CoordinationRecord]:
        """Pure read view of one booked round (None when unknown)."""
        round_id = _check_round_id(round_id)
        with self._lock:
            return self._rounds.get(round_id)

    def round_ids(self) -> Tuple[str, ...]:
        """Sorted ids of booked rounds; pure read."""
        with self._lock:
            return tuple(sorted(self._rounds))

    def round_state(self, round_id: str) -> Optional[str]:
        """Pure read view of a round's lifecycle state."""
        round_id = _check_round_id(round_id)
        with self._lock:
            return self._round_state.get(round_id)

    def merge_record(self, round_id: str) -> Optional[MergeRecord]:
        """Pure read view of one round's merge (None when unmerged)."""
        round_id = _check_round_id(round_id)
        with self._lock:
            return self._merges.get(round_id)

    def stats(self) -> Mapping[str, Any]:
        """Pure read view of ledger counters."""
        with self._lock:
            return {
                "run_id": self._run_id,
                "agents": len(self._agents),
                "rounds_open": sum(
                    1 for s in self._round_state.values() if s == ROUND_OPEN
                ),
                "rounds_merged": sum(
                    1 for s in self._round_state.values() if s == ROUND_MERGED
                ),
                "audit_rows": len(self._audit),
                "schema": MULTI_AGENT_SCHEMA,
            }

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        """Pure read view of the audit event list."""
        with self._lock:
            return tuple(dict(row) for row in self._audit)


def main() -> None:
    run = MultiAgent("run-1")
    rec_a = run.spawn("alice", ROLE_PLANNER, 1)
    rec_b = run.spawn("bob", ROLE_WORKER, 2)
    assert rec_a.verify() and rec_b.verify()
    task_pin = _pin_bytes(b"task: summarise the plan")
    coord = run.coordinate("r1", ["bob", "alice"], 3, task_digest=task_pin)
    assert coord.verify()
    assert coord.participants == ("alice", "bob")
    assert run.round_state("r1") == ROUND_OPEN
    outcome_pin = _pin_bytes(b"outcome: plan summarised")
    merged = run.merge("r1", outcome_pin, 4)
    assert merged.verify()
    assert run.round_state("r1") == ROUND_MERGED
    print("multi-agent OK: spawn, coordinate, merge, pins, audit")


if __name__ == "__main__":
    main()
