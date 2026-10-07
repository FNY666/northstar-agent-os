"""Cooperative Inverse Reinforcement Learning (CIRL) decision ledger, Simulated.

Research note: CIRL (Hadfield-Menell, Dragan, Abbeel, Russell, 2016)
frames value alignment as a cooperative, partial-information game between a
human principal (H) and a robot agent (R): both share a common reward
parameterized by ``theta``, the human knows ``theta`` and the robot does
not. The robot must learn ``theta`` from the human's behavior - demonstrations,
comparisons, corrections, approvals - while acting under uncertainty about
the true objective. The CIRL formalization justifies humility: a robot that
books uncertainty into its beliefs should prefer cautious, corrigible,
information-seeking behavior over optimizing a guess. The dangerous half
of a real CIRL run is the raw material: human trajectories, reward weights,
preference labels, corrections. Those must never be bundled with the
bookkeeping record that tracks the interaction.

This module is that bookkeeping layer. It:

* **interact()** - book one declared human-robot CIRL interaction (minted
  ``int-N`` ids) over a pinned interaction-kind vocabulary; the first
  interaction on an id registers the agent; raw trajectories, prompts,
  demonstrations and reward material travel as ``sha256:`` digest pins only.
* **learn()** - book one declared reward-model learning outcome (minted
  ``lrn-N`` ids) over a pinned method vocabulary with a pinned belief
  outcome (``confident`` / ``uncertain`` / ``conflicted`` / ``unknown``)
  booked **as data**, never proof the agent actually learned the human's
  objective.
* **evaluate()** - pure-read derived CIRL posture of one agent, as data.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``cirl.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked interaction is a host-declared claim, never proof a
human actually demonstrated, corrected, or approved anything; a booked
``confident`` belief is declared data, never proof the robot knows the true
reward; an ``aligned-learning`` posture means the ledger's rule was
satisfied, never that the agent is actually aligned; no interaction is
performed and no reward is learned here.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
CIRL_VERSION = "cirl.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.cirl.v1"

#: Pinned interaction-kind vocabulary (declared, never proof a real CIRL
#: interaction took place).
INTERACTION_KINDS = (
    "demonstration",
    "comparison",
    "correction",
    "instruction",
    "query-response",
    "approval",
    "oversight-check",
    "shutdown-acceptance",
)

#: Pinned reward-learning method vocabulary (declared, never proof of a
#: real learning step).
LEARN_METHODS = (
    "irl",
    "preference-learning",
    "demonstration-learning",
    "correction-learning",
    "active-learning",
    "offline-cirl",
    "interactive-cirl",
    "cooperative-inference",
)

#: Pinned belief-outcome vocabulary (declared data, never measured truth).
BELIEF_OUTCOMES = (
    "confident",
    "uncertain",
    "conflicted",
    "unknown",
)

#: Pinned derived postures for evaluate().
POSTURES = (
    "unevaluated",
    "uninformed",
    "conflicted",
    "unknown",
    "uncertain",
    "confident-learning",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "interacted",
    "learned",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "trajectory",
        "trajectories",
        "demonstration",
        "correction",
        "instruction",
        "prompt",
        "prompts",
        "response",
        "responses",
        "weights",
        "reward",
        "rewards",
        "preference",
        "preferences",
        "label",
        "labels",
        "evidence",
        "text",
        "content",
        "data",
        "raw",
        "notes",
        "note",
        "secret",
        "details",
        "detail",
        "description",
        "human",
        "theta",
        "belief",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CIIRError(Exception):
    """Base error for CIRL-ledger misuse."""


class BadIdError(CIIRError):
    """Malformed agent / interaction / learning id."""


class BadDigestError(CIIRError):
    """Malformed sha256: digest pin."""


class BadKindError(CIIRError):
    """Interaction kind outside the pinned vocabulary."""


class BadMethodError(CIIRError):
    """Learning method outside the pinned vocabulary."""


class BadOutcomeError(CIIRError):
    """Belief outcome outside the pinned vocabulary."""


class UnknownAgentError(CIIRError):
    """Reference to an agent id that was never registered."""


class UnknownInteractionError(CIIRError):
    """Reference to an interaction id that was never booked."""


class SeqOrderError(CIIRError):
    """Caller seq did not strictly increase."""


class AuditKindError(CIIRError):
    """Unknown audit kind or banned raw key in an audit row."""


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_optional_digest(pin: str, field_name: str) -> str:
    if pin == "":
        return pin
    return _require_digest(pin, field_name)


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InteractionRecord:
    """One declared CIRL interaction (minted int-N ids)."""

    interaction_id: str
    agent_id: str
    kind: str
    interaction_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "interaction_id": self.interaction_id,
            "agent_id": self.agent_id,
            "kind": self.kind,
            "interaction_digest": self.interaction_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "interaction_id": self.interaction_id,
                "agent_id": self.agent_id,
                "kind": self.kind,
                "interaction_digest": self.interaction_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class LearningRecord:
    """One declared reward-model learning outcome (minted lrn-N ids)."""

    learning_id: str
    agent_id: str
    method: str
    belief_outcome: str
    belief_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "learning_id": self.learning_id,
            "agent_id": self.agent_id,
            "method": self.method,
            "belief_outcome": self.belief_outcome,
            "belief_digest": self.belief_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "learning_id": self.learning_id,
                "agent_id": self.agent_id,
                "method": self.method,
                "belief_outcome": self.belief_outcome,
                "belief_digest": self.belief_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class EvaluationReport:
    """Derived CIRL posture of one agent (pure read, as data)."""

    agent_id: str
    n_interactions: int
    n_learnings: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "agent_id": self.agent_id,
            "n_interactions": self.n_interactions,
            "n_learnings": self.n_learnings,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "agent_id": self.agent_id,
                "n_interactions": self.n_interactions,
                "n_learnings": self.n_learnings,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def cirl_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the CIRL ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class CIRL:
    """CIRL decision ledger (Simulated).

    ``interact()`` / ``learn()`` mutate the ledger and consume caller seqs;
    ``evaluate()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._agents: Dict[str, None] = {}
        self._interactions: Dict[str, InteractionRecord] = {}
        self._agent_interactions: Dict[str, List[str]] = {}
        self._learnings: Dict[str, LearningRecord] = {}
        self._agent_learnings: Dict[str, List[str]] = {}
        self._int_counter = 0
        self._lrn_counter = 0
        self._audit: List[Dict[str, Any]] = []

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _require_read_seq(self, seq: int) -> int:
        """Validate a read seq (shape only: non-negative int, no consumption)."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("read seq must be a non-negative int")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = cirl_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(cirl_audit_event(audit_kind, seq, **details))

    def _register(self, agent_id: str) -> None:
        if agent_id not in self._agents:
            self._agents[agent_id] = None

    def _require_live(self, agent_id: str) -> None:
        if agent_id not in self._agents:
            raise UnknownAgentError(f"unknown agent: {agent_id!r}")

    # -- interact -------------------------------------------------------------

    def interact(
        self,
        agent_id: str,
        seq: int,
        kind: str = "demonstration",
        interaction_digest: str = "",
    ) -> InteractionRecord:
        """Book one declared CIRL interaction.

        The first interaction on an id registers the agent; raw human
        behavior, demonstrations, and corrections never enter records
        (digest pins only).
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(agent_id, "agent_id")
                if kind not in INTERACTION_KINDS:
                    raise BadKindError(f"bad interaction kind: {kind!r}")
                interaction_digest = _require_optional_digest(
                    interaction_digest, "interaction_digest"
                )
                self._register(agent_id)
                self._int_counter += 1
                interaction_id = f"int-{self._int_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "interaction_id": interaction_id,
                        "agent_id": agent_id,
                        "kind": kind,
                        "interaction_digest": interaction_digest,
                        "seq": seq,
                    }
                )
                record = InteractionRecord(
                    interaction_id=interaction_id,
                    agent_id=agent_id,
                    kind=kind,
                    interaction_digest=interaction_digest,
                    seq=seq,
                    digest=digest,
                )
                self._interactions[interaction_id] = record
                self._agent_interactions.setdefault(agent_id, []).append(
                    interaction_id
                )
                self._emit(
                    "interacted",
                    seq,
                    interaction_id=interaction_id,
                    agent_id=agent_id,
                )
                return record
            except CIIRError:
                self._burn(seq, "interact")
                raise

    # -- learn -----------------------------------------------------------------

    def learn(
        self,
        agent_id: str,
        seq: int,
        method: str = "irl",
        belief_outcome: str = "uncertain",
        belief_digest: str = "",
    ) -> LearningRecord:
        """Book one declared reward-model learning outcome.

        The belief outcome is host-declared data - never proof the agent
        actually learned the human's objective. Requires a registered agent.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(agent_id, "agent_id")
                if method not in LEARN_METHODS:
                    raise BadMethodError(f"bad learn method: {method!r}")
                if belief_outcome not in BELIEF_OUTCOMES:
                    raise BadOutcomeError(
                        f"bad belief outcome: {belief_outcome!r}"
                    )
                belief_digest = _require_optional_digest(
                    belief_digest, "belief_digest"
                )
                self._require_live(agent_id)
                self._lrn_counter += 1
                learning_id = f"lrn-{self._lrn_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "learning_id": learning_id,
                        "agent_id": agent_id,
                        "method": method,
                        "belief_outcome": belief_outcome,
                        "belief_digest": belief_digest,
                        "seq": seq,
                    }
                )
                record = LearningRecord(
                    learning_id=learning_id,
                    agent_id=agent_id,
                    method=method,
                    belief_outcome=belief_outcome,
                    belief_digest=belief_digest,
                    seq=seq,
                    digest=digest,
                )
                self._learnings[learning_id] = record
                self._agent_learnings.setdefault(agent_id, []).append(
                    learning_id
                )
                self._emit(
                    "learned",
                    seq,
                    learning_id=learning_id,
                    agent_id=agent_id,
                    method=method,
                    belief_outcome=belief_outcome,
                )
                return record
            except CIIRError:
                self._burn(seq, "learn")
                raise

    # -- evaluate (pure read) ---------------------------------------------------

    def evaluate(self, agent_id: str, seq: int) -> EvaluationReport:
        """Derived CIRL posture of one agent, as data.

        Posture rules (ledger data, never measured truth):
        - ``unevaluated`` when the agent has no booked interactions
        - ``uninformed`` when it has interactions but no booked learnings
        - ``conflicted`` when any booked belief outcome is ``conflicted``
        - ``unknown`` when any booked belief outcome is ``unknown``
        - ``confident-learning`` when every booked belief is ``confident``
        - ``uncertain`` otherwise
        """
        with self._lock:
            self._require_read_seq(seq)
            _require_id(agent_id, "agent_id")
            if agent_id not in self._agents:
                raise UnknownAgentError(f"unknown agent: {agent_id!r}")
            int_ids = self._agent_interactions.get(agent_id, ())
            lrn_ids = self._agent_learnings.get(agent_id, ())
            outcomes = {self._learnings[lid].belief_outcome for lid in lrn_ids}
            integrity = all(
                self._interactions[iid].verify() for iid in int_ids
            ) and all(self._learnings[lid].verify() for lid in lrn_ids)
            if not int_ids:
                posture = "unevaluated"
            elif not lrn_ids:
                posture = "uninformed"
            elif "conflicted" in outcomes:
                posture = "conflicted"
            elif "unknown" in outcomes:
                posture = "unknown"
            elif outcomes == {"confident"}:
                posture = "confident-learning"
            else:
                posture = "uncertain"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "agent_id": agent_id,
                    "n_interactions": len(int_ids),
                    "n_learnings": len(lrn_ids),
                    "posture": posture,
                    "integrity_ok": integrity,
                }
            )
            return EvaluationReport(
                agent_id=agent_id,
                n_interactions=len(int_ids),
                n_learnings=len(lrn_ids),
                posture=posture,
                integrity_ok=integrity,
                digest=digest,
            )

    # -- views (pure reads) -----------------------------------------------------

    def interaction_record(
        self, interaction_id: str, seq: int
    ) -> InteractionRecord:
        """Return one interaction record (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(interaction_id, "interaction_id")
            if interaction_id not in self._interactions:
                raise UnknownInteractionError(
                    f"unknown interaction: {interaction_id!r}"
                )
            return self._interactions[interaction_id]

    def learning_record(self, learning_id: str, seq: int) -> LearningRecord:
        """Return one learning record (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(learning_id, "learning_id")
            if learning_id not in self._learnings:
                raise UnknownInteractionError(
                    f"unknown learning: {learning_id!r}"
                )
            return self._learnings[learning_id]

    def interactions_for(
        self, agent_id: str, seq: int
    ) -> Tuple[str, ...]:
        """Interaction ids booked for one agent, in mint order (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(agent_id, "agent_id")
            self._require_live(agent_id)
            return tuple(self._agent_interactions.get(agent_id, ()))

    def learnings_for(self, agent_id: str, seq: int) -> Tuple[str, ...]:
        """Learning ids booked for one agent, in mint order (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(agent_id, "agent_id")
            self._require_live(agent_id)
            return tuple(self._agent_learnings.get(agent_id, ()))

    def agent_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered agent ids in registration order (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._agents.keys())

    def interaction_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked interaction ids in mint order (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._interactions.keys())

    def learning_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked learning ids in mint order (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._learnings.keys())

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            return {
                "agents": len(self._agents),
                "interactions": len(self._interactions),
                "learnings": len(self._learnings),
                "rejected": sum(
                    1 for row in self._audit if row["kind"] == "rejected"
                ),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the CIRL ledger end to end."""
    c = CIRL()
    i1 = c.interact("a-1", 1, kind="demonstration")
    assert i1.interaction_id == "int-1"
    l1 = c.learn("a-1", 2, method="irl", belief_outcome="confident")
    assert l1.learning_id == "lrn-1"
    assert c.evaluate("a-1", 3).posture == "confident-learning"
    c.interact("a-1", 4, kind="correction")
    c.learn("a-1", 5, method="correction-learning", belief_outcome="conflicted")
    assert c.evaluate("a-1", 6).posture == "conflicted"
    assert c.stats(7) == {
        "agents": 1,
        "interactions": 2,
        "learnings": 2,
        "rejected": 0,
    }
    print("cirl OK: interact, learn, evaluate, pins, audit")


if __name__ == "__main__":
    main()
