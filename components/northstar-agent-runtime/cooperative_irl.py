"""Cooperative IRL decision ledger for human-robot team alignment, Simulated.

Research note: Cooperative Inverse Reinforcement Learning
(Hadfield-Menell et al., 2016) frames alignment as a two-player
cooperative game: the human and the robot share a reward function that is
known to the human but unknown to the robot. The robot must infer the
human's preferences through interaction - demonstrations, instructions,
corrections, feedback - while acting helpfully. The dangerous half of such
a game is the raw material: human identities, demonstration transcripts,
instruction text, belief states, reward guesses. Those must never be
bundled with the bookkeeping record that tracks the game's lifecycle.

This module is that bookkeeping layer. It:

* **register_team()** - declare one human-robot team (user-supplied team
  id); human/robot identities travel as ``sha256:`` digest pins only.
* **interact()** - book one declared interaction turn (minted ``int-N``
  ids) over a pinned role vocabulary (``human``/``robot``) and a pinned
  action-kind vocabulary; raw demonstration/instruction text travels as
  digest pins only.
* **learn()** - book one declared belief update over the shared reward
  (minted ``lrn-N`` ids) over a pinned learning-kind vocabulary and a
  pinned outcome vocabulary; booked as data, never proof the robot's
  beliefs actually improved.
* **evaluate()** - pure-read derived cooperation posture per team, as
  data.
* **retire()** - terminal; retired ids are never recycled.

Distinct-layer rationale: ``irl.py`` owns the standard observe/infer
lifecycle, ``preference_learning.py`` owns preference-pair collection,
``value_learning.py`` owns value inference from observations - this module
is the *cooperative game* decision ledger none of them own: declared
human-robot interaction turns and declared belief updates, with derived
cooperation posture booked as data.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``cooperative-irl.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked ``cooperative`` posture is a ledger verdict derived
from host-declared outcomes, never proof the robot actually shares the
human's reward; a booked ``improved`` belief update is the host's
declaration, never evidence the robot learned anything real; a booked
``misaligned`` posture is the ledger's reading of declared regressions,
never proof of a real value divergence.
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
COOPERATIVE_IRL_VERSION = "cooperative-irl.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.cooperative-irl.v1"

#: Pinned player-role vocabulary (declared, never proof of who acted).
ROLES = (
    "human",
    "robot",
)

#: Pinned interaction action-kind vocabulary (declared, never proof a
#: real demonstration or instruction occurred).
ACTION_KINDS = (
    "demonstration",
    "instruction",
    "correction",
    "feedback",
    "collaboration",
    "query",
    "guidance",
    "approval",
)

#: Pinned belief-update (learning) kind vocabulary (declared).
LEARNING_KINDS = (
    "reward-inference",
    "preference-update",
    "value-belief-shift",
    "strategy-refinement",
    "deference-increase",
    "communication-refinement",
)

#: Pinned learning-outcome vocabulary (declared, never proof of learning).
LEARNING_OUTCOMES = (
    "improved",
    "regressed",
    "unchanged",
    "inconclusive",
)

#: Pinned derived cooperation postures for evaluate().
POSTURES = (
    "uncoordinated",
    "misaligned",
    "inconclusive",
    "cooperative",
)

#: Pinned retirement reasons.
RETIRE_REASONS = (
    "manual",
    "team-complete",
    "team-disbanded",
    "superseded",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "teamed",
    "interacted",
    "learned",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "human",
        "robot",
        "human_id",
        "robot_id",
        "demonstration",
        "instruction",
        "correction",
        "feedback",
        "transcript",
        "action",
        "action_text",
        "belief",
        "belief_text",
        "belief_state",
        "reward",
        "reward_guess",
        "preferences",
        "preference",
        "policy",
        "weights",
        "trace",
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
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CooperativeIRLError(Exception):
    """Base error for cooperative-IRL ledger misuse."""


class BadIdError(CooperativeIRLError):
    """Malformed team / interaction / learning id."""


class BadDigestError(CooperativeIRLError):
    """Malformed sha256: digest pin."""


class BadRoleError(CooperativeIRLError):
    """Role outside the pinned vocabulary."""


class BadActionKindError(CooperativeIRLError):
    """Action kind outside the pinned vocabulary."""


class BadLearningKindError(CooperativeIRLError):
    """Learning kind outside the pinned vocabulary."""


class BadOutcomeError(CooperativeIRLError):
    """Learning outcome outside the pinned vocabulary."""


class UnknownTeamError(CooperativeIRLError):
    """Reference to a team id that was never registered."""


class DuplicateTeamError(CooperativeIRLError):
    """A team id was already registered (ids are never recycled)."""


class RetiredTeamError(CooperativeIRLError):
    """Mutation attempted against a retired team."""


class BadReasonError(CooperativeIRLError):
    """Retirement reason outside the pinned vocabulary."""


class SeqOrderError(CooperativeIRLError):
    """Caller seq did not strictly increase."""


class AuditKindError(CooperativeIRLError):
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
class TeamRecord:
    """One declared human-robot team (user-supplied team id)."""

    team_id: str
    human_digest: str
    robot_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "team_id": self.team_id,
            "human_digest": self.human_digest,
            "robot_digest": self.robot_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "team_id": self.team_id,
                "human_digest": self.human_digest,
                "robot_digest": self.robot_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class InteractionRecord:
    """One declared interaction turn (minted int-N ids)."""

    interaction_id: str
    team_id: str
    role: str
    action_kind: str
    action_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "interaction_id": self.interaction_id,
            "team_id": self.team_id,
            "role": self.role,
            "action_kind": self.action_kind,
            "action_digest": self.action_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "interaction_id": self.interaction_id,
                "team_id": self.team_id,
                "role": self.role,
                "action_kind": self.action_kind,
                "action_digest": self.action_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class LearningRecord:
    """One declared belief update over the shared reward (minted lrn-N)."""

    learning_id: str
    team_id: str
    learning_kind: str
    outcome: str
    belief_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "learning_id": self.learning_id,
            "team_id": self.team_id,
            "learning_kind": self.learning_kind,
            "outcome": self.outcome,
            "belief_digest": self.belief_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "learning_id": self.learning_id,
                "team_id": self.team_id,
                "learning_kind": self.learning_kind,
                "outcome": self.outcome,
                "belief_digest": self.belief_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a team's cooperative game."""

    team_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "team_id": self.team_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "team_id": self.team_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class CooperationReport:
    """Pure-read derived cooperation posture of one team."""

    team_id: str
    n_interactions: int
    n_learning: int
    n_improved: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "team_id": self.team_id,
            "n_interactions": self.n_interactions,
            "n_learning": self.n_learning,
            "n_improved": self.n_improved,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "team_id": self.team_id,
                "n_interactions": self.n_interactions,
                "n_learning": self.n_learning,
                "n_improved": self.n_improved,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def cooperative_irl_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the cooperative-IRL ledger."""
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


class CooperativeIRL:
    """Cooperative-IRL game ledger (Simulated).

    ``register_team()`` / ``interact()`` / ``learn()`` / ``retire()``
    mutate the ledger and consume caller seqs; ``evaluate()`` and all
    views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._teams: Dict[str, TeamRecord] = {}
        self._interactions: Dict[str, InteractionRecord] = {}
        self._learnings: Dict[str, LearningRecord] = {}
        self._team_interactions: Dict[str, List[str]] = {}
        self._team_learnings: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._interaction_counter = 0
        self._learning_counter = 0
        self._audit: List[Dict[str, Any]] = []

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = cooperative_irl_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(cooperative_irl_audit_event(audit_kind, seq, **details))

    def _require_known(self, team_id: str) -> None:
        if team_id not in self._teams:
            raise UnknownTeamError(f"team was never registered: {team_id!r}")

    def _require_live(self, team_id: str) -> None:
        self._require_known(team_id)
        if team_id in self._retired:
            raise RetiredTeamError(f"team is retired: {team_id!r}")

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: only stdlib imports (+ the in-repo sibling)."""
        import ast as _ast
        import pathlib as _pathlib
        allowed = {"__future__", "threading", "dataclasses", "hashlib",
                   "json", "typing", "canonical_json", "ast", "pathlib"}
        tree = _ast.parse(_pathlib.Path(__file__).read_text())
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] not in allowed:
                        return False
            elif isinstance(node, _ast.ImportFrom) and node.module:
                if node.module.split(".")[0] not in allowed:
                    return False
        return True

    # -- register_team --------------------------------------------------------

    def register_team(
        self,
        team_id: str,
        seq: int,
        human_digest: str = "",
        robot_digest: str = "",
    ) -> TeamRecord:
        """Declare one human-robot team.

        Player identities travel as ``sha256:`` digest pins only; raw
        identities never enter records.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(team_id, "team_id")
                human_digest = _require_optional_digest(human_digest, "human_digest")
                robot_digest = _require_optional_digest(robot_digest, "robot_digest")
                if team_id in self._teams:
                    raise DuplicateTeamError(f"team already registered: {team_id!r}")
                if team_id in self._retired:
                    raise DuplicateTeamError(f"team id was retired, never recycled: {team_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "team_id": team_id,
                        "human_digest": human_digest,
                        "robot_digest": robot_digest,
                        "seq": seq,
                    }
                )
                record = TeamRecord(
                    team_id=team_id,
                    human_digest=human_digest,
                    robot_digest=robot_digest,
                    seq=seq,
                    digest=digest,
                )
                self._teams[team_id] = record
                self._team_interactions[team_id] = []
                self._team_learnings[team_id] = []
                self._emit(
                    "teamed",
                    seq,
                    team_id=team_id,
                )
                return record
            except CooperativeIRLError:
                self._burn(seq, "register_team")
                raise

    # -- interact ---------------------------------------------------------------

    def interact(
        self,
        team_id: str,
        seq: int,
        role: str = "human",
        action_kind: str = "demonstration",
        action_digest: str = "",
    ) -> InteractionRecord:
        """Book one declared interaction turn for a team.

        Raw demonstration/instruction text never enters records - the
        action payload travels as a ``sha256:`` digest pin only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(team_id, "team_id")
                if role not in ROLES:
                    raise BadRoleError(f"bad role: {role!r}")
                if action_kind not in ACTION_KINDS:
                    raise BadActionKindError(f"bad action kind: {action_kind!r}")
                action_digest = _require_optional_digest(action_digest, "action_digest")
                self._require_live(team_id)
                self._interaction_counter += 1
                interaction_id = f"int-{self._interaction_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "interaction_id": interaction_id,
                        "team_id": team_id,
                        "role": role,
                        "action_kind": action_kind,
                        "action_digest": action_digest,
                        "seq": seq,
                    }
                )
                record = InteractionRecord(
                    interaction_id=interaction_id,
                    team_id=team_id,
                    role=role,
                    action_kind=action_kind,
                    action_digest=action_digest,
                    seq=seq,
                    digest=digest,
                )
                self._interactions[interaction_id] = record
                self._team_interactions[team_id].append(interaction_id)
                self._emit(
                    "interacted",
                    seq,
                    interaction_id=interaction_id,
                    team_id=team_id,
                    role=role,
                    action_kind=action_kind,
                )
                return record
            except CooperativeIRLError:
                self._burn(seq, "interact")
                raise

    # -- learn -------------------------------------------------------------------

    def learn(
        self,
        team_id: str,
        seq: int,
        learning_kind: str = "reward-inference",
        outcome: str = "inconclusive",
        belief_digest: str = "",
    ) -> LearningRecord:
        """Book one declared belief update over the shared reward.

        The outcome is booked as data, never proof the robot's beliefs
        actually improved; the belief state travels as a ``sha256:``
        digest pin only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(team_id, "team_id")
                if learning_kind not in LEARNING_KINDS:
                    raise BadLearningKindError(f"bad learning kind: {learning_kind!r}")
                if outcome not in LEARNING_OUTCOMES:
                    raise BadOutcomeError(f"bad learning outcome: {outcome!r}")
                belief_digest = _require_optional_digest(belief_digest, "belief_digest")
                self._require_live(team_id)
                self._learning_counter += 1
                learning_id = f"lrn-{self._learning_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "learning_id": learning_id,
                        "team_id": team_id,
                        "learning_kind": learning_kind,
                        "outcome": outcome,
                        "belief_digest": belief_digest,
                        "seq": seq,
                    }
                )
                record = LearningRecord(
                    learning_id=learning_id,
                    team_id=team_id,
                    learning_kind=learning_kind,
                    outcome=outcome,
                    belief_digest=belief_digest,
                    seq=seq,
                    digest=digest,
                )
                self._learnings[learning_id] = record
                self._team_learnings[team_id].append(learning_id)
                self._emit(
                    "learned",
                    seq,
                    learning_id=learning_id,
                    team_id=team_id,
                    learning_kind=learning_kind,
                    outcome=outcome,
                )
                return record
            except CooperativeIRLError:
                self._burn(seq, "learn")
                raise

    # -- retire -------------------------------------------------------------------

    def retire(self, team_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a team's cooperative game.

        Retired ids are never recycled; post-retire mutations are refused,
        reads still work.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(team_id, "team_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                self._require_known(team_id)
                if team_id in self._retired:
                    raise RetiredTeamError(f"team already retired: {team_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "team_id": team_id,
                        "reason": reason,
                        "seq": seq,
                    }
                )
                record = RetireRecord(
                    team_id=team_id, reason=reason, seq=seq, digest=digest
                )
                self._retired[team_id] = record
                self._emit("retired", seq, team_id=team_id, reason=reason)
                return record
            except CooperativeIRLError:
                self._burn(seq, "retire")
                raise

    # -- evaluate (pure read) -------------------------------------------------------

    def evaluate(self, team_id: str, seq: int) -> CooperationReport:
        """Derived cooperation posture of one team, as data.

        Posture rules (ledger data, never measured truth):
        - ``uncoordinated`` when the team has no booked interactions
        - ``inconclusive`` when interactions exist but no learning was booked
        - ``misaligned`` when any booked learning outcome is ``regressed``
        - ``inconclusive`` when any booked learning outcome is
          ``inconclusive`` (and none is ``regressed``)
        - ``cooperative`` when at least one learning outcome is
          ``improved`` (and none is worse)
        - ``inconclusive`` when every booked learning outcome is
          ``unchanged``
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(team_id, "team_id")
            self._require_known(team_id)
            int_ids = self._team_interactions[team_id]
            lrn_ids = self._team_learnings[team_id]
            outcomes = {self._learnings[lid].outcome for lid in lrn_ids}
            n_improved = sum(
                1 for lid in lrn_ids if self._learnings[lid].outcome == "improved"
            )
            if not int_ids:
                posture = "uncoordinated"
            elif not lrn_ids:
                posture = "inconclusive"
            elif "regressed" in outcomes:
                posture = "misaligned"
            elif "inconclusive" in outcomes:
                posture = "inconclusive"
            elif "improved" in outcomes:
                posture = "cooperative"
            else:
                posture = "inconclusive"
            all_ok = all(
                self._interactions[iid].verify() for iid in int_ids
            ) and all(self._learnings[lid].verify() for lid in lrn_ids)
            record = CooperationReport(
                team_id=team_id,
                n_interactions=len(int_ids),
                n_learning=len(lrn_ids),
                n_improved=n_improved,
                posture=posture,
                integrity_ok=all_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "team_id": team_id,
                        "n_interactions": len(int_ids),
                        "n_learning": len(lrn_ids),
                        "n_improved": n_improved,
                        "posture": posture,
                        "integrity_ok": all_ok,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return record

    # -- views (pure reads) ------------------------------------------------------

    def team_record(self, team_id: str, seq: int) -> TeamRecord:
        """Return one team record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(team_id, "team_id")
            self._require_known(team_id)
            return self._teams[team_id]

    def interaction_record(self, interaction_id: str, seq: int) -> InteractionRecord:
        """Return one interaction record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(interaction_id, "interaction_id")
            if interaction_id not in self._interactions:
                raise BadIdError(f"unknown interaction: {interaction_id!r}")
            return self._interactions[interaction_id]

    def learning_record(self, learning_id: str, seq: int) -> LearningRecord:
        """Return one learning record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(learning_id, "learning_id")
            if learning_id not in self._learnings:
                raise BadIdError(f"unknown learning: {learning_id!r}")
            return self._learnings[learning_id]

    def team_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered team ids in registration order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._teams.keys())

    def interaction_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked interaction ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._interactions.keys())

    def learning_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked learning ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._learnings.keys())

    def interactions_for(self, team_id: str, seq: int) -> Tuple[str, ...]:
        """Interaction ids booked against one team, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(team_id, "team_id")
            self._require_known(team_id)
            return tuple(self._team_interactions[team_id])

    def learnings_for(self, team_id: str, seq: int) -> Tuple[str, ...]:
        """Learning ids booked against one team, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(team_id, "team_id")
            self._require_known(team_id)
            return tuple(self._team_learnings[team_id])

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired team ids (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "teams": len(self._teams),
                "interactions": len(self._interactions),
                "learnings": len(self._learnings),
                "retired": len(self._retired),
                "rejected": sum(
                    1 for row in self._audit if row["kind"] == "rejected"
                ),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the cooperative-IRL ledger end to end."""
    c = CooperativeIRL()
    t = c.register_team("team-1", 1, human_digest=_digest_pin({"h": 1}))
    assert t.verify()
    i1 = c.interact("team-1", 2, role="human", action_kind="demonstration")
    c.interact("team-1", 3, role="robot", action_kind="query")
    c.learn("team-1", 4, learning_kind="reward-inference", outcome="improved")
    rep = c.evaluate("team-1", 5)
    assert rep.posture == "cooperative"
    assert rep.n_interactions == 2 and rep.n_learning == 1 and rep.n_improved == 1
    assert rep.integrity_ok
    assert i1.interaction_id == "int-1"
    assert c.interactions_for("team-1", 6) == ("int-1", "int-2")
    assert c.stats(7)["rejected"] == 0
    print("cooperative-irl OK: register, interact, learn, evaluate, pins, audit")


if __name__ == "__main__":
    main()
