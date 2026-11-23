"""Inverse Reinforcement Learning (observe/infer/evaluate) interface, simulated.

Research motivation: Ng & Russell (2000) framed the inverse problem --
given observed behavior, recover a reward function the behavior is (near-)
optimal for -- and its successors (maximum-entropy IRL / Ziebart 2008,
 apprenticeship learning / Abbeel & Ng 2004, GAIL / Ho & Ermon 2016,
AIRL / Fu et al. 2018) reduce preference inference to one operational
shape: the host declares observed trajectories, the host declares an
inferred reward model, and the ledger books both as data.

This module is the *IRL ledger* half of that shape:

- ``IRL.observe(trajectory_id, agent_id, seq, trajectory_digest="")``
  -- book one declared observation of expert behavior. Raw state-action
  sequences never enter a record; the trajectory travels as a
  ``sha256:`` digest pin only.
- ``IRL.infer(agent_id, seq, method="maximum-entropy", reward_digest="")``
  -- book one declared reward inference for the agent over the pinned
  method vocabulary. The inferred reward is *host-reported data* --
  the module ran no optimizer, solved no MDP, and recovered nothing.
- ``IRL.evaluate(agent_id, seq)`` -- pure read view: frozen
  ``InferenceReport`` with counts, latest inference, and
  ``integrity_ok`` derived as data (tamper reported, never raised).
- ``IRL.retire(agent_id, seq, reason="manual")`` -- terminal; retired
  ids are never recycled; post-retire mutations are refused, reads
  still work.
- ``irl_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``observed`` / ``inferred`` / ``retired`` / ``rejected``);
  caller-supplied seqs only. Raw trajectories, reward weights, and
  feature maps never cross the audit boundary -- audit rows carry
  ids, method names, digests, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``trajectory_id`` / ``agent_id`` must be non-empty str, <= 256
  chars, no whitespace.
- ``trajectory_digest`` / ``reward_digest`` must be ``sha256:<64hex>``
  pins (validated when supplied; may be empty for observations).
- ``method`` must be in the pinned vocabulary.
- ``infer`` on an unknown agent raises ``UnknownAgentError``;
  one inference per agent is not required -- repeatable as a chain.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* trajectories and *host-reported*
  reward inferences. A booked ``maximum-entropy`` inference means the
  host reported that method -- the module solved no inverse problem,
  sampled no trajectories, and proves nothing about any real agent's
  preferences or intent.
- Digests pin inputs; verification re-derives them. A ``True`` from
  ``verify()`` means "this record's pins match its payload", never
  "the reward is correct".
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if IRL state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
IRL_VERSION = "irl.v1"

#: Schema pin carried by records and audit events.
SCHEMA_PIN = "northstar.irl.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
AUDIT_KINDS = ("observed", "inferred", "retired", "rejected")

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_AUDIT_KEYS = frozenset(
    {"trajectory", "trajectories", "reward", "rewards", "weights",
     "features", "feature_map", "states", "actions", "content",
     "text", "payload", "raw", "evidence"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned IRL method vocabulary. Methods are bookkeeping labels, not claims.
METHOD_NG_RUSSELL = "ng-and-russell"
METHOD_MAX_ENTROPY = "maximum-entropy"
METHOD_APPRENTICESHIP = "apprenticeship"
METHOD_GAIL = "gail"
METHOD_AIRL = "airl"
METHOD_BAIR = "bair"
METHOD_MAX_MARGIN = "max-margin"
METHOD_BEHAVIORAL_CLONE = "behavioral-cloning"
INFERENCE_METHODS = (
    METHOD_NG_RUSSELL,
    METHOD_MAX_ENTROPY,
    METHOD_APPRENTICESHIP,
    METHOD_GAIL,
    METHOD_AIRL,
    METHOD_BAIR,
    METHOD_MAX_MARGIN,
    METHOD_BEHAVIORAL_CLONE,
)

#: Pinned inference-outcome vocabulary. Outcomes are data, never truth.
OUTCOME_RECOVERED = "recovered"
OUTCOME_AMBIGUOUS = "ambiguous"
OUTCOME_INCONCLUSIVE = "inconclusive"
INFERENCE_OUTCOMES = (OUTCOME_RECOVERED, OUTCOME_AMBIGUOUS, OUTCOME_INCONCLUSIVE)

#: Pinned retire-reason vocabulary.
RETIRE_REASONS = ("manual", "task-complete", "superseded", "stale")

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class IRLError(Exception):
    """Base error for the IRL ledger (fail-closed)."""


class BadIdError(IRLError):
    """Raised when a trajectory/agent id is malformed."""


class BadDigestError(IRLError):
    """Raised when a digest is not a sha256: pin (when non-empty)."""


class BadMethodError(IRLError):
    """Raised when an inference method is not in the pinned vocabulary."""


class BadOutcomeError(IRLError):
    """Raised when an inference outcome is not in the pinned vocabulary."""


class BadReasonError(IRLError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class DuplicateTrajectoryError(IRLError):
    """Raised when a trajectory id is observed twice."""


class UnknownAgentError(IRLError):
    """Raised when an agent id names no observed agent."""


class UnknownTrajectoryError(IRLError):
    """Raised when a trajectory id names no booked trajectory."""


class RetiredAgentError(IRLError):
    """Raised when mutating a retired agent."""


class SeqOrderError(IRLError):
    """Raised when a seq is not strictly increasing (rewind)."""


class BadSeqError(IRLError):
    """Raised when a seq is not a non-negative int (bool rejected)."""


class AuditKindError(IRLError):
    """Raised when an audit kind or detail is malformed."""


def _require_id(value: Any, name: str) -> str:
    if (not isinstance(value, str) or not value
            or len(value) > _MAX_ID_LEN or value != value.strip()
            or any(ch.isspace() for ch in value)):
        raise BadIdError(f"bad {name}: {value!r}")
    return value


def _require_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BadSeqError(f"bad seq: {value!r}")
    return value


def _require_optional_digest(value: Any, name: str) -> str:
    if value in ("", None):
        return ""
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise BadDigestError(f"bad {name}: {value!r}")
    return value


def _digest_pin(payload: Dict[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(payload)


@dataclass(frozen=True)
class TrajectoryRecord:
    """One booked observation of expert behavior (as data)."""
    trajectory_id: str
    agent_id: str
    trajectory_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; True means the pin matches."""
        return self.digest == _digest_pin({
            "schema": SCHEMA_PIN,
            "trajectory_id": self.trajectory_id,
            "agent_id": self.agent_id,
            "trajectory_digest": self.trajectory_digest,
            "seq": self.seq,
        })


@dataclass(frozen=True)
class InferenceRecord:
    """One booked reward inference (host-reported, as data)."""
    inference_id: str
    agent_id: str
    method: str
    outcome: str
    reward_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; True means the pin matches."""
        return self.digest == _digest_pin({
            "schema": SCHEMA_PIN,
            "inference_id": self.inference_id,
            "agent_id": self.agent_id,
            "method": self.method,
            "outcome": self.outcome,
            "reward_digest": self.reward_digest,
            "seq": self.seq,
        })


@dataclass(frozen=True)
class InferenceReport:
    """Pure-read derived inference posture of one agent, as data."""
    agent_id: str
    n_trajectories: int
    n_inferences: int
    latest_method: str
    latest_outcome: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; True means the pin matches."""
        return self.digest == _digest_pin({
            "schema": SCHEMA_PIN,
            "agent_id": self.agent_id,
            "n_trajectories": self.n_trajectories,
            "n_inferences": self.n_inferences,
            "latest_method": self.latest_method,
            "latest_outcome": self.latest_outcome,
            "integrity_ok": self.integrity_ok,
        })


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of an agent's IRL lifecycle."""
    agent_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; True means the pin matches."""
        return self.digest == _digest_pin({
            "schema": SCHEMA_PIN,
            "agent_id": self.agent_id,
            "reason": self.reason,
            "seq": self.seq,
        })


def irl_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event for the IRL ledger.

    Raw trajectories, reward weights, and feature maps are banned at
    the builder level: any banned key in ``details`` raises
    ``AuditKindError``.
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"bad audit kind: {kind!r}")
    _require_seq(seq)
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned audit detail key: {key!r}")
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "kind": f"irl.{kind}",
        "seq": seq,
        "details": dict(details),
    }
    event["digest"] = _digest_pin(event)
    return event


class IRL:
    """IRL observe/infer/evaluate decision ledger (simulated)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._trajectories: Dict[str, TrajectoryRecord] = {}
        self._agent_trajectories: Dict[str, list] = {}
        self._inferences: Dict[str, InferenceRecord] = {}
        self._agent_inferences: Dict[str, list] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._inference_counter = 0
        self._audit: list = []

    # -- seq discipline --------------------------------------------------------

    def _claim(self, seq: int) -> None:
        _require_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq rewind: {seq!r} <= {self._last_seq!r}")
        self._last_seq = seq

    def _check_seq(self, seq: int) -> None:
        _require_seq(seq)

    def _burn(self, seq: int, action: str) -> None:
        self._audit.append(irl_audit_event(
            "rejected", seq, action=action))

    # -- observe ---------------------------------------------------------------

    def observe(self, trajectory_id: str, agent_id: str, seq: int,
                trajectory_digest: str = "") -> TrajectoryRecord:
        """Book one declared observation of expert behavior.

        The first observation registers the agent. Raw trajectories
        never enter the record; the trajectory travels as a
        ``sha256:`` digest pin only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(trajectory_id, "trajectory_id")
                _require_id(agent_id, "agent_id")
                trajectory_digest = _require_optional_digest(
                    trajectory_digest, "trajectory_digest")
                if trajectory_id in self._trajectories:
                    raise DuplicateTrajectoryError(
                        f"trajectory already observed: {trajectory_id!r}")
                if agent_id in self._retired:
                    raise RetiredAgentError(
                        f"agent retired: {agent_id!r}")
                record = TrajectoryRecord(
                    trajectory_id=trajectory_id,
                    agent_id=agent_id,
                    trajectory_digest=trajectory_digest,
                    seq=seq,
                    digest=_digest_pin({
                        "schema": SCHEMA_PIN,
                        "trajectory_id": trajectory_id,
                        "agent_id": agent_id,
                        "trajectory_digest": trajectory_digest,
                        "seq": seq,
                    }),
                )
                self._trajectories[trajectory_id] = record
                self._agent_trajectories.setdefault(agent_id, []).append(
                    trajectory_id)
                self._audit.append(irl_audit_event(
                    "observed", seq,
                    trajectory_id=trajectory_id,
                    agent_id=agent_id,
                    trajectory_digest=trajectory_digest))
                return record
            except IRLError:
                self._burn(seq, "observe")
                raise

    # -- infer -----------------------------------------------------------------

    def infer(self, agent_id: str, seq: int,
              method: str = METHOD_MAX_ENTROPY,
              outcome: str = OUTCOME_RECOVERED,
              reward_digest: str = "") -> InferenceRecord:
        """Book one declared reward inference (host-reported, as data).

        The method is a pinned vocabulary label; the outcome is booked
        as data, never proof the reward is correct. Repeatable as a
        chain.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(agent_id, "agent_id")
                if method not in INFERENCE_METHODS:
                    raise BadMethodError(f"bad method: {method!r}")
                if outcome not in INFERENCE_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                reward_digest = _require_optional_digest(
                    reward_digest, "reward_digest")
                if agent_id in self._retired:
                    raise RetiredAgentError(
                        f"agent retired: {agent_id!r}")
                if agent_id not in self._agent_trajectories:
                    raise UnknownAgentError(
                        f"agent never observed: {agent_id!r}")
                self._inference_counter += 1
                inference_id = f"inf-{self._inference_counter}"
                record = InferenceRecord(
                    inference_id=inference_id,
                    agent_id=agent_id,
                    method=method,
                    outcome=outcome,
                    reward_digest=reward_digest,
                    seq=seq,
                    digest=_digest_pin({
                        "schema": SCHEMA_PIN,
                        "inference_id": inference_id,
                        "agent_id": agent_id,
                        "method": method,
                        "outcome": outcome,
                        "reward_digest": reward_digest,
                        "seq": seq,
                    }),
                )
                self._inferences[inference_id] = record
                self._agent_inferences.setdefault(agent_id, []).append(
                    inference_id)
                self._audit.append(irl_audit_event(
                    "inferred", seq,
                    inference_id=inference_id,
                    agent_id=agent_id,
                    method=method,
                    outcome=outcome,
                    reward_digest=reward_digest))
                return record
            except IRLError:
                self._burn(seq, "infer")
                raise

    # -- evaluate (pure read) ---------------------------------------------------

    def evaluate(self, agent_id: str, seq: int) -> InferenceReport:
        """Pure-read derived inference posture of one agent, as data.

        Validates the seq shape, consumes nothing, writes no audit row.
        ``integrity_ok`` re-derives every booked digest; tamper is
        reported as data, never raised.
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(agent_id, "agent_id")
            if agent_id not in self._agent_trajectories:
                raise UnknownAgentError(
                    f"agent never observed: {agent_id!r}")
            traj_ids = self._agent_trajectories[agent_id]
            inf_ids = self._agent_inferences.get(agent_id, [])
            latest_method = ""
            latest_outcome = ""
            if inf_ids:
                latest = self._inferences[inf_ids[-1]]
                latest_method = latest.method
                latest_outcome = latest.outcome
            integrity_ok = all(
                self._trajectories[tid].verify() for tid in traj_ids
            ) and all(
                self._inferences[iid].verify() for iid in inf_ids
            )
            report = InferenceReport(
                agent_id=agent_id,
                n_trajectories=len(traj_ids),
                n_inferences=len(inf_ids),
                latest_method=latest_method,
                latest_outcome=latest_outcome,
                integrity_ok=integrity_ok,
                digest=_digest_pin({
                    "schema": SCHEMA_PIN,
                    "agent_id": agent_id,
                    "n_trajectories": len(traj_ids),
                    "n_inferences": len(inf_ids),
                    "latest_method": latest_method,
                    "latest_outcome": latest_outcome,
                    "integrity_ok": integrity_ok,
                }),
            )
            return report

    # -- retire ----------------------------------------------------------------

    def retire(self, agent_id: str, seq: int,
               reason: str = "manual") -> RetireRecord:
        """Terminally retire an agent's IRL lifecycle.

        Retired ids are never recycled; post-retire mutations are
        refused, reads still work.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(agent_id, "agent_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                if agent_id not in self._agent_trajectories:
                    raise UnknownAgentError(
                        f"agent never observed: {agent_id!r}")
                if agent_id in self._retired:
                    raise RetiredAgentError(
                        f"agent already retired: {agent_id!r}")
                record = RetireRecord(
                    agent_id=agent_id,
                    reason=reason,
                    seq=seq,
                    digest=_digest_pin({
                        "schema": SCHEMA_PIN,
                        "agent_id": agent_id,
                        "reason": reason,
                        "seq": seq,
                    }),
                )
                self._retired[agent_id] = record
                self._audit.append(irl_audit_event(
                    "retired", seq, agent_id=agent_id, reason=reason))
                return record
            except IRLError:
                self._burn(seq, "retire")
                raise

    # -- pure-read views ---------------------------------------------------------

    def trajectory_record(self, trajectory_id: str,
                          seq: int) -> TrajectoryRecord:
        """Return one booked trajectory record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(trajectory_id, "trajectory_id")
            if trajectory_id not in self._trajectories:
                raise UnknownTrajectoryError(
                    f"unknown trajectory: {trajectory_id!r}")
            return self._trajectories[trajectory_id]

    def inference_record(self, inference_id: str,
                         seq: int) -> InferenceRecord:
        """Return one booked inference record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(inference_id, "inference_id")
            if inference_id not in self._inferences:
                raise UnknownAgentError(
                    f"unknown inference: {inference_id!r}")
            return self._inferences[inference_id]

    def trajectories_for(self, agent_id: str, seq: int) -> Tuple[str, ...]:
        """Trajectory ids booked against one agent, in mint order."""
        with self._lock:
            self._check_seq(seq)
            _require_id(agent_id, "agent_id")
            if agent_id not in self._agent_trajectories:
                raise UnknownAgentError(
                    f"agent never observed: {agent_id!r}")
            return tuple(self._agent_trajectories[agent_id])

    def inferences_for(self, agent_id: str, seq: int) -> Tuple[str, ...]:
        """Inference ids booked against one agent, in mint order."""
        with self._lock:
            self._check_seq(seq)
            _require_id(agent_id, "agent_id")
            if agent_id not in self._agent_trajectories:
                raise UnknownAgentError(
                    f"agent never observed: {agent_id!r}")
            return tuple(self._agent_inferences.get(agent_id, ()))

    def agent_ids(self, seq: int) -> Tuple[str, ...]:
        """All observed agent ids in first-observation order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._agent_trajectories.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired agent ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "agents": len(self._agent_trajectories),
                "trajectories": len(self._trajectories),
                "inferences": len(self._inferences),
                "retired": len(self._retired),
                "rejected": sum(
                    1 for row in self._audit if row["kind"] == "irl.rejected"),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    # -- stdlib check ------------------------------------------------------------

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: imports are stdlib-only plus canonical_json."""
        import ast
        import pathlib
        tree = ast.parse(pathlib.Path(__file__).read_text())
        allowed = {"hashlib", "re", "threading", "dataclasses", "typing",
                   "__future__", "canonical_json", "json", "ast", "pathlib"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] not in allowed:
                        return False
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] not in allowed:
                    return False
        return True


def main() -> None:
    """Self-check: exercise the IRL ledger end to end."""
    irl = IRL()
    irl.observe("traj-1", "agent-1", 1)
    inf = irl.infer("agent-1", 2, method="maximum-entropy",
                    outcome="recovered")
    assert irl.trajectory_record("traj-1", 3).verify()
    assert inf.inference_id == "inf-1"
    rep = irl.evaluate("agent-1", 4)
    assert rep.n_trajectories == 1 and rep.n_inferences == 1
    assert rep.latest_method == "maximum-entropy"
    assert rep.integrity_ok
    irl.retire("agent-1", 5, reason="task-complete")
    assert irl.stats(6) == {
        "agents": 1, "trajectories": 1, "inferences": 1,
        "retired": 1, "rejected": 0,
    }
    print("irl OK: observe, infer, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
