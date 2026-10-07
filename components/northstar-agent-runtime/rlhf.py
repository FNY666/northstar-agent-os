"""Reinforcement learning from human feedback (RLHF) interface, simulated.

Research motivation: RLHF is the dominant pipeline for aligning language
models with human preferences -- InstructGPT (Ouyang et al., 2022) and
its descendants all reduce to the same three mechanics: collect human
preference pairs over model responses, fit a reward model on them, then
optimize the policy against the reward model with a KL constraint to a
reference policy (PPO, Schulman et al., 2017). Getting the bookkeeping
wrong (reward logged against the wrong policy checkpoint, a training
step booked without its reward batch, an evaluation that silently mixes
checkpoints) corrupts the alignment run before any gradient is computed.

This module is the *decision bookkeeping* half of that shape, pinned so
the runtime's alignment plumbing speaks one dialect:

- ``RLHF.register_policy(policy_id, seq)`` -- declare the policy
  checkpoint being aligned (the SFT artifact travels as a digest pin,
  bytes never enter a record). Returns a frozen ``PolicyRecord``.
- ``RLHF.preference(prompt_digest, better_digest, worse_digest, seq)``
  -- book one human preference pair. Prompt and response texts never
  enter records or cross the audit boundary; they travel as ``sha256:``
  digest pins only. Returns a frozen ``PreferenceRecord`` (``pref-N``).
- ``RLHF.reward(response_digest, seq, value, policy_id="")`` -- book one
  host-reported scalar reward from the (simulated) reward model.
  ``value`` is a finite float in [0, 1]; it is host-reported data, never
  proof that a reward model scored the response. Returns a frozen
  ``RewardRecord`` (``rew-N``).
- ``RLHF.train(policy_id, seq, reward_ids, kl=0.0, loss=0.0)`` -- book
  one PPO-shaped policy update step against a declared batch of
  rewards. Books the *decision*; it does not run gradient descent and
  proves no real optimization happened. Returns a frozen ``TrainRecord``
  (``train-N``).
- ``RLHF.evaluate(policy_id, seq)`` -- frozen ``EvaluationReport``:
  pure read view (seq validated, never consumed, no audit row) with the
  reward count, mean reward, train-step count, and KL-budget status as
  data.
- ``rlhf_audit_event(kind, detail, seq)`` -- ``audit.ndjson/1`` records
  (``policy-registered`` / ``preference-booked`` / ``reward-booked`` /
  ``train-step`` / ``rejected``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``policy_id`` must be a non-empty str and is never recycled;
  re-registering refuses with ``DuplicatePolicyError``.
- Digest arguments must be ``sha256:<64 hex>`` pins; raw text is
  refused fail-closed (it must never be pinned here).
- A preference pair's ``better_digest`` must differ from
  ``worse_digest`` (a self-comparison books no information).
- ``value`` must be a finite float (bool refused -- ``True`` must not
  alias ``1``) in [0, 1]; ``kl`` must be finite and >= 0; ``loss`` must
  be finite.
- ``train`` reward ids must name already-booked rewards; unknown ids
  refuse with ``UnknownRewardError``.
- Seqs are ints (not bool), >= 0, strictly increasing; rewinds raise
  bare without consuming. Failed mutations consume their seq and book
  a ``rejected`` audit row.

Honest scope:

- This module books *declared* preference pairs, *host-reported*
  reward values, and *declared* training steps. It runs no reward
  model, no policy network, and no optimizer -- the GIGO boundary is
  the caller's: a booked reward is ledger truth, never proof that a
  reward model scored the response.
- The KL figure is host-reported; the module cannot verify the policy
  actually stayed within a KL budget of any reference policy.
- ``evaluate()`` aggregates booked records; it cannot observe real
  model behavior, judge response quality, or certify alignment.
- No persistence: the registry is in-memory. Pair with the durable
  audit writer if alignment runs must survive a restart.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

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
RLHF_VERSION = "rlhf.v1"

#: Schema pin carried by records and audit events.
RLHF_SCHEMA = "northstar.rlhf.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_POLICY_REGISTERED = "policy-registered"
KIND_PREFERENCE_BOOKED = "preference-booked"
KIND_REWARD_BOOKED = "reward-booked"
KIND_TRAIN_STEP = "train-step"
KIND_REJECTED = "rejected"
_KINDS = (KIND_POLICY_REGISTERED, KIND_PREFERENCE_BOOKED,
          KIND_REWARD_BOOKED, KIND_TRAIN_STEP, KIND_REJECTED)

#: Keys that may never cross the audit boundary (raw alignment material).
_BANNED_AUDIT_KEYS = frozenset({
    "prompt", "response", "better", "worse", "text", "value",
    "kl", "loss", "payload", "raw", "rewards", "pairs",
})

#: KL budget reference: a host-reported cumulative KL above this marks
#: the evaluation report ``kl_budget_exceeded=True``. A ledger health
#: signal, not a training-stability claim.
KL_BUDGET = 0.2

#: Digest shape: ``sha256:<64 lowercase hex>``.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RLHFError(Exception):
    """Base error for RLHF bookkeeping (programming errors)."""


class BadPolicyError(RLHFError):
    """Raised when a policy_id or base digest is malformed."""


class DuplicatePolicyError(RLHFError):
    """Raised when a policy_id is registered twice."""


class UnknownPolicyError(RLHFError):
    """Raised when a policy_id names no registered policy."""


class BadDigestError(RLHFError):
    """Raised when a digest argument is not a sha256 pin (or is raw text)."""


class BadPreferenceError(RLHFError):
    """Raised when a preference pair is malformed (e.g. better == worse)."""


class BadRewardError(RLHFError):
    """Raised when a reward value is malformed."""


class UnknownRewardError(RLHFError):
    """Raised when a reward id names no booked reward."""


class BadTrainError(RLHFError):
    """Raised when a train step's KL/loss/batch is malformed."""


class SeqOrderError(RLHFError):
    """Raised when a seq is not strictly increasing."""


class AuditKindError(RLHFError):
    """Raised when an audit event kind is unknown."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_policy_id(value: object) -> str:
    """Validate a policy identifier: non-empty str."""
    if not isinstance(value, str):
        raise BadPolicyError(
            f"policy_id must be str, got {type(value).__name__}"
        )
    if not value:
        raise BadPolicyError("policy_id must be non-empty")
    return value


def _check_digest(value: object, name: str) -> str:
    """Validate a sha256 digest pin; raw text is refused fail-closed."""
    if not isinstance(value, str):
        raise BadDigestError(
            f"{name} must be a sha256 digest pin, "
            f"got {type(value).__name__}"
        )
    if not _DIGEST_RE.match(value):
        raise BadDigestError(
            f"{name} must match 'sha256:<64 hex>' -- raw text is refused; "
            f"pin it before booking"
        )
    return value


def _check_reward_value(value: object) -> float:
    """Validate a reward-model score: finite float in [0, 1], never bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadRewardError(
            f"reward value must be a number, got {type(value).__name__}"
        )
    fvalue = float(value)
    if not math.isfinite(fvalue):
        raise BadRewardError("reward value must be finite")
    if fvalue < 0.0 or fvalue > 1.0:
        raise BadRewardError(
            f"reward value must be in [0, 1], got {fvalue!r}"
        )
    return fvalue


def _check_kl(value: object) -> float:
    """Validate a host-reported KL divergence: finite, >= 0, never bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadTrainError(
            f"kl must be a number, got {type(value).__name__}"
        )
    fvalue = float(value)
    if not math.isfinite(fvalue):
        raise BadTrainError("kl must be finite")
    if fvalue < 0.0:
        raise BadTrainError(f"kl must be >= 0, got {fvalue!r}")
    return fvalue


def _check_loss(value: object) -> float:
    """Validate a host-reported policy loss: finite, never bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadTrainError(
            f"loss must be a number, got {type(value).__name__}"
        )
    fvalue = float(value)
    if not math.isfinite(fvalue):
        raise BadTrainError("loss must be finite")
    return fvalue


def _pin(scope: str, *parts: object) -> str:
    """Digest-pin a canonical body under a scope tag."""
    return "sha256:" + jcs_sha256_hex({"scope": scope, "parts": list(parts)})


@dataclass(frozen=True)
class PolicyRecord:
    """One declared policy checkpoint (frozen)."""
    policy_id: str
    base_digest: str
    seq: int
    digest: str
    version: str = RLHF_VERSION
    schema: str = RLHF_SCHEMA

    def verify(self) -> bool:
        """Recompute the digest pin; False on any tampering."""
        return self.digest == _pin("policy", self.policy_id,
                                   self.base_digest, self.seq)

    def as_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "base_digest": self.base_digest,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class PreferenceRecord:
    """One booked human preference pair (frozen)."""
    preference_id: str
    prompt_digest: str
    better_digest: str
    worse_digest: str
    seq: int
    digest: str
    version: str = RLHF_VERSION
    schema: str = RLHF_SCHEMA

    def verify(self) -> bool:
        """Recompute the digest pin; False on any tampering."""
        return self.digest == _pin("preference", self.preference_id,
                                   self.prompt_digest, self.better_digest,
                                   self.worse_digest, self.seq)

    def as_dict(self) -> dict:
        return {
            "preference_id": self.preference_id,
            "prompt_digest": self.prompt_digest,
            "better_digest": self.better_digest,
            "worse_digest": self.worse_digest,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RewardRecord:
    """One booked host-reported reward-model score (frozen)."""
    reward_id: str
    policy_id: str
    prompt_digest: str
    response_digest: str
    value: float
    seq: int
    digest: str
    version: str = RLHF_VERSION
    schema: str = RLHF_SCHEMA

    def verify(self) -> bool:
        """Recompute the digest pin; False on any tampering."""
        return self.digest == _pin("reward", self.reward_id, self.policy_id,
                                   self.prompt_digest, self.response_digest,
                                   self.value, self.seq)

    def as_dict(self) -> dict:
        return {
            "reward_id": self.reward_id,
            "policy_id": self.policy_id,
            "prompt_digest": self.prompt_digest,
            "response_digest": self.response_digest,
            "value": self.value,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TrainRecord:
    """One booked PPO-shaped policy update step (frozen)."""
    train_id: str
    policy_id: str
    reward_ids: Tuple[str, ...]
    kl: float
    loss: float
    seq: int
    digest: str
    version: str = RLHF_VERSION
    schema: str = RLHF_SCHEMA

    def verify(self) -> bool:
        """Recompute the digest pin; False on any tampering."""
        return self.digest == _pin("train", self.train_id, self.policy_id,
                                   list(self.reward_ids), self.kl,
                                   self.loss, self.seq)

    def as_dict(self) -> dict:
        return {
            "train_id": self.train_id,
            "policy_id": self.policy_id,
            "reward_ids": list(self.reward_ids),
            "kl": self.kl,
            "loss": self.loss,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class EvaluationReport:
    """Alignment-ledger evaluation for one policy (frozen).

    Pure read view: aggregates booked records only. ``kl_budget_exceeded``
    is ledger health as data -- it never proves a training instability.
    """
    policy_id: str
    reward_count: int
    mean_reward: float
    train_steps: int
    total_kl: float
    kl_budget_exceeded: bool
    seq: int
    digest: str
    version: str = RLHF_VERSION
    schema: str = RLHF_SCHEMA

    def verify(self) -> bool:
        """Recompute the digest pin; False on any tampering."""
        return self.digest == _pin("evaluate", self.policy_id,
                                   self.reward_count, self.mean_reward,
                                   self.train_steps, self.total_kl,
                                   self.seq)

    def as_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "reward_count": self.reward_count,
            "mean_reward": self.mean_reward,
            "train_steps": self.train_steps,
            "total_kl": self.total_kl,
            "kl_budget_exceeded": self.kl_budget_exceeded,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


class RLHF:
    """In-memory RLHF decision ledger (thread-safe)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._policies: Dict[str, PolicyRecord] = {}
        self._preferences: Dict[str, PreferenceRecord] = {}
        self._rewards: Dict[str, RewardRecord] = {}
        self._trains: Dict[str, TrainRecord] = {}
        self._audit: List[dict] = []
        self._last_seq = 0
        self._pref_counter = 0
        self._reward_counter = 0
        self._train_counter = 0

    def _claim(self, seq: object) -> int:
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq: int, error: Exception) -> None:
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(rlhf_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        self._audit.append(rlhf_audit_event(audit_kind, detail, seq))

    # -- mutations ---------------------------------------------------------

    def register_policy(self, policy_id: object, seq: object,
                        base_digest: object = "") -> PolicyRecord:
        """Declare the policy checkpoint being aligned.

        ``base_digest`` pins the SFT/pre-trained artifact when known;
        empty means "unpinned base".
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                policy_id = _check_policy_id(policy_id)
                if base_digest:
                    base_digest = _check_digest(base_digest, "base_digest")
                elif not isinstance(base_digest, str):
                    raise BadPolicyError(
                        "base_digest must be str or empty, "
                        f"got {type(base_digest).__name__}"
                    )
                if policy_id in self._policies:
                    raise DuplicatePolicyError(
                        f"policy_id {policy_id!r} already registered"
                    )
            except RLHFError as e:
                self._burn(seq, e)
            record = PolicyRecord(
                policy_id=policy_id,
                base_digest=base_digest,
                seq=seq,
                digest=_pin("policy", policy_id, base_digest, seq),
            )
            self._policies[policy_id] = record
            self._last_seq = seq
            self._emit(KIND_POLICY_REGISTERED,
                       {"policy_id": policy_id, "digest": record.digest}, seq)
            return record

    def preference(self, prompt_digest: object, better_digest: object,
                   worse_digest: object, seq: object) -> PreferenceRecord:
        """Book one human preference pair (digest pins only)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                prompt_digest = _check_digest(prompt_digest, "prompt_digest")
                better_digest = _check_digest(better_digest, "better_digest")
                worse_digest = _check_digest(worse_digest, "worse_digest")
                if better_digest == worse_digest:
                    raise BadPreferenceError(
                        "better_digest must differ from worse_digest "
                        "(a self-comparison books no information)"
                    )
            except RLHFError as e:
                self._burn(seq, e)
            self._pref_counter += 1
            preference_id = f"pref-{self._pref_counter}"
            record = PreferenceRecord(
                preference_id=preference_id,
                prompt_digest=prompt_digest,
                better_digest=better_digest,
                worse_digest=worse_digest,
                seq=seq,
                digest=_pin("preference", preference_id, prompt_digest,
                            better_digest, worse_digest, seq),
            )
            self._preferences[preference_id] = record
            self._last_seq = seq
            self._emit(KIND_PREFERENCE_BOOKED,
                       {"preference_id": preference_id,
                        "digest": record.digest}, seq)
            return record

    def reward(self, response_digest: object, seq: object, value: object,
               prompt_digest: object = "",
               policy_id: object = "") -> RewardRecord:
        """Book one host-reported reward-model score."""
        with self._lock:
            seq = self._claim(seq)
            try:
                response_digest = _check_digest(response_digest,
                                                "response_digest")
                if prompt_digest:
                    prompt_digest = _check_digest(prompt_digest,
                                                  "prompt_digest")
                elif not isinstance(prompt_digest, str):
                    raise BadRewardError(
                        "prompt_digest must be str or empty, "
                        f"got {type(prompt_digest).__name__}"
                    )
                if policy_id:
                    policy_id = _check_policy_id(policy_id)
                    if policy_id not in self._policies:
                        raise UnknownPolicyError(
                            f"unknown policy_id {policy_id!r}"
                        )
                elif not isinstance(policy_id, str):
                    raise BadRewardError(
                        "policy_id must be str or empty, "
                        f"got {type(policy_id).__name__}"
                    )
                value = _check_reward_value(value)
            except RLHFError as e:
                self._burn(seq, e)
            self._reward_counter += 1
            reward_id = f"rew-{self._reward_counter}"
            record = RewardRecord(
                reward_id=reward_id,
                policy_id=policy_id,
                prompt_digest=prompt_digest,
                response_digest=response_digest,
                value=value,
                seq=seq,
                digest=_pin("reward", reward_id, policy_id, prompt_digest,
                            response_digest, value, seq),
            )
            self._rewards[reward_id] = record
            self._last_seq = seq
            self._emit(KIND_REWARD_BOOKED,
                       {"reward_id": reward_id, "digest": record.digest}, seq)
            return record

    def train(self, policy_id: object, seq: object, reward_ids: object,
              kl: object = 0.0, loss: object = 0.0) -> TrainRecord:
        """Book one PPO-shaped policy update step.

        ``reward_ids`` must name already-booked rewards; the step is the
        *decision* to train on that batch, not proof that gradients ran.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                policy_id = _check_policy_id(policy_id)
                if policy_id not in self._policies:
                    raise UnknownPolicyError(
                        f"unknown policy_id {policy_id!r}"
                    )
                if (not isinstance(reward_ids, (list, tuple))
                        or not reward_ids):
                    raise BadTrainError(
                        "reward_ids must be a non-empty list of reward ids"
                    )
                checked_ids: List[str] = []
                for rid in reward_ids:
                    if not isinstance(rid, str) or not rid:
                        raise BadTrainError(
                            f"reward id must be a non-empty str, got {rid!r}"
                        )
                    if rid not in self._rewards:
                        raise UnknownRewardError(
                            f"unknown reward id {rid!r}"
                        )
                    checked_ids.append(rid)
                kl = _check_kl(kl)
                loss = _check_loss(loss)
            except RLHFError as e:
                self._burn(seq, e)
            self._train_counter += 1
            train_id = f"train-{self._train_counter}"
            ids_tuple = tuple(checked_ids)
            record = TrainRecord(
                train_id=train_id,
                policy_id=policy_id,
                reward_ids=ids_tuple,
                kl=kl,
                loss=loss,
                seq=seq,
                digest=_pin("train", train_id, policy_id,
                            list(ids_tuple), kl, loss, seq),
            )
            self._trains[train_id] = record
            self._last_seq = seq
            self._emit(KIND_TRAIN_STEP,
                       {"train_id": train_id, "digest": record.digest}, seq)
            return record

    def evaluate(self, policy_id: object, seq: object) -> EvaluationReport:
        """Aggregate the alignment ledger for one policy.

        Pure read view: validates seq shape, consumes nothing, writes no
        audit row. Empty ledgers are data, never raised.
        """
        _check_seq(seq)
        policy_id = _check_policy_id(policy_id)
        with self._lock:
            if policy_id not in self._policies:
                raise UnknownPolicyError(
                    f"unknown policy_id {policy_id!r}"
                )
            values = [r.value for r in self._rewards.values()
                      if r.policy_id == policy_id]
            steps = [t for t in self._trains.values()
                     if t.policy_id == policy_id]
            reward_count = len(values)
            mean_reward = sum(values) / reward_count if values else 0.0
            total_kl = sum(t.kl for t in steps)
            report = EvaluationReport(
                policy_id=policy_id,
                reward_count=reward_count,
                mean_reward=mean_reward,
                train_steps=len(steps),
                total_kl=total_kl,
                kl_budget_exceeded=total_kl > KL_BUDGET,
                seq=seq,
                digest=_pin("evaluate", policy_id, reward_count,
                            mean_reward, len(steps), total_kl, seq),
            )
            return report

    # -- pure read views ---------------------------------------------------

    def policy(self, policy_id: object) -> PolicyRecord:
        """Read back one registered policy."""
        policy_id = _check_policy_id(policy_id)
        with self._lock:
            record = self._policies.get(policy_id)
        if record is None:
            raise UnknownPolicyError(
                f"unknown policy_id {policy_id!r}"
            )
        return record

    def preference_record(self, preference_id: object) -> PreferenceRecord:
        """Read back one booked preference pair."""
        if not isinstance(preference_id, str) or not preference_id:
            raise BadPreferenceError(
                f"preference_id must be a non-empty str, "
                f"got {preference_id!r}"
            )
        with self._lock:
            record = self._preferences.get(preference_id)
        if record is None:
            raise BadPreferenceError(
                f"unknown preference_id {preference_id!r}"
            )
        return record

    def reward_record(self, reward_id: object) -> RewardRecord:
        """Read back one booked reward."""
        if not isinstance(reward_id, str) or not reward_id:
            raise BadRewardError(
                f"reward_id must be a non-empty str, got {reward_id!r}"
            )
        with self._lock:
            record = self._rewards.get(reward_id)
        if record is None:
            raise UnknownRewardError(f"unknown reward id {reward_id!r}")
        return record

    def train_record(self, train_id: object) -> TrainRecord:
        """Read back one booked train step."""
        if not isinstance(train_id, str) or not train_id:
            raise BadTrainError(
                f"train_id must be a non-empty str, got {train_id!r}"
            )
        with self._lock:
            record = self._trains.get(train_id)
        if record is None:
            raise BadTrainError(f"unknown train id {train_id!r}")
        return record

    def policy_ids(self) -> Tuple[str, ...]:
        """Sorted ids of registered policies."""
        with self._lock:
            return tuple(sorted(self._policies))

    def preference_ids(self) -> Tuple[str, ...]:
        """Ids of booked preference pairs in booking order."""
        with self._lock:
            return tuple(self._preferences)

    def reward_ids(self) -> Tuple[str, ...]:
        """Ids of booked rewards in booking order."""
        with self._lock:
            return tuple(self._rewards)

    def train_ids(self) -> Tuple[str, ...]:
        """Ids of booked train steps in booking order."""
        with self._lock:
            return tuple(self._trains)

    def audit_log(self) -> Tuple[dict, ...]:
        """Append-only audit trail."""
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> dict:
        """Snapshot of the whole ledger."""
        with self._lock:
            return {
                "policies": [p.as_dict() for p in self._policies.values()],
                "preferences": [p.as_dict()
                                for p in self._preferences.values()],
                "rewards": [r.as_dict() for r in self._rewards.values()],
                "trains": [t.as_dict() for t in self._trains.values()],
                "version": RLHF_VERSION,
                "schema": RLHF_SCHEMA,
            }


def rlhf_audit_event(kind: str, detail: object, seq: object) -> dict:
    """Audit-shaped record for an RLHF observation.

    Raw alignment material (digests' sources, reward values, KL/loss
    figures) never crosses the audit boundary -- the detail carries ids
    and digest pins only.
    """
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, dict):
        raise TypeError(
            f"detail must be a dict, got {type(detail).__name__}"
        )
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise ValueError(
                f"audit detail must not carry raw alignment material: {key!r}"
            )
    return {
        "event": "rlhf",
        "kind": kind,
        "audit_seq": seq,
        "detail": dict(detail),
        "schema": AUDIT_SCHEMA,
    }


def main() -> None:
    r = RLHF()
    base = "sha256:" + "ab" * 32
    policy = r.register_policy("sft-7b", seq=1, base_digest=base)
    assert policy.verify(), policy
    prompt = "sha256:" + "cd" * 32
    better = "sha256:" + "ef" * 32
    worse = "sha256:" + "01" * 32
    pref = r.preference(prompt, better, worse, seq=2)
    assert pref.verify(), pref
    rew = r.reward(better, seq=3, value=0.8, prompt_digest=prompt,
                   policy_id="sft-7b")
    assert rew.verify(), rew
    step = r.train("sft-7b", seq=4, reward_ids=[rew.reward_id],
                   kl=0.05, loss=1.25)
    assert step.verify(), step
    report = r.evaluate("sft-7b", seq=4)  # pure read: seq reuse is fine
    assert report.verify(), report
    assert report.reward_count == 1 and report.train_steps == 1, report
    assert report.mean_reward == 0.8, report
    assert report.kl_budget_exceeded is False, report
    print("rlhf OK: register, preference, reward, train, evaluate")


if __name__ == "__main__":
    main()
