"""Multi-armed bandit (arm/pull/reward) interface, simulated.

Research motivation: multi-armed bandits are the exploration/exploitation
workhorse -- UCB, Thompson sampling, epsilon-greedy -- used to pick
variants, prompts, tool calls, or retry targets online. Every credible
implementation reduces to the same ledger: declare arms, book pull
decisions, book host-reported rewards, and derive per-arm statistics.
Getting the bookkeeping wrong (double-counted rewards, lost pulls,
silent re-arming) corrupts the policy before any regret analysis runs.

This module is the *decision ledger* half of that shape:

- ``BanditAlgorithm.arm(arm_id, seq)`` -- declare an arm. Returns a
  frozen ``ArmRecord`` with a ``sha256:`` digest pin. Duplicate ids are
  refused fail-closed; ids are never recycled.
- ``BanditAlgorithm.pull(arm_id, seq)`` -- book one pull decision on a
  declared arm. Returns a frozen ``PullRecord`` with a minted
  ``pull-N`` id. This books the *decision*, not proof of execution.
- ``BanditAlgorithm.reward(pull_id, value, seq)`` -- book the
  host-reported reward for a pull. Rewards are normalized to [0, 1],
  finite floats (bool refused). One reward per pull -- a second booking
  raises ``DuplicateRewardError``.
- ``BanditAlgorithm.recommend(seq)`` -- deterministic UCB1
  recommendation: the arm maximizing mean + sqrt(2 ln t / n) (unpulled
  arms score +infinity, so every arm is tried first; ties break by
  lowest arm_id). Returns a frozen ``RecommendationRecord``.
- ``BanditAlgorithm.ucb_scores(seq)`` -- pure read view of per-arm
  UCB1 scores as data (validates seq shape, consumes nothing).
- ``bandit_algorithm_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``arm-registered`` / ``pulled`` / ``rewarded`` /
  ``recommended`` / ``rejected``); caller-supplied seqs only. Raw
  reward values never cross the audit boundary -- audit rows carry
  ids, counts, and digest pins only.

Fail-closed edges (fail loudly, never guess):

- ``arm_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``pull`` on an unknown arm raises ``UnknownArmError``.
- ``reward`` on an unknown pull raises ``UnknownPullError``; a second
  reward on the same pull raises ``DuplicateRewardError``.
- ``value`` must be a finite float in [0, 1] (ints 0/1 accepted and
  stored as float; bool, NaN, inf, out-of-range refused).
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* decisions and *host-reported* rewards.
  A booked reward is a ledger entry, not a verified measurement --
  rewards are GIGO: the module cannot prove the host ran the pull or
  measured honestly.
- ``recommend()`` computes the UCB1 *score* deterministically from the
  ledger; it does not randomize, sample posteriors, or promise regret
  bounds. Determinism is the point: the same ledger always yields the
  same recommendation.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if bandit state must survive a restart.
"""

from __future__ import annotations

import hashlib
import math
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
BANDIT_ALGORITHM_VERSION = "bandit-algorithm.v1"

#: Schema pin carried by records and audit events.
BANDIT_ALGORITHM_SCHEMA = "northstar.bandit-algorithm.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ARM_REGISTERED = "arm-registered"
KIND_PULLED = "pulled"
KIND_REWARDED = "rewarded"
KIND_RECOMMENDED = "recommended"
KIND_REJECTED = "rejected"
_KINDS = (KIND_ARM_REGISTERED, KIND_PULLED, KIND_REWARDED,
          KIND_RECOMMENDED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"value", "reward", "payload", "raw", "scores", "data"})

#: Max arm-id length.
_MAX_ARM_ID_LEN = 256


class BanditAlgorithmError(Exception):
    """Base error for the bandit algorithm ledger (programming errors)."""


class BadArmError(BanditAlgorithmError):
    """Raised when an arm id is malformed."""


class DuplicateArmError(BanditAlgorithmError):
    """Raised when an arm id is registered twice."""


class UnknownArmError(BanditAlgorithmError):
    """Raised when an arm id names no declared arm."""


class UnknownPullError(BanditAlgorithmError):
    """Raised when a pull id names no booked pull."""


class DuplicateRewardError(BanditAlgorithmError):
    """Raised when a pull is rewarded twice."""


class BadRewardError(BanditAlgorithmError):
    """Raised when a reward value is malformed."""


class NoArmsError(BanditAlgorithmError):
    """Raised when recommend() is called with no declared arms."""


class SeqOrderError(BanditAlgorithmError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(BanditAlgorithmError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_arm_id(arm_id: object) -> str:
    """Validate an arm id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(arm_id, bool) or not isinstance(arm_id, str):
        raise BadArmError(f"arm_id must be str, got {type(arm_id).__name__}")
    if not arm_id:
        raise BadArmError("arm_id must not be empty")
    if len(arm_id) > _MAX_ARM_ID_LEN:
        raise BadArmError(f"arm_id too long (>{_MAX_ARM_ID_LEN} chars)")
    if any(ch.isspace() for ch in arm_id):
        raise BadArmError("arm_id must not contain whitespace")
    return arm_id


def _check_reward(value: object) -> float:
    """Validate a reward: finite float in [0, 1]; bool refused."""
    if isinstance(value, bool):
        raise BadRewardError("reward must not be bool")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise BadRewardError(
            f"reward must be float, got {type(value).__name__}")
    if not math.isfinite(value):
        raise BadRewardError(f"reward must be finite, got {value!r}")
    if not 0.0 <= value <= 1.0:
        raise BadRewardError(f"reward must be in [0, 1], got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": BANDIT_ALGORITHM_SCHEMA,
        "parts": list(parts),
    })


def _safe_score(score: float) -> object:
    """Make a UCB score JSON-encodable for digest input (+inf -> 'inf')."""
    if math.isinf(score):
        return "inf" if score > 0 else "-inf"
    return score


def bandit_algorithm_audit_event(kind: str, detail: Dict[str, object],
                                 seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the bandit ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": BANDIT_ALGORITHM_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class ArmRecord:
    """Frozen record of a declared arm."""
    arm_id: str
    seq: int
    digest: str

    def verify(self, arm_id: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("arm", arm_id, self.seq)


@dataclass(frozen=True)
class PullRecord:
    """Frozen record of one booked pull decision."""
    pull_id: str
    arm_id: str
    seq: int
    digest: str

    def verify(self, arm_id: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("pull", self.pull_id, arm_id, self.seq)


@dataclass(frozen=True)
class RewardRecord:
    """Frozen record of one host-reported reward for a pull."""
    pull_id: str
    arm_id: str
    value: float
    seq: int
    digest: str

    def verify(self, arm_id: str, value: float) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("reward", self.pull_id, arm_id,
                                   repr(value), self.seq)


@dataclass(frozen=True)
class ArmStats:
    """Per-arm derived statistics as data (not a record)."""
    arm_id: str
    pulls: int
    rewards: int
    mean: Optional[float]


@dataclass(frozen=True)
class ScoresReport:
    """Pure read view of per-arm UCB1 scores (seq validated, not consumed)."""
    seq: int
    # (arm_id, score) sorted by arm_id; +inf for never-pulled arms.
    scores: Tuple[Tuple[str, float], ...]


@dataclass(frozen=True)
class RecommendationRecord:
    """Frozen record of one UCB1 recommendation decision."""
    arm_id: str
    # (arm_id, score) sorted by arm_id, taken from the ledger at book time.
    scores: Tuple[Tuple[str, float], ...]
    seq: int
    digest: str

    def verify(self, arm_id: str, seq: int,
               scores: Tuple[Tuple[str, float], ...]) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "recommend", arm_id, seq,
            [[aid, _safe_score(s)] for aid, s in scores])


class BanditAlgorithm:
    """Deterministic multi-armed bandit decision ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no randomness.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._arms: Dict[str, ArmRecord] = {}
        self._pulls: Dict[str, PullRecord] = {}
        self._rewards: Dict[str, RewardRecord] = {}
        self._pull_counter = 0
        self._last_seq = 0
        self._audit: list = []

    # -- seq discipline ---------------------------------------------------

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
        self._audit.append(bandit_algorithm_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, kind: str, detail: Dict[str, object], seq: int) -> None:
        self._audit.append(bandit_algorithm_audit_event(kind, detail, seq))

    # -- mutations ---------------------------------------------------------

    def arm(self, arm_id: object, seq: object) -> ArmRecord:
        """Declare an arm; duplicate ids refused fail-closed."""
        with self._lock:
            seq = self._claim(seq)
            try:
                arm_id = _check_arm_id(arm_id)
                if arm_id in self._arms:
                    raise DuplicateArmError(
                        f"arm already registered: {arm_id!r}")
            except BanditAlgorithmError as e:
                self._burn(seq, e)
            rec = ArmRecord(arm_id=arm_id, seq=seq,
                            digest=_pin("arm", arm_id, seq))
            self._arms[arm_id] = rec
            self._last_seq = seq
            self._emit(KIND_ARM_REGISTERED,
                       {"arm_id": arm_id, "digest": rec.digest}, seq)
            return rec

    def pull(self, arm_id: object, seq: object) -> PullRecord:
        """Book one pull decision on a declared arm (minted ``pull-N`` id)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                arm_id = _check_arm_id(arm_id)
                if arm_id not in self._arms:
                    raise UnknownArmError(f"unknown arm: {arm_id!r}")
            except BanditAlgorithmError as e:
                self._burn(seq, e)
            self._pull_counter += 1
            pull_id = f"pull-{self._pull_counter}"
            rec = PullRecord(pull_id=pull_id, arm_id=arm_id, seq=seq,
                             digest=_pin("pull", pull_id, arm_id, seq))
            self._pulls[pull_id] = rec
            self._last_seq = seq
            self._emit(KIND_PULLED,
                       {"pull_id": pull_id, "arm_id": arm_id,
                        "digest": rec.digest}, seq)
            return rec

    def reward(self, pull_id: object, value: object,
               seq: object) -> RewardRecord:
        """Book the host-reported reward for a pull (one per pull)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                if pull_id not in self._pulls:
                    raise UnknownPullError(f"unknown pull: {pull_id!r}")
                if pull_id in self._rewards:
                    raise DuplicateRewardError(
                        f"pull already rewarded: {pull_id!r}")
                value = _check_reward(value)
            except BanditAlgorithmError as e:
                self._burn(seq, e)
            pull = self._pulls[pull_id]
            rec = RewardRecord(pull_id=pull_id, arm_id=pull.arm_id,
                               value=value, seq=seq,
                               digest=_pin("reward", pull_id, pull.arm_id,
                                           repr(value), seq))
            self._rewards[pull_id] = rec
            self._last_seq = seq
            # Raw reward value banned from the audit boundary: digest pin.
            self._emit(KIND_REWARDED,
                       {"pull_id": pull_id, "arm_id": pull.arm_id,
                        "digest": rec.digest}, seq)
            return rec

    def recommend(self, seq: object) -> RecommendationRecord:
        """Book a deterministic UCB1 recommendation (max score, arm_id tie-break)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                if not self._arms:
                    raise NoArmsError("no arms declared")
                scores = self._scores_locked()
                # Never-pulled arms score +inf: explore first, by arm_id.
                best = max(scores, key=lambda pair: (pair[1],))[0]
                # Deterministic tie-break on equal scores: lowest arm_id.
                best_score = dict(scores)[best]
                for aid, score in scores:
                    if score == best_score and aid < best:
                        best = aid
            except BanditAlgorithmError as e:
                self._burn(seq, e)
            rec = RecommendationRecord(
                arm_id=best, scores=scores, seq=seq,
                digest=_pin("recommend", best, seq,
                            [[aid, _safe_score(s)] for aid, s in scores]))
            self._last_seq = seq
            self._emit(KIND_RECOMMENDED,
                       {"arm_id": best, "digest": rec.digest}, seq)
            return rec

    # -- derived state (internal) ------------------------------------------

    def _scores_locked(self) -> Tuple[Tuple[str, float], ...]:
        """Per-arm UCB1 scores, sorted by arm_id. Call with the lock held."""
        total_pulls = len(self._pulls)
        out = []
        for arm_id in sorted(self._arms):
            pulls = [p for p in self._pulls.values()
                     if p.arm_id == arm_id]
            n = len(pulls)
            if n == 0:
                out.append((arm_id, math.inf))
                continue
            rewards = [self._rewards[p.pull_id].value for p in pulls
                       if p.pull_id in self._rewards]
            mean = sum(rewards) / len(rewards) if rewards else 0.0
            score = mean + math.sqrt(2.0 * math.log(total_pulls) / n)
            out.append((arm_id, score))
        return tuple(out)

    # -- views --------------------------------------------------------------

    def arm_record(self, arm_id: str) -> Optional[ArmRecord]:
        """Return the arm record, or None when unknown (pure read)."""
        return self._arms.get(arm_id)

    def arm_ids(self) -> Tuple[str, ...]:
        """Sorted declared arm ids (pure read)."""
        return tuple(sorted(self._arms))

    def pull_record(self, pull_id: str) -> Optional[PullRecord]:
        """Return the pull record, or None when unknown (pure read)."""
        return self._pulls.get(pull_id)

    def reward_record(self, pull_id: str) -> Optional[RewardRecord]:
        """Return the reward record, or None when unrewarded (pure read)."""
        return self._rewards.get(pull_id)

    def stats(self, seq: object) -> Tuple[ArmStats, ...]:
        """Per-arm stats as data: seq validated, never consumed."""
        _check_seq(seq)
        out = []
        for arm_id in sorted(self._arms):
            pulls = [p for p in self._pulls.values()
                     if p.arm_id == arm_id]
            rewards = [self._rewards[p.pull_id].value for p in pulls
                       if p.pull_id in self._rewards]
            mean = (sum(rewards) / len(rewards)) if rewards else None
            out.append(ArmStats(arm_id=arm_id, pulls=len(pulls),
                                rewards=len(rewards), mean=mean))
        return tuple(out)

    def ucb_scores(self, seq: object) -> ScoresReport:
        """Pure read view of per-arm UCB1 scores (seq validated, not consumed)."""
        _check_seq(seq)
        with self._lock:
            return ScoresReport(seq=seq, scores=self._scores_locked())

    def total_pulls(self) -> int:
        """Total booked pulls (pure read)."""
        return len(self._pulls)

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main() -> None:
    """Self-check: arm, pull, reward, UCB1 recommendation."""
    ba = BanditAlgorithm()
    a = ba.arm("good", 1)
    b = ba.arm("bad", 2)
    assert a.verify("good") and b.verify("bad")
    # Unpulled arms score +inf: lowest arm_id explored first.
    rec = ba.recommend(3)
    assert rec.arm_id == "bad", rec  # "bad" < "good"
    # Good arm earns reward 1.0, bad arm earns 0.0.
    p1 = ba.pull("good", 4)
    ba.reward(p1.pull_id, 1.0, 5)
    p2 = ba.pull("bad", 6)
    ba.reward(p2.pull_id, 0.0, 7)
    rec = ba.recommend(8)
    assert rec.arm_id == "good", rec
    assert rec.verify("good", 8, rec.scores)
    stats = {s.arm_id: s for s in ba.stats(8)}
    assert stats["good"].mean == 1.0 and stats["bad"].mean == 0.0
    assert len(ba.audit_log()) == 8
    print("bandit-algorithm OK: arm, pull, reward, ucb1-recommend")


if __name__ == "__main__":
    main()
