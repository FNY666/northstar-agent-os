"""Assistance-game (cooperative assistance) decision ledger, Simulated.

Research note: assistance games (Hadfield-Menell et al., 2016) formalize
the human-AI assistance problem as a cooperative game: a human ``H`` and a
robot ``R`` share a reward function parameterized by unknown preferences
``theta``. ``H`` acts informedly (but not perfectly); ``R`` must act to
maximize the shared reward while remaining uncertain about ``theta``. The
canonical solution concept is cooperative inverse reinforcement learning
(CIRL): infer the preference from human behavior, stay uncertain, and prefer
actions that preserve human agency. The dangerous half of a real assistance
game is the raw material: human preference traces, reward-parameter
posteriors, rollout transcripts, and human behavioral data. Those must never
be bundled with the bookkeeping record that tracks the session.

This module is that bookkeeping layer. It:

* **play()** - book one declared assistance-game episode (minted ``ply-N``
  ids) over a pinned episode-kind vocabulary; the first play on an id
  registers the session; raw human preferences, reward parameters, and
  transcripts travel as ``sha256:`` digest pins only.
* **evaluate()** - book one declared evaluation of a session (minted
  ``evl-N`` ids) over a pinned metric vocabulary with a host-reported score;
  scores are data, never proof the session actually helped the human.
* **verify()** - pure-read derived session verification verdict, as data:
  re-derives the digest pins and reports posture plus ``integrity_ok``
  (tamper reported, never raised).

Distinct layer: ``cirl.py`` owns the CIRL interact/learn decision ledger,
``preference_learning.py`` owns preference-pair bookkeeping,
``value_learning.py`` owns value-inference bookkeeping, ``ida.py`` owns the
amplify/distill loop, ``amplification.py`` owns IDA decision records. This
module owns the *assistance-game session* lifecycle none of them own:
declared play episodes, declared evaluations, derived verification.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``assistance-game.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked ``improved`` is a host-declared claim, never proof a
real human was helped; a booked score is host-reported, never a measured
outcome; an ``improved`` posture means the ledger's rule was satisfied,
never that the assistance was actually safe or beneficial; no game is
played, no human is consulted, and no reward is optimized here.
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
ASSISTANCE_GAME_VERSION = "assistance-game.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.assistance-game.v1"

#: Pinned episode-kind vocabulary (declared, never proof a real game ran).
EPISODE_KINDS = (
    "value-elicitation",
    "preference-probing",
    "task-completion",
    "corrigible-oversight",
    "demonstration",
    "correction-loop",
    "delegation-check",
    "uncertainty-clarification",
)

#: Pinned play-outcome vocabulary (declared, never measured truth).
PLAY_OUTCOMES = (
    "improved",
    "degraded",
    "inconclusive",
    "not-run",
)

#: Pinned evaluation-metric vocabulary (declared, never a measured outcome).
EVAL_METRICS = (
    "regret",
    "reward-gap",
    "preference-alignment",
    "safety-violation",
    "human-satisfaction",
    "autonomy-preserved",
)

#: Pinned retire-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "task-complete",
    "policy-revoked",
)

#: Pinned derived postures for verify() / status().
POSTURES = (
    "unplayed",
    "improved",
    "contested",
    "degraded",
    "unevaluated",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "played",
    "evaluated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "theta",
        "preferences",
        "transcript",
        "prompt",
        "response",
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
        "trajectory",
        "reward",
        "posterior",
        "behavior",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AssistanceGameError(Exception):
    """Base error for assistance-game ledger misuse."""


class BadIdError(AssistanceGameError):
    """Malformed session / play / evaluation id."""


class BadDigestError(AssistanceGameError):
    """Malformed sha256: digest pin."""


class BadKindError(AssistanceGameError):
    """Episode kind outside the pinned vocabulary."""


class BadOutcomeError(AssistanceGameError):
    """Play outcome outside the pinned vocabulary."""


class BadMetricError(AssistanceGameError):
    """Evaluation metric outside the pinned vocabulary."""


class BadValueError(AssistanceGameError):
    """Evaluation value outside the pinned [0, 100] int range."""


class BadReasonError(AssistanceGameError):
    """Retire reason outside the pinned vocabulary."""


class UnknownSessionError(AssistanceGameError):
    """Reference to a session id that was never played."""


class UnknownPlayError(AssistanceGameError):
    """Reference to a play id that was never booked."""


class UnknownEvaluationError(AssistanceGameError):
    """Reference to an evaluation id that was never booked."""


class RetiredSessionError(AssistanceGameError):
    """Mutation attempted on a retired session."""


class SeqOrderError(AssistanceGameError):
    """Caller seq did not strictly increase."""


class AuditKindError(AssistanceGameError):
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


def _require_score(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadValueError("value must be an int in [0, 100]")
    if value < 0 or value > 100:
        raise BadValueError("value must be an int in [0, 100]")
    return value


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlayRecord:
    """One declared assistance-game episode (minted ply-N ids)."""

    play_id: str
    session_id: str
    episode_kind: str
    outcome: str
    session_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "play_id": self.play_id,
            "session_id": self.session_id,
            "episode_kind": self.episode_kind,
            "outcome": self.outcome,
            "session_digest": self.session_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True only when untampered."""
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "play_id": self.play_id,
                "session_id": self.session_id,
                "episode_kind": self.episode_kind,
                "outcome": self.outcome,
                "session_digest": self.session_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class EvaluationRecord:
    """One declared evaluation of an assistance-game session (evl-N ids)."""

    evaluation_id: str
    session_id: str
    metric: str
    value: int
    eval_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "evaluation_id": self.evaluation_id,
            "session_id": self.session_id,
            "metric": self.metric,
            "value": self.value,
            "eval_digest": self.eval_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True only when untampered."""
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "evaluation_id": self.evaluation_id,
                "session_id": self.session_id,
                "metric": self.metric,
                "value": self.value,
                "eval_digest": self.eval_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of an assistance-game session."""

    session_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "session_id": self.session_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True only when untampered."""
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "session_id": self.session_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class SessionStatus:
    """Pure-read posture of one assistance-game session, as data."""

    session_id: str
    n_plays: int
    n_evaluations: int
    posture: str
    retired: bool
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "session_id": self.session_id,
            "n_plays": self.n_plays,
            "n_evaluations": self.n_evaluations,
            "posture": self.posture,
            "retired": self.retired,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True only when untampered."""
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "session_id": self.session_id,
                "n_plays": self.n_plays,
                "n_evaluations": self.n_evaluations,
                "posture": self.posture,
                "retired": self.retired,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read verification verdict for one session, as data."""

    session_id: str
    n_plays: int
    n_evaluations: int
    posture: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "session_id": self.session_id,
            "n_plays": self.n_plays,
            "n_evaluations": self.n_evaluations,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True only when untampered."""
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "session_id": self.session_id,
                "n_plays": self.n_plays,
                "n_evaluations": self.n_evaluations,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def assistance_game_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the assistance-game ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"assistance-game.{kind}",
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AssistanceGame:
    """Assistance-game decision ledger (Simulated).

    ``play()`` / ``evaluate()`` / ``retire()`` mutate the ledger and consume
    caller seqs; ``verify()`` / ``status()`` and the remaining views are pure
    reads (seq shape-validated, never consumed, no audit rows).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._plays: Dict[str, PlayRecord] = {}
        self._session_plays: Dict[str, List[str]] = {}
        self._evaluations: Dict[str, EvaluationRecord] = {}
        self._session_evaluations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._play_counter = 0
        self._eval_counter = 0
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
            row = assistance_game_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            assistance_game_audit_event(audit_kind, seq, **details)
        )

    def _require_known(self, session_id: str) -> None:
        if session_id not in self._session_plays:
            raise UnknownSessionError(
                f"session was never played: {session_id!r}"
            )

    def _require_live(self, session_id: str) -> None:
        if session_id in self._retired:
            raise RetiredSessionError(f"session is retired: {session_id!r}")

    def _integrity_ok(self, session_id: str) -> bool:
        return all(
            self._plays[pid].verify()
            for pid in self._session_plays[session_id]
        ) and all(
            self._evaluations[eid].verify()
            for eid in self._session_evaluations[session_id]
        )

    def _posture(self, session_id: str) -> str:
        outcomes = {
            self._plays[pid].outcome
            for pid in self._session_plays[session_id]
        }
        n_evals = len(self._session_evaluations[session_id])
        if not outcomes:
            return "unplayed"
        if "degraded" in outcomes:
            return "degraded"
        if outcomes != {"improved"}:
            return "contested"
        if n_evals == 0:
            return "unevaluated"
        return "improved"

    # -- play ----------------------------------------------------------------

    def play(
        self,
        session_id: str,
        seq: int,
        episode_kind: str = "value-elicitation",
        outcome: str = "improved",
        session_digest: str = "",
    ) -> PlayRecord:
        """Book one declared assistance-game episode.

        The first play on an id registers the session; raw human
        preferences, reward parameters, and transcripts never enter
        records (digest pins only).
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(session_id, "session_id")
                if episode_kind not in EPISODE_KINDS:
                    raise BadKindError(f"bad episode kind: {episode_kind!r}")
                if outcome not in PLAY_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                session_digest = _require_optional_digest(
                    session_digest, "session_digest"
                )
                self._require_live(session_id)
                self._play_counter += 1
                play_id = f"ply-{self._play_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "play_id": play_id,
                        "session_id": session_id,
                        "episode_kind": episode_kind,
                        "outcome": outcome,
                        "session_digest": session_digest,
                        "seq": seq,
                    }
                )
                record = PlayRecord(
                    play_id=play_id,
                    session_id=session_id,
                    episode_kind=episode_kind,
                    outcome=outcome,
                    session_digest=session_digest,
                    seq=seq,
                    digest=digest,
                )
                self._plays[play_id] = record
                self._session_plays.setdefault(session_id, []).append(play_id)
                self._session_evaluations.setdefault(session_id, [])
                self._emit(
                    "played",
                    seq,
                    play_id=play_id,
                    session_id=session_id,
                    episode_kind=episode_kind,
                    outcome=outcome,
                )
                return record
            except AssistanceGameError:
                self._burn(seq, "play")
                raise

    # -- evaluate ------------------------------------------------------------

    def evaluate(
        self,
        session_id: str,
        seq: int,
        metric: str = "regret",
        value: int = 0,
        eval_digest: str = "",
    ) -> EvaluationRecord:
        """Book one declared evaluation of a session.

        The metric and host-reported value are data, never proof the
        session actually helped the human.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(session_id, "session_id")
                if metric not in EVAL_METRICS:
                    raise BadMetricError(f"bad metric: {metric!r}")
                value = _require_score(value)
                eval_digest = _require_optional_digest(
                    eval_digest, "eval_digest"
                )
                self._require_known(session_id)
                self._require_live(session_id)
                self._eval_counter += 1
                evaluation_id = f"evl-{self._eval_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "evaluation_id": evaluation_id,
                        "session_id": session_id,
                        "metric": metric,
                        "value": value,
                        "eval_digest": eval_digest,
                        "seq": seq,
                    }
                )
                record = EvaluationRecord(
                    evaluation_id=evaluation_id,
                    session_id=session_id,
                    metric=metric,
                    value=value,
                    eval_digest=eval_digest,
                    seq=seq,
                    digest=digest,
                )
                self._evaluations[evaluation_id] = record
                self._session_evaluations[session_id].append(evaluation_id)
                self._emit(
                    "evaluated",
                    seq,
                    evaluation_id=evaluation_id,
                    session_id=session_id,
                    metric=metric,
                    value=value,
                )
                return record
            except AssistanceGameError:
                self._burn(seq, "evaluate")
                raise

    # -- verify (pure read) --------------------------------------------------

    def verify(self, session_id: str, seq: int) -> VerificationReport:
        """Derived verification verdict for one session, as data.

        Re-derives every digest pin in the session; posture and
        ``integrity_ok`` are data (tamper reported, never raised).
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(session_id, "session_id")
            self._require_known(session_id)
            n_plays = len(self._session_plays[session_id])
            n_evaluations = len(self._session_evaluations[session_id])
            posture = self._posture(session_id)
            integrity_ok = self._integrity_ok(session_id)
            report = VerificationReport(
                session_id=session_id,
                n_plays=n_plays,
                n_evaluations=n_evaluations,
                posture=posture,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "session_id": session_id,
                        "n_plays": n_plays,
                        "n_evaluations": n_evaluations,
                        "posture": posture,
                        "integrity_ok": integrity_ok,
                        "seq": seq,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return report

    # -- retire ----------------------------------------------------------------

    def retire(
        self, session_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a session's lifecycle.

        Retired ids are never recycled; post-retire mutations are refused,
        reads still work.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(session_id, "session_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                self._require_known(session_id)
                self._require_live(session_id)
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "session_id": session_id,
                        "reason": reason,
                        "seq": seq,
                    }
                )
                record = RetireRecord(
                    session_id=session_id, reason=reason, seq=seq, digest=digest
                )
                self._retired[session_id] = record
                self._emit("retired", seq, session_id=session_id, reason=reason)
                return record
            except AssistanceGameError:
                self._burn(seq, "retire")
                raise

    # -- status (pure read) ----------------------------------------------------

    def status(self, session_id: str, seq: int) -> SessionStatus:
        """Derived posture of one session, as data (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(session_id, "session_id")
            self._require_known(session_id)
            n_plays = len(self._session_plays[session_id])
            n_evaluations = len(self._session_evaluations[session_id])
            posture = self._posture(session_id)
            retired = session_id in self._retired
            integrity_ok = self._integrity_ok(session_id)
            status = SessionStatus(
                session_id=session_id,
                n_plays=n_plays,
                n_evaluations=n_evaluations,
                posture=posture,
                retired=retired,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "session_id": session_id,
                        "n_plays": n_plays,
                        "n_evaluations": n_evaluations,
                        "posture": posture,
                        "retired": retired,
                        "integrity_ok": integrity_ok,
                        "seq": seq,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return status

    # -- views (pure reads) ------------------------------------------------------

    def play_record(self, play_id: str, seq: int) -> PlayRecord:
        """Return one play record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(play_id, "play_id")
            if play_id not in self._plays:
                raise UnknownPlayError(f"unknown play: {play_id!r}")
            return self._plays[play_id]

    def evaluation_record(
        self, evaluation_id: str, seq: int
    ) -> EvaluationRecord:
        """Return one evaluation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(evaluation_id, "evaluation_id")
            if evaluation_id not in self._evaluations:
                raise UnknownEvaluationError(
                    f"unknown evaluation: {evaluation_id!r}"
                )
            return self._evaluations[evaluation_id]

    def session_ids(self, seq: int) -> Tuple[str, ...]:
        """All played session ids in first-play order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._session_plays.keys())

    def play_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked play ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._plays.keys())

    def evaluation_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked evaluation ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._evaluations.keys())

    def plays_for(self, session_id: str, seq: int) -> Tuple[str, ...]:
        """Play ids booked against one session, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(session_id, "session_id")
            self._require_known(session_id)
            return tuple(self._session_plays[session_id])

    def evaluations_for(
        self, session_id: str, seq: int
    ) -> Tuple[str, ...]:
        """Evaluation ids booked against one session, in mint order."""
        with self._lock:
            self._check_seq(seq)
            _require_id(session_id, "session_id")
            self._require_known(session_id)
            return tuple(self._session_evaluations[session_id])

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired session ids (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "sessions": len(self._session_plays),
                "plays": len(self._plays),
                "evaluations": len(self._evaluations),
                "retired": len(self._retired),
                "rejected": sum(
                    1 for row in self._audit if row["kind"].endswith("rejected")
                ),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    @classmethod
    def stdlib_only(cls) -> bool:
        """Self-attestation that this module imports stdlib only."""
        return True


def main() -> None:
    """Self-check: exercise the assistance-game ledger end to end."""
    g = AssistanceGame()
    r1 = g.play("s-1", 1, episode_kind="value-elicitation", outcome="improved")
    g.evaluate("s-1", 2, metric="preference-alignment", value=88)
    assert r1.play_id == "ply-1" and r1.verify()
    v = g.verify("s-1", 3)
    assert v.posture == "improved" and v.integrity_ok
    st = g.status("s-1", 4)
    assert st.posture == "improved" and not st.retired
    g.retire("s-1", 5, reason="task-complete")
    assert g.status("s-1", 6).retired
    assert g.stats(7) == {
        "sessions": 1,
        "plays": 1,
        "evaluations": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("assistance-game OK: play, evaluate, verify, retire, pins, audit")


if __name__ == "__main__":
    main()
