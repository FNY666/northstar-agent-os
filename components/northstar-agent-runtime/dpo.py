"""DPO: Direct Preference Optimization bookkeeping for agents.

Research note: Direct Preference Optimization (Rafailov et al., 2023,
"Direct Preference Optimization: Your Language Model is Secretly a
Reward Model") replaces the RLHF reward-model + PPO pipeline with a
single classification-style objective over human preference pairs:

    L_DPO = -log sigma(beta * (Delta_policy - Delta_ref))

where ``Delta_policy = log pi_theta(y_w|x) - log pi_theta(y_l|x)`` and
``Delta_ref`` is the same margin under the frozen reference policy.
This module is the *ledger* layer for that practice:

* **prefer()** books one human preference pair (minted ``pref-N``):
  the prompt, the chosen response, and the rejected response are
  pinned by ``sha256:`` digest only - raw text never enters a record.
  A pair whose chosen and rejected digests are identical is refused
  fail-closed (there is no preference to learn).
* **optimize()** books one declared DPO step (minted ``opt-N``) against
  a booked pair: the host reports the four log-probabilities
  (policy/ref x chosen/rejected) and the module deterministically
  computes the per-pair DPO loss term via a numerically stable
  ``softplus(-x)`` form (``-log sigma(x)`` is overflow-free for any
  finite input). Log-probabilities are host-reported GIGO; the module
  only proves the arithmetic, never that a model really updated.
* **loss()** is a *pure read* view: a digest-pinned ``LossReport``
  recomputing the loss from the booked inputs. It validates seq shape,
  consumes nothing, and books no audit rows.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs, no wall-clock, RLock guarding,
fail-closed taxonomy, stdlib-only with the standard
``canonical_json`` try/except fallback, ``sha256:`` digest pins, and
``audit.ndjson/1`` events.

Honest scope: the module books *declared* preference pairs and
*declared* optimization steps; it cannot verify that a human actually
preferred the chosen response, that the log-probabilities are real
model outputs, or that any training happened. Raw prompts and raw
responses never enter records and never cross the audit boundary
(digest pins only).
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
DPO_VERSION = "dpo.v1"

#: Schema pin carried by records and audit events.
DPO_SCHEMA = "northstar.dpo.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_PREFERRED = "dpo.preferred"
KIND_OPTIMIZED = "dpo.optimized"
KIND_REJECTED = "dpo.rejected"
_KINDS = frozenset({KIND_PREFERRED, KIND_OPTIMIZED, KIND_REJECTED})

#: Digest prefix for all pins.
_DIGEST_PREFIX = "sha256:"

#: Max length for view id arguments.
_MAX_ID_LEN = 128


# ---------------------------------------------------------------------------
# Fail-closed taxonomy
# ---------------------------------------------------------------------------


class DPOError(Exception):
    """Base class for all DPO ledger errors."""


class BadDigestError(DPOError):
    """A digest argument is malformed."""


class IdenticalResponsesError(DPOError):
    """Chosen and rejected digests are identical: no preference to learn."""


class UnknownPreferenceError(DPOError):
    """The named preference pair is not booked."""


class BadBetaError(DPOError):
    """The KL-penalty beta is outside (0, 1] or not a number."""


class BadLogProbError(DPOError):
    """A log-probability is non-finite or positive (not a log-probability)."""


class UnknownOptimizationError(DPOError):
    """The named optimization step is not booked."""


class SeqOrderError(DPOError):
    """Seq is not a strictly increasing int."""


class AuditKindError(DPOError):
    """Unknown audit kind, or banned detail key."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise DPOError(f"{what} must be a str, got {type(value).__name__}")
    if not value or len(value) > _MAX_ID_LEN:
        raise DPOError(f"{what} must be a non-empty str of at most {_MAX_ID_LEN} chars")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = False) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        if allow_empty:
            return ""
        raise BadDigestError(f"{what} must be a non-empty sha256:-prefixed digest")
    if not value.startswith(_DIGEST_PREFIX) or len(value) <= len(_DIGEST_PREFIX):
        raise BadDigestError(f"{what} must be a non-empty sha256:-prefixed digest")
    if len(value) > _MAX_ID_LEN + 64:
        raise BadDigestError(f"{what} too long")
    return value


def _check_beta(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadBetaError(f"beta must be a number, got {type(value).__name__}")
    beta = float(value)
    if beta != beta or beta in (float("inf"), float("-inf")):
        raise BadBetaError("beta must be finite")
    if not 0.0 < beta <= 1.0:
        raise BadBetaError(f"beta must be in (0, 1], got {beta!r}")
    return beta


def _check_logprob(value: Any, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadLogProbError(f"{what} must be a number, got {type(value).__name__}")
    lp = float(value)
    if lp != lp or lp in (float("inf"), float("-inf")):
        raise BadLogProbError(f"{what} must be finite")
    if lp > 0.0:
        raise BadLogProbError(f"{what} must be <= 0 (log-probabilities are non-positive)")
    return lp


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > 2**53 - 1:
                raise DPOError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise DPOError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise DPOError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# DPO loss arithmetic (deterministic, numerically stable)
# ---------------------------------------------------------------------------


def _dpo_loss_term(beta: float, margin: float) -> float:
    """Return -log sigma(beta * margin) via stable softplus(-x).

    margin = Delta_policy - Delta_ref. Any finite input is safe: the
    softplus form never overflows, unlike exp-based sigmoid math.
    """
    x = beta * margin
    y = -x
    return max(y, 0.0) + math.log1p(math.exp(-abs(y)))


def _margins(
    logp_policy_chosen: float,
    logp_policy_rejected: float,
    logp_ref_chosen: float,
    logp_ref_rejected: float,
) -> Tuple[float, float, float]:
    policy_margin = logp_policy_chosen - logp_policy_rejected
    ref_margin = logp_ref_chosen - logp_ref_rejected
    return policy_margin, ref_margin, policy_margin - ref_margin


def _preference_pin(
    pref_id: str, prompt_digest: str, chosen_digest: str, rejected_digest: str
) -> str:
    return _digest_pin((pref_id, prompt_digest, chosen_digest, rejected_digest), "preference")


def _optimize_pin(
    opt_id: str,
    pref_id: str,
    beta: float,
    logp_policy_chosen: float,
    logp_policy_rejected: float,
    logp_ref_chosen: float,
    logp_ref_rejected: float,
    margin: float,
    loss: float,
) -> str:
    return _digest_pin(
        (
            opt_id,
            pref_id,
            repr(beta),
            repr(logp_policy_chosen),
            repr(logp_policy_rejected),
            repr(logp_ref_chosen),
            repr(logp_ref_rejected),
            repr(margin),
            repr(loss),
        ),
        "optimization",
    )


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PreferenceRecord:
    """One booked human preference pair; responses pinned by digest only."""

    pref_id: str
    prompt_digest: str
    chosen_digest: str
    rejected_digest: str
    digest: str
    seq: int
    schema: str = DPO_SCHEMA

    def verify(self) -> bool:
        return self.digest == _preference_pin(
            self.pref_id, self.prompt_digest, self.chosen_digest, self.rejected_digest
        )


@dataclass(frozen=True)
class OptimizeRecord:
    """One declared DPO step: host-reported log-probs plus the computed loss term.

    ``loss`` is the deterministic per-pair term
    ``-log sigma(beta * (Delta_policy - Delta_ref))``.
    """

    opt_id: str
    pref_id: str
    beta: float
    logp_policy_chosen: float
    logp_policy_rejected: float
    logp_ref_chosen: float
    logp_ref_rejected: float
    policy_margin: float
    ref_margin: float
    margin: float
    loss: float
    digest: str
    seq: int
    schema: str = DPO_SCHEMA

    def verify(self) -> bool:
        policy_margin, ref_margin, margin = _margins(
            self.logp_policy_chosen,
            self.logp_policy_rejected,
            self.logp_ref_chosen,
            self.logp_ref_rejected,
        )
        loss = _dpo_loss_term(self.beta, margin)
        return (
            repr(self.policy_margin) == repr(policy_margin)
            and repr(self.ref_margin) == repr(ref_margin)
            and repr(self.margin) == repr(margin)
            and repr(self.loss) == repr(loss)
            and self.digest
            == _optimize_pin(
                self.opt_id,
                self.pref_id,
                self.beta,
                self.logp_policy_chosen,
                self.logp_policy_rejected,
                self.logp_ref_chosen,
                self.logp_ref_rejected,
                self.margin,
                self.loss,
            )
        )


@dataclass(frozen=True)
class LossReport:
    """Pure read view of one booked DPO step: margins and the recomputed loss."""

    opt_id: str
    pref_id: str
    beta: float
    policy_margin: float
    ref_margin: float
    margin: float
    loss: float
    digest: str
    seq: int
    schema: str = DPO_SCHEMA

    def verify(self) -> bool:
        loss = _dpo_loss_term(self.beta, self.margin)
        return repr(self.loss) == repr(loss) and self.digest == _digest_pin(
            (
                self.opt_id,
                self.pref_id,
                repr(self.beta),
                repr(self.policy_margin),
                repr(self.ref_margin),
                repr(self.margin),
                repr(self.loss),
            ),
            "loss-report",
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def dpo_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw prompts/responses never cross this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "prompt",
        "chosen",
        "rejected",
        "response",
        "text",
        "content",
        "payload",
        "raw",
        "value",
        "body",
        "message",
        "reason",
        "justification",
        "explanation",
        "action",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "dpo",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# DPO ledger
# ---------------------------------------------------------------------------


class DPO:
    """Direct Preference Optimization bookkeeping ledger: prefer, optimize, loss."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # pref_id -> PreferenceRecord (insertion order)
        self._preferences: Dict[str, PreferenceRecord] = {}
        # opt_id -> OptimizeRecord (insertion order)
        self._optimizations: Dict[str, OptimizeRecord] = {}
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(dpo_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: DPOError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def prefer(
        self,
        prompt_digest: str,
        chosen_digest: str,
        rejected_digest: str,
        seq: int,
    ) -> PreferenceRecord:
        """Book one human preference pair (minted ``pref-N``). Responses are digest-pinned only."""
        with self._lock:
            seq = self._claim(seq)
            try:
                prompt_digest = _check_digest(prompt_digest, "prompt_digest", allow_empty=True)
                chosen_digest = _check_digest(chosen_digest, "chosen_digest")
                rejected_digest = _check_digest(rejected_digest, "rejected_digest")
                if chosen_digest == rejected_digest:
                    raise IdenticalResponsesError(
                        "chosen and rejected digests are identical: no preference to learn"
                    )
            except DPOError as exc:
                self._fail(seq, exc)
            pref_id = f"pref-{len(self._preferences) + 1}"
            record = PreferenceRecord(
                pref_id=pref_id,
                prompt_digest=prompt_digest,
                chosen_digest=chosen_digest,
                rejected_digest=rejected_digest,
                digest=_preference_pin(pref_id, prompt_digest, chosen_digest, rejected_digest),
                seq=seq,
            )
            self._preferences[pref_id] = record
            self._emit(
                KIND_PREFERRED,
                seq,
                pref_id=pref_id,
                prompt_digest=prompt_digest,
                chosen_digest=chosen_digest,
                rejected_digest=rejected_digest,
            )
            return record

    def optimize(
        self,
        pref_id: str,
        seq: int,
        beta: float = 0.1,
        *,
        logp_policy_chosen: float,
        logp_policy_rejected: float,
        logp_ref_chosen: float,
        logp_ref_rejected: float,
    ) -> OptimizeRecord:
        """Book one declared DPO step (minted ``opt-N``) against a booked pair.

        The host reports the four log-probabilities (GIGO); the module
        deterministically computes the per-pair DPO loss term
        ``-log sigma(beta * (Delta_policy - Delta_ref))``.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                pref_id = _check_id(pref_id, "pref_id")
                if pref_id not in self._preferences:
                    raise UnknownPreferenceError(f"unknown preference pair: {pref_id!r}")
                beta = _check_beta(beta)
                lpc = _check_logprob(logp_policy_chosen, "logp_policy_chosen")
                lpr = _check_logprob(logp_policy_rejected, "logp_policy_rejected")
                lrc = _check_logprob(logp_ref_chosen, "logp_ref_chosen")
                lrr = _check_logprob(logp_ref_rejected, "logp_ref_rejected")
            except DPOError as exc:
                self._fail(seq, exc, pref_id=str(pref_id))
            policy_margin, ref_margin, margin = _margins(lpc, lpr, lrc, lrr)
            loss = _dpo_loss_term(beta, margin)
            opt_id = f"opt-{len(self._optimizations) + 1}"
            record = OptimizeRecord(
                opt_id=opt_id,
                pref_id=pref_id,
                beta=beta,
                logp_policy_chosen=lpc,
                logp_policy_rejected=lpr,
                logp_ref_chosen=lrc,
                logp_ref_rejected=lrr,
                policy_margin=policy_margin,
                ref_margin=ref_margin,
                margin=margin,
                loss=loss,
                digest=_optimize_pin(
                    opt_id, pref_id, beta, lpc, lpr, lrc, lrr, margin, loss
                ),
                seq=seq,
            )
            self._optimizations[opt_id] = record
            self._emit(
                KIND_OPTIMIZED,
                seq,
                opt_id=opt_id,
                pref_id=pref_id,
                beta=beta,
                loss=loss,
                margin=margin,
            )
            return record

    # -- pure reads ---------------------------------------------------------

    def loss(self, opt_id: str, seq: int) -> LossReport:
        """Pure read view of one booked DPO step: margins and the recomputed loss.

        Validates seq shape, consumes nothing, books no audit rows.
        """
        with self._lock:
            _check_seq(seq)
            opt_id = _check_id(opt_id, "opt_id")
            if opt_id not in self._optimizations:
                raise UnknownOptimizationError(f"unknown optimization step: {opt_id!r}")
            opt = self._optimizations[opt_id]
            return LossReport(
                opt_id=opt.opt_id,
                pref_id=opt.pref_id,
                beta=opt.beta,
                policy_margin=opt.policy_margin,
                ref_margin=opt.ref_margin,
                margin=opt.margin,
                loss=opt.loss,
                digest=_digest_pin(
                    (
                        opt.opt_id,
                        opt.pref_id,
                        repr(opt.beta),
                        repr(opt.policy_margin),
                        repr(opt.ref_margin),
                        repr(opt.margin),
                        repr(opt.loss),
                    ),
                    "loss-report",
                ),
                seq=seq,
            )

    def preference(self, pref_id: str, seq: int) -> PreferenceRecord:
        """Pure read view of one booked preference pair."""
        with self._lock:
            _check_seq(seq)
            pref_id = _check_id(pref_id, "pref_id")
            if pref_id not in self._preferences:
                raise UnknownPreferenceError(f"unknown preference pair: {pref_id!r}")
            return self._preferences[pref_id]

    def optimization(self, opt_id: str, seq: int) -> OptimizeRecord:
        """Pure read view of one booked optimization step."""
        with self._lock:
            _check_seq(seq)
            opt_id = _check_id(opt_id, "opt_id")
            if opt_id not in self._optimizations:
                raise UnknownOptimizationError(f"unknown optimization step: {opt_id!r}")
            return self._optimizations[opt_id]

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: counts of booked pairs and optimization steps."""
        with self._lock:
            _check_seq(seq)
            return {
                "schema": DPO_SCHEMA,
                "preferences": len(self._preferences),
                "optimizations": len(self._optimizations),
                "audit_rows": len(self._audit_events),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the booked audit events in order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit_events)


def main() -> None:
    """Self-check: prefer, optimize, loss, pins, audit."""
    ledger = DPO()
    pref = ledger.prefer("sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64, 1)
    assert pref.verify()
    assert pref.pref_id == "pref-1"
    # margins: policy 1.0, ref 1.0 -> margin 0 -> loss = ln(2)
    opt = ledger.optimize(
        pref.pref_id,
        2,
        beta=0.5,
        logp_policy_chosen=-1.0,
        logp_policy_rejected=-2.0,
        logp_ref_chosen=-1.5,
        logp_ref_rejected=-2.5,
    )
    assert opt.verify()
    assert opt.opt_id == "opt-1"
    assert abs(opt.loss - math.log(2)) < 1e-12
    rep = ledger.loss(opt.opt_id, 3)
    assert rep.verify()
    assert rep.loss == opt.loss
    assert rep.margin == 0.0
    stats = ledger.stats(3)
    assert stats["preferences"] == 1 and stats["optimizations"] == 1
    assert [e["kind"] for e in ledger.audit_log(3)] == [KIND_PREFERRED, KIND_OPTIMIZED]
    print("dpo OK: prefer, optimize, loss, pins, audit")


if __name__ == "__main__":
    main()
