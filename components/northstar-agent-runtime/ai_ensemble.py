"""AI ensemble: ensemble-composition decision ledger, Simulated.

Research note: ensemble methods combine multiple member models into one
declared decision - majority vote, weighted vote, stacking, boosting,
bagging, mixture of experts, snapshot ensembles, Bayesian model
averaging and kin. This module is the *decision ledger* for declared
ensemble compositions: which systems were declared to combine which
members (over a pinned strategy vocabulary), what member-agreement
verdicts were declared against them, and what robustness posture the
ledger derives - defensible bookkeeping, never proof that an ensemble
is really more robust.

This module owns the ensemble -> verify -> evaluate lifecycle:

* **ensemble()** - book one declared ensemble composition (minted
  ``ens-N`` ids; pinned 8-strategy vocabulary; pinned agreement
  verdict vocabulary booked *as data*); the first composition
  registers its system; raw member outputs, vote tallies, weights,
  and model internals never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one ensemble record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the ensemble was really built.
* **evaluate()** - **pure read**: derive one system's ensemble
  posture as data (``unassembled`` -> ``divided`` -> ``contested`` ->
  ``plural`` -> ``consensus``) with agreement tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: detector and voting mechanics
modules own *how* members detect or vote; ``ai_robustness.py`` owns
robustness-*test* governance; ``ai_redundancy.py``-style layers own
operational failover - this module is the ensemble-*composition
declaration* ledger none of them own: declared combinations over the
pinned ensemble-strategy vocabulary, declared member-agreement
verdicts, and the ledger-rule posture that turns declared agreement
into a robustness claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-ensemble.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module builds no ensembles, runs no member models,
and proves nothing about real robustness. A booked ``unanimous``
verdict means "the host declared it", never "the members really
agreed"; a booked ``split`` verdict means "the host declared it",
never "the members really disagreed". Member outputs, vote tallies,
weights, and model internals never enter records or cross the audit
boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_ENSEMBLE_VERSION = "ai-ensemble.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-ensemble.v1"

#: Pinned ensemble-strategy vocabulary (the combination families declared).
ENSEMBLE_STRATEGIES = (
    "majority-vote",
    "weighted-vote",
    "stacking",
    "boosting",
    "bagging",
    "mixture-of-experts",
    "snapshot-ensemble",
    "bayesian-average",
)

#: Pinned member-agreement vocabulary (booked as data, never proof).
AGREEMENTS = (
    "unanimous",
    "majority",
    "plurality",
    "split",
    "not-assessed",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unassembled",
    "divided",
    "contested",
    "plural",
    "consensus",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "ensembled",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        # ensemble raw material
        "member_outputs",
        "member_predictions",
        "member_logits",
        "member_models",
        "member_weights",
        "votes",
        "vote_tally",
        "vote_tallies",
        "vote",
        "ballots",
        "ensemble_output",
        "combined_output",
        "stacked_output",
        "blended_prediction",
        "meta_learner",
        "base_learners",
        "weak_learners",
        "gating_network",
        "expert_outputs",
        "confidence_scores",
        "confidences",
        "predictions",
        "prediction",
        "logits",
        "logit",
        "scores",
        "output",
        "outputs",
        "response",
        "responses",
        # model internals
        "weights",
        "model_weights",
        "parameters",
        "params",
        "activations",
        "gradients",
        "embeddings",
        "attention",
        "attention_weights",
        "attention_maps",
        "features",
        "feature_importance",
        "feature_vector",
        "prompt",
        "prompts",
        "input_text",
        "input_tokens",
        "tokens",
        "token_list",
        "explanation",
        "explanations",
        # generic sensitive / raw material
        "payload",
        "payloads",
        "exploit",
        "exploits",
        "shellcode",
        "credential",
        "credentials",
        "password",
        "api_key",
        "secret",
        "token",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "command_output",
        "stderr",
        "stdout",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIEnsembleError(Exception):
    """Base class for all ai-ensemble ledger errors."""


class BadInputError(AIEnsembleError):
    pass


class UnknownSystemError(AIEnsembleError):
    pass


class RetiredSystemError(AIEnsembleError):
    pass


class BadStrategyError(AIEnsembleError):
    pass


class BadAgreementError(AIEnsembleError):
    pass


class BadDigestError(AIEnsembleError):
    pass


class BadReasonError(AIEnsembleError):
    pass


class UnknownEnsembleError(AIEnsembleError):
    pass


class UnknownRecordError(AIEnsembleError):
    pass


class SeqOrderError(AIEnsembleError):
    pass


class AuditKindError(AIEnsembleError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadInputError(f"{what} must be a non-empty string")
    return value


def _check_strategy(value: Any) -> str:
    if value not in ENSEMBLE_STRATEGIES:
        raise BadStrategyError(f"ensemble_strategy must be one of {ENSEMBLE_STRATEGIES}")
    return value


def _check_agreement(value: Any) -> str:
    if value not in AGREEMENTS:
        raise BadAgreementError(f"agreement must be one of {AGREEMENTS}")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnsembleRecord:
    ensemble_id: str
    system_id: str
    seq: int
    ensemble_strategy: str
    agreement: str
    ensemble_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _ensemble_payload(self), "ai-ensemble.ensemble"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-ensemble.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-ensemble.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_ensembles: int
    n_unanimous: int
    n_majority: int
    n_plurality: int
    n_split: int
    n_not_assessed: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-ensemble.evaluate"
        )


def _ensemble_payload(rec: "EnsembleRecord") -> Dict[str, Any]:
    return {
        "ensemble_id": rec.ensemble_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "ensemble_strategy": rec.ensemble_strategy,
        "agreement": rec.agreement,
        "ensemble_digest": rec.ensemble_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_ensembles": rep.n_ensembles,
        "n_unanimous": rep.n_unanimous,
        "n_majority": rep.n_majority,
        "n_plurality": rep.n_plurality,
        "n_split": rep.n_split,
        "n_not_assessed": rep.n_not_assessed,
        "integrity_ok": rep.integrity_ok,
    }


def ai_ensemble_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIEnsembleError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-ensemble",
        "version": AI_ENSEMBLE_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIEnsemble:
    """AI ensemble-composition decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All agreements are booked as
    data - never proof that members really agreed or disagreed.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._ensembles: Dict[str, EnsembleRecord] = {}
        self._system_ensembles: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._ensemble_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_ensemble_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-ensemble",
                "version": AI_ENSEMBLE_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_ensemble_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def ensemble(
        self,
        system_id: str,
        seq: int,
        ensemble_strategy: str = "majority-vote",
        agreement: str = "not-assessed",
        ensemble_digest: str = "",
    ) -> EnsembleRecord:
        """Book one declared ensemble composition (minted ``ens-N`` id).

        The first composition on an id registers the system. Raw member
        outputs, vote tallies, weights, and model internals never enter
        records - digest pins only. Fail-closed: failed mutations consume
        their seq and book an ``ai-ensemble.rejected`` row; rewinds raise
        bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                ensemble_strategy = _check_strategy(ensemble_strategy)
                agreement = _check_agreement(agreement)
                ensemble_digest = _check_digest(ensemble_digest, "ensemble_digest")
                self._require_live(system_id)
            except AIEnsembleError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._ensemble_counter += 1
            ensemble_id = f"ens-{self._ensemble_counter}"
            provisional = EnsembleRecord(
                ensemble_id=ensemble_id,
                system_id=system_id,
                seq=seq,
                ensemble_strategy=ensemble_strategy,
                agreement=agreement,
                ensemble_digest=ensemble_digest,
                digest="",
            )
            digest = _digest_pin(_ensemble_payload(provisional), "ai-ensemble.ensemble")
            rec = EnsembleRecord(
                ensemble_id=ensemble_id,
                system_id=system_id,
                seq=seq,
                ensemble_strategy=ensemble_strategy,
                agreement=agreement,
                ensemble_digest=ensemble_digest,
                digest=digest,
            )
            self._ensembles[ensemble_id] = rec
            self._system_ensembles.setdefault(system_id, []).append(ensemble_id)
            self._emit(
                "ensembled",
                seq,
                ensemble_id=ensemble_id,
                system_id=system_id,
                ensemble_strategy=ensemble_strategy,
                agreement=agreement,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_ensembles:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIEnsembleError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-ensemble.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._ensembles[eid].verify()
            for eid in self._system_ensembles.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "unanimous": 0,
            "majority": 0,
            "plurality": 0,
            "split": 0,
            "not-assessed": 0,
        }
        ids = self._system_ensembles.get(system_id, [])
        for eid in ids:
            tallies[self._ensembles[eid].agreement] += 1
        if not ids:
            return "unassembled", tallies
        if tallies["split"]:
            return "divided", tallies
        if tallies["not-assessed"]:
            return "contested", tallies
        if tallies["plurality"]:
            return "plural", tallies
        return "consensus", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._ensembles.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-ensemble.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's ensemble posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_ensembles:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_ensembles=len(self._system_ensembles[system_id]),
                n_unanimous=tallies["unanimous"],
                n_majority=tallies["majority"],
                n_plurality=tallies["plurality"],
                n_split=tallies["split"],
                n_not_assessed=tallies["not-assessed"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-ensemble.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_ensembles=len(self._system_ensembles[system_id]),
                n_unanimous=tallies["unanimous"],
                n_majority=tallies["majority"],
                n_plurality=tallies["plurality"],
                n_split=tallies["split"],
                n_not_assessed=tallies["not-assessed"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) --------------------------------------------------

    def ensemble_record(self, ensemble_id: str, seq: int) -> EnsembleRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._ensembles.get(ensemble_id)
            if rec is None:
                raise UnknownEnsembleError(
                    f"unknown ensemble: {ensemble_id!r}"
                )
            return rec

    def ensembles_for(self, system_id: str, seq: int) -> Tuple[EnsembleRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._ensembles[eid]
                for eid in self._system_ensembles.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_ensembles.keys()))

    def ensemble_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._ensembles.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_ensembles),
                "n_ensembles": len(self._ensembles),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# stdlib self-check and CLI
# ---------------------------------------------------------------------------


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: exercise ensemble -> verify -> evaluate."""
    ledger = AIEnsemble()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.ensemble(
        "sys-1", 1, ensemble_strategy="stacking", agreement="unanimous"
    )
    assert rec.verify()
    rec2 = ledger.ensemble(
        "sys-1", 2, ensemble_strategy="majority-vote", agreement="majority"
    )
    assert rec2.verify()
    rep = ledger.verify(rec.ensemble_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "consensus"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-ensemble OK: ensemble, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
