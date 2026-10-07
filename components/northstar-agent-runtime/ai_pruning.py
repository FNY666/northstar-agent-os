"""AI pruning: declared pruning-operation decision ledger, Simulated.

Research note: pruning shrinks a model - weight pruning, neuron pruning,
channel pruning, structured vs unstructured, layer pruning, attention-head
pruning, token pruning and kin - trading capacity for size, speed, or cost.
This module is the *decision ledger* for declared pruning operations:
which models had which pruning runs booked (over a pinned method
vocabulary), what sparsity levels and verdicts were declared against
them, and what pruning posture the ledger derives - defensible
bookkeeping, never proof that a model was really pruned or that it still
behaves the same.

This module owns the prune -> verify -> evaluate lifecycle:

* **prune()** - book one declared pruning operation (minted ``prn-N``
  ids; pinned 8-kind vocabulary; host-reported sparsity ``[0,100]``;
  pinned verdict vocabulary booked *as data*); the first prune registers
  its model; raw weights, masks, and pruning schedules never enter
  records - digest pins only.
* **verify()** - **pure read**: re-derive one prune record's digest pin;
  verdict ``verified`` / ``tampered`` booked as data, never as proof the
  pruning really happened.
* **evaluate()** - **pure read**: derive one model's pruning posture as
  data (``unpruned`` -> ``failed`` -> ``contested`` ->
  ``partially-pruned`` -> ``pruned``) with verdict tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of a model id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_sparsity.py`` would own
sparsity *measurement* mechanics; ``ai_compression.py`` would own the
compression-tooling lifecycle; ``ai_robustness.py`` owns robustness-test
governance - this module is the pruning-*operation* decision ledger none
of them own: declared pruning runs over the pinned pruning-kind
vocabulary, declared sparsity values, and the ledger-rule posture that
turns declared verdicts into a pruning claim, always as data, never as
measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-pruning.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module prunes nothing, inspects no weights, and
proves nothing about real sparsity or preserved behaviour. A booked
``pruned`` verdict means "the host declared it", never "the model is
pruned"; a booked sparsity of ``90`` means "the host reported it", never
"the model is 90% sparse". Weights, masks, schedules, accuracy reports,
and model internals never enter records or cross the audit boundary -
digest pins only.
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
AI_PRUNING_VERSION = "ai-pruning.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-pruning.v1"

#: Pinned pruning-method vocabulary (the pruning families declared).
PRUNING_KINDS = (
    "weight-pruning",
    "neuron-pruning",
    "channel-pruning",
    "structured-pruning",
    "unstructured-pruning",
    "layer-pruning",
    "attention-head-pruning",
    "token-pruning",
)

#: Pinned verdict vocabulary (booked as data, never proof).
VERDICTS = (
    "pruned",
    "partial",
    "failed",
    "inconclusive",
    "not-pruned",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unpruned",
    "failed",
    "contested",
    "partially-pruned",
    "pruned",
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
    "pruned",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "weight_matrix",
        "parameters",
        "params",
        "param_dict",
        "mask",
        "masks",
        "pruning_mask",
        "sparsity_mask",
        "activations",
        "gradients",
        "embeddings",
        "attention",
        "attention_weights",
        "attention_heads",
        "neurons",
        "neuron_scores",
        "channels",
        "channel_scores",
        "layers",
        "layer_indices",
        "head_scores",
        "token_scores",
        "importance_scores",
        "sensitivity_scores",
        "schedule",
        "pruning_schedule",
        "fine_tune_schedule",
        "accuracy",
        "accuracy_report",
        "perplexity",
        "eval_results",
        "benchmark_results",
        "checkpoint",
        "checkpoint_data",
        "weights_file",
        "snapshot",
        "snapshots",
        "dump",
        "dumps",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "logits",
        "logit",
        "scores",
        "prediction",
        "tokens",
        "token_list",
        "features",
        "feature_vector",
        "embedding_vector",
        "dataset",
        "training_data",
        "calibration_data",
        "model_architecture",
        "config",
        "hyperparameters",
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
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIPruningError(Exception):
    """Base class for all ai-pruning ledger errors."""


class BadModelError(AIPruningError):
    pass


class UnknownModelError(AIPruningError):
    pass


class RetiredModelError(AIPruningError):
    pass


class BadPruningKindError(AIPruningError):
    pass


class BadVerdictError(AIPruningError):
    pass


class BadSparsityError(AIPruningError):
    pass


class BadDigestError(AIPruningError):
    pass


class BadReasonError(AIPruningError):
    pass


class UnknownPruneError(AIPruningError):
    pass


class UnknownRecordError(AIPruningError):
    pass


class SeqOrderError(AIPruningError):
    pass


class AuditKindError(AIPruningError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadModelError(f"{what} must be a non-empty string")
    return value


def _check_kind(value: Any) -> str:
    if value not in PRUNING_KINDS:
        raise BadPruningKindError(f"pruning_kind must be one of {PRUNING_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in VERDICTS:
        raise BadVerdictError(f"verdict must be one of {VERDICTS}")
    return value


def _check_sparsity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSparsityError("sparsity must be an int in [0, 100]")
    if value < 0 or value > 100:
        raise BadSparsityError("sparsity must be an int in [0, 100]")
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
class PruneRecord:
    prune_id: str
    model_id: str
    seq: int
    pruning_kind: str
    sparsity: int
    verdict: str
    prune_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _prune_payload(self), "ai-pruning.prune"
        )


@dataclass(frozen=True)
class RetireRecord:
    model_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-pruning.retire"
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
            _verify_payload(self), "ai-pruning.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    model_id: str
    seq: int
    posture: str
    n_prunes: int
    n_pruned: int
    n_partial: int
    n_failed: int
    n_inconclusive: int
    n_not_pruned: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-pruning.evaluate"
        )


def _prune_payload(rec: "PruneRecord") -> Dict[str, Any]:
    return {
        "prune_id": rec.prune_id,
        "model_id": rec.model_id,
        "seq": rec.seq,
        "pruning_kind": rec.pruning_kind,
        "sparsity": rec.sparsity,
        "verdict": rec.verdict,
        "prune_digest": rec.prune_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"model_id": rec.model_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "model_id": rep.model_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_prunes": rep.n_prunes,
        "n_pruned": rep.n_pruned,
        "n_partial": rep.n_partial,
        "n_failed": rep.n_failed,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_pruned": rep.n_not_pruned,
        "integrity_ok": rep.integrity_ok,
    }


def ai_pruning_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIPruningError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-pruning",
        "version": AI_PRUNING_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIPruning:
    """AI pruning-operation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts and sparsity
    values are booked as data - never proof a model was really pruned or
    is really sparse.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._prunes: Dict[str, PruneRecord] = {}
        self._model_prunes: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._prune_counter = 0
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
            row = ai_pruning_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-pruning",
                "version": AI_PRUNING_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_pruning_audit_event(audit_kind, seq, **details))

    def _require_live(self, model_id: str) -> None:
        if model_id in self._retired:
            raise RetiredModelError(f"model is retired: {model_id!r}")

    # -- mutations ---------------------------------------------------------

    def prune(
        self,
        model_id: str,
        seq: int,
        pruning_kind: str = "weight-pruning",
        sparsity: int = 0,
        verdict: str = "not-pruned",
        prune_digest: str = "",
    ) -> PruneRecord:
        """Book one declared pruning operation (minted ``prn-N`` id).

        The first prune on an id registers the model. Raw weights,
        masks, and pruning schedules never enter records - digest pins
        only. Sparsity is host-reported (int ``[0, 100]``), booked as
        data. Fail-closed: failed mutations consume their seq and book
        an ``ai-pruning.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                model_id = _check_id(model_id, "model_id")
                self._require_seq(seq)
                pruning_kind = _check_kind(pruning_kind)
                sparsity = _check_sparsity(sparsity)
                verdict = _check_verdict(verdict)
                prune_digest = _check_digest(prune_digest, "prune_digest")
                self._require_live(model_id)
            except AIPruningError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._prune_counter += 1
            prune_id = f"prn-{self._prune_counter}"
            provisional = PruneRecord(
                prune_id=prune_id,
                model_id=model_id,
                seq=seq,
                pruning_kind=pruning_kind,
                sparsity=sparsity,
                verdict=verdict,
                prune_digest=prune_digest,
                digest="",
            )
            digest = _digest_pin(_prune_payload(provisional), "ai-pruning.prune")
            rec = PruneRecord(
                prune_id=prune_id,
                model_id=model_id,
                seq=seq,
                pruning_kind=pruning_kind,
                sparsity=sparsity,
                verdict=verdict,
                prune_digest=prune_digest,
                digest=digest,
            )
            self._prunes[prune_id] = rec
            self._model_prunes.setdefault(model_id, []).append(prune_id)
            self._emit(
                "pruned",
                seq,
                prune_id=prune_id,
                model_id=model_id,
                pruning_kind=pruning_kind,
                sparsity=sparsity,
                verdict=verdict,
            )
            return rec

    def retire(
        self, model_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a model id; ids are never recycled."""
        with self._lock:
            try:
                model_id = _check_id(model_id, "model_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if model_id not in self._model_prunes:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                if model_id in self._retired:
                    raise RetiredModelError(
                        f"model already retired: {model_id!r}"
                    )
            except AIPruningError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                model_id=model_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-pruning.retire")
            rec = RetireRecord(
                model_id=model_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[model_id] = rec
            self._emit("retired", seq, model_id=model_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, model_id: str) -> bool:
        return all(
            self._prunes[pid].verify()
            for pid in self._model_prunes.get(model_id, [])
        )

    def _posture(self, model_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "pruned": 0,
            "partial": 0,
            "failed": 0,
            "inconclusive": 0,
            "not-pruned": 0,
        }
        ids = self._model_prunes.get(model_id, [])
        for pid in ids:
            tallies[self._prunes[pid].verdict] += 1
        if not ids:
            return "unpruned", tallies
        if tallies["failed"]:
            return "failed", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if tallies["partial"] or tallies["not-pruned"]:
            return "partially-pruned", tallies
        return "pruned", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._prunes.get(record_id)
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
            digest = _digest_pin(_verify_payload(provisional), "ai-pruning.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, model_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one model's pruning posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            model_id = _check_id(model_id, "model_id")
            if model_id not in self._model_prunes:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            posture, tallies = self._posture(model_id)
            provisional = EvaluationReport(
                model_id=model_id,
                seq=seq,
                posture=posture,
                n_prunes=len(self._model_prunes[model_id]),
                n_pruned=tallies["pruned"],
                n_partial=tallies["partial"],
                n_failed=tallies["failed"],
                n_inconclusive=tallies["inconclusive"],
                n_not_pruned=tallies["not-pruned"],
                integrity_ok=self._integrity_ok(model_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-pruning.evaluate")
            return EvaluationReport(
                model_id=model_id,
                seq=seq,
                posture=posture,
                n_prunes=len(self._model_prunes[model_id]),
                n_pruned=tallies["pruned"],
                n_partial=tallies["partial"],
                n_failed=tallies["failed"],
                n_inconclusive=tallies["inconclusive"],
                n_not_pruned=tallies["not-pruned"],
                integrity_ok=self._integrity_ok(model_id),
                digest=digest,
            )

    # -- views (pure reads) --------------------------------------------------

    def prune_record(self, prune_id: str, seq: int) -> PruneRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._prunes.get(prune_id)
            if rec is None:
                raise UnknownPruneError(f"unknown prune: {prune_id!r}")
            return rec

    def prunes_for(self, model_id: str, seq: int) -> Tuple[PruneRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._prunes[pid]
                for pid in self._model_prunes.get(model_id, [])
            )

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._model_prunes.keys()))

    def prune_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._prunes.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_models": len(self._model_prunes),
                "n_prunes": len(self._prunes),
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
    """Self-check: exercise prune -> verify -> evaluate."""
    ledger = AIPruning()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.prune(
        "mdl-1", 1, pruning_kind="structured-pruning", sparsity=75,
        verdict="pruned",
    )
    assert rec.verify()
    rec2 = ledger.prune(
        "mdl-1", 2, pruning_kind="weight-pruning", sparsity=40,
        verdict="partial",
    )
    assert rec2.verify()
    rep = ledger.verify(rec.prune_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("mdl-1", 4)
    assert ev.posture == "partially-pruned"
    ret = ledger.retire("mdl-1", 5)
    assert ret.verify()
    print("ai-pruning OK: prune, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
