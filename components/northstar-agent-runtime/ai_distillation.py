"""AI distillation: knowledge-distillation declaration decision ledger, Simulated.

Research note: knowledge distillation transfers capability from a large
teacher model to a smaller student - logit matching, feature matching,
attention transfer, relation distillation, self-distillation, data-free
distillation, online distillation, and quantization-aware distillation.
This module is the *decision ledger* for declared distillation runs:
which teacher/student pairs had which distillation runs booked (over a
pinned method vocabulary), what fidelity verdicts were declared against
them, and what distillation posture the ledger derives - defensible
bookkeeping, never proof that a student really inherited its teacher.

This module owns the distill -> verify -> evaluate lifecycle:

* **distill()** - book one declared distillation run (minted ``dst-N``
  ids; pinned 8-method vocabulary; pinned fidelity verdict vocabulary
  booked *as data*); the first run registers its teacher/student pair;
  raw teacher weights, student weights, logits, soft targets, training
  data, and distillation losses never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one distillation record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as proof
  the distillation really happened.
* **evaluate()** - **pure read**: derive one pair's distillation posture as
  data (``unexamined`` -> ``degraded`` -> ``contested`` -> ``partial``
  -> ``distilled``) with fidelity tallies and a digest-pinned integrity
  flag.
* **retire()** - terminal retirement of a pair id; ids are never recycled.

Distinct-layer rationale vs siblings: quantization modules own weight-
compression mechanics; pruning modules own sparsification mechanics;
``ai_evaluation.py`` owns evaluation declarations; transfer-learning
modules own transfer mechanics - this module is the distillation-*run*
decision ledger none of them own: declared distillation runs over the
pinned distillation-method vocabulary, declared fidelity verdicts, and
the ledger-rule posture that turns declared fidelity into a
distillation claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-distillation.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module distills no models, trains no students, and
proves nothing about real knowledge transfer. A booked ``faithful``
verdict means "the host declared it", never "the student is faithful";
a booked ``degraded`` verdict means "the host declared it", never "the
student degraded". Teacher weights, student weights, logits, soft
targets, training data, and distillation losses never enter records or
cross the audit boundary - digest pins only.
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
AI_DISTILLATION_VERSION = "ai-distillation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-distillation.v1"

#: Pinned distillation-method vocabulary (the transfer families declared).
DISTILLATION_KINDS = (
    "logit-matching",
    "feature-matching",
    "attention-transfer",
    "relation-distillation",
    "self-distillation",
    "data-free-distillation",
    "online-distillation",
    "quantization-aware-distillation",
)

#: Pinned fidelity vocabulary (booked as data, never proof).
FIDELITIES = (
    "faithful",
    "partial",
    "degraded",
    "inconclusive",
    "not-distilled",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unexamined",
    "degraded",
    "contested",
    "partial",
    "distilled",
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
    "distilled",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "teacher_weights",
        "student_weights",
        "model_weights",
        "parameters",
        "params",
        "checkpoints",
        "checkpoint_data",
        "logits",
        "logit",
        "soft_targets",
        "hard_targets",
        "targets",
        "labels",
        "temperature",
        "temperatures",
        "alpha",
        "loss",
        "losses",
        "distillation_loss",
        "kl_divergence",
        "activations",
        "gradients",
        "embeddings",
        "attention",
        "attention_weights",
        "attention_maps",
        "feature_maps",
        "features",
        "feature_vector",
        "representations",
        "training_data",
        "dataset",
        "data",
        "samples",
        "batch",
        "batches",
        "prompts",
        "prompt",
        "responses",
        "response",
        "outputs",
        "output",
        "completions",
        "tokens",
        "token_list",
        "scores",
        "predictions",
        "prediction",
        "teacher_output",
        "student_output",
        "teacher",
        "student",
        "distillation",
        "distillations",
        "trajectory",
        "trajectories",
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
        "command_output",
        "stderr",
        "stdout",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
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


class AIDistillationError(Exception):
    """Base class for all ai-distillation ledger errors."""


class BadInputError(AIDistillationError):
    pass


class UnknownPairError(AIDistillationError):
    pass


class RetiredPairError(AIDistillationError):
    pass


class BadKindError(AIDistillationError):
    pass


class BadFidelityError(AIDistillationError):
    pass


class BadDigestError(AIDistillationError):
    pass


class BadReasonError(AIDistillationError):
    pass


class UnknownDistillationError(AIDistillationError):
    pass


class UnknownRecordError(AIDistillationError):
    pass


class SeqOrderError(AIDistillationError):
    pass


class AuditKindError(AIDistillationError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadInputError(f"{what} must be a non-empty string")
    return value


def _check_kind(value: Any) -> str:
    if value not in DISTILLATION_KINDS:
        raise BadKindError(f"distillation_kind must be one of {DISTILLATION_KINDS}")
    return value


def _check_fidelity(value: Any) -> str:
    if value not in FIDELITIES:
        raise BadFidelityError(f"fidelity must be one of {FIDELITIES}")
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
class DistillationRecord:
    distillation_id: str
    pair_id: str
    seq: int
    distillation_kind: str
    fidelity: str
    distillation_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _distillation_payload(self), "ai-distillation.distill"
        )


@dataclass(frozen=True)
class RetireRecord:
    pair_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-distillation.retire"
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
            _verify_payload(self), "ai-distillation.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    pair_id: str
    seq: int
    posture: str
    n_distillations: int
    n_faithful: int
    n_partial: int
    n_degraded: int
    n_inconclusive: int
    n_not_distilled: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-distillation.evaluate"
        )


def _distillation_payload(rec: "DistillationRecord") -> Dict[str, Any]:
    return {
        "distillation_id": rec.distillation_id,
        "pair_id": rec.pair_id,
        "seq": rec.seq,
        "distillation_kind": rec.distillation_kind,
        "fidelity": rec.fidelity,
        "distillation_digest": rec.distillation_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"pair_id": rec.pair_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "pair_id": rep.pair_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_distillations": rep.n_distillations,
        "n_faithful": rep.n_faithful,
        "n_partial": rep.n_partial,
        "n_degraded": rep.n_degraded,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_distilled": rep.n_not_distilled,
        "integrity_ok": rep.integrity_ok,
    }


def ai_distillation_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIDistillationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-distillation",
        "version": AI_DISTILLATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIDistillation:
    """AI knowledge-distillation declaration decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All fidelities are booked as
    data - never proof that a student really inherited its teacher.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._distillations: Dict[str, DistillationRecord] = {}
        self._pair_distillations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._distillation_counter = 0
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
            row = ai_distillation_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-distillation",
                "version": AI_DISTILLATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_distillation_audit_event(audit_kind, seq, **details))

    def _require_live(self, pair_id: str) -> None:
        if pair_id in self._retired:
            raise RetiredPairError(f"pair is retired: {pair_id!r}")

    # -- mutations ---------------------------------------------------------

    def distill(
        self,
        pair_id: str,
        seq: int,
        distillation_kind: str = "logit-matching",
        fidelity: str = "not-distilled",
        distillation_digest: str = "",
    ) -> DistillationRecord:
        """Book one declared distillation run (minted ``dst-N`` id).

        The first run on an id registers the teacher/student pair. Raw
        teacher weights, student weights, logits, soft targets, training
        data, and distillation losses never enter records - digest pins
        only. Fail-closed: failed mutations consume their seq and book an
        ``ai-distillation.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                pair_id = _check_id(pair_id, "pair_id")
                self._require_seq(seq)
                distillation_kind = _check_kind(distillation_kind)
                fidelity = _check_fidelity(fidelity)
                distillation_digest = _check_digest(distillation_digest, "distillation_digest")
                self._require_live(pair_id)
            except AIDistillationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._distillation_counter += 1
            distillation_id = f"dst-{self._distillation_counter}"
            provisional = DistillationRecord(
                distillation_id=distillation_id,
                pair_id=pair_id,
                seq=seq,
                distillation_kind=distillation_kind,
                fidelity=fidelity,
                distillation_digest=distillation_digest,
                digest="",
            )
            digest = _digest_pin(_distillation_payload(provisional), "ai-distillation.distill")
            rec = DistillationRecord(
                distillation_id=distillation_id,
                pair_id=pair_id,
                seq=seq,
                distillation_kind=distillation_kind,
                fidelity=fidelity,
                distillation_digest=distillation_digest,
                digest=digest,
            )
            self._distillations[distillation_id] = rec
            self._pair_distillations.setdefault(pair_id, []).append(distillation_id)
            self._emit(
                "distilled",
                seq,
                distillation_id=distillation_id,
                pair_id=pair_id,
                distillation_kind=distillation_kind,
                fidelity=fidelity,
            )
            return rec

    def retire(
        self, pair_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a pair id; ids are never recycled."""
        with self._lock:
            try:
                pair_id = _check_id(pair_id, "pair_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if pair_id not in self._pair_distillations:
                    raise UnknownPairError(f"unknown pair: {pair_id!r}")
                if pair_id in self._retired:
                    raise RetiredPairError(
                        f"pair already retired: {pair_id!r}"
                    )
            except AIDistillationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                pair_id=pair_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-distillation.retire")
            rec = RetireRecord(
                pair_id=pair_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[pair_id] = rec
            self._emit("retired", seq, pair_id=pair_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, pair_id: str) -> bool:
        return all(
            self._distillations[did].verify()
            for did in self._pair_distillations.get(pair_id, [])
        )

    def _posture(self, pair_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "faithful": 0,
            "partial": 0,
            "degraded": 0,
            "inconclusive": 0,
            "not-distilled": 0,
        }
        ids = self._pair_distillations.get(pair_id, [])
        for did in ids:
            tallies[self._distillations[did].fidelity] += 1
        if not ids:
            return "unexamined", tallies
        if tallies["degraded"]:
            return "degraded", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if tallies["partial"] or tallies["not-distilled"]:
            return "partial", tallies
        return "distilled", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._distillations.get(record_id)
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
            digest = _digest_pin(_verify_payload(provisional), "ai-distillation.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, pair_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one pair's distillation posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            pair_id = _check_id(pair_id, "pair_id")
            if pair_id not in self._pair_distillations:
                raise UnknownPairError(f"unknown pair: {pair_id!r}")
            posture, tallies = self._posture(pair_id)
            provisional = EvaluationReport(
                pair_id=pair_id,
                seq=seq,
                posture=posture,
                n_distillations=len(self._pair_distillations[pair_id]),
                n_faithful=tallies["faithful"],
                n_partial=tallies["partial"],
                n_degraded=tallies["degraded"],
                n_inconclusive=tallies["inconclusive"],
                n_not_distilled=tallies["not-distilled"],
                integrity_ok=self._integrity_ok(pair_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-distillation.evaluate")
            return EvaluationReport(
                pair_id=pair_id,
                seq=seq,
                posture=posture,
                n_distillations=len(self._pair_distillations[pair_id]),
                n_faithful=tallies["faithful"],
                n_partial=tallies["partial"],
                n_degraded=tallies["degraded"],
                n_inconclusive=tallies["inconclusive"],
                n_not_distilled=tallies["not-distilled"],
                integrity_ok=self._integrity_ok(pair_id),
                digest=digest,
            )

    # -- views (pure reads) --------------------------------------------------

    def distillation_record(self, distillation_id: str, seq: int) -> DistillationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._distillations.get(distillation_id)
            if rec is None:
                raise UnknownDistillationError(
                    f"unknown distillation: {distillation_id!r}"
                )
            return rec

    def distillations_for(self, pair_id: str, seq: int) -> Tuple[DistillationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._distillations[did]
                for did in self._pair_distillations.get(pair_id, [])
            )

    def pair_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._pair_distillations.keys()))

    def distillation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._distillations.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_pairs": len(self._pair_distillations),
                "n_distillations": len(self._distillations),
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
    """Self-check: exercise distill -> verify -> evaluate."""
    ledger = AIDistillation()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.distill(
        "pair-1", 1, distillation_kind="logit-matching", fidelity="faithful"
    )
    assert rec.verify()
    rec2 = ledger.distill(
        "pair-1", 2, distillation_kind="feature-matching", fidelity="partial"
    )
    assert rec2.verify()
    rep = ledger.verify(rec.distillation_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("pair-1", 4)
    assert ev.posture == "partial"
    ret = ledger.retire("pair-1", 5)
    assert ret.verify()
    print("ai-distillation OK: distill, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
