"""AI saliency: saliency-map computation decision ledger, Simulated.

Research note: saliency maps attribute a model's output to parts of its
input - gradient, integrated gradients, SHAP, LIME, attention rollout and
kin. This module is the *decision ledger* for declared saliency
computations: which inputs had which saliency maps booked (over a pinned
method vocabulary), what fidelity verdicts were declared against them,
and what interpretability posture the ledger derives - defensible
bookkeeping, never proof that a saliency map is really faithful.

This module owns the compute -> verify -> evaluate lifecycle:

* **compute()** - book one declared saliency computation (minted ``sal-N``
  ids; pinned 8-method vocabulary; pinned fidelity verdict vocabulary
  booked *as data*); the first computation registers its input; raw
  saliency maps, heatmap arrays, pixel data, and model internals never
  enter records - digest pins only.
* **verify()** - **pure read**: re-derive one saliency record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as proof
  the map was really computed.
* **evaluate()** - **pure read**: derive one input's saliency posture as
  data (``unexamined`` -> ``misleading`` -> ``contested`` -> ``partial``
  -> ``explained``) with fidelity tallies and a digest-pinned integrity
  flag.
* **retire()** - terminal retirement of an input id; ids are never
  recycled.

Distinct-layer rationale vs siblings: mechanistic modules own circuit
analysis; probing modules own linear-probe mechanics; ``ai_attribution.py``
owns input-attribution bookkeeping - this module is the saliency-*map
computation* decision ledger none of them own: declared computations
over the pinned saliency-method vocabulary, declared fidelity verdicts,
and the ledger-rule posture that turns declared fidelity into an
interpretability claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-saliency.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module computes no saliency maps, inspects no model
internals, and proves nothing about real interpretability. A booked
``faithful`` verdict means "the host declared it", never "the map is
faithful"; a booked ``misleading`` verdict means "the host declared it",
never "the map is unfaithful". Saliency maps, heatmap arrays, pixel data,
input content, and model internals never enter records or cross the
audit boundary - digest pins only.
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
AI_SALIENCY_VERSION = "ai-saliency.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-saliency.v1"

#: Pinned saliency-method vocabulary (the map families declared).
SALIENCY_METHODS = (
    "gradient",
    "integrated-gradients",
    "smoothgrad",
    "grad-cam",
    "lime",
    "shap",
    "attention-rollout",
    "occlusion",
)

#: Pinned fidelity vocabulary (booked as data, never proof).
FIDELITIES = (
    "faithful",
    "partial",
    "misleading",
    "inconclusive",
    "not-computed",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unexamined",
    "misleading",
    "contested",
    "partial",
    "explained",
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
    "computed",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
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
        # saliency raw material
        "saliency_map",
        "saliency",
        "heatmap",
        "heatmaps",
        "attribution",
        "attributions",
        "mask",
        "masks",
        "pixels",
        "pixel_data",
        "input_image",
        "input_text",
        "input_tokens",
        "tokens",
        "token_list",
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
        "features",
        "feature_importance",
        "feature_vector",
        "explanation",
        "explanations",
        "baseline",
        "reference_input",
        "perturbed_input",
        "perturbation",
        "occlusion_mask",
        "kernel",
        "superpixels",
        "interpretable_model",
        "surrogate_model",
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
        "checkpoint_data",
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


class AISaliencyError(Exception):
    """Base class for all ai-saliency ledger errors."""


class BadInputError(AISaliencyError):
    pass


class UnknownInputError(AISaliencyError):
    pass


class RetiredInputError(AISaliencyError):
    pass


class BadMethodError(AISaliencyError):
    pass


class BadFidelityError(AISaliencyError):
    pass


class BadDigestError(AISaliencyError):
    pass


class BadReasonError(AISaliencyError):
    pass


class UnknownSaliencyError(AISaliencyError):
    pass


class UnknownRecordError(AISaliencyError):
    pass


class SeqOrderError(AISaliencyError):
    pass


class AuditKindError(AISaliencyError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadInputError(f"{what} must be a non-empty string")
    return value


def _check_method(value: Any) -> str:
    if value not in SALIENCY_METHODS:
        raise BadMethodError(f"saliency_method must be one of {SALIENCY_METHODS}")
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
class SaliencyRecord:
    saliency_id: str
    input_id: str
    seq: int
    saliency_method: str
    fidelity: str
    compute_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _saliency_payload(self), "ai-saliency.compute"
        )


@dataclass(frozen=True)
class RetireRecord:
    input_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-saliency.retire"
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
            _verify_payload(self), "ai-saliency.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    input_id: str
    seq: int
    posture: str
    n_saliencies: int
    n_faithful: int
    n_partial: int
    n_misleading: int
    n_inconclusive: int
    n_not_computed: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-saliency.evaluate"
        )


def _saliency_payload(rec: "SaliencyRecord") -> Dict[str, Any]:
    return {
        "saliency_id": rec.saliency_id,
        "input_id": rec.input_id,
        "seq": rec.seq,
        "saliency_method": rec.saliency_method,
        "fidelity": rec.fidelity,
        "compute_digest": rec.compute_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"input_id": rec.input_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "input_id": rep.input_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_saliencies": rep.n_saliencies,
        "n_faithful": rep.n_faithful,
        "n_partial": rep.n_partial,
        "n_misleading": rep.n_misleading,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_computed": rep.n_not_computed,
        "integrity_ok": rep.integrity_ok,
    }


def ai_saliency_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AISaliencyError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-saliency",
        "version": AI_SALIENCY_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AISaliency:
    """AI saliency-map computation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All fidelities are booked as
    data - never proof that a map is really faithful or misleading.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._saliencies: Dict[str, SaliencyRecord] = {}
        self._input_saliencies: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._saliency_counter = 0
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
            row = ai_saliency_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-saliency",
                "version": AI_SALIENCY_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_saliency_audit_event(audit_kind, seq, **details))

    def _require_live(self, input_id: str) -> None:
        if input_id in self._retired:
            raise RetiredInputError(f"input is retired: {input_id!r}")

    # -- mutations ---------------------------------------------------------

    def compute(
        self,
        input_id: str,
        seq: int,
        saliency_method: str = "gradient",
        fidelity: str = "not-computed",
        compute_digest: str = "",
    ) -> SaliencyRecord:
        """Book one declared saliency computation (minted ``sal-N`` id).

        The first computation on an id registers the input. Raw saliency
        maps, heatmap arrays, pixel data, and model internals never enter
        records - digest pins only. Fail-closed: failed mutations consume
        their seq and book an ``ai-saliency.rejected`` row; rewinds raise
        bare.
        """
        with self._lock:
            try:
                input_id = _check_id(input_id, "input_id")
                self._require_seq(seq)
                saliency_method = _check_method(saliency_method)
                fidelity = _check_fidelity(fidelity)
                compute_digest = _check_digest(compute_digest, "compute_digest")
                self._require_live(input_id)
            except AISaliencyError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._saliency_counter += 1
            saliency_id = f"sal-{self._saliency_counter}"
            provisional = SaliencyRecord(
                saliency_id=saliency_id,
                input_id=input_id,
                seq=seq,
                saliency_method=saliency_method,
                fidelity=fidelity,
                compute_digest=compute_digest,
                digest="",
            )
            digest = _digest_pin(_saliency_payload(provisional), "ai-saliency.compute")
            rec = SaliencyRecord(
                saliency_id=saliency_id,
                input_id=input_id,
                seq=seq,
                saliency_method=saliency_method,
                fidelity=fidelity,
                compute_digest=compute_digest,
                digest=digest,
            )
            self._saliencies[saliency_id] = rec
            self._input_saliencies.setdefault(input_id, []).append(saliency_id)
            self._emit(
                "computed",
                seq,
                saliency_id=saliency_id,
                input_id=input_id,
                saliency_method=saliency_method,
                fidelity=fidelity,
            )
            return rec

    def retire(
        self, input_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire an input id; ids are never recycled."""
        with self._lock:
            try:
                input_id = _check_id(input_id, "input_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if input_id not in self._input_saliencies:
                    raise UnknownInputError(f"unknown input: {input_id!r}")
                if input_id in self._retired:
                    raise RetiredInputError(
                        f"input already retired: {input_id!r}"
                    )
            except AISaliencyError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                input_id=input_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-saliency.retire")
            rec = RetireRecord(
                input_id=input_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[input_id] = rec
            self._emit("retired", seq, input_id=input_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, input_id: str) -> bool:
        return all(
            self._saliencies[sid].verify()
            for sid in self._input_saliencies.get(input_id, [])
        )

    def _posture(self, input_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "faithful": 0,
            "partial": 0,
            "misleading": 0,
            "inconclusive": 0,
            "not-computed": 0,
        }
        ids = self._input_saliencies.get(input_id, [])
        for sid in ids:
            tallies[self._saliencies[sid].fidelity] += 1
        if not ids:
            return "unexamined", tallies
        if tallies["misleading"]:
            return "misleading", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if tallies["partial"] or tallies["not-computed"]:
            return "partial", tallies
        return "explained", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._saliencies.get(record_id)
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
            digest = _digest_pin(_verify_payload(provisional), "ai-saliency.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, input_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one input's saliency posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            input_id = _check_id(input_id, "input_id")
            if input_id not in self._input_saliencies:
                raise UnknownInputError(f"unknown input: {input_id!r}")
            posture, tallies = self._posture(input_id)
            provisional = EvaluationReport(
                input_id=input_id,
                seq=seq,
                posture=posture,
                n_saliencies=len(self._input_saliencies[input_id]),
                n_faithful=tallies["faithful"],
                n_partial=tallies["partial"],
                n_misleading=tallies["misleading"],
                n_inconclusive=tallies["inconclusive"],
                n_not_computed=tallies["not-computed"],
                integrity_ok=self._integrity_ok(input_id),
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-saliency.evaluate")
            return EvaluationReport(
                input_id=input_id,
                seq=seq,
                posture=posture,
                n_saliencies=len(self._input_saliencies[input_id]),
                n_faithful=tallies["faithful"],
                n_partial=tallies["partial"],
                n_misleading=tallies["misleading"],
                n_inconclusive=tallies["inconclusive"],
                n_not_computed=tallies["not-computed"],
                integrity_ok=self._integrity_ok(input_id),
                digest=digest,
            )

    # -- views (pure reads) --------------------------------------------------

    def saliency_record(self, saliency_id: str, seq: int) -> SaliencyRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._saliencies.get(saliency_id)
            if rec is None:
                raise UnknownSaliencyError(
                    f"unknown saliency: {saliency_id!r}"
                )
            return rec

    def saliencies_for(self, input_id: str, seq: int) -> Tuple[SaliencyRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._saliencies[sid]
                for sid in self._input_saliencies.get(input_id, [])
            )

    def input_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._input_saliencies.keys()))

    def saliency_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._saliencies.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_inputs": len(self._input_saliencies),
                "n_saliencies": len(self._saliencies),
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
    """Self-check: exercise compute -> verify -> evaluate."""
    ledger = AISaliency()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.compute(
        "inp-1", 1, saliency_method="shap", fidelity="faithful"
    )
    assert rec.verify()
    rec2 = ledger.compute(
        "inp-1", 2, saliency_method="gradient", fidelity="partial"
    )
    assert rec2.verify()
    rep = ledger.verify(rec.saliency_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("inp-1", 4)
    assert ev.posture == "partial"
    ret = ledger.retire("inp-1", 5)
    assert ret.verify()
    print("ai-saliency OK: compute, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
