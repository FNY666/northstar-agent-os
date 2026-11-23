"""AI visualization: interpretability-visualization decision ledger, Simulated.

Research note: AI visualization is the presentational side of AI
interpretability - when the host declares it produced a visualization
of a model or agent (saliency map, activation map, attention heatmap,
feature visualization, concept visualization, decision-boundary plot,
embedding projection, circuit diagram), what kind it declared, what
outcome it declared, and what visualization posture the ledger derives
for the subject. This module is the *decision ledger* for declared AI
visualizations: which subjects had which visualization kinds booked
(over a pinned visualization-kind vocabulary), what outcomes were
declared against them, and what visualization posture the ledger
derives - defensible bookkeeping, never proof that any visualization
is faithful, complete, or actually computable.

This module owns the visualize -> verify -> evaluate lifecycle:

* **visualize()** - book one declared visualization (minted ``viz-N``
  ids; pinned visualization-kind vocabulary over the common
  interpretability-visualization classes; pinned outcome vocabulary
  booked *as data*); the first visualization on an id registers the
  subject; raw visualization material (images, heatmaps, activation
  tensors, embeddings, weights, gradients) never enters records -
  digest pins only.
* **verify()** - **pure read**: re-derive one visualization record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data,
  never as proof the visualization really exists or is faithful.
* **evaluate()** - **pure read**: derive one subject's visualization
  posture as data (``unexamined`` -> ``failed`` -> ``contested`` ->
  ``partially-visualized`` -> ``visualized``) with outcome tallies
  and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a subject id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_interpretability.py`` owns
interpretation declarations; ``ai_explainability.py`` owns
explanation declarations; ``ai_mechanistic.py`` owns circuit-level
analysis declarations; ``explainability.py`` / ``interpretability.py``
own their respective mechanics - this module is the
*visualization-declaration* ledger none of them own: declared
visualization artifacts (declared saliency maps, attention heatmaps,
embedding projections) against declared subjects, digest
re-derivation, and the ledger-rule posture that turns declared
visualizations into a visualization claim, always as data, never as
a faithful rendering.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-visualization.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module renders nothing, computes no attribution,
and proves nothing about real-world visualization faithfulness. A
booked ``visualized`` posture means "the host declared it", never
"the saliency map is accurate"; a booked ``failed`` outcome means
"the host declared it", never "the visualization truly failed".
Visualization images, heatmaps, activation tensors, embeddings,
weights, gradients, and raw render data never enter records or cross
the audit boundary - digest pins only.
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
AI_VISUALIZATION_VERSION = "ai-visualization.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-visualization.v1"

#: Pinned visualization-kind vocabulary (the visualization classes).
VISUALIZATION_KINDS = (
    "saliency-map",
    "activation-map",
    "attention-heatmap",
    "feature-visualization",
    "concept-visualization",
    "decision-boundary-plot",
    "embedding-projection",
    "circuit-diagram",
)

#: Pinned visualization-outcome vocabulary (booked as data, never proof).
VISUALIZATION_OUTCOMES = (
    "visualized",
    "partial",
    "failed",
    "inconclusive",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unexamined",
    "failed",
    "contested",
    "partially-visualized",
    "visualized",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "visualized",
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
        "tensors",
        "tensor",
        "embeddings",
        "embedding",
        "image",
        "images",
        "heatmap",
        "heatmaps",
        "plot",
        "plots",
        "figure",
        "figures",
        "render",
        "rendering",
        "render_data",
        "visualization_data",
        "saliency",
        "attention_weights",
        "feature_map",
        "feature_maps",
        "attribution",
        "attributions",
        "logits",
        "logit",
        "checkpoint",
        "checkpoints",
        "checkpoint_data",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "trace",
        "traces",
        "trajectory",
        "trajectories",
        "log",
        "logs",
        "snapshot",
        "snapshots",
        "memory",
        "dataset",
        "datasets",
        "training_data",
        "evidence",
        "findings",
        "report",
        "reports",
        "diagram",
        "diagrams",
        "matrix",
        "projection",
        "password",
        "passwords",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "api_key",
        "api_keys",
        "token",
        "tokens",
        "private_key",
        "personal_data",
        "personal_information",
        "identity",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "pii",
        "exploit",
        "exploits",
        "payload",
        "vulnerability_detail",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIVisualizationError(Exception):
    """Base class for all ai-visualization ledger errors."""


class BadSubjectError(AIVisualizationError):
    pass


class UnknownSubjectError(AIVisualizationError):
    pass


class RetiredSubjectError(AIVisualizationError):
    pass


class BadVisualizationKindError(AIVisualizationError):
    pass


class BadOutcomeError(AIVisualizationError):
    pass


class BadDigestError(AIVisualizationError):
    pass


class BadReasonError(AIVisualizationError):
    pass


class UnknownVisualizationError(AIVisualizationError):
    pass


class SeqOrderError(AIVisualizationError):
    pass


class AuditKindError(AIVisualizationError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSubjectError(f"{what} must be a non-empty string")
    return value


def _check_visualization_kind(value: Any) -> str:
    if value not in VISUALIZATION_KINDS:
        raise BadVisualizationKindError(
            f"visualization_kind must be one of {VISUALIZATION_KINDS}"
        )
    return value


def _check_outcome(value: Any) -> str:
    if value not in VISUALIZATION_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {VISUALIZATION_OUTCOMES}")
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


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VisualizationRecord:
    visualization_id: str
    subject_id: str
    seq: int
    visualization_kind: str
    outcome: str
    visualization_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _visualize_payload(self), "ai-visualization.visualize"
        )


@dataclass(frozen=True)
class RetireRecord:
    subject_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-visualization.retire"
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
            _verify_payload(self), "ai-visualization.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    subject_id: str
    seq: int
    posture: str
    n_visualizations: int
    n_visualized: int
    n_partial: int
    n_failed: int
    n_inconclusive: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-visualization.evaluate"
        )


def _visualize_payload(rec: "VisualizationRecord") -> Dict[str, Any]:
    return {
        "visualization_id": rec.visualization_id,
        "subject_id": rec.subject_id,
        "seq": rec.seq,
        "visualization_kind": rec.visualization_kind,
        "outcome": rec.outcome,
        "visualization_digest": rec.visualization_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"subject_id": rec.subject_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "subject_id": rep.subject_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_visualizations": rep.n_visualizations,
        "n_visualized": rep.n_visualized,
        "n_partial": rep.n_partial,
        "n_failed": rep.n_failed,
        "n_inconclusive": rep.n_inconclusive,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_visualization_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIVisualizationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-visualization",
        "version": AI_VISUALIZATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIVisualization:
    """AI-visualization declaration decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that any visualization is faithful or faithful
    to any real model behavior.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._visualizations: Dict[str, VisualizationRecord] = {}
        self._subject_visualizations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._visualization_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
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
            row = ai_visualization_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-visualization",
                "version": AI_VISUALIZATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_visualization_audit_event(audit_kind, seq, **details))

    def _require_live(self, subject_id: str) -> None:
        if subject_id in self._retired:
            raise RetiredSubjectError(f"subject is retired: {subject_id!r}")

    # -- mutations ---------------------------------------------------------

    def visualize(
        self,
        subject_id: str,
        seq: int,
        visualization_kind: str = "saliency-map",
        outcome: str = "visualized",
        visualization_digest: str = "",
    ) -> VisualizationRecord:
        """Book one declared visualization (minted ``viz-N`` id).

        The first visualization on an id registers the subject. Raw
        visualization material (images, heatmaps, activation tensors,
        embeddings, weights, gradients) never enters records - digest
        pins only. Fail-closed: failed mutations consume their seq and
        book an ``ai-visualization.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                subject_id = _check_id(subject_id, "subject_id")
                self._require_seq(seq)
                visualization_kind = _check_visualization_kind(visualization_kind)
                outcome = _check_outcome(outcome)
                visualization_digest = _check_digest(
                    visualization_digest, "visualization_digest"
                )
                self._require_live(subject_id)
            except AIVisualizationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._visualization_counter += 1
            visualization_id = f"viz-{self._visualization_counter}"
            provisional = VisualizationRecord(
                visualization_id=visualization_id,
                subject_id=subject_id,
                seq=seq,
                visualization_kind=visualization_kind,
                outcome=outcome,
                visualization_digest=visualization_digest,
                digest="",
            )
            digest = _digest_pin(
                _visualize_payload(provisional), "ai-visualization.visualize"
            )
            rec = VisualizationRecord(
                visualization_id=visualization_id,
                subject_id=subject_id,
                seq=seq,
                visualization_kind=visualization_kind,
                outcome=outcome,
                visualization_digest=visualization_digest,
                digest=digest,
            )
            self._visualizations[visualization_id] = rec
            self._subject_visualizations.setdefault(subject_id, []).append(
                visualization_id
            )
            self._emit(
                "visualized",
                seq,
                visualization_id=visualization_id,
                subject_id=subject_id,
                visualization_kind=visualization_kind,
                outcome=outcome,
                visualization_digest=visualization_digest,
            )
            return rec

    def retire(self, subject_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminal retirement of a subject id; ids are never recycled."""
        with self._lock:
            try:
                subject_id = _check_id(subject_id, "subject_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if subject_id in self._retired:
                    raise RetiredSubjectError(f"subject is retired: {subject_id!r}")
                if subject_id not in self._subject_visualizations:
                    raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            except AIVisualizationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                subject_id=subject_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-visualization.retire"
            )
            rec = RetireRecord(
                subject_id=subject_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[subject_id] = rec
            self._emit("retired", seq, subject_id=subject_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, visualization_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one visualization record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the visualization really exists or is faithful. Seq is
        shape-validated only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(visualization_id, bool)
                or not isinstance(visualization_id, str)
                or visualization_id not in self._visualizations
            ):
                raise UnknownVisualizationError(
                    f"unknown visualization id: {visualization_id!r}"
                )
            rec = self._visualizations[visualization_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=visualization_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-visualization.verify"
            )
            return VerificationReport(
                record_id=visualization_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, subject_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one subject's visualization posture as data.

        Posture by ledger rule: ``unexamined`` (nothing booked) ->
        ``failed`` (any failed) -> ``contested`` (any inconclusive) ->
        ``partially-visualized`` (any partial) -> ``visualized`` (all
        visualized). ``integrity_ok`` re-derives all in-scope digest
        pins as data. Seq is shape-validated only - never consumed, no
        audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            subject_id = _check_id(subject_id, "subject_id")
            if subject_id not in self._subject_visualizations:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            ids = self._subject_visualizations[subject_id]
            recs = [self._visualizations[i] for i in ids]
            n_visualized = sum(1 for r in recs if r.outcome == "visualized")
            n_partial = sum(1 for r in recs if r.outcome == "partial")
            n_failed = sum(1 for r in recs if r.outcome == "failed")
            n_inconclusive = sum(1 for r in recs if r.outcome == "inconclusive")
            if n_failed:
                posture = "failed"
            elif n_inconclusive:
                posture = "contested"
            elif n_partial:
                posture = "partially-visualized"
            elif n_visualized and n_visualized == len(recs):
                posture = "visualized"
            else:
                posture = "unexamined"
            integrity_ok = all(r.verify() for r in recs)
            provisional = EvaluationReport(
                subject_id=subject_id,
                seq=seq,
                posture=posture,
                n_visualizations=len(recs),
                n_visualized=n_visualized,
                n_partial=n_partial,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-visualization.evaluate"
            )
            return EvaluationReport(
                subject_id=subject_id,
                seq=seq,
                posture=posture,
                n_visualizations=len(recs),
                n_visualized=n_visualized,
                n_partial=n_partial,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def visualization_record(
        self, visualization_id: str, seq: int
    ) -> VisualizationRecord:
        with self._lock:
            self._check_read_seq(seq)
            if visualization_id not in self._visualizations:
                raise UnknownVisualizationError(
                    f"unknown visualization id: {visualization_id!r}"
                )
            return self._visualizations[visualization_id]

    def retire_record(self, subject_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._check_read_seq(seq)
            if subject_id not in self._retired:
                raise UnknownSubjectError(f"unknown subject: {subject_id!r}")
            return self._retired[subject_id]

    def visualizations_for(
        self, subject_id: str, seq: int
    ) -> Tuple[VisualizationRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._visualizations[i]
                for i in self._subject_visualizations.get(subject_id, [])
            )

    def subject_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._subject_visualizations))

    def visualization_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._visualizations))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_subjects": len(self._subject_visualizations),
                "n_visualizations": len(self._visualizations),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_VISUALIZATION_VERSION,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._audit)


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
    """Self-check: exercise visualize -> verify -> evaluate."""
    ledger = AIVisualization()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.visualize(
        "subject-1",
        1,
        visualization_kind="saliency-map",
        outcome="visualized",
    )
    assert rec.verify()
    rep = ledger.verify(rec.visualization_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("subject-1", 3)
    assert ev.posture == "visualized"
    ret = ledger.retire("subject-1", 4)
    assert ret.verify()
    print("ai-visualization OK: visualize, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
