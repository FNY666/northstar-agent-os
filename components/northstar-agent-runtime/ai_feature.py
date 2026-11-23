"""AI feature: AI-feature-extraction decision ledger, Simulated.

Research note: AI feature extraction is the interpretability side of
model inspection - given a deployed AI system, what feature claims the
host declared it extracted (activation patterns, embedding vectors,
attention weights, neuron responses, gradient signals, representation
clusters, feature visualizations, probe classifiers), what verdict it
declared for each extraction, and what extraction posture the ledger
derives for the system. This module is the *decision ledger* for
declared AI feature extractions: which systems had which feature kinds
booked (over a pinned feature-kind vocabulary), what verdicts were
declared against them, and what extraction posture the ledger derives -
defensible bookkeeping, never proof that any feature was really
extracted or that any interpretation is faithful.

This module owns the extract -> verify -> evaluate lifecycle:

* **extract()** - book one declared feature extraction (minted
  ``fea-N`` ids; pinned feature-kind vocabulary over the common
  feature classes; pinned verdict vocabulary booked *as data*); the
  first extraction on an id registers the system; raw feature
  material - activations, embeddings, weights, gradients, probe
  outputs, visualizations - never enters records - digest pins only.
* **verify()** - **pure read**: re-derive one feature record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the feature was really extracted.
* **evaluate()** - **pure read**: derive one system's feature
  posture as data (``unextracted`` -> ``failed`` -> ``contested`` ->
  ``partially-extracted`` -> ``extracted``) with verdict tallies and
  a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``feature_engineering.py``
owns ML feature-engineering mechanics (pipelines, transforms);
``feature_store.py`` owns feature storage and retrieval;
``feature_flags.py`` owns runtime feature flags;
``feature_viz.py`` owns feature-visualization mechanics;
``probing.py`` owns probing-run mechanics; ``attribution.py`` owns
attribution mechanics; ``ai_concept.py`` owns concept-level
extraction; ``ai_safety.py`` owns the assessment -> mitigation
lifecycle - this module is the *AI feature-extraction* decision
ledger none of them own: declared feature extractions against
declared systems, digest re-derivation, and the ledger-rule posture
that turns declared extractions into a feature claim, always as
data, never as measured interpretation.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-feature.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module extracts nothing, interprets nothing, and
proves nothing about real-world model internals. A booked
``extracted`` posture means "the host declared it", never "the
feature is faithful"; a booked ``failed`` verdict means "the host
declared it", never "the extraction truly failed". Feature material,
activations, embeddings, gradients, probe outputs, visualizations,
and model internals never enter records or cross the audit boundary
- digest pins only.
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
AI_FEATURE_VERSION = "ai-feature.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-feature.v1"

#: Pinned feature-kind vocabulary (the feature classes).
FEATURE_KINDS = (
    "activation-pattern",
    "embedding-vector",
    "attention-weight",
    "neuron-response",
    "gradient-signal",
    "representation-cluster",
    "feature-visualization",
    "probe-classifier",
)

#: Pinned feature-verdict vocabulary (booked as data, never proof).
FEATURE_VERDICTS = (
    "extracted",
    "partial",
    "failed",
    "inconclusive",
    "not-attempted",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unextracted",
    "failed",
    "contested",
    "partially-extracted",
    "extracted",
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
    "extracted",
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
        "policy",
        "policies",
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
        "activations",
        "activation",
        "activation_map",
        "embeddings",
        "embedding",
        "embedding_vector",
        "attention",
        "attention_weights",
        "attention_map",
        "neurons",
        "neuron",
        "neuron_response",
        "gradients",
        "gradient",
        "gradient_signal",
        "representations",
        "representation",
        "cluster",
        "clusters",
        "visualization",
        "visualizations",
        "saliency",
        "saliency_map",
        "probe",
        "probes",
        "probe_output",
        "probe_outputs",
        "classifier_output",
        "feature_vector",
        "feature_map",
        "feature_material",
        "hidden_state",
        "hidden_states",
        "logits",
        "logit",
        "layer_output",
        "layer_outputs",
        "weights_snapshot",
        "model_dump",
        "checkpoint_data",
        "checkpoint",
        "checkpoints",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "evidence",
        "findings",
        "report",
        "reports",
        "dataset",
        "datasets",
        "training_data",
        "pii",
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
        "identity_document",
        "document",
        "documents",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "exploit",
        "exploits",
        "payload",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIFeatureError(Exception):
    """Base class for all ai-feature ledger errors."""


class BadSystemError(AIFeatureError):
    pass


class UnknownSystemError(AIFeatureError):
    pass


class RetiredSystemError(AIFeatureError):
    pass


class BadFeatureKindError(AIFeatureError):
    pass


class BadVerdictError(AIFeatureError):
    pass


class BadDigestError(AIFeatureError):
    pass


class BadReasonError(AIFeatureError):
    pass


class UnknownFeatureError(AIFeatureError):
    pass


class SeqOrderError(AIFeatureError):
    pass


class AuditKindError(AIFeatureError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_feature_kind(value: Any) -> str:
    if value not in FEATURE_KINDS:
        raise BadFeatureKindError(f"feature_kind must be one of {FEATURE_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in FEATURE_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {FEATURE_VERDICTS}")
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
class FeatureRecord:
    feature_id: str
    system_id: str
    seq: int
    feature_kind: str
    verdict: str
    feature_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _extract_payload(self), "ai-feature.extract"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-feature.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-feature.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_features: int
    n_extracted: int
    n_partial: int
    n_failed: int
    n_inconclusive: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-feature.evaluate"
        )


def _extract_payload(rec: "FeatureRecord") -> Dict[str, Any]:
    return {
        "feature_id": rec.feature_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "feature_kind": rec.feature_kind,
        "verdict": rec.verdict,
        "feature_digest": rec.feature_digest,
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
        "n_features": rep.n_features,
        "n_extracted": rep.n_extracted,
        "n_partial": rep.n_partial,
        "n_failed": rep.n_failed,
        "n_inconclusive": rep.n_inconclusive,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_feature_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIFeatureError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-feature",
        "version": AI_FEATURE_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIFeature:
    """AI-feature feature-extraction decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts are booked as
    data - never proof that any feature was really extracted.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._features: Dict[str, FeatureRecord] = {}
        self._system_features: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._feature_counter = 0
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
            row = ai_feature_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-feature",
                "version": AI_FEATURE_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_feature_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def extract(
        self,
        system_id: str,
        seq: int,
        feature_kind: str = "activation-pattern",
        verdict: str = "extracted",
        feature_digest: str = "",
    ) -> FeatureRecord:
        """Book one declared feature extraction (minted ``fea-N`` id).

        The first extraction on an id registers the system. Raw feature
        material - activations, embeddings, weights, gradients, probe
        outputs, visualizations - never enters records - digest pins
        only. Fail-closed: failed mutations consume their seq and book
        an ``ai-feature.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                feature_kind = _check_feature_kind(feature_kind)
                verdict = _check_verdict(verdict)
                feature_digest = _check_digest(feature_digest, "feature_digest")
                self._require_live(system_id)
            except AIFeatureError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._feature_counter += 1
            feature_id = f"fea-{self._feature_counter}"
            provisional = FeatureRecord(
                feature_id=feature_id,
                system_id=system_id,
                seq=seq,
                feature_kind=feature_kind,
                verdict=verdict,
                feature_digest=feature_digest,
                digest="",
            )
            digest = _digest_pin(_extract_payload(provisional), "ai-feature.extract")
            rec = FeatureRecord(
                feature_id=feature_id,
                system_id=system_id,
                seq=seq,
                feature_kind=feature_kind,
                verdict=verdict,
                feature_digest=feature_digest,
                digest=digest,
            )
            self._features[feature_id] = rec
            self._system_features.setdefault(system_id, []).append(feature_id)
            self._emit(
                "extracted",
                seq,
                feature_id=feature_id,
                system_id=system_id,
                feature_kind=feature_kind,
                verdict=verdict,
                feature_digest=feature_digest,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id in self._retired:
                    raise RetiredSystemError(f"system is retired: {system_id!r}")
                if system_id not in self._system_features:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
            except AIFeatureError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-feature.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, feature_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one feature record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the feature was really extracted. Seq is shape-validated
        only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(feature_id, bool)
                or not isinstance(feature_id, str)
                or feature_id not in self._features
            ):
                raise UnknownFeatureError(f"unknown feature id: {feature_id!r}")
            rec = self._features[feature_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=feature_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-feature.verify")
            return VerificationReport(
                record_id=feature_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's feature posture as data.

        Posture by ledger rule: ``unextracted`` (nothing booked) ->
        ``failed`` (any failed) -> ``contested`` (any inconclusive) ->
        ``partially-extracted`` (any partial or not-attempted) ->
        ``extracted`` (all extracted). ``integrity_ok`` re-derives all
        in-scope digest pins as data. Seq is shape-validated only -
        never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_features:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            ids = self._system_features[system_id]
            recs = [self._features[i] for i in ids]
            n_extracted = sum(1 for r in recs if r.verdict == "extracted")
            n_partial = sum(1 for r in recs if r.verdict == "partial")
            n_failed = sum(1 for r in recs if r.verdict == "failed")
            n_inconclusive = sum(1 for r in recs if r.verdict == "inconclusive")
            if n_failed:
                posture = "failed"
            elif n_inconclusive:
                posture = "contested"
            elif n_partial or any(r.verdict == "not-attempted" for r in recs):
                posture = "partially-extracted"
            elif n_extracted and n_extracted == len(recs):
                posture = "extracted"
            else:
                posture = "unextracted"
            integrity_ok = all(r.verify() for r in recs)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_features=len(recs),
                n_extracted=n_extracted,
                n_partial=n_partial,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-feature.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_features=len(recs),
                n_extracted=n_extracted,
                n_partial=n_partial,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def feature_record(self, feature_id: str, seq: int) -> FeatureRecord:
        with self._lock:
            self._check_read_seq(seq)
            if feature_id not in self._features:
                raise UnknownFeatureError(f"unknown feature id: {feature_id!r}")
            return self._features[feature_id]

    def retire_record(self, system_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._check_read_seq(seq)
            if system_id not in self._retired:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return self._retired[system_id]

    def features_for(self, system_id: str, seq: int) -> Tuple[FeatureRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._features[i] for i in self._system_features.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._system_features))

    def feature_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._features))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_systems": len(self._system_features),
                "n_features": len(self._features),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_FEATURE_VERSION,
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
    """Self-check: exercise extract -> verify -> evaluate."""
    ledger = AIFeature()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.extract(
        "system-1",
        1,
        feature_kind="activation-pattern",
        verdict="extracted",
    )
    assert rec.verify()
    rep = ledger.verify(rec.feature_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("system-1", 3)
    assert ev.posture == "extracted"
    ret = ledger.retire("system-1", 4)
    assert ret.verify()
    print("ai-feature OK: extract, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
