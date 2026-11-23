"""Feature visualization: interpretability visualization decision ledger, Simulated.

Research note: feature visualization (Olah et al., Distill) synthesizes
images that maximally activate a neuron or direction in a network -
activation maximization, feature inversion, gradient ascent, dataset
examples, caricatures, attribution maps. The interpretability claim is
fragile: a pretty picture can suggest a feature "means" something while
the optimization, the priors, and the cherry-picking carry the load.
What matters here is the *decision ledger*: which models had which
features visualized by which declared method, what outcome the host
declared, whether the booked record still verifies, and which pairwise
comparisons were declared - defensible bookkeeping, not proof that a
feature was understood.

This module owns the visualize -> verify -> compare lifecycle:

* **visualize()** - book one declared feature-visualization run (minted
  ``viz-N`` ids; pinned method and outcome vocabularies); the first run
  registers the model; raw activations, images, pixels, weights, and
  feature vectors never enter records - digest pins only; outcomes booked
  as data, never proof a feature was understood.
* **verify()** - derive one digest-pinned verification report (pure read)
  by ledger rule: re-derived digest matches -> ``consistent``; mismatch
  -> ``tampered`` - derived as data, never proof the image was faithful.
* **compare()** - book one declared comparison between two booked
  visualizations (minted ``cmp-N`` ids; pinned similarity vocabulary);
  unknown or self comparisons refused fail-closed; the verdict is booked
  as data, never proof the features are related.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``feature-viz.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module runs no optimization, renders no image,
observes no activations, and understands no features. A booked
``generated`` means "the host declared a visualization was generated",
never "the feature was visualized faithfully". A derived ``consistent``
means "the ledger rule is satisfied", never "the image means what it
claims".
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
FEATURE_VIZ_VERSION = "feature-viz.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.feature-viz.v1"

#: Pinned visualization-method vocabulary (Olah-style taxonomy).
VIZ_METHODS = (
    "activation-maximization",
    "feature-inversion",
    "gradient-ascent",
    "dataset-examples",
    "caricature",
    "attribution-map",
)

#: Pinned per-run outcome vocabulary, booked as data.
VIZ_OUTCOMES = (
    "generated",
    "failed",
    "ambiguous",
    "inconclusive",
)

#: Pinned verification-verdict vocabulary, derived by ledger rule.
VERIFICATION_VERDICTS = (
    "consistent",
    "tampered",
)

#: Pinned comparison-verdict vocabulary, booked as data.
COMPARISON_VERDICTS = (
    "identical",
    "similar",
    "different",
    "incomparable",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "visualized",
    "compared",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "activation",
        "activations",
        "image",
        "images",
        "pixels",
        "weights",
        "feature_vector",
        "feature_vectors",
        "feature_map",
        "gradients",
        "gradient",
        "saliency",
        "heatmap",
        "attribution",
        "attributions",
        "logits",
        "layer_output",
        "visualization",
        "visualization_image",
        "comparison_image",
        "input",
        "output",
        "outputs",
        "raw",
        "text",
        "content",
        "data",
        "detail",
        "details",
        "description",
        "trace",
        "transcript",
        "prompt",
        "response",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class FeatureVizError(Exception):
    """Base error for feature-viz ledger misuse."""


class BadIdError(FeatureVizError):
    """Malformed model, visualization, or comparison id."""


class UnknownVisualizationError(FeatureVizError):
    """Visualization id never booked."""


class UnknownComparisonError(FeatureVizError):
    """Comparison id never booked."""


class UnknownModelError(FeatureVizError):
    """Model never registered by a visualization run."""


class BadMethodError(FeatureVizError):
    """Unknown visualization method."""


class BadOutcomeError(FeatureVizError):
    """Unknown visualization outcome."""


class BadVerdictError(FeatureVizError):
    """Unknown comparison verdict."""


class BadDigestError(FeatureVizError):
    """Malformed digest pin."""


class SelfComparisonError(FeatureVizError):
    """Comparison of a visualization with itself."""


class SeqOrderError(FeatureVizError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(FeatureVizError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VisualizationRecord:
    viz_id: str
    model_id: str
    method: str
    outcome: str
    feature_digest: str
    model_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "viz_id": self.viz_id,
            "model_id": self.model_id,
            "method": self.method,
            "outcome": self.outcome,
            "feature_digest": self.feature_digest,
            "model_digest": self.model_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "viz_id": self.viz_id,
                "model_id": self.model_id,
                "method": self.method,
                "outcome": self.outcome,
                "feature_digest": self.feature_digest,
                "model_digest": self.model_digest,
            }
        )


@dataclass(frozen=True)
class ComparisonRecord:
    comparison_id: str
    viz_id_a: str
    viz_id_b: str
    verdict: str
    comparison_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "comparison_id": self.comparison_id,
            "viz_id_a": self.viz_id_a,
            "viz_id_b": self.viz_id_b,
            "verdict": self.verdict,
            "comparison_digest": self.comparison_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "comparison_id": self.comparison_id,
                "viz_id_a": self.viz_id_a,
                "viz_id_b": self.viz_id_b,
                "verdict": self.verdict,
                "comparison_digest": self.comparison_digest,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    viz_id: str
    model_id: str
    method: str
    outcome: str
    verdict: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "viz_id": self.viz_id,
            "model_id": self.model_id,
            "method": self.method,
            "outcome": self.outcome,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "viz_id": self.viz_id,
                "model_id": self.model_id,
                "method": self.method,
                "outcome": self.outcome,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def feature_viz_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the viz ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class FeatureViz:
    """Feature-visualization interpretability decision ledger, Simulated.

    ``visualize()`` / ``compare()`` mutate the ledger and consume caller
    seqs; ``verify()`` and the other views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._vizzes: Dict[str, VisualizationRecord] = {}
        self._models: Dict[str, List[str]] = {}
        self._comparisons: Dict[str, ComparisonRecord] = {}
        self._viz_comparisons: Dict[str, List[str]] = {}
        self._viz_counter = 0
        self._cmp_counter = 0
        self._audit: List[Dict[str, object]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        """Shape-validate a caller seq (bool/float/str refused)."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")
        return seq

    def _claim_seq(self, seq_v: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq_v <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq_v} after {self._seq}"
            )
        self._seq = seq_v

    def _burn(self, seq_v: int, method: str, exc: FeatureVizError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            feature_viz_audit_event(
                "rejected",
                seq_v,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _emit(self, audit_kind: str, seq_v: int, **details: Any) -> None:
        self._audit.append(
            feature_viz_audit_event(audit_kind, seq_v, **details)
        )

    # -- mutations ----------------------------------------------------------

    def visualize(
        self,
        model_id: str,
        seq: int,
        method: str = "activation-maximization",
        outcome: str = "generated",
        feature_digest: str = "",
        model_digest: str = "",
    ) -> VisualizationRecord:
        """Book one declared feature-visualization run.

        The first run registers the model. Raw activations, images,
        pixels, weights, and feature vectors travel as digest pins only -
        they never enter records. The declared outcome is booked as data,
        never proof a feature was understood.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                if not isinstance(method, str) or method not in VIZ_METHODS:
                    raise BadMethodError(
                        f"method must be one of {sorted(VIZ_METHODS)}"
                    )
                if not isinstance(outcome, str) or outcome not in VIZ_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(VIZ_OUTCOMES)}"
                    )
                fpin = _require_digest(feature_digest, "feature_digest")
                mpin = _require_digest(model_digest, "model_digest")
                self._viz_counter += 1
                vid = f"viz-{self._viz_counter}"
                rec = VisualizationRecord(
                    viz_id=vid,
                    model_id=mid,
                    method=method,
                    outcome=outcome,
                    feature_digest=fpin,
                    model_digest=mpin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "viz_id": vid,
                            "model_id": mid,
                            "method": method,
                            "outcome": outcome,
                            "feature_digest": fpin,
                            "model_digest": mpin,
                        }
                    ),
                )
                self._vizzes[vid] = rec
                self._models.setdefault(mid, []).append(vid)
                self._emit(
                    "visualized",
                    seq_v,
                    viz_id=vid,
                    model_id=mid,
                    method=method,
                    outcome=outcome,
                )
                return rec
            except FeatureVizError as exc:
                self._burn(seq_v, "visualize", exc)
                raise

    def compare(
        self,
        viz_id_a: str,
        viz_id_b: str,
        seq: int,
        verdict: str = "similar",
        comparison_digest: str = "",
    ) -> ComparisonRecord:
        """Book one declared comparison between two booked visualizations.

        Both ids must be booked; self-comparisons are refused fail-closed.
        The verdict is booked as data, never proof the features are
        related.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                aid = _require_id(viz_id_a, "viz_id_a")
                bid = _require_id(viz_id_b, "viz_id_b")
                if aid not in self._vizzes:
                    raise UnknownVisualizationError(
                        f"visualization not booked: {aid!r}"
                    )
                if bid not in self._vizzes:
                    raise UnknownVisualizationError(
                        f"visualization not booked: {bid!r}"
                    )
                if aid == bid:
                    raise SelfComparisonError(
                        "cannot compare a visualization with itself"
                    )
                if not isinstance(verdict, str) or verdict not in COMPARISON_VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(COMPARISON_VERDICTS)}"
                    )
                cpin = _require_digest(comparison_digest, "comparison_digest")
                self._cmp_counter += 1
                cid = f"cmp-{self._cmp_counter}"
                rec = ComparisonRecord(
                    comparison_id=cid,
                    viz_id_a=aid,
                    viz_id_b=bid,
                    verdict=verdict,
                    comparison_digest=cpin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "comparison_id": cid,
                            "viz_id_a": aid,
                            "viz_id_b": bid,
                            "verdict": verdict,
                            "comparison_digest": cpin,
                        }
                    ),
                )
                self._comparisons[cid] = rec
                self._viz_comparisons.setdefault(aid, []).append(cid)
                self._viz_comparisons.setdefault(bid, []).append(cid)
                self._emit(
                    "compared",
                    seq_v,
                    comparison_id=cid,
                    viz_id_a=aid,
                    viz_id_b=bid,
                    verdict=verdict,
                )
                return rec
            except FeatureVizError as exc:
                self._burn(seq_v, "compare", exc)
                raise

    # -- pure-read views ------------------------------------------------------

    def verify(self, viz_id: str, seq: int) -> VerificationReport:
        """Derive a verification report for a booked visualization (pure read).

        Ledger rule: re-derived digest matches -> ``consistent``;
        mismatch -> ``tampered``. Derived as data, never proof the image
        was faithful. Writes no audit row; seq is shape-validated only.
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(viz_id, "viz_id")
            if viz_id not in self._vizzes:
                raise UnknownVisualizationError(
                    f"visualization not booked: {viz_id!r}"
                )
            rec = self._vizzes[viz_id]
            integrity = rec.verify()
            verdict = "consistent" if integrity else "tampered"
            return VerificationReport(
                viz_id=rec.viz_id,
                model_id=rec.model_id,
                method=rec.method,
                outcome=rec.outcome,
                verdict=verdict,
                integrity_ok=integrity,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "viz_id": rec.viz_id,
                        "model_id": rec.model_id,
                        "method": rec.method,
                        "outcome": rec.outcome,
                        "verdict": verdict,
                        "integrity_ok": integrity,
                    }
                ),
            )

    def visualization_record(self, viz_id: str, seq: int) -> VisualizationRecord:
        """Return one visualization record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(viz_id, "viz_id")
            if viz_id not in self._vizzes:
                raise UnknownVisualizationError(
                    f"visualization not booked: {viz_id!r}"
                )
            return self._vizzes[viz_id]

    def comparison_record(self, comparison_id: str, seq: int) -> ComparisonRecord:
        """Return one comparison record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(comparison_id, "comparison_id")
            if comparison_id not in self._comparisons:
                raise UnknownComparisonError(
                    f"comparison not booked: {comparison_id!r}"
                )
            return self._comparisons[comparison_id]

    def visualizations_for(self, model_id: str, seq: int) -> Tuple[str, ...]:
        """Visualization ids booked for a model, in booking order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            if mid not in self._models:
                raise UnknownModelError(f"model not registered: {mid!r}")
            return tuple(self._models[mid])

    def comparisons_for(self, viz_id: str, seq: int) -> Tuple[str, ...]:
        """Comparison ids involving a visualization, in booking order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(viz_id, "viz_id")
            if viz_id not in self._vizzes:
                raise UnknownVisualizationError(
                    f"visualization not booked: {viz_id!r}"
                )
            return tuple(self._viz_comparisons.get(viz_id, ()))

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered model ids in registration order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._models.keys())

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "models": len(self._models),
                "visualizations": len(self._vizzes),
                "comparisons": len(self._comparisons),
                "rejected": self._rejected,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, object], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the feature-viz ledger end to end."""
    fv = FeatureViz()
    pin = "sha256:" + "ab" * 32
    v1 = fv.visualize(
        "m-1", 1, method="activation-maximization",
        outcome="generated", feature_digest=pin, model_digest=pin,
    )
    v2 = fv.visualize(
        "m-1", 2, method="dataset-examples",
        outcome="ambiguous", feature_digest=pin, model_digest=pin,
    )
    assert v1.verify() and v2.verify()
    rep = fv.verify(v1.viz_id, 3)
    assert rep.verdict == "consistent" and rep.integrity_ok
    c1 = fv.compare(v1.viz_id, v2.viz_id, 4, verdict="different", comparison_digest=pin)
    assert c1.verify()
    assert fv.visualizations_for("m-1", 5) == (v1.viz_id, v2.viz_id)
    assert fv.comparisons_for(v1.viz_id, 6) == (c1.comparison_id,)
    assert fv.stats(7) == {
        "models": 1,
        "visualizations": 2,
        "comparisons": 1,
        "rejected": 0,
    }
    print("feature-viz OK: visualize, verify, compare, pins, audit")


if __name__ == "__main__":
    main()
