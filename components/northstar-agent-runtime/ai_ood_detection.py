"""AI OOD detection: out-of-distribution detection decision ledger, Simulated.

Research note: out-of-distribution (OOD) detection - flagging inputs that
the model was not trained on (covariate shift, concept drift, novel
classes, corrupted or adversarial inputs) - never *proves* that an input
is truly out-of-distribution. OOD scores (Mahalanobis distance, energy,
softmax confidence, density estimates, reconstruction error) are thresholded
claims made by the host under a declared method configuration; thresholds
are host-chosen, calibration drifts, and every verdict is a declared claim,
not a proof of distributional truth.

What matters here is the *decision ledger*: which inputs from which
systems were run through which declared OOD methods, what verdicts were
declared with what input digest pins, and how each verdict was itself
verified - defensible bookkeeping, never proof that any input was (or was
not) truly out-of-distribution.

This module owns the detect -> verify -> evaluate lifecycle:

* **detect()** - book one declared OOD-detection verdict for an input
  (minted ``ood-N`` ids; pinned 8-term OOD-method vocabulary and pinned
  verdict vocabulary ``ood`` / ``in-distribution`` / ``inconclusive``).
  The first detection registers its system. Raw inputs, embeddings,
  activations, scores, and thresholds never enter records - digest pins
  only.
* **verify()** - book one declared verification of a detection verdict
  (minted ``ver-N`` ids; pinned outcome vocabulary ``confirmed`` /
  ``overturned`` / ``inconclusive``), booked **as data**, never proof the
  verdict was correct. Fail-closed on unknown detections and on
  double-verification.
* **evaluate()** - pure read: per-system detection/verification tallies
  with ledger-derived integrity, all booked as data.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs sibling detection ledgers: modules such as
``ai_detection`` book verdicts about AI-generated *content*, and anomaly
modules book verdicts about *system behaviour*; this module is the
*input-distribution* ledger none of them own: input -> declared OOD
method -> declared verdict -> declared verification.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-ood-detection.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no detectors, scores no inputs,
inspects no embeddings, and proves nothing about real
out-of-distribution status. A booked ``ood`` verdict means "the host
declared it", never "the input was truly out-of-distribution". Inputs,
embeddings, activations, scores, thresholds, and training data never
enter records or cross the audit boundary - digest pins only.
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
AI_OOD_DETECTION_VERSION = "ai-ood-detection.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-ood-detection.v1"

#: Pinned OOD-method vocabulary (the OOD methods this ledger tracks).
OOD_METHODS = (
    "mahalanobis",
    "energy-score",
    "softmax-threshold",
    "density-estimate",
    "reconstruction-error",
    "ensemble-disagreement",
    "knn-distance",
    "grad-norm",
)

#: Pinned OOD-verdict vocabulary (booked as data, never proof).
VERDICTS = (
    "ood",
    "in-distribution",
    "inconclusive",
)

#: Pinned verification-outcome vocabulary (booked as data, never proof).
VERIFY_OUTCOMES = (
    "confirmed",
    "overturned",
    "inconclusive",
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
    "detected",
    "verified",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "embedding",
        "embeddings",
        "feature",
        "features",
        "activation",
        "activations",
        "logits",
        "score",
        "scores",
        "distance",
        "distances",
        "threshold",
        "thresholds",
        "training_data",
        "calibration",
        "loss",
        "gradient",
        "gradients",
        "input",
        "inputs",
        "sample",
        "samples",
        "payload",
        "prompt",
        "response",
        "content",
        "text",
        "note",
        "notes",
        "detail",
        "details",
        "description",
        "report",
        "evidence",
        "result",
        "results",
        "raw",
        "secret",
        "key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIOODDetectionError(Exception):
    """Base error for AI OOD-detection ledger misuse."""


class BadIdError(AIOODDetectionError):
    """Malformed system, input, detection, or verification id."""


class RetiredSystemError(AIOODDetectionError):
    """System id already retired; never recycled."""


class UnknownSystemError(AIOODDetectionError):
    """System not registered."""


class BadMethodError(AIOODDetectionError):
    """Unknown OOD method."""


class BadDigestError(AIOODDetectionError):
    """Malformed sha256: digest pin."""


class BadVerdictError(AIOODDetectionError):
    """Unknown OOD verdict."""


class UnknownDetectionError(AIOODDetectionError):
    """Detection id not booked."""


class BadOutcomeError(AIOODDetectionError):
    """Unknown verification outcome."""


class AlreadyVerifiedError(AIOODDetectionError):
    """Detection already has a booked verification."""


class BadReasonError(AIOODDetectionError):
    """Unknown retirement reason."""


class SeqOrderError(AIOODDetectionError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(AIOODDetectionError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: Any, field_name: str) -> str:
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
class DetectionRecord:
    detection_id: str
    system_id: str
    input_id: str
    method: str
    verdict: str
    input_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "system_id": self.system_id,
            "input_id": self.input_id,
            "method": self.method,
            "verdict": self.verdict,
            "input_digest": self.input_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "detection_id": self.detection_id,
                "system_id": self.system_id,
                "input_id": self.input_id,
                "method": self.method,
                "verdict": self.verdict,
                "input_digest": self.input_digest,
            }
        )


@dataclass(frozen=True)
class VerificationRecord:
    verification_id: str
    detection_id: str
    system_id: str
    outcome: str
    review_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "verification_id": self.verification_id,
            "detection_id": self.detection_id,
            "system_id": self.system_id,
            "outcome": self.outcome,
            "review_digest": self.review_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "verification_id": self.verification_id,
                "detection_id": self.detection_id,
                "system_id": self.system_id,
                "outcome": self.outcome,
                "review_digest": self.review_digest,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class OODEvaluation:
    system_id: str
    n_detections: int
    n_ood: int
    n_in_distribution: int
    n_inconclusive: int
    n_verified: int
    n_confirmed: int
    n_overturned: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_detections": self.n_detections,
            "n_ood": self.n_ood,
            "n_in_distribution": self.n_in_distribution,
            "n_inconclusive": self.n_inconclusive,
            "n_verified": self.n_verified,
            "n_confirmed": self.n_confirmed,
            "n_overturned": self.n_overturned,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_detections": self.n_detections,
                "n_ood": self.n_ood,
                "n_in_distribution": self.n_in_distribution,
                "n_inconclusive": self.n_inconclusive,
                "n_verified": self.n_verified,
                "n_confirmed": self.n_confirmed,
                "n_overturned": self.n_overturned,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_ood_detection_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the AI OOD-detection ledger."""
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


class AIOODDetection:
    """AI OOD-detection decision ledger, Simulated.

    ``detect()`` / ``verify()`` / ``retire()`` mutate the ledger and
    consume caller seqs; ``evaluate()`` and the other views are pure
    reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._detections_by_system: Dict[str, List[str]] = {}
        self._verifications: Dict[str, VerificationRecord] = {}
        self._verifications_by_detection: Dict[str, str] = {}
        self._verifications_by_system: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._det_counter = 0
        self._ver_counter = 0
        self._seq = 0
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int, not bool")
        return seq

    def _claim_seq(self, seq: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq} after {self._seq}"
            )
        self._seq = seq

    def _burn(self, seq: int, method: str, exc: AIOODDetectionError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            ai_ood_detection_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_live_system(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system already retired: {system_id!r}")

    def _require_known_system(self, system_id: str) -> None:
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    # -- mutations ----------------------------------------------------------

    def detect(
        self,
        system_id: Any,
        input_id: Any,
        seq: Any,
        method: Any = "mahalanobis",
        verdict: Any = "inconclusive",
        input_digest: Any = "",
    ) -> DetectionRecord:
        """Book one declared OOD-detection verdict (minted ``ood-N``).

        The first detection registers its system. Raw inputs, embeddings,
        activations, scores, and thresholds travel as a digest pin only;
        they never enter records.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                iid = _require_id(input_id, "input_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(method, str) or method not in OOD_METHODS:
                    raise BadMethodError(
                        f"method must be one of {sorted(OOD_METHODS)}"
                    )
                if not isinstance(verdict, str) or verdict not in VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(VERDICTS)}"
                    )
                pin = _require_digest(input_digest, "input_digest")
                self._det_counter += 1
                did = f"ood-{self._det_counter}"
                rec = DetectionRecord(
                    detection_id=did,
                    system_id=sid,
                    input_id=iid,
                    method=method,
                    verdict=verdict,
                    input_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "detection_id": did,
                            "system_id": sid,
                            "input_id": iid,
                            "method": method,
                            "verdict": verdict,
                            "input_digest": pin,
                        }
                    ),
                )
                self._detections[did] = rec
                self._systems.setdefault(sid, []).append(did)
                self._detections_by_system.setdefault(sid, []).append(did)
                self._audit.append(
                    ai_ood_detection_audit_event(
                        "detected",
                        seq_v,
                        detection_id=did,
                        system_id=sid,
                        input_id=iid,
                        method=method,
                        verdict=verdict,
                    )
                )
                return rec
            except AIOODDetectionError as exc:
                self._burn(seq_v, "detect", exc)
                raise

    def verify(
        self,
        detection_id: Any,
        seq: Any,
        outcome: Any = "inconclusive",
        review_digest: Any = "",
    ) -> VerificationRecord:
        """Book one declared verification of a detection (minted ``ver-N``).

        Outcomes are booked **as data**, never proof the verdict was
        correct. Fail-closed on unknown detections and on
        double-verification.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                did = _require_id(detection_id, "detection_id")
                det = self._detections.get(did)
                if det is None:
                    raise UnknownDetectionError(f"unknown detection: {did!r}")
                self._require_live_system(det.system_id)
                if not isinstance(outcome, str) or outcome not in VERIFY_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(VERIFY_OUTCOMES)}"
                    )
                if did in self._verifications_by_detection:
                    raise AlreadyVerifiedError(
                        f"detection already verified: {did!r}"
                    )
                pin = _require_digest(review_digest, "review_digest")
                self._ver_counter += 1
                vid = f"ver-{self._ver_counter}"
                rec = VerificationRecord(
                    verification_id=vid,
                    detection_id=did,
                    system_id=det.system_id,
                    outcome=outcome,
                    review_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "verification_id": vid,
                            "detection_id": did,
                            "system_id": det.system_id,
                            "outcome": outcome,
                            "review_digest": pin,
                        }
                    ),
                )
                self._verifications[vid] = rec
                self._verifications_by_detection[did] = vid
                self._verifications_by_system.setdefault(det.system_id, []).append(vid)
                self._audit.append(
                    ai_ood_detection_audit_event(
                        "verified",
                        seq_v,
                        verification_id=vid,
                        detection_id=did,
                        system_id=det.system_id,
                        outcome=outcome,
                    )
                )
                return rec
            except AIOODDetectionError as exc:
                self._burn(seq_v, "verify", exc)
                raise

    def retire(
        self,
        system_id: Any,
        seq: Any,
        reason: Any = "manual",
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system already retired: {sid!r}")
                self._require_known_system(sid)
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(RETIRE_REASONS)}"
                    )
                rec = RetireRecord(
                    system_id=sid,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "system_id": sid,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[sid] = rec
                self._audit.append(
                    ai_ood_detection_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except AIOODDetectionError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views -----------------------------------------------------

    def detection_record(self, detection_id: Any, seq: Any) -> DetectionRecord:
        """Return one detection record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            did = _require_id(detection_id, "detection_id")
            if did not in self._detections:
                raise UnknownDetectionError(f"unknown detection: {did!r}")
            return self._detections[did]

    def verification_record(self, verification_id: Any, seq: Any) -> VerificationRecord:
        """Return one verification record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            vid = _require_id(verification_id, "verification_id")
            if vid not in self._verifications:
                raise UnknownDetectionError(f"unknown verification: {vid!r}")
            return self._verifications[vid]

    def verification_for(self, detection_id: Any, seq: Any) -> str:
        """Verification id booked against one detection, if any (pure read)."""
        with self._lock:
            self._check_seq(seq)
            did = _require_id(detection_id, "detection_id")
            if did not in self._detections:
                raise UnknownDetectionError(f"unknown detection: {did!r}")
            if did not in self._verifications_by_detection:
                raise UnknownDetectionError(f"no verification for detection: {did!r}")
            return self._verifications_by_detection[did]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """Registered system ids (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(sorted(self._systems))

    def detection_ids(self, seq: Any) -> Tuple[str, ...]:
        """Booked detection ids (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(sorted(self._detections))

    def detections_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Detection ids booked against one system (pure read)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._detections_by_system.get(sid, ()))

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """Retired system ids (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(sorted(self._retired))

    def evaluate(self, system_id: Any, seq: Any) -> OODEvaluation:
        """Per-system detection/verification tallies (pure read).

        All figures are booked **as data**, never proof of any real
        distributional property.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            det_ids = self._detections_by_system.get(sid, [])
            ver_ids = self._verifications_by_system.get(sid, [])
            n_ood = sum(
                1 for did in det_ids if self._detections[did].verdict == "ood"
            )
            n_in = sum(
                1
                for did in det_ids
                if self._detections[did].verdict == "in-distribution"
            )
            n_inc = sum(
                1
                for did in det_ids
                if self._detections[did].verdict == "inconclusive"
            )
            n_conf = sum(
                1 for vid in ver_ids if self._verifications[vid].outcome == "confirmed"
            )
            n_over = sum(
                1
                for vid in ver_ids
                if self._verifications[vid].outcome == "overturned"
            )
            integrity_ok = all(
                self._detections[did].verify() for did in det_ids
            ) and all(self._verifications[vid].verify() for vid in ver_ids)
            return OODEvaluation(
                system_id=sid,
                n_detections=len(det_ids),
                n_ood=n_ood,
                n_in_distribution=n_in,
                n_inconclusive=n_inc,
                n_verified=len(ver_ids),
                n_confirmed=n_conf,
                n_overturned=n_over,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "n_detections": len(det_ids),
                        "n_ood": n_ood,
                        "n_in_distribution": n_in,
                        "n_inconclusive": n_inc,
                        "n_verified": len(ver_ids),
                        "n_confirmed": n_conf,
                        "n_overturned": n_over,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: Any) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "systems": len(self._systems),
                "detections": len(self._detections),
                "verifications": len(self._verifications),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


# ---------------------------------------------------------------------------
# stdlib-only AST self-check
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
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    od = AIOODDetection()
    pin = "sha256:" + "ab" * 32
    det = od.detect(
        "sys-1", "input-1", 1, method="mahalanobis",
        verdict="ood", input_digest=pin,
    )
    assert det.detection_id == "ood-1"
    ver = od.verify("ood-1", 2, outcome="confirmed", review_digest=pin)
    assert ver.verification_id == "ver-1"
    od.retire("sys-1", 3, reason="decommissioned")
    ev = od.evaluate("sys-1", 4)
    assert ev.verify()
    assert ev.integrity_ok is True
    assert ev.n_ood == 1
    assert ev.n_confirmed == 1
    assert od.stats(5) == {
        "systems": 1,
        "detections": 1,
        "verifications": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("ai-ood-detection OK: detect, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
