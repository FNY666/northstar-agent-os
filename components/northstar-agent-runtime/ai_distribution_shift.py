"""AI distribution shift: detection decision ledger, Simulated.

Research note: detecting distribution shift between a reference
dataset and production data (covariate shift, label shift, concept
drift, prior shift, domain shift, temporal drift, selection bias)
never *proves* a model will fail - two-sample tests misfire on
correlated samples, drift scores depend on declared reference
windows, threshold crossings are host-declared, and every verdict is
a claim made by the host under a declared reference slice and a
declared production slice. What matters here is the *decision
ledger*: which systems had which declared shift detections booked
against which declared shift kinds, with what host-reported severity
and digest pins, and how each detection was itself verified -
defensible bookkeeping, never proof that the data really shifted.

This module owns the detect -> verify -> evaluate lifecycle:

* **detect()** - book one declared shift detection (minted ``det-N``
  ids; pinned 8-term shift-kind vocabulary and pinned verdict
  vocabulary ``shift-detected`` / ``suspected`` / ``inconclusive`` /
  ``no-shift`` / ``not-assessed``). The first detection registers its
  system. Raw samples, feature statistics, drift scores, labels, and
  data slices never enter records - digest pins only.
* **verify()** - pure read over any booked record: re-derives the
  digest pin; verdict ``verified`` / ``tampered`` booked as data.
* **evaluate()** - pure read: ledger-rule posture derived as data -
  ``unexamined`` -> ``shifted`` (any shift-detected) -> ``suspect``
  (any suspected) -> ``contested`` (any inconclusive) -> ``unassessed``
  (any not-assessed) -> ``clean`` (all no-shift), with verdict tallies
  and digest-pinned ``integrity_ok``.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs sibling monitoring ledgers:
``ai_monitoring`` owns declared metric watches and alerts;
``ai_detection`` owns declared AI-generated-content verdicts;
``ai_surveillance`` owns declared behavior observations - this module
is the *distribution-shift detection* decision ledger none of them
own: system -> declared shift kind -> declared verdict -> declared
severity -> digest-pinned verification.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-distribution-shift.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no two-sample tests, reads no data,
computes no drift scores, and proves nothing about real production
data. A booked ``shift-detected`` verdict means "the host declared
it", never "the distribution really shifted". Samples, feature
statistics, drift scores, labels, and data slices never enter records
or cross the audit boundary - digest pins only.
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
AI_DISTRIBUTION_SHIFT_VERSION = "ai-distribution-shift.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-distribution-shift.v1"

#: Pinned shift-kind vocabulary (the shift classes this ledger tracks).
SHIFT_KINDS = (
    "covariate-shift",
    "label-shift",
    "concept-drift",
    "prior-shift",
    "domain-shift",
    "temporal-drift",
    "selection-bias",
    "covariate-drift",
)

#: Pinned verdict vocabulary (booked as data, never proof).
VERDICTS = (
    "shift-detected",
    "suspected",
    "inconclusive",
    "no-shift",
    "not-assessed",
)

#: Pinned verify verdicts (pure read, as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned posture ladder (ledger-rule derivation, as data).
POSTURES = (
    "unexamined",
    "shifted",
    "suspect",
    "contested",
    "unassessed",
    "clean",
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
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "samples",
        "sample",
        "feature_stats",
        "feature_statistics",
        "drift_scores",
        "drift_score",
        "p_values",
        "p_value",
        "kl_divergence",
        "wasserstein",
        "labels",
        "label",
        "input_data",
        "reference_data",
        "production_data",
        "data_slice",
        "embeddings",
        "embedding",
        "activations",
        "scores",
        "score",
        "metrics",
        "metric",
        "histograms",
        "histogram",
        "distributions",
        "distribution",
        "raw_data",
        "raw",
        "telemetry",
        "user_data",
        "pii",
        "predictions",
        "prediction",
        "ground_truth",
        "dataset",
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
        "secret",
        "key",
        "weights",
        "model_weights",
        "parameters",
        "params",
        "loss",
        "reward",
        "rewards",
        "feedback",
        "preference",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIDistributionShiftError(Exception):
    """Base error for AI distribution-shift ledger misuse."""


class BadIdError(AIDistributionShiftError):
    """Malformed system or detection id."""


class RetiredSystemError(AIDistributionShiftError):
    """System id already retired; never recycled."""


class UnknownSystemError(AIDistributionShiftError):
    """System not registered."""


class BadShiftKindError(AIDistributionShiftError):
    """Unknown shift kind."""


class BadVerdictError(AIDistributionShiftError):
    """Unknown shift verdict."""


class BadSeverityError(AIDistributionShiftError):
    """Severity not an int in [0, 100] (bool refused)."""


class BadDigestError(AIDistributionShiftError):
    """Malformed sha256: digest pin."""


class UnknownDetectionError(AIDistributionShiftError):
    """Detection id not booked."""


class BadReasonError(AIDistributionShiftError):
    """Unknown retirement reason."""


class SeqOrderError(AIDistributionShiftError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(AIDistributionShiftError):
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


def _require_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int in [0, 100], not bool")
    if value < 0 or value > 100:
        raise BadSeverityError("severity must be an int in [0, 100]")
    return value


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
    shift_kind: str
    verdict: str
    severity: int
    detection_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "system_id": self.system_id,
            "shift_kind": self.shift_kind,
            "verdict": self.verdict,
            "severity": self.severity,
            "detection_digest": self.detection_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "detection_id": self.detection_id,
                "system_id": self.system_id,
                "shift_kind": self.shift_kind,
                "verdict": self.verdict,
                "severity": self.severity,
                "detection_digest": self.detection_digest,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    verdict: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "record_id": self.record_id,
            "verdict": self.verdict,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "record_id": self.record_id,
                "verdict": self.verdict,
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
class ShiftEvaluation:
    system_id: str
    posture: str
    n_detections: int
    n_shift_detected: int
    n_suspected: int
    n_inconclusive: int
    n_no_shift: int
    n_not_assessed: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "posture": self.posture,
            "n_detections": self.n_detections,
            "n_shift_detected": self.n_shift_detected,
            "n_suspected": self.n_suspected,
            "n_inconclusive": self.n_inconclusive,
            "n_no_shift": self.n_no_shift,
            "n_not_assessed": self.n_not_assessed,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "posture": self.posture,
                "n_detections": self.n_detections,
                "n_shift_detected": self.n_shift_detected,
                "n_suspected": self.n_suspected,
                "n_inconclusive": self.n_inconclusive,
                "n_no_shift": self.n_no_shift,
                "n_not_assessed": self.n_not_assessed,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_distribution_shift_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the shift ledger."""
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


class AIDistributionShift:
    """AI distribution-shift detection decision ledger, Simulated.

    ``detect()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``verify()`` / ``evaluate()`` and the other views are pure
    reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._detections_by_system: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._det_counter = 0
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

    def _burn(self, seq: int, method: str, exc: AIDistributionShiftError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            ai_distribution_shift_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_known_system(self, system_id: str) -> None:
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    # -- mutations --------------------------------------------------------

    def detect(
        self,
        system_id: Any,
        seq: Any,
        shift_kind: Any = "covariate-shift",
        verdict: Any = "not-assessed",
        severity: Any = 0,
        detection_digest: Any = "",
    ) -> DetectionRecord:
        """Book one declared shift detection (minted ``det-N``).

        The first detection registers its system. Raw samples,
        feature statistics, drift scores, labels, and data slices
        travel as a digest pin only; they never enter records.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(shift_kind, str) or shift_kind not in SHIFT_KINDS:
                    raise BadShiftKindError(
                        f"shift_kind must be one of {sorted(SHIFT_KINDS)}"
                    )
                if not isinstance(verdict, str) or verdict not in VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(VERDICTS)}"
                    )
                sev = _require_severity(severity)
                pin = _require_digest(detection_digest, "detection_digest")
                self._det_counter += 1
                did = f"det-{self._det_counter}"
                rec = DetectionRecord(
                    detection_id=did,
                    system_id=sid,
                    shift_kind=shift_kind,
                    verdict=verdict,
                    severity=sev,
                    detection_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "detection_id": did,
                            "system_id": sid,
                            "shift_kind": shift_kind,
                            "verdict": verdict,
                            "severity": sev,
                            "detection_digest": pin,
                        }
                    ),
                )
                self._detections[did] = rec
                self._systems.setdefault(sid, []).append(did)
                self._detections_by_system.setdefault(sid, []).append(did)
                self._audit.append(
                    ai_distribution_shift_audit_event(
                        "detected",
                        seq_v,
                        detection_id=did,
                        system_id=sid,
                        shift_kind=shift_kind,
                        verdict=verdict,
                        severity=sev,
                    )
                )
                return rec
            except AIDistributionShiftError as exc:
                self._burn(seq_v, "detect", exc)
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
                    ai_distribution_shift_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except AIDistributionShiftError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure reads -------------------------------------------------------

    def verify(self, record_id: Any, seq: Any) -> VerificationReport:
        """Re-derive one record's digest pin (pure read).

        Accepts a detection id or a retired system id; verdict
        ``verified`` / ``tampered`` is booked as data (tamper is
        reported, never raised).
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            rid = _require_id(record_id, "record_id")
            rec = self._detections.get(rid)
            if rec is None and rid in self._retired:
                rec = self._retired[rid]
            if rec is None:
                raise UnknownDetectionError(f"unknown record: {rid!r}")
            ok = rec.verify()
            verdict = "verified" if ok else "tampered"
            return VerificationReport(
                record_id=rid,
                verdict=verdict,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "record_id": rid,
                        "verdict": verdict,
                    }
                ),
            )

    def evaluate(self, system_id: Any, seq: Any) -> ShiftEvaluation:
        """Per-system shift posture, derived by ledger rule (pure read).

        Posture ladder as data: ``unexamined`` -> ``shifted`` (any
        shift-detected) -> ``suspect`` (any suspected) -> ``contested``
        (any inconclusive) -> ``unassessed`` (any not-assessed) ->
        ``clean`` (all no-shift). Verdict tallies and ``integrity_ok``
        are data, never proof of real distribution behavior.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            det_ids = self._detections_by_system[sid]
            n_det = n_sus = n_inc = n_clean = n_una = 0
            for did in det_ids:
                verdict = self._detections[did].verdict
                if verdict == "shift-detected":
                    n_det += 1
                elif verdict == "suspected":
                    n_sus += 1
                elif verdict == "inconclusive":
                    n_inc += 1
                elif verdict == "no-shift":
                    n_clean += 1
                else:
                    n_una += 1
            if n_det > 0:
                posture = "shifted"
            elif n_sus > 0:
                posture = "suspect"
            elif n_inc > 0:
                posture = "contested"
            elif n_una > 0:
                posture = "unassessed"
            else:
                posture = "clean"
            integrity_ok = all(
                self._detections[did].verify() for did in det_ids
            )
            return ShiftEvaluation(
                system_id=sid,
                posture=posture,
                n_detections=len(det_ids),
                n_shift_detected=n_det,
                n_suspected=n_sus,
                n_inconclusive=n_inc,
                n_no_shift=n_clean,
                n_not_assessed=n_una,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "posture": posture,
                        "n_detections": len(det_ids),
                        "n_shift_detected": n_det,
                        "n_suspected": n_sus,
                        "n_inconclusive": n_inc,
                        "n_no_shift": n_clean,
                        "n_not_assessed": n_una,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def detection_record(self, detection_id: Any, seq: Any) -> DetectionRecord:
        """Return one detection record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            did = _require_id(detection_id, "detection_id")
            if did not in self._detections:
                raise UnknownDetectionError(f"unknown detection: {did!r}")
            return self._detections[did]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def detection_ids(self, seq: Any) -> Tuple[str, ...]:
        """All detection ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"det-{i}" for i in range(1, self._det_counter + 1))

    def detections_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Detection ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._detections_by_system[sid])

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired system ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

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
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


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
    """Self-check: exercise detect -> verify -> evaluate -> retire."""
    ledger = AIDistributionShift()
    pin = "sha256:" + "ab" * 32
    det = ledger.detect(
        "system-1", 1, shift_kind="covariate-shift",
        verdict="shift-detected", severity=75, detection_digest=pin,
    )
    assert det.detection_id == "det-1"
    assert det.verify()
    rep = ledger.verify("det-1", 2)
    assert rep.verdict == "verified"
    assert rep.verify()
    ev = ledger.evaluate("system-1", 3)
    assert ev.verify()
    assert ev.posture == "shifted"
    assert ev.integrity_ok is True
    ledger.retire("system-1", 4, reason="decommissioned")
    assert ledger.verify("system-1", 5).verdict == "verified"
    assert ledger.stats(6) == {
        "systems": 1,
        "detections": 1,
        "retired": 1,
        "rejected": 0,
    }
    assert stdlib_only()
    print("ai-distribution-shift OK: detect, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
