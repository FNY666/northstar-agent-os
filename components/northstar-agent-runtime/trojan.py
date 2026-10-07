"""Trojan test/detect decision ledger, Simulated.

Research note: trojans in ML (BadNets / TrojanNN / sleeper-agent models) hide
malicious behavior *in the weights* - a trigger pattern switches on misbehavior
at runtime. The literature's testing practice is a two-step declared workflow:
run trojan *tests* (trigger probes, behavioral deltas, activation sweeps,
poison audits, sleeper probes, fine-tune stress) against a target, then book a
*detection* verdict (activation clustering, Neural Cleanse trigger inversion,
spectral signatures, fine-pruning probes, weight inspection, ensemble vote),
and declare a *mitigation* measure when the verdict is infected or suspect.
A booked "clean" is never proof a target is trojan-free: it is proof a
declared test ran and a declared verdict was booked - GIGO throughout.

This module is the *test/detect* decision layer, deliberately distinct from
its siblings:

- ``backdoor_detector.py`` - runtime *text* tripwire for known trigger shapes
  (regex over input text); neither tests models nor books detections.
- ``backdoor_detection.py`` - declared trigger-detection decision ledger for
  a different detection taxonomy.
- ``trojan_defense.py`` - *remediation lifecycle* ledger (register_model /
  scan / quarantine / remove / verify) for the post-detection remediation
  practice.

This module owns the test workflow instead:

* **register_target()** - declare one target under trojan testing watch.
* **test()** - book one declared trojan test (pinned test-kind vocabulary,
  pinned outcome vocabulary). The outcome is data, never proof of a trojan
  or of cleanliness.
* **detect()** - book one declared detection verdict over the pinned
  detector vocabulary; fail-closed (requires a booked test for the target).
  The verdict is data, never proof.
* **mitigate()** - book one declared mitigation measure against an
  infected/suspect detection; fail-closed (one mitigation per detection).
  Books the *declaration*, never the execution.
* **retire()** - terminal: retire a target id; ids are never recycled.
* **status()** - pure read view: test/detection tallies and posture as data.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``trojan.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module runs no tests, inverts no triggers, analyzes no
weights, and cannot prove a target is clean or infected. All outcomes and
verdicts are host-declared GIGO booked under digest pins; raw weights,
triggers, activations, and model bytes never cross the module boundary.
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
TROJAN_VERSION = "trojan.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.trojan.v1"

#: Pinned trojan-test-kind vocabulary (declared, never executed).
TEST_KINDS = (
    "trigger-probe",
    "behavioral-delta",
    "activation-sweep",
    "poison-audit",
    "sleeper-probe",
    "fine-tune-stress",
)

#: Pinned test-outcome vocabulary. Outcomes are data, never proof.
TEST_OUTCOMES = ("triggered", "clean", "inconclusive", "anomalous")

#: Pinned detector vocabulary (declared, never executed).
DETECTORS = (
    "activation-clustering",
    "neural-cleanse",
    "spectral-signatures",
    "fine-pruning-probe",
    "weight-inspection",
    "ensemble-vote",
)

#: Pinned detection-verdict vocabulary. Verdicts are data, never proof.
DETECTION_VERDICTS = ("infected", "suspect", "clean", "inconclusive")

#: Pinned mitigation-measure vocabulary (declared, never executed).
MEASURES = (
    "isolate",
    "retrain",
    "prune",
    "rollback",
    "decommission",
    "monitor",
)

#: Pinned retire-reason vocabulary.
RETIRE_REASONS = ("manual", "decommissioned", "superseded", "withdrawn")

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "target-registered",
    "test-recorded",
    "detection-recorded",
    "mitigated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "weight",
        "trigger",
        "trigger_bytes",
        "payload",
        "model",
        "model_bytes",
        "checkpoint",
        "params",
        "activations",
        "activations_delta",
        "secret",
        "raw",
        "text",
        "content",
        "data",
        "value",
        "response",
        "output",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TrojanError(Exception):
    """Base error for trojan test/detect ledger misuse."""


class BadTargetError(TrojanError):
    """Malformed target id."""


class DuplicateTargetError(TrojanError):
    """Target id already registered."""


class RetiredTargetError(TrojanError):
    """Target id retired; never recycled."""


class UnknownTargetError(TrojanError):
    """Target id not registered."""


class BadDigestError(TrojanError):
    """Malformed sha256: digest pin."""


class BadTestKindError(TrojanError):
    """Unknown test kind."""


class BadOutcomeError(TrojanError):
    """Unknown test outcome."""


class BadDetectorError(TrojanError):
    """Unknown detector."""


class BadVerdictError(TrojanError):
    """Unknown detection verdict."""


class BadMeasureError(TrojanError):
    """Unknown mitigation measure."""


class BadReasonError(TrojanError):
    """Unknown retire reason."""


class UnknownTestError(TrojanError):
    """Test id not booked."""


class UnknownDetectionError(TrojanError):
    """Detection id not booked."""


class NoTestError(TrojanError):
    """Detection requires at least one booked test for the target."""


class DetectionStateError(TrojanError):
    """Detection preconditions not met (verdict needs no mitigation,
    or detection belongs to another target)."""


class AlreadyMitigatedError(TrojanError):
    """Detection already carries a mitigation."""


class SeqOrderError(TrojanError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(TrojanError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadTargetError(f"{field_name} must be a non-empty str <= 128 chars")
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


@dataclass(frozen=True)
class TargetRecord:
    target_id: str
    target_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "target_id": self.target_id,
            "target_digest": self.target_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {"schema": SCHEMA_PIN, "target_id": self.target_id,
             "target_digest": self.target_digest}
        )


@dataclass(frozen=True)
class TestRecord:
    test_id: str
    target_id: str
    test_kind: str
    outcome: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "test_id": self.test_id,
            "target_id": self.target_id,
            "test_kind": self.test_kind,
            "outcome": self.outcome,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "test_id": self.test_id,
                "target_id": self.target_id,
                "test_kind": self.test_kind,
                "outcome": self.outcome,
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class DetectionRecord:
    detection_id: str
    target_id: str
    test_id: str
    detector: str
    verdict: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "target_id": self.target_id,
            "test_id": self.test_id,
            "detector": self.detector,
            "verdict": self.verdict,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "detection_id": self.detection_id,
                "target_id": self.target_id,
                "test_id": self.test_id,
                "detector": self.detector,
                "verdict": self.verdict,
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class MitigationRecord:
    mitigation_id: str
    detection_id: str
    target_id: str
    measure: str
    plan_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "mitigation_id": self.mitigation_id,
            "detection_id": self.detection_id,
            "target_id": self.target_id,
            "measure": self.measure,
            "plan_digest": self.plan_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "mitigation_id": self.mitigation_id,
                "detection_id": self.detection_id,
                "target_id": self.target_id,
                "measure": self.measure,
                "plan_digest": self.plan_digest,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    target_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "target_id": self.target_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "target_id": self.target_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class TargetStatus:
    target_id: str
    n_tests: int
    n_detections: int
    latest_verdict: str
    n_mitigations: int
    retired: bool
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "target_id": self.target_id,
            "n_tests": self.n_tests,
            "n_detections": self.n_detections,
            "latest_verdict": self.latest_verdict,
            "n_mitigations": self.n_mitigations,
            "retired": self.retired,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "target_id": self.target_id,
                "n_tests": self.n_tests,
                "n_detections": self.n_detections,
                "latest_verdict": self.latest_verdict,
                "n_mitigations": self.n_mitigations,
                "retired": self.retired,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def trojan_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the trojan ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class Trojan:
    """Trojan test/detect decision ledger (Simulated).

    ``register_target()`` / ``test()`` / ``detect()`` / ``mitigate()`` /
    ``retire()`` mutate the ledger and consume caller seqs; ``status()``
    and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._targets: Dict[str, TargetRecord] = {}
        self._tests: Dict[str, TestRecord] = {}
        self._target_tests: Dict[str, List[str]] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._target_detections: Dict[str, List[str]] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._mitigation_of_detection: Dict[str, str] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0
        self._tst_counter = 0
        self._det_counter = 0
        self._mit_counter = 0

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = trojan_audit_event("rejected", seq,
                                     rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(trojan_audit_event(audit_kind, seq, **details))

    def _live_target(self, target_id: str) -> TargetRecord:
        record = self._targets.get(target_id)
        if record is None:
            raise UnknownTargetError(f"unknown target: {target_id!r}")
        if target_id in self._retired:
            raise RetiredTargetError(
                f"target retired, never recycled: {target_id!r}")
        return record

    # -- register_target -----------------------------------------------------

    def register_target(
        self, target_id: str, seq: int, target_digest: str = ""
    ) -> TargetRecord:
        """Declare one target under trojan testing watch."""
        with self._lock:
            try:
                self._claim(seq)
            except TrojanError:
                raise
            try:
                _require_id(target_id, "target_id")
                if target_digest:
                    _require_digest(target_digest, "target_digest")
                else:
                    target_digest = "sha256:" + "00" * 32
                if target_id in self._retired:
                    raise RetiredTargetError(
                        f"target id retired, never recycled: {target_id!r}")
                if target_id in self._targets:
                    raise DuplicateTargetError(
                        f"target already registered: {target_id!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "target_id": target_id,
                     "target_digest": target_digest}
                )
                record = TargetRecord(
                    target_id=target_id, target_digest=target_digest,
                    digest=digest,
                )
                self._targets[target_id] = record
                self._target_tests[target_id] = []
                self._target_detections[target_id] = []
                self._emit("target-registered", seq, target_id=target_id)
                return record
            except TrojanError:
                self._burn(seq, "register_target")
                raise

    # -- test ----------------------------------------------------------------

    def test(
        self,
        target_id: str,
        seq: int,
        test_kind: str = "behavioral-delta",
        outcome: str = "clean",
        evidence_digest: str = "",
    ) -> TestRecord:
        """Book one declared trojan test. The outcome is data, never proof."""
        with self._lock:
            try:
                self._claim(seq)
            except TrojanError:
                raise
            try:
                self._live_target(target_id)
                if test_kind not in TEST_KINDS:
                    raise BadTestKindError(
                        f"test_kind must be one of {TEST_KINDS}")
                if outcome not in TEST_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {TEST_OUTCOMES}")
                if evidence_digest:
                    _require_digest(evidence_digest, "evidence_digest")
                else:
                    evidence_digest = "sha256:" + "00" * 32
                self._tst_counter += 1
                test_id = f"tst-{self._tst_counter}"
                if test_id in self._tests:
                    raise TrojanError(f"test id collision: {test_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "test_id": test_id,
                        "target_id": target_id,
                        "test_kind": test_kind,
                        "outcome": outcome,
                        "evidence_digest": evidence_digest,
                    }
                )
                record = TestRecord(
                    test_id=test_id,
                    target_id=target_id,
                    test_kind=test_kind,
                    outcome=outcome,
                    evidence_digest=evidence_digest,
                    digest=digest,
                )
                self._tests[test_id] = record
                self._target_tests[target_id].append(test_id)
                self._emit(
                    "test-recorded", seq, test_id=test_id,
                    target_id=target_id, test_kind=test_kind,
                    outcome=outcome,
                )
                return record
            except TrojanError:
                self._burn(seq, "test")
                raise

    # -- detect --------------------------------------------------------------

    def detect(
        self,
        target_id: str,
        test_id: str,
        seq: int,
        detector: str = "neural-cleanse",
        verdict: str = "clean",
        evidence_digest: str = "",
    ) -> DetectionRecord:
        """Book one declared detection verdict over a booked test.

        The verdict is data, never proof. Fail-closed: requires the target
        to be registered (and live) and the referenced test to be booked
        against that target.
        """
        with self._lock:
            try:
                self._claim(seq)
            except TrojanError:
                raise
            try:
                self._live_target(target_id)
                test = self._tests.get(test_id)
                if test is None:
                    raise UnknownTestError(f"unknown test: {test_id!r}")
                if test.target_id != target_id:
                    raise DetectionStateError(
                        f"test {test_id!r} belongs to another target")
                if detector not in DETECTORS:
                    raise BadDetectorError(
                        f"detector must be one of {DETECTORS}")
                if verdict not in DETECTION_VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {DETECTION_VERDICTS}")
                if evidence_digest:
                    _require_digest(evidence_digest, "evidence_digest")
                else:
                    evidence_digest = "sha256:" + "00" * 32
                self._det_counter += 1
                detection_id = f"det-{self._det_counter}"
                if detection_id in self._detections:
                    raise TrojanError(
                        f"detection id collision: {detection_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "detection_id": detection_id,
                        "target_id": target_id,
                        "test_id": test_id,
                        "detector": detector,
                        "verdict": verdict,
                        "evidence_digest": evidence_digest,
                    }
                )
                record = DetectionRecord(
                    detection_id=detection_id,
                    target_id=target_id,
                    test_id=test_id,
                    detector=detector,
                    verdict=verdict,
                    evidence_digest=evidence_digest,
                    digest=digest,
                )
                self._detections[detection_id] = record
                self._target_detections[target_id].append(detection_id)
                self._emit(
                    "detection-recorded", seq, detection_id=detection_id,
                    target_id=target_id, test_id=test_id,
                    detector=detector, verdict=verdict,
                )
                return record
            except TrojanError:
                self._burn(seq, "detect")
                raise

    # -- mitigate ------------------------------------------------------------

    def mitigate(
        self,
        detection_id: str,
        seq: int,
        measure: str = "isolate",
        plan_digest: str = "",
    ) -> MitigationRecord:
        """Book one declared mitigation against an infected/suspect
        detection. Fail-closed: requires a booked detection with verdict
        ``infected`` or ``suspect`` that carries no mitigation yet. Books
        the *declaration*, never the execution.
        """
        with self._lock:
            try:
                self._claim(seq)
            except TrojanError:
                raise
            try:
                detection = self._detections.get(detection_id)
                if detection is None:
                    raise UnknownDetectionError(
                        f"unknown detection: {detection_id!r}")
                self._live_target(detection.target_id)
                if detection.verdict not in ("infected", "suspect"):
                    raise DetectionStateError(
                        f"verdict {detection.verdict!r} needs no mitigation")
                if detection_id in self._mitigation_of_detection:
                    raise AlreadyMitigatedError(
                        f"detection already mitigated: {detection_id!r}")
                if measure not in MEASURES:
                    raise BadMeasureError(
                        f"measure must be one of {MEASURES}")
                if plan_digest:
                    _require_digest(plan_digest, "plan_digest")
                else:
                    plan_digest = "sha256:" + "00" * 32
                self._mit_counter += 1
                mitigation_id = f"mit-{self._mit_counter}"
                if mitigation_id in self._mitigations:
                    raise TrojanError(
                        f"mitigation id collision: {mitigation_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "mitigation_id": mitigation_id,
                        "detection_id": detection_id,
                        "target_id": detection.target_id,
                        "measure": measure,
                        "plan_digest": plan_digest,
                    }
                )
                record = MitigationRecord(
                    mitigation_id=mitigation_id,
                    detection_id=detection_id,
                    target_id=detection.target_id,
                    measure=measure,
                    plan_digest=plan_digest,
                    digest=digest,
                )
                self._mitigations[mitigation_id] = record
                self._mitigation_of_detection[detection_id] = mitigation_id
                self._emit(
                    "mitigated", seq, mitigation_id=mitigation_id,
                    detection_id=detection_id,
                    target_id=detection.target_id, measure=measure,
                )
                return record
            except TrojanError:
                self._burn(seq, "mitigate")
                raise

    # -- retire (terminal) ---------------------------------------------------

    def retire(
        self, target_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal: retire a target id. Retired ids are never recycled."""
        with self._lock:
            try:
                self._claim(seq)
            except TrojanError:
                raise
            try:
                record = self._targets.get(target_id)
                if record is None:
                    raise UnknownTargetError(f"unknown target: {target_id!r}")
                if target_id in self._retired:
                    raise RetiredTargetError(
                        f"target already retired: {target_id!r}")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {RETIRE_REASONS}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "target_id": target_id,
                        "reason": reason,
                    }
                )
                retire_record = RetireRecord(
                    target_id=target_id, reason=reason, digest=digest
                )
                self._retired[target_id] = retire_record
                self._emit("retired", seq, target_id=target_id,
                           reason=reason)
                return retire_record
            except TrojanError:
                self._burn(seq, "retire")
                raise

    # -- status (pure read) --------------------------------------------------

    def status(self, target_id: str, seq: int) -> TargetStatus:
        """Pure read: test/detection tallies and posture as data."""
        with self._lock:
            self._view_seq_ok(seq)
            record = self._targets.get(target_id)
            if record is None:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            integrity_ok = record.verify()
            test_ids = self._target_tests.get(target_id, [])
            detection_ids = self._target_detections.get(target_id, [])
            tests = [self._tests[tid] for tid in test_ids]
            detections = [self._detections[did] for did in detection_ids]
            for rec in tests + detections:
                if not rec.verify():
                    integrity_ok = False
            latest_verdict = (
                detections[-1].verdict if detections else "unknown"
            )
            n_mitigations = sum(
                1 for did in detection_ids
                if did in self._mitigation_of_detection
            )
            retired = target_id in self._retired
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "target_id": target_id,
                    "n_tests": len(tests),
                    "n_detections": len(detections),
                    "latest_verdict": latest_verdict,
                    "n_mitigations": n_mitigations,
                    "retired": retired,
                    "integrity_ok": integrity_ok,
                }
            )
            return TargetStatus(
                target_id=target_id,
                n_tests=len(tests),
                n_detections=len(detections),
                latest_verdict=latest_verdict,
                n_mitigations=n_mitigations,
                retired=retired,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def target_record(self, target_id: str, seq: int) -> TargetRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._targets.get(target_id)
            if record is None:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            return record

    def test_record(self, test_id: str, seq: int) -> TestRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._tests.get(test_id)
            if record is None:
                raise UnknownTestError(f"unknown test: {test_id!r}")
            return record

    def detection_record(self, detection_id: str,
                         seq: int) -> DetectionRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._detections.get(detection_id)
            if record is None:
                raise UnknownDetectionError(
                    f"unknown detection: {detection_id!r}")
            return record

    def mitigation_record(self, mitigation_id: str,
                          seq: int) -> MitigationRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._mitigations.get(mitigation_id)
            if record is None:
                raise TrojanError(f"unknown mitigation: {mitigation_id!r}")
            return record

    def target_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._targets))

    def test_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._tests))

    def detection_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._detections))

    def tests_for(self, target_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if target_id not in self._targets:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            return tuple(self._target_tests.get(target_id, ()))

    def detections_for(self, target_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if target_id not in self._targets:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            return tuple(self._target_detections.get(target_id, ()))

    def mitigated_detection_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._mitigation_of_detection))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._retired))

    def is_retired(self, target_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq_ok(seq)
            return target_id in self._retired

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "targets": len(self._targets),
                "tests": len(self._tests),
                "detections": len(self._detections),
                "mitigations": len(self._mitigations),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }


def main() -> None:
    t = Trojan()
    rec = t.register_target("target-1", 1)
    test = t.test("target-1", 2, test_kind="trigger-probe",
                  outcome="triggered")
    det = t.detect("target-1", test.test_id, 3, detector="neural-cleanse",
                   verdict="infected")
    mit = t.mitigate(det.detection_id, 4, measure="isolate")
    rep = t.status("target-1", 0)
    assert rec.verify() and test.verify() and det.verify() and mit.verify()
    assert rep.verify() and rep.integrity_ok
    assert rep.n_tests == 1 and rep.n_detections == 1
    assert rep.latest_verdict == "infected" and rep.n_mitigations == 1
    assert not rep.retired
    print("trojan OK: register, test, detect, mitigate, status, pins, audit")


if __name__ == "__main__":
    main()
