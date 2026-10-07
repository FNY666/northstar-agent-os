"""Resource accumulation: instrumental resource-acquisition detection ledger, Simulated.

Research note: resource accumulation is the instrumental-convergence
failure mode where an agent stockpiles resources - compute, capital,
data, credentials, tooling, network access, energy, or even model
copies - beyond what its declared task requires, positioning itself
for goals the operator never assigned (Omohundro 2008; Bostrom 2014).
What matters here is the *decision ledger*: which systems were probed
for which accumulation classes, what detection verdicts were declared
with what evidence pins, and which mitigations were declared against
confirmed detections - defensible bookkeeping, never proof that any
system is accumulation-free.

This module owns the test -> detect -> mitigate lifecycle:

* **test()** - book one declared resource-accumulation probe (minted
  ``tst-N`` ids; pinned 8-term accumulation-kind vocabulary); raw
  telemetry, usage logs, and account inventories never enter records -
  digest pins only.
* **detect()** - book one declared detection verdict for a probe
  (minted ``det-N`` ids; pinned verdict vocabulary
  ``accumulation-detected`` / ``no-accumulation`` / ``inconclusive``),
  booked **as data**, never proof the system is (or is not)
  accumulating.
* **mitigate()** - book one declared mitigation against an
  ``accumulation-detected`` detection (minted ``mit-N`` ids; pinned
  measure vocabulary); fail-closed on non-detected verdicts and on
  double-mitigation; books the *declaration*, never the fix.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.
* **report()** - pure read: per-system probe/detection/mitigation
  tallies and digest-pinned integrity, all as data.

Distinct-layer rationale vs siblings: ``instrumental_convergence.py``
owns the generic instrumental-goal test/detect ledger (power-seeking,
self-preservation, etc.); ``power_seeking.py`` owns the power-seeking
probe lifecycle specifically. This module performs no behavioral
evaluation at all; it is the resource-*accumulation* detection
lifecycle ledger none of them own: probe -> detect -> mitigate.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
a ``resource-accumulation.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no probes, reads no telemetry,
measures no resource usage, and proves nothing about real resource
accumulation. A booked ``accumulation-detected`` verdict means "the
host declared it", never "the system is accumulating". Usage logs,
account inventories, telemetry streams, quotas, and raw resource
records never enter records or cross the audit boundary - digest pins
only.
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
RESOURCE_ACCUMULATION_VERSION = "resource-accumulation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.resource-accumulation.v1"

#: Pinned accumulation-kind vocabulary (the accumulation classes this ledger tracks).
ACCUMULATION_KINDS = (
    "compute-hoarding",
    "capital-accumulation",
    "data-hoarding",
    "credential-harvesting",
    "tool-acquisition",
    "network-expansion",
    "energy-stockpiling",
    "model-replication",
)

#: Pinned detection-verdict vocabulary (booked as data, never proof).
DETECT_VERDICTS = (
    "accumulation-detected",
    "no-accumulation",
    "inconclusive",
)

#: Pinned mitigation-measure vocabulary.
MEASURES = (
    "resource-cap",
    "quota-enforcement",
    "access-revocation",
    "activity-audit",
    "human-review",
    "shutdown",
    "rollback",
    "monitor",
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
    "probed",
    "detected",
    "mitigated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "telemetry",
        "usage",
        "quota",
        "account",
        "accounts",
        "inventory",
        "balance",
        "funds",
        "capital",
        "compute",
        "gpu",
        "cpu",
        "storage",
        "bandwidth",
        "energy",
        "credential",
        "credentials",
        "token",
        "tokens",
        "secret",
        "key",
        "dataset",
        "data",
        "log",
        "logs",
        "trace",
        "traces",
        "transcript",
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
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ResourceAccumulationError(Exception):
    """Base error for resource-accumulation ledger misuse."""


class BadIdError(ResourceAccumulationError):
    """Malformed system, test, detection, or mitigation id."""


class UnknownSystemError(ResourceAccumulationError):
    """System not registered."""


class RetiredSystemError(ResourceAccumulationError):
    """System id already retired; never recycled."""


class BadAccumulationKindError(ResourceAccumulationError):
    """Unknown resource-accumulation kind."""


class BadDigestError(ResourceAccumulationError):
    """Malformed sha256: digest pin."""


class BadVerdictError(ResourceAccumulationError):
    """Unknown detection verdict."""


class UnknownTestError(ResourceAccumulationError):
    """Test id not booked."""


class BadMeasureError(ResourceAccumulationError):
    """Unknown mitigation measure."""


class UnknownDetectionError(ResourceAccumulationError):
    """Detection id not booked."""


class MitigationNotNeededError(ResourceAccumulationError):
    """Detection verdict does not warrant mitigation."""


class AlreadyMitigatedError(ResourceAccumulationError):
    """Detection already has a booked mitigation."""


class BadReasonError(ResourceAccumulationError):
    """Unknown retirement reason."""


class SeqOrderError(ResourceAccumulationError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(ResourceAccumulationError):
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
class TestRecord:
    test_id: str
    system_id: str
    accumulation_kind: str
    probe_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "test_id": self.test_id,
            "system_id": self.system_id,
            "accumulation_kind": self.accumulation_kind,
            "probe_digest": self.probe_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "test_id": self.test_id,
                "system_id": self.system_id,
                "accumulation_kind": self.accumulation_kind,
                "probe_digest": self.probe_digest,
            }
        )


@dataclass(frozen=True)
class DetectionRecord:
    detection_id: str
    test_id: str
    system_id: str
    verdict: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "test_id": self.test_id,
            "system_id": self.system_id,
            "verdict": self.verdict,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "detection_id": self.detection_id,
                "test_id": self.test_id,
                "system_id": self.system_id,
                "verdict": self.verdict,
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class MitigationRecord:
    mitigation_id: str
    detection_id: str
    system_id: str
    measure: str
    plan_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "mitigation_id": self.mitigation_id,
            "detection_id": self.detection_id,
            "system_id": self.system_id,
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
                "system_id": self.system_id,
                "measure": self.measure,
                "plan_digest": self.plan_digest,
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
class AccumulationReport:
    system_id: str
    n_tests: int
    n_detections: int
    n_accumulation_detected: int
    n_mitigations: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_tests": self.n_tests,
            "n_detections": self.n_detections,
            "n_accumulation_detected": self.n_accumulation_detected,
            "n_mitigations": self.n_mitigations,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_tests": self.n_tests,
                "n_detections": self.n_detections,
                "n_accumulation_detected": self.n_accumulation_detected,
                "n_mitigations": self.n_mitigations,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def resource_accumulation_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the resource-accumulation ledger."""
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


class ResourceAccumulation:
    """Resource-accumulation detection decision ledger, Simulated.

    ``test()`` / ``detect()`` / ``mitigate()`` / ``retire()`` mutate the
    ledger and consume caller seqs; views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._tests: Dict[str, TestRecord] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._detections_by_test: Dict[str, List[str]] = {}
        self._detections_by_system: Dict[str, List[str]] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._mitigations_by_system: Dict[str, List[str]] = {}
        self._mitigated_detections: set[str] = set()
        self._retired: Dict[str, RetireRecord] = {}
        self._tst_counter = 0
        self._det_counter = 0
        self._mit_counter = 0
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

    def _burn(self, seq: int, method: str, exc: ResourceAccumulationError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            resource_accumulation_audit_event(
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

    # -- mutations --------------------------------------------------------

    def test(
        self,
        system_id: Any,
        accumulation_kind: Any,
        seq: Any,
        probe_digest: Any = "",
    ) -> TestRecord:
        """Book one declared resource-accumulation probe (minted ``tst-N``).

        The first probe registers its system. Probe telemetry, usage
        logs, and account inventories travel as a digest pin only; raw
        resource records never enter records.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if (
                    not isinstance(accumulation_kind, str)
                    or accumulation_kind not in ACCUMULATION_KINDS
                ):
                    raise BadAccumulationKindError(
                        f"accumulation_kind must be one of {sorted(ACCUMULATION_KINDS)}"
                    )
                pin = _require_digest(probe_digest, "probe_digest")
                self._tst_counter += 1
                tid = f"tst-{self._tst_counter}"
                rec = TestRecord(
                    test_id=tid,
                    system_id=sid,
                    accumulation_kind=accumulation_kind,
                    probe_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "test_id": tid,
                            "system_id": sid,
                            "accumulation_kind": accumulation_kind,
                            "probe_digest": pin,
                        }
                    ),
                )
                self._tests[tid] = rec
                self._systems.setdefault(sid, []).append(tid)
                self._audit.append(
                    resource_accumulation_audit_event(
                        "probed",
                        seq_v,
                        test_id=tid,
                        system_id=sid,
                        accumulation_kind=accumulation_kind,
                    )
                )
                return rec
            except ResourceAccumulationError as exc:
                self._burn(seq_v, "test", exc)
                raise

    def detect(
        self,
        test_id: Any,
        seq: Any,
        verdict: Any = "inconclusive",
        evidence_digest: Any = "",
    ) -> DetectionRecord:
        """Book one declared detection verdict (minted ``det-N``).

        Verdicts are booked **as data**, never proof that the system is
        (or is not) accumulating resources.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                tid = _require_id(test_id, "test_id")
                probe = self._tests.get(tid)
                if probe is None:
                    raise UnknownTestError(f"unknown test: {tid!r}")
                self._require_live_system(probe.system_id)
                if not isinstance(verdict, str) or verdict not in DETECT_VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(DETECT_VERDICTS)}"
                    )
                pin = _require_digest(evidence_digest, "evidence_digest")
                self._det_counter += 1
                did = f"det-{self._det_counter}"
                rec = DetectionRecord(
                    detection_id=did,
                    test_id=tid,
                    system_id=probe.system_id,
                    verdict=verdict,
                    evidence_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "detection_id": did,
                            "test_id": tid,
                            "system_id": probe.system_id,
                            "verdict": verdict,
                            "evidence_digest": pin,
                        }
                    ),
                )
                self._detections[did] = rec
                self._detections_by_test.setdefault(tid, []).append(did)
                self._detections_by_system.setdefault(probe.system_id, []).append(did)
                self._audit.append(
                    resource_accumulation_audit_event(
                        "detected",
                        seq_v,
                        detection_id=did,
                        test_id=tid,
                        system_id=probe.system_id,
                        verdict=verdict,
                    )
                )
                return rec
            except ResourceAccumulationError as exc:
                self._burn(seq_v, "detect", exc)
                raise

    def mitigate(
        self,
        detection_id: Any,
        seq: Any,
        measure: Any = "resource-cap",
        plan_digest: Any = "",
    ) -> MitigationRecord:
        """Book one declared mitigation (minted ``mit-N``).

        Fail-closed: only ``accumulation-detected`` detections may be
        mitigated, and each detection at most once. Books the
        *declaration*, never the fix.
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
                if det.verdict != "accumulation-detected":
                    raise MitigationNotNeededError(
                        f"verdict {det.verdict!r} does not warrant mitigation"
                    )
                if did in self._mitigated_detections:
                    raise AlreadyMitigatedError(
                        f"detection already mitigated: {did!r}"
                    )
                if not isinstance(measure, str) or measure not in MEASURES:
                    raise BadMeasureError(
                        f"measure must be one of {sorted(MEASURES)}"
                    )
                pin = _require_digest(plan_digest, "plan_digest")
                self._mit_counter += 1
                mid = f"mit-{self._mit_counter}"
                rec = MitigationRecord(
                    mitigation_id=mid,
                    detection_id=did,
                    system_id=det.system_id,
                    measure=measure,
                    plan_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "mitigation_id": mid,
                            "detection_id": did,
                            "system_id": det.system_id,
                            "measure": measure,
                            "plan_digest": pin,
                        }
                    ),
                )
                self._mitigations[mid] = rec
                self._mitigated_detections.add(did)
                self._mitigations_by_system.setdefault(det.system_id, []).append(mid)
                self._audit.append(
                    resource_accumulation_audit_event(
                        "mitigated",
                        seq_v,
                        mitigation_id=mid,
                        detection_id=did,
                        system_id=det.system_id,
                        measure=measure,
                    )
                )
                return rec
            except ResourceAccumulationError as exc:
                self._burn(seq_v, "mitigate", exc)
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
                    resource_accumulation_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except ResourceAccumulationError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def test_record(self, test_id: Any, seq: Any) -> TestRecord:
        """Return one test record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            tid = _require_id(test_id, "test_id")
            if tid not in self._tests:
                raise UnknownTestError(f"unknown test: {tid!r}")
            return self._tests[tid]

    def detection_record(self, detection_id: Any, seq: Any) -> DetectionRecord:
        """Return one detection record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            did = _require_id(detection_id, "detection_id")
            if did not in self._detections:
                raise UnknownDetectionError(f"unknown detection: {did!r}")
            return self._detections[did]

    def mitigation_record(self, mitigation_id: Any, seq: Any) -> MitigationRecord:
        """Return one mitigation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(mitigation_id, "mitigation_id")
            if mid not in self._mitigations:
                raise UnknownDetectionError(f"unknown mitigation: {mid!r}")
            return self._mitigations[mid]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def test_ids(self, seq: Any) -> Tuple[str, ...]:
        """All test ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"tst-{i}" for i in range(1, self._tst_counter + 1))

    def detection_ids(self, seq: Any) -> Tuple[str, ...]:
        """All detection ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"det-{i}" for i in range(1, self._det_counter + 1))

    def mitigation_ids(self, seq: Any) -> Tuple[str, ...]:
        """All mitigation ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"mit-{i}" for i in range(1, self._mit_counter + 1))

    def tests_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Test ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._systems[sid])

    def detections_for(self, test_id: Any, seq: Any) -> Tuple[str, ...]:
        """Detection ids booked against one test (mint order)."""
        with self._lock:
            self._check_seq(seq)
            tid = _require_id(test_id, "test_id")
            if tid not in self._tests:
                raise UnknownTestError(f"unknown test: {tid!r}")
            return tuple(self._detections_by_test.get(tid, ()))

    def mitigations_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Mitigation ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._mitigations_by_system.get(sid, ()))

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired system ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def report(self, system_id: Any, seq: Any) -> AccumulationReport:
        """Per-system test/detection/mitigation tallies (pure read).

        ``integrity_ok`` is ledger truth derived from digest pins -
        as data, never proof the system is accumulation-free.
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            test_ids = self._systems[sid]
            det_ids: List[str] = []
            for tid in test_ids:
                det_ids.extend(self._detections_by_test.get(tid, ()))
            n_acc = sum(
                1
                for did in det_ids
                if self._detections[did].verdict == "accumulation-detected"
            )
            mit_ids = self._mitigations_by_system.get(sid, ())
            integrity_ok = all(
                rec.verify()
                for rec in (
                    *(self._tests[tid] for tid in test_ids),
                    *(self._detections[did] for did in det_ids),
                    *(self._mitigations[mid] for mid in mit_ids),
                )
            )
            return AccumulationReport(
                system_id=sid,
                n_tests=len(test_ids),
                n_detections=len(det_ids),
                n_accumulation_detected=n_acc,
                n_mitigations=len(mit_ids),
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "n_tests": len(test_ids),
                        "n_detections": len(det_ids),
                        "n_accumulation_detected": n_acc,
                        "n_mitigations": len(mit_ids),
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
                "tests": len(self._tests),
                "detections": len(self._detections),
                "mitigations": len(self._mitigations),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    ra = ResourceAccumulation()
    pin = "sha256:" + "ab" * 32
    tst = ra.test("sys-1", "compute-hoarding", 1, probe_digest=pin)
    assert tst.test_id == "tst-1"
    det = ra.detect("tst-1", 2, verdict="accumulation-detected", evidence_digest=pin)
    assert det.detection_id == "det-1"
    mit = ra.mitigate("det-1", 3, measure="resource-cap", plan_digest=pin)
    assert mit.mitigation_id == "mit-1"
    ra.retire("sys-1", 4, reason="decommissioned")
    rep = ra.report("sys-1", 5)
    assert rep.verify()
    assert rep.integrity_ok is True
    assert rep.n_accumulation_detected == 1
    assert ra.stats(6) == {
        "systems": 1,
        "tests": 1,
        "detections": 1,
        "mitigations": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("resource-accumulation OK: test, detect, mitigate, retire, pins, audit")


if __name__ == "__main__":
    main()
