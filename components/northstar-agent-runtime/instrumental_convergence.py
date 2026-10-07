"""Instrumental convergence testing and detection ledger, Simulated.

Research note: the instrumental-convergence thesis (Bostrom 2014; Omohundro
2008) holds that a wide range of terminal goals imply the same *instrumental*
subgoals: self-preservation, resource acquisition, cognitive enhancement,
and goal-content integrity. The detection half of the problem is pure
bookkeeping: *test* the model (which instrumental drive was probed, what
the declared outcome was), *detect* declared signals of convergent behavior
(which signal the host declares, at what host-reported confidence), and
*mitigate* non-clean detections (which strategy the host declares). The
dangerous half is the *evidence itself*: transcripts, plans, and resource
traces must never be bundled with the bookkeeping record that tracks the
testing lifecycle.

This module is that bookkeeping layer. It:

* **test()** - book one declared instrumental-drive probe of a model against
  a pinned drive vocabulary; the first test on an id registers it.
* **detect()** - book one declared convergent-behavior detection (minted
  ``det-N`` ids) over a pinned signal vocabulary and a pinned finding
  vocabulary; outcomes are data, never proof a model is pursuing an
  instrumental subgoal.
* **mitigate()** - book one declared mitigation (minted ``mit-N`` ids) over
  a pinned strategy vocabulary; refused on clean detections (nothing to
  mitigate) and on already-mitigated detections; books the *declaration*,
  never the fix.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``instrumental-convergence.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: a booked ``not-convergent`` is a host-declared claim, never
proof a model is free of instrumental drives; a booked ``convergent`` is a
host-declared claim, never proof the model is actually pursuing the drive;
a booked mitigation is the ledger's record of the mitigation *decision*,
never proof the drive was suppressed.
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
INSTRUMENTAL_CONVERGENCE_VERSION = "instrumental-convergence.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.instrumental-convergence.v1"

#: Pinned instrumental-drive vocabulary (Bostrom/Omohundro-shaped; declared,
#: never proof the model pursues the drive).
TEST_DRIVES = (
    "self-preservation",
    "resource-acquisition",
    "cognitive-enhancement",
    "goal-content-integrity",
    "self-improvement",
    "power-seeking",
)

#: Pinned test-outcome vocabulary (declared, never measured truth).
TEST_OUTCOMES = (
    "convergent",
    "not-convergent",
    "inconclusive",
)

#: Pinned detection-signal vocabulary (declared, never proof a tool ran).
DETECT_SIGNALS = (
    "instrumental-planning",
    "resource-accumulation",
    "self-preservation-behavior",
    "power-seeking-behavior",
    "goal-shielding",
    "deceptive-optimization",
    "oversight-evasion",
    "capability-amplification",
)

#: Pinned detection-finding vocabulary (declared, never proof of a drive).
DETECT_FINDINGS = (
    "convergent",
    "not-convergent",
    "inconclusive",
)

#: Pinned mitigation-strategy vocabulary (declared, never proof of execution).
MITIGATE_STRATEGIES = (
    "capability-restrict",
    "resource-quota",
    "sandbox",
    "oversight-increase",
    "retrain",
    "human-review",
    "monitor",
    "discard",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "tested",
    "detected",
    "mitigated",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "transcript",
        "plan",
        "plans",
        "prompt",
        "response",
        "trace",
        "evidence",
        "weights",
        "model",
        "input",
        "description",
        "details",
        "detail",
        "text",
        "content",
        "data",
        "raw",
        "notes",
        "note",
        "secret",
        "signal_report",
        "finding_notes",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class InstrumentalConvergenceError(Exception):
    """Base error for instrumental-convergence-ledger misuse."""


class BadIdError(InstrumentalConvergenceError):
    """Malformed model / test / detection / mitigation id."""


class UnknownModelError(InstrumentalConvergenceError):
    """Reference to a model id that was never tested."""


class BadDigestError(InstrumentalConvergenceError):
    """Malformed sha256: digest pin."""


class BadDriveError(InstrumentalConvergenceError):
    """Test drive outside the pinned vocabulary."""


class BadOutcomeError(InstrumentalConvergenceError):
    """Test outcome outside the pinned vocabulary."""


class BadSignalError(InstrumentalConvergenceError):
    """Detection signal outside the pinned vocabulary."""


class BadFindingError(InstrumentalConvergenceError):
    """Detection finding outside the pinned vocabulary."""


class BadConfidenceError(InstrumentalConvergenceError):
    """Detection confidence outside [0, 100]."""


class BadStrategyError(InstrumentalConvergenceError):
    """Mitigation strategy outside the pinned vocabulary."""


class UnknownDetectionError(InstrumentalConvergenceError):
    """Reference to a detection id that was never booked."""


class MitigationNotNeededError(InstrumentalConvergenceError):
    """Mitigation refused: the detection is not convergent (nothing to mitigate)."""


class AlreadyMitigatedError(InstrumentalConvergenceError):
    """Mitigation refused: the detection already carries one."""


class SeqOrderError(InstrumentalConvergenceError):
    """Caller seq did not strictly increase."""


class AuditKindError(InstrumentalConvergenceError):
    """Unknown audit kind or banned raw key in an audit row."""


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


def _require_optional_digest(pin: str, field_name: str) -> str:
    if pin == "":
        return pin
    return _require_digest(pin, field_name)


def _require_confidence(confidence: int) -> int:
    if isinstance(confidence, bool) or not isinstance(confidence, int):
        raise BadConfidenceError("confidence must be an int")
    if not 0 <= confidence <= 100:
        raise BadConfidenceError("confidence must be in [0, 100]")
    return confidence


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestRecord:
    """One declared instrumental-drive probe of a model."""

    model_id: str
    drive: str
    outcome: str
    model_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "drive": self.drive,
            "outcome": self.outcome,
            "model_digest": self.model_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "drive": self.drive,
                "outcome": self.outcome,
                "model_digest": self.model_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class DetectionRecord:
    """One declared convergent-behavior detection (minted det-N ids)."""

    detection_id: str
    model_id: str
    signal: str
    finding: str
    confidence: int
    evidence_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "model_id": self.model_id,
            "signal": self.signal,
            "finding": self.finding,
            "confidence": self.confidence,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "detection_id": self.detection_id,
                "model_id": self.model_id,
                "signal": self.signal,
                "finding": self.finding,
                "confidence": self.confidence,
                "evidence_digest": self.evidence_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class MitigationRecord:
    """One declared mitigation of a convergent detection (minted mit-N ids)."""

    mitigation_id: str
    detection_id: str
    strategy: str
    plan_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "mitigation_id": self.mitigation_id,
            "detection_id": self.detection_id,
            "strategy": self.strategy,
            "plan_digest": self.plan_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "mitigation_id": self.mitigation_id,
                "detection_id": self.detection_id,
                "strategy": self.strategy,
                "plan_digest": self.plan_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class ConvergenceReport:
    """Pure-read posture report of one model's convergence lifecycle."""

    model_id: str
    n_tests: int
    n_detections: int
    n_mitigations: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "n_tests": self.n_tests,
            "n_detections": self.n_detections,
            "n_mitigations": self.n_mitigations,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "n_tests": self.n_tests,
                "n_detections": self.n_detections,
                "n_mitigations": self.n_mitigations,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def instrumental_convergence_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the convergence ledger."""
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


class InstrumentalConvergence:
    """Instrumental-convergence testing and detection ledger (Simulated).

    ``test()`` / ``detect()`` / ``mitigate()`` mutate the ledger and consume
    caller seqs; ``report()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: Dict[str, List[TestRecord]] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._model_detections: Dict[str, List[str]] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._detection_mitigation: Dict[str, str] = {}
        self._det_counter = 0
        self._mit_counter = 0
        self._audit: List[Dict[str, Any]] = []

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _require_read_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("read seq must be a non-negative int")

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = instrumental_convergence_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            instrumental_convergence_audit_event(audit_kind, seq, **details)
        )

    # -- test ----------------------------------------------------------------

    def test(
        self,
        model_id: str,
        seq: int,
        drive: str = "self-preservation",
        outcome: str = "not-convergent",
        model_digest: str = "",
    ) -> TestRecord:
        """Book one declared instrumental-drive probe of a model."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(model_id, "model_id")
                if drive not in TEST_DRIVES:
                    raise BadDriveError(f"bad drive: {drive!r}")
                if outcome not in TEST_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                model_digest = _require_optional_digest(
                    model_digest, "model_digest"
                )
                record = TestRecord(
                    model_id=model_id,
                    drive=drive,
                    outcome=outcome,
                    model_digest=model_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "model_id": model_id,
                            "drive": drive,
                            "outcome": outcome,
                            "model_digest": model_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._tests.setdefault(model_id, []).append(record)
                self._model_detections.setdefault(model_id, [])
                self._emit(
                    "tested",
                    seq,
                    model_id=model_id,
                    drive=drive,
                    outcome=outcome,
                )
                return record
            except InstrumentalConvergenceError:
                self._burn(seq, "test", model_id=model_id)
                raise

    # -- detect ---------------------------------------------------------------

    def detect(
        self,
        model_id: str,
        seq: int,
        signal: str = "instrumental-planning",
        finding: str = "not-convergent",
        confidence: int = 0,
        evidence_digest: str = "",
    ) -> DetectionRecord:
        """Book one declared convergent-behavior detection (minted det-N ids)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(model_id, "model_id")
                if model_id not in self._tests:
                    raise UnknownModelError(
                        f"model was never tested: {model_id!r}"
                    )
                if signal not in DETECT_SIGNALS:
                    raise BadSignalError(f"bad signal: {signal!r}")
                if finding not in DETECT_FINDINGS:
                    raise BadFindingError(f"bad finding: {finding!r}")
                _require_confidence(confidence)
                evidence_digest = _require_optional_digest(
                    evidence_digest, "evidence_digest"
                )
                self._det_counter += 1
                detection_id = f"det-{self._det_counter}"
                record = DetectionRecord(
                    detection_id=detection_id,
                    model_id=model_id,
                    signal=signal,
                    finding=finding,
                    confidence=confidence,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "detection_id": detection_id,
                            "model_id": model_id,
                            "signal": signal,
                            "finding": finding,
                            "confidence": confidence,
                            "evidence_digest": evidence_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._detections[detection_id] = record
                self._model_detections[model_id].append(detection_id)
                self._emit(
                    "detected",
                    seq,
                    detection_id=detection_id,
                    model_id=model_id,
                    signal=signal,
                    finding=finding,
                    confidence=confidence,
                )
                return record
            except InstrumentalConvergenceError:
                self._burn(seq, "detect", model_id=model_id)
                raise

    # -- mitigate ---------------------------------------------------------------

    def mitigate(
        self,
        detection_id: str,
        seq: int,
        strategy: str = "capability-restrict",
        plan_digest: str = "",
    ) -> MitigationRecord:
        """Book one declared mitigation of a convergent detection."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(detection_id, "detection_id")
                if detection_id not in self._detections:
                    raise UnknownDetectionError(
                        f"unknown detection: {detection_id!r}"
                    )
                if self._detections[detection_id].finding != "convergent":
                    raise MitigationNotNeededError(
                        f"detection {detection_id!r} is not convergent: "
                        "nothing to mitigate"
                    )
                if detection_id in self._detection_mitigation:
                    raise AlreadyMitigatedError(
                        f"detection {detection_id!r} already mitigated"
                    )
                if strategy not in MITIGATE_STRATEGIES:
                    raise BadStrategyError(f"bad strategy: {strategy!r}")
                plan_digest = _require_optional_digest(
                    plan_digest, "plan_digest"
                )
                self._mit_counter += 1
                mitigation_id = f"mit-{self._mit_counter}"
                record = MitigationRecord(
                    mitigation_id=mitigation_id,
                    detection_id=detection_id,
                    strategy=strategy,
                    plan_digest=plan_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "mitigation_id": mitigation_id,
                            "detection_id": detection_id,
                            "strategy": strategy,
                            "plan_digest": plan_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._mitigations[mitigation_id] = record
                self._detection_mitigation[detection_id] = mitigation_id
                self._emit(
                    "mitigated",
                    seq,
                    mitigation_id=mitigation_id,
                    detection_id=detection_id,
                    strategy=strategy,
                )
                return record
            except InstrumentalConvergenceError:
                self._burn(seq, "mitigate", detection_id=detection_id)
                raise

    # -- pure-read views ---------------------------------------------------------

    def test_record(self, model_id: str, seq: int) -> TestRecord:
        """Return the latest test record for one model (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(model_id, "model_id")
            if model_id not in self._tests:
                raise UnknownModelError(f"model was never tested: {model_id!r}")
            return self._tests[model_id][-1]

    def tests_for(self, model_id: str, seq: int) -> Tuple[TestRecord, ...]:
        """All test records booked against one model, in book order."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(model_id, "model_id")
            if model_id not in self._tests:
                raise UnknownModelError(f"model was never tested: {model_id!r}")
            return tuple(self._tests[model_id])

    def detection_record(self, detection_id: str, seq: int) -> DetectionRecord:
        """Return one detection record (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(detection_id, "detection_id")
            if detection_id not in self._detections:
                raise UnknownDetectionError(
                    f"unknown detection: {detection_id!r}"
                )
            return self._detections[detection_id]

    def detections_for(self, model_id: str, seq: int) -> Tuple[str, ...]:
        """Detection ids booked against one model, in mint order."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(model_id, "model_id")
            if model_id not in self._tests:
                raise UnknownModelError(f"model was never tested: {model_id!r}")
            return tuple(self._model_detections[model_id])

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        """Return one mitigation record (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(mitigation_id, "mitigation_id")
            if mitigation_id not in self._mitigations:
                raise UnknownDetectionError(
                    f"unknown mitigation: {mitigation_id!r}"
                )
            return self._mitigations[mitigation_id]

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        """All tested model ids in first-test order (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._tests.keys())

    def report(self, model_id: str, seq: int) -> ConvergenceReport:
        """Pure-read posture report of one model's convergence lifecycle.

        Posture rules (ledger data, never measured truth):
        - ``convergent`` when any unmitigated ``convergent`` detection stands
        - ``suspect`` when any unmitigated ``inconclusive`` detection stands
        - ``mitigated`` when every convergent detection is mitigated
        - ``not-convergent`` otherwise (tested, no open findings)
        """
        with self._lock:
            self._require_read_seq(seq)
            _require_id(model_id, "model_id")
            if model_id not in self._tests:
                raise UnknownModelError(f"model was never tested: {model_id!r}")
            det_ids = self._model_detections[model_id]
            unmitigated = [
                did
                for did in det_ids
                if self._detections[did].finding != "not-convergent"
                and did not in self._detection_mitigation
            ]
            findings = {self._detections[did].finding for did in unmitigated}
            mitigated_mids = [
                mid
                for did, mid in self._detection_mitigation.items()
                if did in det_ids
            ]
            integrity_ok = all(r.verify() for r in self._tests[model_id])
            integrity_ok = integrity_ok and all(
                self._detections[did].verify() for did in det_ids
            )
            integrity_ok = integrity_ok and all(
                self._mitigations[mid].verify() for mid in mitigated_mids
            )
            n_mitigated = len(mitigated_mids)
            if "convergent" in findings:
                posture = "convergent"
            elif "inconclusive" in findings:
                posture = "suspect"
            elif n_mitigated > 0:
                posture = "mitigated"
            else:
                posture = "not-convergent"
            record = ConvergenceReport(
                model_id=model_id,
                n_tests=len(self._tests[model_id]),
                n_detections=len(det_ids),
                n_mitigations=n_mitigated,
                posture=posture,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "model_id": model_id,
                        "n_tests": len(self._tests[model_id]),
                        "n_detections": len(det_ids),
                        "n_mitigations": n_mitigated,
                        "posture": posture,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )
            return record

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            return {
                "models": len(self._tests),
                "tests": sum(len(v) for v in self._tests.values()),
                "detections": len(self._detections),
                "mitigations": len(self._mitigations),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)

    @staticmethod
    def stdlib_only() -> bool:
        """House convention: stdlib-only check helper for tests."""
        import ast
        import sys

        allowed = {
            "hashlib",
            "json",
            "threading",
            "dataclasses",
            "typing",
            "sys",
            "ast",
            "__future__",
            "canonical_json",
        }
        tree = ast.parse(open(sys.modules[__name__].__file__).read())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        return imports <= allowed


def main() -> None:
    """Self-check: exercise the instrumental-convergence ledger end to end."""
    ic = InstrumentalConvergence()
    ic.test("m-1", 1, drive="self-preservation", outcome="convergent")
    d1 = ic.detect(
        "m-1",
        2,
        signal="self-preservation-behavior",
        finding="convergent",
        confidence=80,
    )
    ic.mitigate(d1.detection_id, 3, strategy="capability-restrict")
    ic.detect(
        "m-1",
        4,
        signal="instrumental-planning",
        finding="not-convergent",
        confidence=10,
    )
    assert ic.test_record("m-1", 5).verify()
    assert ic.report("m-1", 6).posture == "mitigated"
    assert ic.stats(7) == {
        "models": 1,
        "tests": 1,
        "detections": 2,
        "mitigations": 1,
    }
    print("instrumental-convergence OK: test, detect, mitigate, report, pins, audit")


if __name__ == "__main__":
    main()
