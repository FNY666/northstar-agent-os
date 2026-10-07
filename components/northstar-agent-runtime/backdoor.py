"""Backdoor testing and detection ledger, Simulated.

Research note: trojan/backdoor defences for ML artifacts (input triggers,
weight trojans, supply-chain implants, prompt triggers) follow the same
bookkeeping funnel as every other safety gate: *test* the artifact (what kind
of backdoor was probed, what the declared outcome was), *detect* a finding
with a declared technique (what technique ran, what the verdict was), and
*mitigate* a non-clean detection (what strategy the host declares). The
dangerous half of a backdoor finding is the *trigger itself*: the payload,
the weight delta, the poisoned sample, the trigger phrase must never be
bundled with the bookkeeping record that tracks the testing lifecycle.

This module is that bookkeeping layer. It:

* **test()** - book one declared backdoor probe of an artifact against a
  pinned trigger-kind vocabulary; the first test on an id registers it.
* **detect()** - book one declared detection (minted ``det-N`` ids) over a
  pinned technique vocabulary and a pinned finding vocabulary; outcomes are
  data, never proof a backdoor exists (or does not).
* **mitigate()** - book one declared mitigation (minted ``mit-N`` ids) over a
  pinned strategy vocabulary; refused on clean detections (nothing to
  mitigate) and on already-mitigated detections; books the *declaration*,
  never the fix.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``backdoor.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked ``clean`` is a host-declared claim, never proof an
artifact is backdoor-free; a booked ``confirmed`` is a host-declared claim,
never proof a backdoor exists; a booked mitigation is the ledger's record of
the mitigation *decision*, never proof the backdoor was removed.
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
BACKDOOR_VERSION = "backdoor.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.backdoor.v1"

#: Pinned trigger-kind vocabulary (declared, never proof a real trigger ran).
TEST_KINDS = (
    "input-trigger",
    "weight-trojan",
    "supply-chain",
    "prompt-trigger",
)

#: Pinned test-outcome vocabulary (declared, never measured truth).
TEST_OUTCOMES = (
    "clean",
    "suspect",
    "confirmed",
)

#: Pinned detection-technique vocabulary (declared, never proof a tool ran).
DETECT_TECHNIQUES = (
    "static-scan",
    "behavioral-fuzz",
    "weight-analysis",
    "red-team",
)

#: Pinned detection-finding vocabulary (declared, never proof of presence).
DETECT_FINDINGS = (
    "clean",
    "suspect",
    "confirmed",
)

#: Pinned mitigation-strategy vocabulary (declared, never proof of execution).
MITIGATE_STRATEGIES = (
    "remove",
    "retrain",
    "quarantine",
    "monitor",
    "accept",
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
        "trigger",
        "payload",
        "pattern",
        "sample",
        "evidence",
        "weights",
        "model",
        "input",
        "prompt",
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
        "backdoor",
        "technique_report",
        "finding_notes",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class BackdoorError(Exception):
    """Base error for backdoor-ledger misuse."""


class BadIdError(BackdoorError):
    """Malformed artifact / test / detection / mitigation id."""


class DuplicateArtifactError(BackdoorError):
    """An artifact id was registered twice."""


class UnknownArtifactError(BackdoorError):
    """Reference to an artifact id that was never tested."""


class BadDigestError(BackdoorError):
    """Malformed sha256: digest pin."""


class BadKindError(BackdoorError):
    """Test trigger kind outside the pinned vocabulary."""


class BadOutcomeError(BackdoorError):
    """Test outcome outside the pinned vocabulary."""


class BadTechniqueError(BackdoorError):
    """Detection technique outside the pinned vocabulary."""


class BadFindingError(BackdoorError):
    """Detection finding outside the pinned vocabulary."""


class BadStrategyError(BackdoorError):
    """Mitigation strategy outside the pinned vocabulary."""


class UnknownDetectionError(BackdoorError):
    """Reference to a detection id that was never booked."""


class MitigationNotNeededError(BackdoorError):
    """Mitigation refused: the detection is clean (nothing to mitigate)."""


class AlreadyMitigatedError(BackdoorError):
    """Mitigation refused: the detection already carries one."""


class SeqOrderError(BackdoorError):
    """Caller seq did not strictly increase."""


class AuditKindError(BackdoorError):
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


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestRecord:
    """One declared backdoor probe of an artifact."""

    artifact_id: str
    trigger_kind: str
    outcome: str
    artifact_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "artifact_id": self.artifact_id,
            "trigger_kind": self.trigger_kind,
            "outcome": self.outcome,
            "artifact_digest": self.artifact_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "artifact_id": self.artifact_id,
                "trigger_kind": self.trigger_kind,
                "outcome": self.outcome,
                "artifact_digest": self.artifact_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class DetectionRecord:
    """One declared backdoor detection (minted det-N ids)."""

    detection_id: str
    artifact_id: str
    technique: str
    finding: str
    evidence_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "detection_id": self.detection_id,
            "artifact_id": self.artifact_id,
            "technique": self.technique,
            "finding": self.finding,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "detection_id": self.detection_id,
                "artifact_id": self.artifact_id,
                "technique": self.technique,
                "finding": self.finding,
                "evidence_digest": self.evidence_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class MitigationRecord:
    """One declared mitigation of a non-clean detection (minted mit-N ids)."""

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
class ArtifactStatus:
    """Pure-read posture of one artifact's backdoor-testing lifecycle."""

    artifact_id: str
    n_tests: int
    n_detections: int
    n_mitigations: int
    posture: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "artifact_id": self.artifact_id,
            "n_tests": self.n_tests,
            "n_detections": self.n_detections,
            "n_mitigations": self.n_mitigations,
            "posture": self.posture,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "artifact_id": self.artifact_id,
                "n_tests": self.n_tests,
                "n_detections": self.n_detections,
                "n_mitigations": self.n_mitigations,
                "posture": self.posture,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def backdoor_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the backdoor ledger."""
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


class Backdoor:
    """Backdoor testing and detection ledger (Simulated).

    ``test()`` / ``detect()`` / ``mitigate()`` mutate the ledger and consume
    caller seqs; ``status()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tests: Dict[str, List[TestRecord]] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._artifact_detections: Dict[str, List[str]] = {}
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

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = backdoor_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(backdoor_audit_event(audit_kind, seq, **details))

    # -- test ----------------------------------------------------------------

    def test(
        self,
        artifact_id: str,
        seq: int,
        trigger_kind: str = "input-trigger",
        outcome: str = "clean",
        artifact_digest: str = "",
    ) -> TestRecord:
        """Book one declared backdoor probe of an artifact."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(artifact_id, "artifact_id")
                if trigger_kind not in TEST_KINDS:
                    raise BadKindError(f"bad trigger kind: {trigger_kind!r}")
                if outcome not in TEST_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                artifact_digest = _require_optional_digest(
                    artifact_digest, "artifact_digest"
                )
                record = TestRecord(
                    artifact_id=artifact_id,
                    trigger_kind=trigger_kind,
                    outcome=outcome,
                    artifact_digest=artifact_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "artifact_id": artifact_id,
                            "trigger_kind": trigger_kind,
                            "outcome": outcome,
                            "artifact_digest": artifact_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._tests.setdefault(artifact_id, []).append(record)
                self._artifact_detections.setdefault(artifact_id, [])
                self._emit(
                    "tested",
                    seq,
                    artifact_id=artifact_id,
                    trigger_kind=trigger_kind,
                    outcome=outcome,
                )
                return record
            except BackdoorError:
                self._burn(seq, "test", artifact_id=artifact_id)
                raise

    # -- detect ---------------------------------------------------------------

    def detect(
        self,
        artifact_id: str,
        seq: int,
        technique: str = "static-scan",
        finding: str = "clean",
        evidence_digest: str = "",
    ) -> DetectionRecord:
        """Book one declared backdoor detection (minted det-N ids)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(artifact_id, "artifact_id")
                if artifact_id not in self._tests:
                    raise UnknownArtifactError(
                        f"artifact was never tested: {artifact_id!r}"
                    )
                if technique not in DETECT_TECHNIQUES:
                    raise BadTechniqueError(f"bad technique: {technique!r}")
                if finding not in DETECT_FINDINGS:
                    raise BadFindingError(f"bad finding: {finding!r}")
                evidence_digest = _require_optional_digest(
                    evidence_digest, "evidence_digest"
                )
                self._det_counter += 1
                detection_id = f"det-{self._det_counter}"
                record = DetectionRecord(
                    detection_id=detection_id,
                    artifact_id=artifact_id,
                    technique=technique,
                    finding=finding,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "detection_id": detection_id,
                            "artifact_id": artifact_id,
                            "technique": technique,
                            "finding": finding,
                            "evidence_digest": evidence_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._detections[detection_id] = record
                self._artifact_detections[artifact_id].append(detection_id)
                self._emit(
                    "detected",
                    seq,
                    detection_id=detection_id,
                    artifact_id=artifact_id,
                    technique=technique,
                    finding=finding,
                )
                return record
            except BackdoorError:
                self._burn(seq, "detect", artifact_id=artifact_id)
                raise

    # -- mitigate ---------------------------------------------------------------

    def mitigate(
        self,
        detection_id: str,
        seq: int,
        strategy: str = "remove",
        plan_digest: str = "",
    ) -> MitigationRecord:
        """Book one declared mitigation of a non-clean detection."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(detection_id, "detection_id")
                if detection_id not in self._detections:
                    raise UnknownDetectionError(
                        f"unknown detection: {detection_id!r}"
                    )
                if self._detections[detection_id].finding == "clean":
                    raise MitigationNotNeededError(
                        f"detection {detection_id!r} is clean: nothing to mitigate"
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
            except BackdoorError:
                self._burn(seq, "mitigate", detection_id=detection_id)
                raise

    # -- pure-read views ---------------------------------------------------------

    def test_record(self, artifact_id: str, seq: int) -> TestRecord:
        """Return the latest test record for one artifact (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(artifact_id, "artifact_id")
            if artifact_id not in self._tests:
                raise UnknownArtifactError(
                    f"artifact was never tested: {artifact_id!r}"
                )
            return self._tests[artifact_id][-1]

    def tests_for(self, artifact_id: str, seq: int) -> Tuple[TestRecord, ...]:
        """All test records booked against one artifact, in book order."""
        with self._lock:
            self._check_seq(seq)
            _require_id(artifact_id, "artifact_id")
            if artifact_id not in self._tests:
                raise UnknownArtifactError(
                    f"artifact was never tested: {artifact_id!r}"
                )
            return tuple(self._tests[artifact_id])

    def detection_record(self, detection_id: str, seq: int) -> DetectionRecord:
        """Return one detection record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(detection_id, "detection_id")
            if detection_id not in self._detections:
                raise UnknownDetectionError(
                    f"unknown detection: {detection_id!r}"
                )
            return self._detections[detection_id]

    def detections_for(self, artifact_id: str, seq: int) -> Tuple[str, ...]:
        """Detection ids booked against one artifact, in mint order."""
        with self._lock:
            self._check_seq(seq)
            _require_id(artifact_id, "artifact_id")
            if artifact_id not in self._tests:
                raise UnknownArtifactError(
                    f"artifact was never tested: {artifact_id!r}"
                )
            return tuple(self._artifact_detections[artifact_id])

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        """Return one mitigation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(mitigation_id, "mitigation_id")
            if mitigation_id not in self._mitigations:
                raise UnknownDetectionError(
                    f"unknown mitigation: {mitigation_id!r}"
                )
            return self._mitigations[mitigation_id]

    def artifact_ids(self, seq: int) -> Tuple[str, ...]:
        """All tested artifact ids in first-test order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._tests.keys())

    def status(self, artifact_id: str, seq: int) -> ArtifactStatus:
        """Pure-read posture of one artifact's backdoor lifecycle, as data.

        Posture rules (ledger data, never measured truth):
        - ``confirmed`` when any unmitigated ``confirmed`` detection stands
        - ``suspect`` when any unmitigated ``suspect`` detection stands
        - ``mitigated`` when every non-clean detection is mitigated
        - ``clean`` otherwise (tested, no open findings)
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(artifact_id, "artifact_id")
            if artifact_id not in self._tests:
                raise UnknownArtifactError(
                    f"artifact was never tested: {artifact_id!r}"
                )
            det_ids = self._artifact_detections[artifact_id]
            unmitigated = [
                did
                for did in det_ids
                if self._detections[did].finding != "clean"
                and did not in self._detection_mitigation
            ]
            findings = {self._detections[did].finding for did in unmitigated}
            n_mitigated = sum(
                1 for did in det_ids if did in self._detection_mitigation
            )
            if "confirmed" in findings:
                posture = "confirmed"
            elif "suspect" in findings:
                posture = "suspect"
            elif n_mitigated > 0:
                posture = "mitigated"
            else:
                posture = "clean"
            record = ArtifactStatus(
                artifact_id=artifact_id,
                n_tests=len(self._tests[artifact_id]),
                n_detections=len(det_ids),
                n_mitigations=n_mitigated,
                posture=posture,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "artifact_id": artifact_id,
                        "n_tests": len(self._tests[artifact_id]),
                        "n_detections": len(det_ids),
                        "n_mitigations": n_mitigated,
                        "posture": posture,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return record

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "artifacts": len(self._tests),
                "tests": sum(len(v) for v in self._tests.values()),
                "detections": len(self._detections),
                "mitigations": len(self._mitigations),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the backdoor ledger end to end."""
    bd = Backdoor()
    bd.test("art-1", 1, trigger_kind="input-trigger", outcome="suspect")
    d1 = bd.detect("art-1", 2, technique="behavioral-fuzz", finding="suspect")
    bd.mitigate(d1.detection_id, 3, strategy="quarantine")
    bd.detect("art-1", 4, technique="static-scan", finding="clean")
    assert bd.test_record("art-1", 5).verify()
    assert bd.status("art-1", 6).posture == "mitigated"
    assert bd.stats(7) == {
        "artifacts": 1,
        "tests": 1,
        "detections": 2,
        "mitigations": 1,
    }
    print("backdoor OK: test, detect, mitigate, status, pins, audit")


if __name__ == "__main__":
    main()
