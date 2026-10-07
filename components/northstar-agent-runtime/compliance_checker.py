"""compliance_checker.py — SOC2 control verification bookkeeping.

SOC2 trust-service-criteria-shaped control checks as a deterministic
single-host state machine. A control is *defined* with required evidence
types; host-reported evidence is then checked against the definition and
a report is produced. Simulated: the ledger books reported claims, it
cannot observe the audited system and cannot prove a control is truly
satisfied (the GIGO boundary shared with every other bookkeeping module
in this repo).
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Tuple

VERSION = "compliance-checker.v1"
SCHEMA = "northstar.compliance-checker.v1"
AUDIT_KINDS = (
    "control-defined",
    "evidence-attached",
    "checked",
    "report-generated",
    "rejected",
)


class ComplianceError(Exception):
    """Base for all compliance_checker errors."""


class UnknownControlError(ComplianceError):
    pass


class DuplicateControlError(ComplianceError):
    pass


class BadEvidenceError(ComplianceError):
    pass


class CheckError(ComplianceError):
    pass


# ---------------------------------------------------------------------------
# Canonical encoding (type-tagged; same caveats as the rest of the batch line)
# ---------------------------------------------------------------------------

_MAX_ABS_INT = 2 ** 53


def _canonical(value: Any) -> str:
    if value is None:
        return "n"
    if isinstance(value, bool):
        return "b:1" if value else "b:0"
    if isinstance(value, int):
        if abs(value) > _MAX_ABS_INT:
            raise BadEvidenceError("int magnitude exceeds 2**53")
        return "i:%d" % value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise BadEvidenceError("NaN/inf refused")
        if value.is_integer() and abs(value) > _MAX_ABS_INT:
            raise BadEvidenceError("integral float magnitude exceeds 2**53")
        return "f:%r" % value
    if isinstance(value, str):
        return "s:%s" % json.dumps(value, ensure_ascii=True)
    if isinstance(value, (bytes, bytearray)):
        raise BadEvidenceError("bytes not canonicalizable")
    if isinstance(value, Mapping):
        items = []
        for k in sorted(value.keys(), key=lambda x: (str(type(x)), str(x))):
            if not isinstance(k, str):
                raise BadEvidenceError("non-str mapping key refused")
            items.append(_canonical(k) + "=>" + _canonical(value[k]))
        return "m:{" + ",".join(items) + "}"
    if isinstance(value, (list, tuple)):
        return "l:[" + ",".join(_canonical(v) for v in value) + "]"
    raise BadEvidenceError("non-canonicalizable evidence type: %r" % type(value).__name__)


def _digest(*parts: str) -> str:
    return "sha256:" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ComplianceError("seq must be a non-negative int")
    return seq


def _check_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ComplianceError("%s must be a non-empty str" % name)
    return value


def _check_mapping(name: str, value: Any) -> Mapping:
    if not isinstance(value, Mapping):
        raise ComplianceError("%s must be a mapping" % name)
    return value


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ControlRecord:
    control_id: str
    framework: str
    description: str
    required_evidence: Tuple[str, ...]
    digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "framework": self.framework,
            "description": self.description,
            "required_evidence": list(self.required_evidence),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    control_id: str
    kind: str
    payload_digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "control_id": self.control_id,
            "kind": self.kind,
            "payload_digest": self.payload_digest,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class CheckResult:
    control_id: str
    verdict: str  # "pass" | "fail"
    missing: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]
    digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "verdict": self.verdict,
            "missing": list(self.missing),
            "evidence_ids": list(self.evidence_ids),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class ComplianceReport:
    report_id: str
    checked: int
    passed: int
    failed: int
    controls: Tuple[str, ...]
    results_digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "checked": self.checked,
            "passed": self.passed,
            "failed": self.failed,
            "controls": list(self.controls),
            "results_digest": self.results_digest,
            "seq": self.seq,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

class ComplianceChecker:
    """SOC2 control verification bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._controls: dict[str, ControlRecord] = {}
        self._evidence: dict[str, EvidenceRecord] = {}
        self._checks: dict[str, CheckResult] = {}
        self._evidence_count = 0
        self._report_count = 0
        self._last_seq = -1

    def _monotonic(self, seq: int) -> None:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise ComplianceError("seq must strictly increase (last=%d)" % self._last_seq)
        self._last_seq = seq

    def define_control(
        self,
        control_id: str,
        framework: str,
        description: str,
        required_evidence: Tuple[str, ...],
        seq: int,
    ) -> ControlRecord:
        with self._lock:
            control_id = _check_str("control_id", control_id)
            framework = _check_str("framework", framework)
            description = _check_str("description", description)
            if (not isinstance(required_evidence, (list, tuple)) or not required_evidence
                    or any(not isinstance(k, str) or not k for k in required_evidence)
                    or len(set(required_evidence)) != len(tuple(required_evidence))):
                raise ComplianceError(
                    "required_evidence must be a non-empty tuple of unique non-empty strs")
            required = tuple(required_evidence)
            if control_id in self._controls:
                raise DuplicateControlError("control %r already defined" % control_id)
            self._monotonic(seq)
            digest = _digest("control", control_id, framework, description,
                             ",".join(required), str(seq))
            record = ControlRecord(
                control_id=control_id, framework=framework,
                description=description, required_evidence=required,
                digest=digest, seq=seq)
            self._controls[control_id] = record
            return record

    def attach_evidence(
        self, control_id: str, kind: str, payload: Mapping, seq: int
    ) -> EvidenceRecord:
        with self._lock:
            control_id = _check_str("control_id", control_id)
            kind = _check_str("kind", kind)
            payload = _check_mapping("payload", payload)
            if control_id not in self._controls:
                raise UnknownControlError("unknown control %r" % control_id)
            self._monotonic(seq)
            payload_digest = _digest("payload", _canonical(payload))
            self._evidence_count += 1
            evidence_id = "ev-%d" % self._evidence_count
            record = EvidenceRecord(
                evidence_id=evidence_id, control_id=control_id, kind=kind,
                payload_digest=payload_digest, seq=seq)
            self._evidence[evidence_id] = record
            return record

    def check(self, control_id: str, seq: int) -> CheckResult:
        """Evaluate a control against attached evidence.

        Verdict is "pass" iff evidence of every required kind is attached.
        The verdict books reported evidence — never ground truth.
        """
        with self._lock:
            control_id = _check_str("control_id", control_id)
            if control_id not in self._controls:
                raise UnknownControlError("unknown control %r" % control_id)
            self._monotonic(seq)
            required = self._controls[control_id].required_evidence
            attached = sorted(
                {rec.kind for rec in self._evidence.values()
                 if rec.control_id == control_id})
            missing = tuple(k for k in required if k not in attached)
            evidence_ids = tuple(
                sorted(rec.evidence_id for rec in self._evidence.values()
                       if rec.control_id == control_id))
            verdict = "pass" if not missing else "fail"
            digest = _digest("check", control_id, verdict,
                             ",".join(missing), ",".join(evidence_ids), str(seq))
            result = CheckResult(
                control_id=control_id, verdict=verdict, missing=missing,
                evidence_ids=evidence_ids, digest=digest, seq=seq)
            self._checks[control_id] = result
            return result

    def evidence(self, control_id: str | None = None) -> Tuple[EvidenceRecord, ...]:
        with self._lock:
            if control_id is None:
                return tuple(sorted(self._evidence.values(),
                                    key=lambda r: r.evidence_id))
            control_id = _check_str("control_id", control_id)
            if control_id not in self._controls:
                raise UnknownControlError("unknown control %r" % control_id)
            return tuple(sorted(
                (r for r in self._evidence.values() if r.control_id == control_id),
                key=lambda r: r.evidence_id))

    def report(self, seq: int) -> ComplianceReport:
        with self._lock:
            self._monotonic(seq)
            controls = tuple(sorted(self._controls))
            checked = len(self._checks)
            passed = sum(1 for r in self._checks.values() if r.verdict == "pass")
            failed = checked - passed
            results_digest = _digest(
                "report",
                ",".join(sorted(r.control_id + ":" + r.verdict
                                for r in self._checks.values())),
                str(seq))
            self._report_count += 1
            return ComplianceReport(
                report_id="report-%d" % self._report_count,
                checked=checked, passed=passed, failed=failed,
                controls=controls, results_digest=results_digest, seq=seq)

    def controls(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._controls))

    def control(self, control_id: str) -> ControlRecord:
        with self._lock:
            control_id = _check_str("control_id", control_id)
            if control_id not in self._controls:
                raise UnknownControlError("unknown control %r" % control_id)
            return self._controls[control_id]


def compliance_checker_audit_event(
    kind: str, seq: int, control_id: str = "", detail: str = ""
) -> dict:
    if kind not in AUDIT_KINDS:
        raise ComplianceError("unknown audit kind %r" % kind)
    _check_seq(seq)
    return {
        "schema": SCHEMA,
        "kind": kind,
        "control_id": control_id,
        "detail": detail,
        "seq": seq,
    }


def main() -> None:
    cc = ComplianceChecker()
    cc.define_control("CC6.1", "SOC2", "logical access security",
                      ("access-review", "policy-doc"), 0)
    ev = cc.attach_evidence("CC6.1", "access-review",
                            {"reviewer": "sec-team", "quarter": "Q3"}, 1)
    assert ev.evidence_id == "ev-1"
    result = cc.check("CC6.1", 2)
    assert result.verdict == "fail" and result.missing == ("policy-doc",)
    cc.attach_evidence("CC6.1", "policy-doc", {"version": "3"}, 3)
    result = cc.check("CC6.1", 4)
    assert result.verdict == "pass" and result.missing == ()
    rep = cc.report(5)
    assert rep.checked == 1 and rep.passed == 1 and rep.failed == 0
    try:
        cc.define_control("CC6.1", "SOC2", "dup", ("x",), 6)
    except DuplicateControlError:
        pass
    else:
        raise AssertionError("duplicate control accepted")
    try:
        cc.attach_evidence("NOPE", "x", {}, 7)
    except UnknownControlError:
        pass
    else:
        raise AssertionError("unknown control accepted")
    print("compliance-checker OK: define, attach, check, report, refusals")


if __name__ == "__main__":
    main()
