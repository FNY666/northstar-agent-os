"""Compliance reports: SOC 2 / ISO 27001 report, evidence, and attestation bookkeeping.

A ``ComplianceReports`` ledger books host-reported audit posture as a
deterministic single-host state machine:

- ``define_framework(framework_id, seq, controls=())`` pins an audit
  framework and its control vocabulary. Known frameworks ship with a
  pinned control catalog (SOC 2 Type I/II trust-services criteria,
  ISO/IEC 27001 Annex A theme groups); unknown framework ids are
  booked as custom with caller-supplied control ids.
- ``evidence(control_id, seq, artifact_digest, collected_by="")`` books
  an evidence artifact against a control. Only the artifact's
  ``sha256:`` digest enters the ledger — the artifact content itself
  never does.
- ``attest(control_id, seq, verdict, attester="")`` books an auditor
  attestation over a control with a pinned verdict vocabulary.
- ``generate(framework_id, seq, period_label="")`` emits a frozen
  ``ComplianceReport`` aggregating per-control evidence and
  attestations into coverage counts, deficiency listings, and a
  ``sha256:`` report pin with ``verify()`` re-derivation.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``compliance-reports.v1``, schema pin
``northstar.compliance-reports.v1``, ``main()`` self-check.

Honest scope: this module books *reported* audit posture. It cannot
observe the audited system, cannot prove a control is actually
operating effectively, and cannot inspect evidence artifacts (it holds
digests only). A "clean" report means "the host reported attestations
of operating-effectiveness for every in-scope control", never "the
system is compliant". Fail-closed rules keep the ledger honest:
unknown frameworks/controls, duplicate evidence pins on the same
control, and attestations against controls without evidence are all
refused. Pair with ``sbom_generator``/``transparency_log`` for artifact
integrity claims and with real auditor fieldwork for actual assurance.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
COMPLIANCE_REPORTS_VERSION = "compliance-reports.v1"

#: Schema pin carried by records and audit events.
COMPLIANCE_REPORTS_SCHEMA = "northstar.compliance-reports.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

# ---------------------------------------------------------------------------
# Pinned vocabularies
# ---------------------------------------------------------------------------

#: Pinned framework vocabulary. Each known framework ships a pinned
#: control-id catalog; anything else is booked as a custom framework
#: with caller-supplied control ids.
FRAMEWORKS: Dict[str, Tuple[str, ...]] = {
    "soc2-type1": (
        "CC1.1", "CC1.2", "CC1.3", "CC1.4", "CC1.5",
        "CC2.1", "CC2.2", "CC2.3",
        "CC3.1", "CC3.2", "CC3.3", "CC3.4",
        "CC4.1", "CC4.2",
        "CC5.1", "CC5.2", "CC5.3",
        "CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.5", "CC6.6", "CC6.7",
        "CC7.1", "CC7.2", "CC7.3", "CC7.4",
        "CC8.1",
        "CC9.1", "CC9.2",
    ),
    "soc2-type2": (
        "CC1.1", "CC1.2", "CC1.3", "CC1.4", "CC1.5",
        "CC2.1", "CC2.2", "CC2.3",
        "CC3.1", "CC3.2", "CC3.3", "CC3.4",
        "CC4.1", "CC4.2",
        "CC5.1", "CC5.2", "CC5.3",
        "CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.5", "CC6.6", "CC6.7",
        "CC7.1", "CC7.2", "CC7.3", "CC7.4",
        "CC8.1",
        "CC9.1", "CC9.2",
    ),
    "iso27001": (
        "A.5.1", "A.5.2", "A.5.3",
        "A.6.1", "A.6.2", "A.6.3", "A.6.4", "A.6.5", "A.6.6", "A.6.7",
        "A.7.1", "A.7.2", "A.7.3", "A.7.4", "A.7.5",
        "A.8.1", "A.8.2", "A.8.3", "A.8.4", "A.8.5", "A.8.6",
        "A.8.7", "A.8.8", "A.8.9", "A.8.10", "A.8.11", "A.8.12",
        "A.8.13", "A.8.14", "A.8.15",
    ),
    "iso27701": (
        "PIMS.6.1", "PIMS.6.2", "PIMS.6.3",
        "PIMS.7.1", "PIMS.7.2", "PIMS.7.3", "PIMS.7.4", "PIMS.7.5",
        "PIMS.8.1", "PIMS.8.2", "PIMS.8.3", "PIMS.8.4", "PIMS.8.5",
    ),
}

#: Pinned attestation-verdict vocabulary.
VERDICTS = (
    "operating-effectively",
    "deficient",
    "not-applicable",
    "not-tested",
)

#: Audit event kinds.
KIND_FRAMEWORK_DEFINED = "framework-defined"
KIND_EVIDENCE_BOOKED = "evidence-booked"
KIND_ATTESTED = "attested"
KIND_REPORT_GENERATED = "report-generated"
KIND_REJECTED = "rejected"
_KINDS = (
    KIND_FRAMEWORK_DEFINED,
    KIND_EVIDENCE_BOOKED,
    KIND_ATTESTED,
    KIND_REPORT_GENERATED,
    KIND_REJECTED,
)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ComplianceReportsError(Exception):
    """Base error for the compliance-reports module."""


class BadFrameworkError(ComplianceReportsError):
    """Framework id or control catalog malformed."""


class DuplicateFrameworkError(ComplianceReportsError):
    """Framework id already defined."""


class UnknownFrameworkError(ComplianceReportsError):
    """No framework with this id."""


class UnknownControlError(ComplianceReportsError):
    """No control with this id under the framework."""


class BadEvidenceError(ComplianceReportsError):
    """Evidence artifact reference malformed or duplicated."""


class BadAttestationError(ComplianceReportsError):
    """Attestation input malformed or fails precondition."""


class SeqOrderError(ComplianceReportsError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(seq: int, name: str = "seq") -> None:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ComplianceReportsError(f"{name} must be a non-empty string")
    if len(value) > 256:
        raise ComplianceReportsError(f"{name} exceeds 256 chars")
    return value.strip()


def _pin(*parts: Any) -> str:
    """Stable ``sha256:`` pin over a type-tagged canonical payload."""
    tagged = [f"{type(p).__name__}:{p}" for p in parts]
    return "sha256:" + hashlib.sha256(
        jcs_canonical_json({"t": tagged})
    ).hexdigest()


def _check_digest(digest: Any, name: str = "artifact_digest") -> str:
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise BadEvidenceError(f"{name} must be 'sha256:' + 64 hex chars")
    hexpart = digest[len("sha256:"):]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadEvidenceError(f"{name} must be 'sha256:' + 64 hex chars")
    return digest


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FrameworkRecord:
    framework_id: str
    controls: Tuple[str, ...]
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            COMPLIANCE_REPORTS_VERSION, "framework", self.framework_id,
            sorted(self.controls),
        )


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    framework_id: str
    control_id: str
    artifact_digest: str
    collected_by: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            COMPLIANCE_REPORTS_VERSION, "evidence", self.evidence_id,
            self.framework_id, self.control_id, self.artifact_digest,
            self.collected_by, self.seq,
        )


@dataclass(frozen=True)
class AttestationRecord:
    attestation_id: str
    framework_id: str
    control_id: str
    verdict: str
    attester: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            COMPLIANCE_REPORTS_VERSION, "attestation", self.attestation_id,
            self.framework_id, self.control_id, self.verdict,
            self.attester, self.seq,
        )


@dataclass(frozen=True)
class ControlStatus:
    control_id: str
    evidence_count: int
    attestation_count: int
    latest_verdict: Optional[str]


@dataclass(frozen=True)
class ComplianceReport:
    report_id: str
    framework_id: str
    period_label: str
    controls_total: int
    controls_with_evidence: int
    controls_attested: int
    verdict_counts: Tuple[Tuple[str, int], ...]
    deficiencies: Tuple[str, ...]
    statuses: Tuple[ControlStatus, ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            COMPLIANCE_REPORTS_VERSION, "report", self.report_id,
            self.framework_id, self.period_label, self.controls_total,
            self.controls_with_evidence, self.controls_attested,
            sorted(self.verdict_counts), sorted(self.deficiencies),
            self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def compliance_reports_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the compliance-reports module."""
    if kind not in _KINDS:
        raise ComplianceReportsError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise ComplianceReportsError("detail must be a mapping")
    # Evidence artifact content never crosses the audit boundary; pins only.
    banned = {"evidence_content", "artifact_bytes", "artifact_text"}
    if any(k in detail for k in banned):
        raise ComplianceReportsError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": COMPLIANCE_REPORTS_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class ComplianceReports:
    """Deterministic compliance-report / evidence / attestation ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._frameworks: Dict[str, FrameworkRecord] = {}
        self._evidence: Dict[str, EvidenceRecord] = {}
        self._attestations: Dict[str, AttestationRecord] = {}
        self._reports: Dict[str, ComplianceReport] = {}
        self._evidence_seq = 0
        self._attestation_seq = 0
        self._report_seq = 0
        self._audit_log: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _audit_locked(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit_log.append(
            compliance_reports_audit_event(kind, detail, self._last_seq)
        )

    def _reject_locked(self, reason: str) -> None:
        self._audit_locked(KIND_REJECTED, {"reason": reason})

    def _framework_locked(self, framework_id: str) -> FrameworkRecord:
        try:
            return self._frameworks[framework_id]
        except KeyError:
            raise UnknownFrameworkError(f"unknown framework: {framework_id!r}")

    # -- frameworks -----------------------------------------------------

    def define_framework(
        self,
        framework_id: str,
        seq: int,
        controls: Tuple[str, ...] = (),
    ) -> FrameworkRecord:
        """Pin a framework id with its control catalog."""
        with self._lock:
            self._claim_seq(seq)
            fid = _check_id(framework_id, "framework_id").lower()
            if fid in self._frameworks:
                self._reject_locked(f"duplicate framework: {fid!r}")
                raise DuplicateFrameworkError(
                    f"framework already defined: {fid!r}"
                )
            if fid in FRAMEWORKS:
                catalog = tuple(FRAMEWORKS[fid])
                if controls:
                    self._reject_locked("controls not allowed for known framework")
                    raise BadFrameworkError(
                        "known frameworks pin their own control catalog; "
                        "leave controls empty"
                    )
            else:
                if not controls:
                    self._reject_locked("custom framework needs controls")
                    raise BadFrameworkError(
                        "custom framework requires a non-empty controls tuple"
                    )
                cleaned = tuple(_check_id(c, "control id") for c in controls)
                if len(set(cleaned)) != len(cleaned):
                    self._reject_locked("duplicate control ids")
                    raise BadFrameworkError("duplicate control ids")
                catalog = cleaned
            record = FrameworkRecord(
                framework_id=fid,
                controls=catalog,
                digest=_pin(
                    COMPLIANCE_REPORTS_VERSION, "framework", fid,
                    sorted(catalog),
                ),
            )
            self._frameworks[fid] = record
            self._audit_locked(
                KIND_FRAMEWORK_DEFINED,
                {"framework_id": fid, "controls": len(catalog),
                 "digest": record.digest},
            )
            return record

    # -- evidence -------------------------------------------------------

    def evidence(
        self,
        framework_id: str,
        control_id: str,
        artifact_digest: str,
        seq: int,
        collected_by: str = "",
    ) -> EvidenceRecord:
        """Book an evidence artifact digest against a control."""
        with self._lock:
            self._claim_seq(seq)
            fw = self._framework_locked(_check_id(framework_id, "framework_id").lower())
            cid = _check_id(control_id, "control_id")
            if cid not in fw.controls:
                self._reject_locked(f"unknown control: {cid!r}")
                raise UnknownControlError(
                    f"control {cid!r} not in framework {fw.framework_id!r}"
                )
            digest = _check_digest(artifact_digest)
            by = collected_by.strip() if isinstance(collected_by, str) else ""
            for existing in self._evidence.values():
                if (existing.framework_id == fw.framework_id
                        and existing.control_id == cid
                        and existing.artifact_digest == digest):
                    self._reject_locked("duplicate evidence digest")
                    raise BadEvidenceError(
                        "evidence artifact already booked for this control"
                    )
            self._evidence_seq += 1
            evidence_id = f"ev-{self._evidence_seq}"
            record = EvidenceRecord(
                evidence_id=evidence_id,
                framework_id=fw.framework_id,
                control_id=cid,
                artifact_digest=digest,
                collected_by=by,
                seq=seq,
                digest=_pin(
                    COMPLIANCE_REPORTS_VERSION, "evidence", evidence_id,
                    fw.framework_id, cid, digest, by, seq,
                ),
            )
            self._evidence[evidence_id] = record
            self._audit_locked(
                KIND_EVIDENCE_BOOKED,
                {"evidence_id": evidence_id, "framework_id": fw.framework_id,
                 "control_id": cid, "artifact_digest": digest,
                 "digest": record.digest},
            )
            return record

    # -- attestations ---------------------------------------------------

    def attest(
        self,
        framework_id: str,
        control_id: str,
        verdict: str,
        seq: int,
        attester: str = "",
    ) -> AttestationRecord:
        """Book an auditor attestation over a control."""
        with self._lock:
            self._claim_seq(seq)
            fw = self._framework_locked(_check_id(framework_id, "framework_id").lower())
            cid = _check_id(control_id, "control_id")
            if cid not in fw.controls:
                self._reject_locked(f"unknown control: {cid!r}")
                raise UnknownControlError(
                    f"control {cid!r} not in framework {fw.framework_id!r}"
                )
            if verdict not in VERDICTS:
                self._reject_locked(f"unknown verdict: {verdict!r}")
                raise BadAttestationError(
                    f"verdict must be one of {VERDICTS}"
                )
            if verdict != "not-applicable" and verdict != "not-tested":
                has_evidence = any(
                    e.framework_id == fw.framework_id and e.control_id == cid
                    for e in self._evidence.values()
                )
                if not has_evidence:
                    self._reject_locked("attestation without evidence")
                    raise BadAttestationError(
                        "attestation requires booked evidence for the control "
                        "(use not-tested or not-applicable otherwise)"
                    )
            who = attester.strip() if isinstance(attester, str) else ""
            self._attestation_seq += 1
            attestation_id = f"att-{self._attestation_seq}"
            record = AttestationRecord(
                attestation_id=attestation_id,
                framework_id=fw.framework_id,
                control_id=cid,
                verdict=verdict,
                attester=who,
                seq=seq,
                digest=_pin(
                    COMPLIANCE_REPORTS_VERSION, "attestation", attestation_id,
                    fw.framework_id, cid, verdict, who, seq,
                ),
            )
            self._attestations[attestation_id] = record
            self._audit_locked(
                KIND_ATTESTED,
                {"attestation_id": attestation_id,
                 "framework_id": fw.framework_id, "control_id": cid,
                 "verdict": verdict, "digest": record.digest},
            )
            return record

    # -- report ---------------------------------------------------------

    def generate(
        self,
        framework_id: str,
        seq: int,
        period_label: str = "",
    ) -> ComplianceReport:
        """Emit a frozen compliance report aggregating the ledger."""
        with self._lock:
            self._claim_seq(seq)
            fw = self._framework_locked(_check_id(framework_id, "framework_id").lower())
            label = period_label.strip() if isinstance(period_label, str) else ""
            statuses: List[ControlStatus] = []
            verdict_counts: Dict[str, int] = {v: 0 for v in VERDICTS}
            deficiencies: List[str] = []
            for cid in fw.controls:
                ev = sum(
                    1 for e in self._evidence.values()
                    if e.framework_id == fw.framework_id and e.control_id == cid
                )
                atts = sorted(
                    (a for a in self._attestations.values()
                     if a.framework_id == fw.framework_id and a.control_id == cid),
                    key=lambda a: a.seq,
                )
                latest = atts[-1].verdict if atts else None
                if latest is not None:
                    verdict_counts[latest] += 1
                    if latest == "deficient":
                        deficiencies.append(cid)
                statuses.append(ControlStatus(
                    control_id=cid,
                    evidence_count=ev,
                    attestation_count=len(atts),
                    latest_verdict=latest,
                ))
            self._report_seq += 1
            report_id = f"rep-{self._report_seq}"
            counts = tuple(sorted(verdict_counts.items()))
            with_evidence = sum(1 for s in statuses if s.evidence_count > 0)
            attested = sum(1 for s in statuses if s.attestation_count > 0)
            record = ComplianceReport(
                report_id=report_id,
                framework_id=fw.framework_id,
                period_label=label,
                controls_total=len(fw.controls),
                controls_with_evidence=with_evidence,
                controls_attested=attested,
                verdict_counts=counts,
                deficiencies=tuple(sorted(deficiencies)),
                statuses=tuple(statuses),
                seq=seq,
                digest=_pin(
                    COMPLIANCE_REPORTS_VERSION, "report", report_id,
                    fw.framework_id, label, len(fw.controls), with_evidence,
                    attested, sorted(counts), sorted(deficiencies), seq,
                ),
            )
            self._reports[report_id] = record
            self._audit_locked(
                KIND_REPORT_GENERATED,
                {"report_id": report_id, "framework_id": fw.framework_id,
                 "period_label": label,
                 "controls_total": record.controls_total,
                 "deficiencies": len(record.deficiencies),
                 "digest": record.digest},
            )
            return record

    # -- views ----------------------------------------------------------

    def framework(self, framework_id: str) -> FrameworkRecord:
        with self._lock:
            return self._framework_locked(_check_id(framework_id, "framework_id").lower())

    def framework_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._frameworks)

    def evidence_for(self, framework_id: str, control_id: str) -> List[EvidenceRecord]:
        with self._lock:
            fw = self._framework_locked(_check_id(framework_id, "framework_id").lower())
            cid = _check_id(control_id, "control_id")
            return [e for e in self._evidence.values()
                    if e.framework_id == fw.framework_id and e.control_id == cid]

    def attestations_for(self, framework_id: str, control_id: str) -> List[AttestationRecord]:
        with self._lock:
            fw = self._framework_locked(_check_id(framework_id, "framework_id").lower())
            cid = _check_id(control_id, "control_id")
            return [a for a in self._attestations.values()
                    if a.framework_id == fw.framework_id and a.control_id == cid]

    def report(self, report_id: str) -> ComplianceReport:
        with self._lock:
            try:
                return self._reports[_check_id(report_id, "report_id")]
            except KeyError:
                raise ComplianceReportsError(f"unknown report: {report_id!r}")

    def report_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._reports)

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit_log)

    def as_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "schema": COMPLIANCE_REPORTS_SCHEMA,
                "frameworks": sorted(self._frameworks),
                "evidence": len(self._evidence),
                "attestations": len(self._attestations),
                "reports": sorted(self._reports),
            }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    cr = ComplianceReports()
    cr.define_framework("soc2-type2", 1)
    digest = "sha256:" + "ab" * 32
    cr.evidence("soc2-type2", "CC1.1", digest, 2, collected_by="auditor-a")
    cr.attest("soc2-type2", "CC1.1", "operating-effectively", 3, attester="auditor-a")
    rep = cr.generate("soc2-type2", 4, period_label="FY2026-Q1")
    assert rep.verify()
    assert rep.controls_with_evidence == 1
    print("compliance-reports OK: define, evidence, attest, generate, pins")


if __name__ == "__main__":
    main()
