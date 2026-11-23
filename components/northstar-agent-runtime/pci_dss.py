"""PCI DSS compliance lifecycle decision ledger.

Distinct from siblings: ``compliance.py`` owns the generic
framework/check/remediate/attest ledger; ``grc.py`` owns the
multi-framework governance workflow; ``audit_management.py`` owns
audit engagements. This module is the *PCI DSS-specific* layer none
of them own - merchant-level declaration, assessments pinned to the
12 PCI DSS v4.0 requirements (including the ``in-place-with-ccw``
compensating-control finding status), declared remediation, and a
validation report that requires full requirement coverage as data.

* **Merchant levels** - ``register_merchant()`` declares one
  merchant under the pinned level vocabulary (``level-1`` /
  ``level-2`` / ``level-3`` / ``level-4``, by transaction volume);
  ids are never recycled.
* **Assessments** - ``assess()`` books one declared assessment
  (minted ``asm-N``) against a single pinned requirement
  (``req-01`` ... ``req-12``); finding pinned to ``compliant`` /
  ``non-compliant`` / ``in-place-with-ccw`` / ``not-applicable``;
  evidence travels as a ``sha256:`` digest pin only.
* **Remediations** - ``remediate()`` books one declared remediation
  decision (minted ``rem-N``) over the pinned action vocabulary
  (``patch`` / ``reconfigure`` / ``network-segmentation`` /
  ``encrypt`` / ...). Remediation is refused fail-closed when the
  assessment finding is ``compliant``, ``not-applicable`` or
  ``in-place-with-ccw`` (the finding is already addressed); it is
  repeatable as a remediation chain.
* **Validation** - ``validate()`` is a pure read view deriving a
  frozen ``ValidationReport`` from the ledger: assessment counts,
  distinct requirement coverage, finding tallies, remediated
  assessment ids, and ``validated`` as data. The ledger rule:
  validated iff every one of the 12 requirements is covered by at
  least one assessment and every ``non-compliant`` finding has a
  booked remediation - never proof of actual PCI DSS compliance.

The 12 pinned requirements (PCI DSS v4.0): req-01 network security
controls; req-02 secure configurations; req-03 stored account data
protection; req-04 strong cryptography in transit; req-05 malicious
software protection; req-06 secure systems and software; req-07
access restriction by business need; req-08 user identification and
authentication; req-09 physical access restriction; req-10 logging
and monitoring; req-11 regular security testing; req-12 infosec
policies and programs.

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``pci-dss.rejected``; rewinds raise bare), no wall-clock,
   RLock-guarded, fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``pci-dss.v1``; schema pin
   ``northstar.pci-dss.v1``.

Honest scope:
- This module books *declared* PCI DSS decisions - it performs no
  assessment, inspects no evidence, contacts no assessor, and
  validates nothing.
- A booked ``non-compliant`` means "the host declared a finding",
  never "the requirement failed". A booked remediation means "the
  host declared an action", never "the gap was closed". A
  ``validated`` report means the ledger's booked records satisfy the
  ledger rule, never that the merchant is PCI DSS compliant.
- Digest pins prove ledger integrity and ordering, never the truth
  of the declared decisions.
- No persistence: the ledger is in-memory.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


VERSION = "pci-dss.v1"
SCHEMA = "northstar.pci-dss.v1"

KIND_MERCHANT_REGISTERED = "merchant-registered"
KIND_ASSESSED = "assessed"
KIND_REMEDIATED = "remediated"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_MERCHANT_REGISTERED, KIND_ASSESSED, KIND_REMEDIATED,
    KIND_REJECTED,
})

_MERCHANT_LEVELS = ("level-1", "level-2", "level-3", "level-4")

# The 12 PCI DSS v4.0 requirements (see module docstring for titles).
_REQUIREMENTS = tuple(f"req-{i:02d}" for i in range(1, 13))

_FINDINGS = ("compliant", "non-compliant", "in-place-with-ccw",
             "not-applicable")

_SEVERITIES = ("low", "medium", "high", "critical")

_REMEDIATION_ACTIONS = ("patch", "reconfigure", "network-segmentation",
                        "encrypt", "rotate-keys", "access-review",
                        "log-review", "pen-test", "scan-remediate",
                        "policy-update", "vendor-fix", "accept-risk")

# Findings already addressed: nothing left to remediate.
_ADDRESSD_FINDINGS = ("compliant", "not-applicable", "in-place-with-ccw")

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw content must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset({
    "content", "text", "payload", "raw", "evidence", "description",
    "notes", "note", "message", "plan", "plan_text", "rationale",
    "scope_text", "finding_text", "title", "summary", "profile",
    "cardholder", "pan", "card",
})


class PCIDSSError(Exception):
    """Base class for all PCI DSS ledger errors."""


class BadIdError(PCIDSSError):
    """Malformed merchant id, scope id, or assessment id."""


class DuplicateMerchantError(PCIDSSError):
    """Merchant id already registered (ids are never recycled)."""


class UnknownMerchantError(PCIDSSError):
    """Merchant id not registered."""


class BadLevelError(PCIDSSError):
    """Merchant level not in the pinned vocabulary."""


class BadDigestError(PCIDSSError):
    """Digest is not a sha256:<64hex> pin (or empty)."""


class BadRequirementError(PCIDSSError):
    """Requirement not in the pinned req-01..req-12 vocabulary."""


class BadFindingError(PCIDSSError):
    """Finding not in the pinned vocabulary."""


class BadSeverityError(PCIDSSError):
    """Severity not in the pinned vocabulary."""


class UnknownAssessmentError(PCIDSSError):
    """Assessment id not booked."""


class BadRemediationError(PCIDSSError):
    """Remediation action not in the pinned vocabulary."""


class RemediationNotNeededError(PCIDSSError):
    """Remediation booked against an already-addressed finding."""


class SeqOrderError(PCIDSSError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(PCIDSSError):
    """Unknown audit kind, or banned key at the audit boundary."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str) -> str:
    """Validate a sha256:<64hex> digest pin (or empty string)."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{label} must be str, got {type(value).__name__}")
    if value and not _DIGEST_RE.match(value):
        raise BadDigestError(f"{label} must be sha256:<64hex> or empty")
    return value


def _digest_pin(payload: Any) -> str:
    """sha256: digest pin over canonical JSON of payload."""
    return "sha256:" + jcs_sha256_hex(payload)


def pci_dss_audit_event(kind: str, detail: Dict[str, object],
                        seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the PCI DSS ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "audit_version": "audit.ndjson/1",
        "schema": SCHEMA,
        "version": VERSION,
        "kind": "pci-dss." + kind,
        "detail": dict(detail),
        "seq": seq,
    }


def _record_digest(tag: str, fields: Dict[str, object]) -> str:
    return _digest_pin({"pci-dss": tag, **fields})


@dataclass(frozen=True)
class MerchantRecord:
    """One declared PCI DSS merchant registration."""

    merchant_id: str
    level: str
    profile_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "merchant_id": self.merchant_id,
            "level": self.level,
            "profile_pin": self.profile_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("merchant", {
            "merchant_id": self.merchant_id,
            "level": self.level,
            "profile_pin": self.profile_pin})


@dataclass(frozen=True)
class AssessmentRecord:
    """One declared PCI DSS assessment outcome (minted asm-N)."""

    assessment_id: str
    merchant_id: str
    requirement: str
    finding: str
    severity: str
    evidence_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "assessment_id": self.assessment_id,
            "merchant_id": self.merchant_id,
            "requirement": self.requirement,
            "finding": self.finding,
            "severity": self.severity,
            "evidence_pin": self.evidence_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("assessment", {
            "assessment_id": self.assessment_id,
            "merchant_id": self.merchant_id,
            "requirement": self.requirement,
            "finding": self.finding,
            "severity": self.severity,
            "evidence_pin": self.evidence_pin})


@dataclass(frozen=True)
class RemediationRecord:
    """One declared remediation decision (minted rem-N)."""

    remediation_id: str
    assessment_id: str
    action: str
    plan_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "remediation_id": self.remediation_id,
            "assessment_id": self.assessment_id,
            "action": self.action,
            "plan_pin": self.plan_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("remediation", {
            "remediation_id": self.remediation_id,
            "assessment_id": self.assessment_id,
            "action": self.action,
            "plan_pin": self.plan_pin})


@dataclass(frozen=True)
class ValidationReport:
    """A PCI DSS validation verdict derived from the ledger (pure data)."""

    merchant_id: str
    n_assessments: int
    requirements_covered: Tuple[str, ...]
    findings: Tuple[Tuple[str, int], ...]
    remediated_assessments: Tuple[str, ...]
    validated: bool
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "merchant_id": self.merchant_id,
            "n_assessments": self.n_assessments,
            "requirements_covered": list(self.requirements_covered),
            "findings": [
                {"finding": finding, "count": count}
                for finding, count in self.findings
            ],
            "remediated_assessments": list(self.remediated_assessments),
            "validated": self.validated,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("validation", {
            "merchant_id": self.merchant_id,
            "n_assessments": self.n_assessments,
            "requirements_covered": list(self.requirements_covered),
            "findings": [
                {"finding": finding, "count": count}
                for finding, count in self.findings
            ],
            "remediated_assessments": list(self.remediated_assessments),
            "validated": self.validated})


class PCIDSS:
    """Deterministic single-host PCI DSS decision ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._merchants: Dict[str, MerchantRecord] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._remediations: Dict[str, RemediationRecord] = {}
        self._remediation_chain: Dict[str, List[str]] = {}
        self._asm_counter = 0
        self._rem_counter = 0
        self._audit: List[Dict[str, object]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _claim_seq(self, seq_v: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq_v <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq_v} "
                f"after {self._seq}")
        self._seq = seq_v

    def _burn(self, seq_v: int, method: str, exc: PCIDSSError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(pci_dss_audit_event(
            KIND_REJECTED,
            {"method": method, "error": type(exc).__name__,
             "error_detail": str(exc)},
            seq_v))

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq_v: int) -> None:
        self._audit.append(pci_dss_audit_event(audit_kind, detail, seq_v))

    # -- mutations --------------------------------------------------------

    def register_merchant(self, merchant_id: object, level: object,
                          seq: object,
                          profile_digest: object = "") -> MerchantRecord:
        """Declare one PCI DSS merchant under this ledger."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _check_id(merchant_id, "merchant_id")
                if mid in self._merchants:
                    raise DuplicateMerchantError(
                        f"merchant already registered: {mid!r}")
                if not isinstance(level, str) or level not in _MERCHANT_LEVELS:
                    raise BadLevelError(
                        f"level must be one of {sorted(_MERCHANT_LEVELS)}")
                pin = _check_digest(profile_digest, "profile_digest")
                rec = MerchantRecord(
                    merchant_id=mid, level=level, profile_pin=pin,
                    digest=_record_digest("merchant", {
                        "merchant_id": mid, "level": level,
                        "profile_pin": pin}))
                self._merchants[mid] = rec
                self._emit(KIND_MERCHANT_REGISTERED,
                           {"merchant_id": mid, "level": level},
                           seq_v)
                return rec
            except PCIDSSError as exc:
                self._burn(seq_v, "register_merchant", exc)
                raise

    def assess(self, merchant_id: object, seq: object,
               requirement: object = "req-01",
               finding: object = "compliant",
               severity: object = "low",
               evidence_digest: object = "") -> AssessmentRecord:
        """Book one declared PCI DSS assessment outcome (minted asm-N)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _check_id(merchant_id, "merchant_id")
                if mid not in self._merchants:
                    raise UnknownMerchantError(
                        f"unknown merchant: {mid!r}")
                if (not isinstance(requirement, str)
                        or requirement not in _REQUIREMENTS):
                    raise BadRequirementError(
                        "requirement must be one of req-01..req-12")
                if not isinstance(finding, str) or finding not in _FINDINGS:
                    raise BadFindingError(
                        f"finding must be one of {sorted(_FINDINGS)}")
                if (not isinstance(severity, str)
                        or severity not in _SEVERITIES):
                    raise BadSeverityError(
                        f"severity must be one of {sorted(_SEVERITIES)}")
                pin = _check_digest(evidence_digest, "evidence_digest")
                self._asm_counter += 1
                asm_id = f"asm-{self._asm_counter}"
                rec = AssessmentRecord(
                    assessment_id=asm_id, merchant_id=mid,
                    requirement=requirement, finding=finding,
                    severity=severity, evidence_pin=pin,
                    digest=_record_digest("assessment", {
                        "assessment_id": asm_id, "merchant_id": mid,
                        "requirement": requirement, "finding": finding,
                        "severity": severity, "evidence_pin": pin}))
                self._assessments[asm_id] = rec
                self._emit(KIND_ASSESSED,
                           {"assessment_id": asm_id, "merchant_id": mid,
                            "requirement": requirement, "finding": finding,
                            "severity": severity},
                           seq_v)
                return rec
            except PCIDSSError as exc:
                self._burn(seq_v, "assess", exc)
                raise

    def remediate(self, assessment_id: object, seq: object,
                  action: object = "patch",
                  plan_digest: object = "") -> RemediationRecord:
        """Book one declared remediation decision (minted rem-N)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                aid = _check_id(assessment_id, "assessment_id")
                if aid not in self._assessments:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {aid!r}")
                if (not isinstance(action, str)
                        or action not in _REMEDIATION_ACTIONS):
                    raise BadRemediationError(
                        f"action must be one of {sorted(_REMEDIATION_ACTIONS)}")
                finding = self._assessments[aid].finding
                if finding in _ADDRESSD_FINDINGS:
                    raise RemediationNotNeededError(
                        f"no remediation needed for finding {finding!r}")
                pin = _check_digest(plan_digest, "plan_digest")
                self._rem_counter += 1
                rem_id = f"rem-{self._rem_counter}"
                rec = RemediationRecord(
                    remediation_id=rem_id, assessment_id=aid,
                    action=action, plan_pin=pin,
                    digest=_record_digest("remediation", {
                        "remediation_id": rem_id, "assessment_id": aid,
                        "action": action, "plan_pin": pin}))
                self._remediations[rem_id] = rec
                self._remediation_chain.setdefault(aid, []).append(rem_id)
                self._emit(KIND_REMEDIATED,
                           {"remediation_id": rem_id,
                            "assessment_id": aid, "action": action},
                           seq_v)
                return rec
            except PCIDSSError as exc:
                self._burn(seq_v, "remediate", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def validate(self, merchant_id: object,
                 seq: object) -> ValidationReport:
        """Derive a PCI DSS validation report from the ledger (pure read).

        Ledger rule: ``validated`` iff every one of the 12 pinned
        requirements is covered by at least one booked assessment and
        every ``non-compliant`` finding has a booked remediation.
        """
        with self._lock:
            seq_v = _check_seq(seq)
            mid = _check_id(merchant_id, "merchant_id")
            if mid not in self._merchants:
                raise UnknownMerchantError(
                    f"unknown merchant: {mid!r}")
            relevant = [a for a in self._assessments.values()
                        if a.merchant_id == mid]
            covered: List[str] = []
            tally: Dict[str, int] = {}
            remediated: List[str] = []
            for rec in relevant:
                if rec.requirement not in covered:
                    covered.append(rec.requirement)
                tally[rec.finding] = tally.get(rec.finding, 0) + 1
                if rec.finding == "non-compliant" and \
                        self._remediation_chain.get(rec.assessment_id):
                    remediated.append(rec.assessment_id)
            covered_sorted = tuple(sorted(covered))
            findings = tuple(sorted(tally.items()))
            remediated_sorted = tuple(sorted(remediated))
            open_findings = sum(
                count for finding, count in findings
                if finding == "non-compliant"
            ) - len(remediated)
            validated = bool(relevant) and len(covered) == len(_REQUIREMENTS) \
                and open_findings <= 0
            report = ValidationReport(
                merchant_id=mid,
                n_assessments=len(relevant),
                requirements_covered=covered_sorted,
                findings=findings,
                remediated_assessments=remediated_sorted,
                validated=validated,
                digest=_record_digest("validation", {
                    "merchant_id": mid,
                    "n_assessments": len(relevant),
                    "requirements_covered": sorted(covered),
                    "findings": [
                        {"finding": finding, "count": count}
                        for finding, count in findings
                    ],
                    "remediated_assessments": sorted(remediated),
                    "validated": validated}))
            _ = seq_v  # seq shape validated, never consumed
            return report

    def merchant_record(self, merchant_id: object,
                        seq: object) -> MerchantRecord:
        """Return one merchant record (pure read)."""
        with self._lock:
            _check_seq(seq)
            mid = _check_id(merchant_id, "merchant_id")
            if mid not in self._merchants:
                raise UnknownMerchantError(
                    f"unknown merchant: {mid!r}")
            return self._merchants[mid]

    def merchant_ids(self, seq: object) -> Tuple[str, ...]:
        """All registered merchant ids in registration order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._merchants.keys())

    def assessment_record(self, assessment_id: object,
                          seq: object) -> AssessmentRecord:
        """Return one assessment record (pure read)."""
        with self._lock:
            _check_seq(seq)
            aid = _check_id(assessment_id, "assessment_id")
            if aid not in self._assessments:
                raise UnknownAssessmentError(
                    f"unknown assessment: {aid!r}")
            return self._assessments[aid]

    def assessment_ids(self, seq: object) -> Tuple[str, ...]:
        """All assessment ids in mint order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._assessments.keys())

    def assessments_for(self, merchant_id: object,
                        seq: object) -> Tuple[str, ...]:
        """Assessment ids booked against one merchant (mint order)."""
        with self._lock:
            _check_seq(seq)
            mid = _check_id(merchant_id, "merchant_id")
            if mid not in self._merchants:
                raise UnknownMerchantError(
                    f"unknown merchant: {mid!r}")
            return tuple(a.assessment_id for a in self._assessments.values()
                         if a.merchant_id == mid)

    def remediation_record(self, remediation_id: object,
                           seq: object) -> RemediationRecord:
        """Return one remediation record (pure read)."""
        with self._lock:
            _check_seq(seq)
            rid = _check_id(remediation_id, "remediation_id")
            if rid not in self._remediations:
                raise UnknownAssessmentError(
                    f"unknown remediation: {rid!r}")
            return self._remediations[rid]

    def remediations_for(self, assessment_id: object,
                         seq: object) -> Tuple[str, ...]:
        """Remediation ids booked against one assessment (mint order)."""
        with self._lock:
            _check_seq(seq)
            aid = _check_id(assessment_id, "assessment_id")
            if aid not in self._assessments:
                raise UnknownAssessmentError(
                    f"unknown assessment: {aid!r}")
            return tuple(self._remediation_chain.get(aid, ()))

    def audit_log(self, seq: object) -> Tuple[Dict[str, object], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: object) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            _check_seq(seq)
            return {
                "merchants": len(self._merchants),
                "assessments": len(self._assessments),
                "remediations": len(self._remediations),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    p = PCIDSS()
    p.register_merchant("merchant-1", "level-1", 1)
    seq = 2
    for i in range(1, 13):
        p.assess("merchant-1", seq, requirement=f"req-{i:02d}",
                 finding="non-compliant" if i == 4 else "compliant",
                 severity="high" if i == 4 else "low")
        seq += 1
    gap = p.assessment_record("asm-4", seq)
    p.remediate(gap.assessment_id, seq + 1, action="encrypt")
    report = p.validate("merchant-1", seq + 2)
    assert report.verify()
    assert report.validated is True
    assert report.n_assessments == 12
    assert len(report.requirements_covered) == 12
    assert p.stats(seq + 3) == {"merchants": 1, "assessments": 12,
                                "remediations": 1, "rejected": 0}
    print("pci-dss OK: register, assess, remediate, validate, pins, audit")


if __name__ == "__main__":
    main()
