"""Governance, Risk & Compliance (GRC) lifecycle decision ledger.

Distinct from siblings: ``compliance_checker`` evaluates individual
check outcomes against rule sets; ``compliance_reports`` formats
report artifacts; ``risk_assessment`` scores risk factors; and
``step_compliance`` gates single workflow steps. This module is the
*GRC governance workflow* layer none of them own - it books declared
framework registrations, declared assessment outcomes, declared
remediation decisions, and derives certification reports from the
ledger as data.

* **Frameworks** - ``register_framework()`` declares one compliance
  framework under the pinned vocabulary (``iso-27001`` / ``soc-2`` /
  ``nist-csf`` / ``hipaa`` / ``gdpr`` / ``pci-dss``); ids are never
  recycled.
* **Assessments** - ``assess()`` books one declared assessment
  outcome (minted ``asm-N``): a finding over the pinned vocabulary
  (``compliant`` / ``non-compliant`` / ``partial`` /
  ``not-applicable``) plus a host-declared risk level; evidence
  travels as a ``sha256:`` digest pin only.
* **Remediations** - ``remediate()`` books one declared remediation
  decision (minted ``rem-N``) over the pinned action vocabulary
  (``patch`` / ``reconfigure`` / ``training`` / ``policy-update`` /
  ``reassess`` / ``accept-risk`` / ``vendor-fix``). Remediation is
  refused fail-closed when the assessment finding is ``compliant``
  or ``not-applicable`` (there is nothing to fix); repeatable as a
  remediation chain.
* **Certification** - ``certify()`` is a pure read view deriving a
  frozen ``CertificationReport`` from the ledger: assessment counts,
  open findings, remediation tallies, and ``certified`` as data -
  never proof of compliance.

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``grc.rejected``; rewinds raise bare), no wall-clock,
   RLock-guarded, fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``grc.v1``; schema pin ``northstar.grc.v1``.

Honest scope:
- This module books *declared* GRC decisions - it runs no audit,
  inspects no evidence, and certifies nothing.
- A booked ``non-compliant`` means "the host declared a finding",
  never "the control failed". A booked remediation means "the host
  declared an action", never "the gap was closed". A ``certified``
  report means the ledger's booked records satisfy the ledger rule,
  never that the organization is compliant.
- Digest pins prove ledger integrity and ordering, never the truth of
  the declared decisions.
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


VERSION = "grc.v1"
SCHEMA = "northstar.grc.v1"

KIND_FRAMEWORK_REGISTERED = "framework-registered"
KIND_ASSESSED = "assessed"
KIND_REMEDIATED = "remediated"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_FRAMEWORK_REGISTERED, KIND_ASSESSED, KIND_REMEDIATED,
    KIND_REJECTED,
})

_FRAMEWORKS = ("iso-27001", "soc-2", "nist-csf", "hipaa", "gdpr",
               "pci-dss")

_FINDINGS = ("compliant", "non-compliant", "partial", "not-applicable")

_RISK_LEVELS = ("low", "medium", "high", "critical")

_REMEDIATION_ACTIONS = ("patch", "reconfigure", "training",
                        "policy-update", "reassess", "accept-risk",
                        "vendor-fix")

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw content must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset({
    "content", "text", "payload", "raw", "evidence", "description",
    "notes", "note", "message", "plan", "plan_text", "rationale",
    "scope_text", "finding_text", "title", "summary",
})


class GRCError(Exception):
    """Base class for all GRC ledger errors."""


class BadIdError(GRCError):
    """Malformed framework id, scope id, or assessment id."""


class DuplicateFrameworkError(GRCError):
    """Framework id already registered (ids are never recycled)."""


class UnknownFrameworkError(GRCError):
    """Framework id not registered."""


class BadFrameworkError(GRCError):
    """Framework not in the pinned vocabulary."""


class BadDigestError(GRCError):
    """Digest is not a sha256:<64hex> pin (or empty)."""


class BadFindingError(GRCError):
    """Finding not in the pinned vocabulary."""


class BadRiskLevelError(GRCError):
    """Risk level not in the pinned vocabulary."""


class DuplicateAssessmentError(GRCError):
    """Assessment id minted twice (internal misuse)."""


class UnknownAssessmentError(GRCError):
    """Assessment id not booked."""


class BadRemediationError(GRCError):
    """Remediation action not in the pinned vocabulary."""


class RemediationNotNeededError(GRCError):
    """Remediation booked against a compliant/not-applicable finding."""


class SeqOrderError(GRCError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(GRCError):
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


def grc_audit_event(kind: str, detail: Dict[str, object],
                    seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the GRC ledger."""
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
        "kind": "grc." + kind,
        "detail": dict(detail),
        "seq": seq,
    }


def _record_digest(tag: str, fields: Dict[str, object]) -> str:
    return _digest_pin({"grc": tag, **fields})


@dataclass(frozen=True)
class FrameworkRecord:
    """One declared compliance framework registration."""

    framework_id: str
    framework: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "framework_id": self.framework_id,
            "framework": self.framework,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("framework", {
            "framework_id": self.framework_id,
            "framework": self.framework})


@dataclass(frozen=True)
class AssessmentRecord:
    """One declared GRC assessment outcome (minted asm-N)."""

    assessment_id: str
    framework_id: str
    scope_id: str
    finding: str
    risk_level: str
    evidence_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "assessment_id": self.assessment_id,
            "framework_id": self.framework_id,
            "scope_id": self.scope_id,
            "finding": self.finding,
            "risk_level": self.risk_level,
            "evidence_pin": self.evidence_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("assessment", {
            "assessment_id": self.assessment_id,
            "framework_id": self.framework_id,
            "scope_id": self.scope_id,
            "finding": self.finding,
            "risk_level": self.risk_level,
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
class CertificationReport:
    """A certification verdict derived from the ledger (pure data)."""

    framework_id: str
    n_assessments: int
    findings: Tuple[Tuple[str, int], ...]
    remediated_assessments: Tuple[str, ...]
    certified: bool
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "framework_id": self.framework_id,
            "n_assessments": self.n_assessments,
            "findings": [
                {"finding": finding, "count": count}
                for finding, count in self.findings
            ],
            "remediated_assessments": list(self.remediated_assessments),
            "certified": self.certified,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("certification", {
            "framework_id": self.framework_id,
            "n_assessments": self.n_assessments,
            "findings": [
                {"finding": finding, "count": count}
                for finding, count in self.findings
            ],
            "remediated_assessments": list(self.remediated_assessments),
            "certified": self.certified})


class GRC:
    """Deterministic single-host GRC decision ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._frameworks: Dict[str, FrameworkRecord] = {}
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

    def _burn(self, seq_v: int, method: str, exc: GRCError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(grc_audit_event(
            KIND_REJECTED,
            {"method": method, "error": type(exc).__name__,
             "error_detail": str(exc)},
            seq_v))

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq_v: int) -> None:
        self._audit.append(grc_audit_event(audit_kind, detail, seq_v))

    # -- mutations --------------------------------------------------------

    def register_framework(self, framework_id: object, framework: object,
                           seq: object,
                           description_digest: object = "") -> FrameworkRecord:
        """Declare one compliance framework under this ledger."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                fid = _check_id(framework_id, "framework_id")
                if fid in self._frameworks:
                    raise DuplicateFrameworkError(
                        f"framework already registered: {fid!r}")
                if not isinstance(framework, str) or framework not in _FRAMEWORKS:
                    raise BadFrameworkError(
                        f"framework must be one of {sorted(_FRAMEWORKS)}")
                _check_digest(description_digest, "description_digest")
                rec = FrameworkRecord(
                    framework_id=fid, framework=framework,
                    digest=_record_digest("framework", {
                        "framework_id": fid, "framework": framework}))
                self._frameworks[fid] = rec
                self._emit(KIND_FRAMEWORK_REGISTERED,
                           {"framework_id": fid, "framework": framework},
                           seq_v)
                return rec
            except GRCError as exc:
                self._burn(seq_v, "register_framework", exc)
                raise

    def assess(self, framework_id: object, scope_id: object, seq: object,
               finding: object = "compliant",
               risk_level: object = "low",
               evidence_digest: object = "") -> AssessmentRecord:
        """Book one declared assessment outcome (minted asm-N)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                fid = _check_id(framework_id, "framework_id")
                if fid not in self._frameworks:
                    raise UnknownFrameworkError(
                        f"unknown framework: {fid!r}")
                sid = _check_id(scope_id, "scope_id")
                if not isinstance(finding, str) or finding not in _FINDINGS:
                    raise BadFindingError(
                        f"finding must be one of {sorted(_FINDINGS)}")
                if (not isinstance(risk_level, str)
                        or risk_level not in _RISK_LEVELS):
                    raise BadRiskLevelError(
                        f"risk_level must be one of {sorted(_RISK_LEVELS)}")
                pin = _check_digest(evidence_digest, "evidence_digest")
                self._asm_counter += 1
                asm_id = f"asm-{self._asm_counter}"
                rec = AssessmentRecord(
                    assessment_id=asm_id, framework_id=fid, scope_id=sid,
                    finding=finding, risk_level=risk_level,
                    evidence_pin=pin,
                    digest=_record_digest("assessment", {
                        "assessment_id": asm_id, "framework_id": fid,
                        "scope_id": sid, "finding": finding,
                        "risk_level": risk_level, "evidence_pin": pin}))
                self._assessments[asm_id] = rec
                self._emit(KIND_ASSESSED,
                           {"assessment_id": asm_id, "framework_id": fid,
                            "scope_id": sid, "finding": finding,
                            "risk_level": risk_level},
                           seq_v)
                return rec
            except GRCError as exc:
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
                if not isinstance(action, str) or action not in _REMEDIATION_ACTIONS:
                    raise BadRemediationError(
                        f"action must be one of {sorted(_REMEDIATION_ACTIONS)}")
                finding = self._assessments[aid].finding
                if finding in ("compliant", "not-applicable"):
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
            except GRCError as exc:
                self._burn(seq_v, "remediate", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def certify(self, framework_id: object,
                seq: object) -> CertificationReport:
        """Derive a certification report from the ledger (pure read)."""
        with self._lock:
            seq_v = _check_seq(seq)
            fid = _check_id(framework_id, "framework_id")
            if fid not in self._frameworks:
                raise UnknownFrameworkError(
                    f"unknown framework: {fid!r}")
            relevant = [a for a in self._assessments.values()
                        if a.framework_id == fid]
            tally: Dict[str, int] = {}
            remediated: List[str] = []
            for rec in relevant:
                tally[rec.finding] = tally.get(rec.finding, 0) + 1
                if rec.finding in ("non-compliant", "partial") and \
                        self._remediation_chain.get(rec.assessment_id):
                    remediated.append(rec.assessment_id)
            findings = tuple(sorted(tally.items()))
            # Ledger rule: certified iff at least one assessment exists and
            # every non-compliant/partial finding has a booked remediation.
            open_findings = sum(
                count for finding, count in findings
                if finding in ("non-compliant", "partial")
            ) - len(remediated)
            certified = bool(relevant) and open_findings <= 0
            report = CertificationReport(
                framework_id=fid,
                n_assessments=len(relevant),
                findings=findings,
                remediated_assessments=tuple(sorted(remediated)),
                certified=certified,
                digest=_record_digest("certification", {
                    "framework_id": fid,
                    "n_assessments": len(relevant),
                    "findings": [
                        {"finding": finding, "count": count}
                        for finding, count in findings
                    ],
                    "remediated_assessments": sorted(remediated),
                    "certified": certified}))
            _ = seq_v  # seq shape validated, never consumed
            return report

    def framework_record(self, framework_id: object,
                         seq: object) -> FrameworkRecord:
        """Return one framework record (pure read)."""
        with self._lock:
            _check_seq(seq)
            fid = _check_id(framework_id, "framework_id")
            if fid not in self._frameworks:
                raise UnknownFrameworkError(
                    f"unknown framework: {fid!r}")
            return self._frameworks[fid]

    def framework_ids(self, seq: object) -> Tuple[str, ...]:
        """All registered framework ids in registration order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._frameworks.keys())

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

    def assessments_for(self, framework_id: object,
                        seq: object) -> Tuple[str, ...]:
        """Assessment ids booked against one framework (mint order)."""
        with self._lock:
            _check_seq(seq)
            fid = _check_id(framework_id, "framework_id")
            if fid not in self._frameworks:
                raise UnknownFrameworkError(
                    f"unknown framework: {fid!r}")
            return tuple(a.assessment_id for a in self._assessments.values()
                         if a.framework_id == fid)

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
                "frameworks": len(self._frameworks),
                "assessments": len(self._assessments),
                "remediations": len(self._remediations),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    g = GRC()
    g.register_framework("fw1", "iso-27001", 1)
    a1 = g.assess("fw1", "access-control", 2, finding="non-compliant",
                  risk_level="high")
    g.remediate(a1.assessment_id, 3, action="patch")
    g.assess("fw1", "encryption", 4, finding="compliant", risk_level="low")
    report = g.certify("fw1", 5)
    assert report.verify()
    assert report.certified is True
    assert report.n_assessments == 2
    assert g.stats(6) == {"frameworks": 1, "assessments": 2,
                          "remediations": 1, "rejected": 0}
    print("grc OK: register, assess, remediate, certify, pins, audit")


if __name__ == "__main__":
    main()
