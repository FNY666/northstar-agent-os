"""Sarbanes-Oxley (SOX) compliance decision ledger.

Distinct from siblings: ``grc`` owns the multi-framework GRC workflow
ledger (framework registration across six standards); ``compliance``
owns the framework/control check-remediate-attest cycle; ``soc2``,
``hipaa``, ``gdpr`` and ``iso27001`` are batch-53 siblings owning
their own standards. This module is the *SOX control assessment*
ledger: declared control-area assessments with SOX severity
vocabulary (effective / deficient / significant-deficiency /
material-weakness), declared remediation chains, and a derived
attestation report whose opinion (unqualified / qualified / adverse /
not-assessed) is ledger data, never proof of audit readiness.

* **Assessments** - ``assess()`` books one declared assessment
  (minted ``asmt-N``) against a scope id and a pinned control-area
  vocabulary; a finding over the pinned severity vocabulary plus a
  host-declared control-owner label. Evidence travels as a
  ``sha256:`` digest pin only - raw evidence never enters a record.
* **Remediations** - ``remediate()`` books one declared remediation
  decision (minted ``rmd-N``) over the pinned action vocabulary.
  Remediation is refused fail-closed when the assessment finding is
  ``effective`` (there is nothing to fix); repeatable as a
  remediation chain.
* **Attestation** - ``attest()`` is a pure read view deriving a
  frozen ``AttestationReport`` from the ledger: assessment counts,
  finding tallies, remediated assessment ids, and ``opinion`` as
  data - never proof of control effectiveness.

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``sox.rejected``; rewinds raise bare), no wall-clock,
   RLock-guarded, fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``sox.v1``; schema pin ``northstar.sox.v1``.

Honest scope:
- This module books *declared* SOX decisions - it runs no audit,
  inspects no evidence, tests no controls, and certifies nothing.
- A booked ``material-weakness`` means "the host declared a
  finding", never "the control failed". A booked remediation means
  "the host declared an action", never "the gap was closed". An
  ``unqualified`` opinion means the ledger's booked records satisfy
  the ledger rule, never that the entity would pass a real SOX
  audit.
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


VERSION = "sox.v1"
SCHEMA = "northstar.sox.v1"

KIND_ASSESSED = "assessed"
KIND_REMEDIATED = "remediated"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_ASSESSED, KIND_REMEDIATED, KIND_REJECTED,
})

# SOX control areas assessed by this ledger.
_CONTROL_AREAS = (
    "entity-level",
    "financial-reporting",
    "it-general-controls",
    "revenue-recognition",
    "procure-to-pay",
    "record-to-report",
    "hire-to-retire",
    "disclosure-controls",
)

# SOX deficiency severity vocabulary.
_FINDINGS = (
    "effective",
    "deficient",
    "significant-deficiency",
    "material-weakness",
)

# Declared remediation actions.
_REMEDIATION_ACTIONS = (
    "redesign",
    "strengthen",
    "automate",
    "train",
    "accept-risk",
    "reassess",
)

# Opinions derivable by the ledger rule.
_OPINIONS = ("unqualified", "qualified", "adverse", "not-assessed")

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw content must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset({
    "content", "text", "payload", "raw", "evidence", "description",
    "notes", "note", "message", "plan", "plan_text", "rationale",
    "scope_text", "finding_text", "title", "summary", "opinion_text",
})


class SOXError(Exception):
    """Base class for all SOX ledger errors."""


class BadIdError(SOXError):
    """Malformed scope id or assessment id."""


class UnknownAssessmentError(SOXError):
    """Assessment id not booked."""


class BadControlAreaError(SOXError):
    """Control area not in the pinned vocabulary."""


class BadFindingError(SOXError):
    """Finding not in the pinned vocabulary."""


class BadActionError(SOXError):
    """Remediation action not in the pinned vocabulary."""


class BadDigestError(SOXError):
    """Digest is not a sha256:<64hex> pin (or empty)."""


class RemediationNotNeededError(SOXError):
    """Remediation booked against an effective finding."""


class SeqOrderError(SOXError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(SOXError):
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


def sox_audit_event(kind: str, detail: Dict[str, object],
                    seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the SOX ledger."""
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
        "kind": "sox." + kind,
        "detail": dict(detail),
        "seq": seq,
    }


def _record_digest(tag: str, fields: Dict[str, object]) -> str:
    return _digest_pin({"sox": tag, **fields})


@dataclass(frozen=True)
class AssessmentRecord:
    """One declared SOX control-area assessment (minted asmt-N)."""

    assessment_id: str
    scope_id: str
    control_area: str
    finding: str
    control_owner: str
    evidence_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "assessment_id": self.assessment_id,
            "scope_id": self.scope_id,
            "control_area": self.control_area,
            "finding": self.finding,
            "control_owner": self.control_owner,
            "evidence_pin": self.evidence_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("assessment", {
            "assessment_id": self.assessment_id,
            "scope_id": self.scope_id,
            "control_area": self.control_area,
            "finding": self.finding,
            "control_owner": self.control_owner,
            "evidence_pin": self.evidence_pin})


@dataclass(frozen=True)
class RemediationRecord:
    """One declared remediation decision (minted rmd-N)."""

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
class AttestationReport:
    """A SOX opinion derived from the ledger (pure data)."""

    scope_id: str
    n_assessments: int
    findings: Tuple[Tuple[str, int], ...]
    remediated_assessments: Tuple[str, ...]
    opinion: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "scope_id": self.scope_id,
            "n_assessments": self.n_assessments,
            "findings": [
                {"finding": finding, "count": count}
                for finding, count in self.findings
            ],
            "remediated_assessments": list(self.remediated_assessments),
            "opinion": self.opinion,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("attestation", {
            "scope_id": self.scope_id,
            "n_assessments": self.n_assessments,
            "findings": [
                {"finding": finding, "count": count}
                for finding, count in self.findings
            ],
            "remediated_assessments": list(self.remediated_assessments),
            "opinion": self.opinion})


class SOX:
    """Deterministic single-host SOX decision ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._remediations: Dict[str, RemediationRecord] = {}
        self._remediation_chain: Dict[str, List[str]] = {}
        self._asmt_counter = 0
        self._rmd_counter = 0
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

    def _burn(self, seq_v: int, method: str, exc: SOXError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(sox_audit_event(
            KIND_REJECTED,
            {"method": method, "error": type(exc).__name__,
             "error_detail": str(exc)},
            seq_v))

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq_v: int) -> None:
        self._audit.append(sox_audit_event(audit_kind, detail, seq_v))

    # -- mutations --------------------------------------------------------

    def assess(self, scope_id: object, seq: object,
               control_area: object = "financial-reporting",
               finding: object = "effective",
               control_owner: object = "",
               evidence_digest: object = "") -> AssessmentRecord:
        """Book one declared SOX assessment outcome (minted asmt-N)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _check_id(scope_id, "scope_id")
                if (not isinstance(control_area, str)
                        or control_area not in _CONTROL_AREAS):
                    raise BadControlAreaError(
                        f"control_area must be one of "
                        f"{sorted(_CONTROL_AREAS)}")
                if not isinstance(finding, str) or finding not in _FINDINGS:
                    raise BadFindingError(
                        f"finding must be one of {sorted(_FINDINGS)}")
                if (not isinstance(control_owner, str)
                        or any(ch.isspace() for ch in control_owner)
                        or len(control_owner) > _MAX_ID_LEN):
                    raise BadIdError(
                        "control_owner must be a whitespace-free str "
                        f"<= {_MAX_ID_LEN} chars")
                pin = _check_digest(evidence_digest, "evidence_digest")
                self._asmt_counter += 1
                asmt_id = f"asmt-{self._asmt_counter}"
                rec = AssessmentRecord(
                    assessment_id=asmt_id, scope_id=sid,
                    control_area=control_area, finding=finding,
                    control_owner=control_owner, evidence_pin=pin,
                    digest=_record_digest("assessment", {
                        "assessment_id": asmt_id, "scope_id": sid,
                        "control_area": control_area, "finding": finding,
                        "control_owner": control_owner,
                        "evidence_pin": pin}))
                self._assessments[asmt_id] = rec
                self._emit(KIND_ASSESSED,
                           {"assessment_id": asmt_id, "scope_id": sid,
                            "control_area": control_area, "finding": finding,
                            "control_owner": control_owner},
                           seq_v)
                return rec
            except SOXError as exc:
                self._burn(seq_v, "assess", exc)
                raise

    def remediate(self, assessment_id: object, seq: object,
                  action: object = "redesign",
                  plan_digest: object = "") -> RemediationRecord:
        """Book one declared remediation decision (minted rmd-N)."""
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
                    raise BadActionError(
                        f"action must be one of "
                        f"{sorted(_REMEDIATION_ACTIONS)}")
                finding = self._assessments[aid].finding
                if finding == "effective":
                    raise RemediationNotNeededError(
                        "no remediation needed for finding 'effective'")
                pin = _check_digest(plan_digest, "plan_digest")
                self._rmd_counter += 1
                rmd_id = f"rmd-{self._rmd_counter}"
                rec = RemediationRecord(
                    remediation_id=rmd_id, assessment_id=aid,
                    action=action, plan_pin=pin,
                    digest=_record_digest("remediation", {
                        "remediation_id": rmd_id, "assessment_id": aid,
                        "action": action, "plan_pin": pin}))
                self._remediations[rmd_id] = rec
                self._remediation_chain.setdefault(aid, []).append(rmd_id)
                self._emit(KIND_REMEDIATED,
                           {"remediation_id": rmd_id,
                            "assessment_id": aid, "action": action},
                           seq_v)
                return rec
            except SOXError as exc:
                self._burn(seq_v, "remediate", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def attest(self, scope_id: object,
               seq: object) -> AttestationReport:
        """Derive a SOX attestation report from the ledger (pure read)."""
        with self._lock:
            seq_v = _check_seq(seq)
            sid = _check_id(scope_id, "scope_id")
            relevant = [a for a in self._assessments.values()
                        if a.scope_id == sid]
            tally: Dict[str, int] = {}
            remediated: List[str] = []
            for rec in relevant:
                tally[rec.finding] = tally.get(rec.finding, 0) + 1
                if rec.finding != "effective" and \
                        self._remediation_chain.get(rec.assessment_id):
                    remediated.append(rec.assessment_id)
            findings = tuple(sorted(tally.items()))
            # Ledger rule: no assessments -> not-assessed; any unremediated
            # material-weakness -> adverse; any unremediated deficient /
            # significant-deficiency -> qualified; otherwise unqualified.
            open_mw = sum(
                count for finding, count in findings
                if finding == "material-weakness"
            ) - sum(
                1 for aid in remediated
                if self._assessments[aid].finding == "material-weakness"
            )
            open_sig = sum(
                count for finding, count in findings
                if finding in ("deficient", "significant-deficiency")
            ) - sum(
                1 for aid in remediated
                if self._assessments[aid].finding
                in ("deficient", "significant-deficiency")
            )
            if not relevant:
                opinion = "not-assessed"
            elif open_mw > 0:
                opinion = "adverse"
            elif open_sig > 0:
                opinion = "qualified"
            else:
                opinion = "unqualified"
            assert opinion in _OPINIONS
            report = AttestationReport(
                scope_id=sid,
                n_assessments=len(relevant),
                findings=findings,
                remediated_assessments=tuple(sorted(remediated)),
                opinion=opinion,
                digest=_record_digest("attestation", {
                    "scope_id": sid,
                    "n_assessments": len(relevant),
                    "findings": [
                        {"finding": finding, "count": count}
                        for finding, count in findings
                    ],
                    "remediated_assessments": sorted(remediated),
                    "opinion": opinion}))
            _ = seq_v  # seq shape validated, never consumed
            return report

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

    def assessments_for(self, scope_id: object,
                        seq: object) -> Tuple[str, ...]:
        """Assessment ids booked against one scope (mint order)."""
        with self._lock:
            _check_seq(seq)
            sid = _check_id(scope_id, "scope_id")
            return tuple(a.assessment_id for a in self._assessments.values()
                         if a.scope_id == sid)

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
                "assessments": len(self._assessments),
                "remediations": len(self._remediations),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    s = SOX()
    a1 = s.assess("fy2026", 1, control_area="it-general-controls",
                  finding="material-weakness", control_owner="cio")
    s.remediate(a1.assessment_id, 2, action="strengthen")
    s.assess("fy2026", 3, control_area="financial-reporting",
             finding="effective", control_owner="cfo")
    report = s.attest("fy2026", 4)
    assert report.verify()
    assert report.opinion == "unqualified"
    assert report.n_assessments == 2
    assert s.stats(5) == {"assessments": 2, "remediations": 1,
                          "rejected": 0}
    print("sox OK: assess, remediate, attest, pins, audit")


if __name__ == "__main__":
    main()
