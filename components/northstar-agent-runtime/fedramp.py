"""FedRAMP (Federal Risk and Authorization Management Program) authorization ledger.

Distinct from siblings: ``grc`` owns the generic framework/assessment/remediation
lifecycle; ``compliance`` owns control checks and attestations; ``audit_management``
owns audit engagements; ``vendor_risk`` owns third-party risk. This module is the
*FedRAMP authorization decision* layer none of them own - the CSP package
lifecycle: register a cloud service offering under a FedRAMP baseline, book
declared 3PAO-style assessments (readiness / SAP / SAR / penetration-test),
book the authorization decision (JAB P-ATO / agency ATO / FedRAMP Ready) as
terminal data, and book continuous-monitoring (ConMon) observations as a
repeatable chain.

* **Register** - ``register()`` declares one cloud service offering (CSO)
  package under the pinned baseline vocabulary (``low`` / ``moderate`` /
  ``high``); raw offering documents travel as ``sha256:`` digest pins only;
  retired ids are never recycled.
* **Assess** - ``assess()`` books one declared assessment (minted ``asm-N``)
  over the pinned assessment-type vocabulary (``readiness`` / ``sap`` /
  ``sar`` / ``penetration-test``) and the pinned finding vocabulary
  (``compliant`` / ``non-compliant`` / ``partial``). Findings are booked as
  data, never proof of control effectiveness.
* **Authorize** - ``authorize()`` books one terminal authorization decision
  (minted ``ath-N``) over the pinned authorization-type vocabulary
  (``jab-p-ato`` / ``agency-ato`` / ``fedramp-ready``). Fail-closed: it
  requires a booked ``sar`` assessment for the package and refuses when the
  package already carries an authorization.
* **Monitor** - ``monitor()`` books one declared continuous-monitoring
  observation (minted ``mon-N``) over the pinned outcome vocabulary
  (``on-track`` / ``poam-open`` / ``poam-closed`` / ``at-risk``).
  Fail-closed: it requires an active (authorized, non-revoked) package;
  repeatable as a monitoring chain.
* **Revoke** - ``revoke()`` is terminal: the package id is retired forever.

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``fedramp.rejected``; rewinds raise bare), no wall-clock,
   RLock-guarded, fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``fedramp.v1``; schema pin
   ``northstar.fedramp.v1``.

Honest scope:
- This module books *declared* FedRAMP decisions - it performs no
  assessment, contacts no 3PAO, and grants no real authorization.
- A booked ``compliant`` means "the host declared a finding", never "the
  controls passed". A booked ``agency-ato`` means "the ledger holds a
  declared authorization", never "the government authorized this system".
- A booked ``on-track`` ConMon outcome is ledger truth, never proof of
  ongoing compliance.
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


VERSION = "fedramp.v1"
SCHEMA = "northstar.fedramp.v1"

KIND_PACKAGE_REGISTERED = "package-registered"
KIND_ASSESSED = "assessed"
KIND_AUTHORIZED = "authorized"
KIND_MONITORED = "monitored"
KIND_REVOKED = "revoked"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_PACKAGE_REGISTERED, KIND_ASSESSED, KIND_AUTHORIZED,
    KIND_MONITORED, KIND_REVOKED, KIND_REJECTED,
})

# FedRAMP control baselines (NIST SP 800-53 derived).
_BASELINES = ("low", "moderate", "high")

# Assessment phases: Readiness Assessment Report / Security Assessment
# Plan / Security Assessment Report / penetration testing.
_ASSESSMENT_TYPES = ("readiness", "sap", "sar", "penetration-test")

_FINDINGS = ("compliant", "non-compliant", "partial")

# Authorization paths: Joint Authorization Board Provisional ATO /
# agency ATO / FedRAMP Ready designation.
_AUTHORIZATION_TYPES = ("jab-p-ato", "agency-ato", "fedramp-ready")

# Continuous-monitoring (ConMon) outcome vocabulary.
_MONITOR_OUTCOMES = ("on-track", "poam-open", "poam-closed", "at-risk")

_REVOKE_REASONS = ("manual", "assessment-failed", "poam-expired",
                   "superseded")

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw content must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset({
    "content", "text", "payload", "raw", "evidence", "offering",
    "description", "notes", "note", "message", "plan", "plan_text",
    "rationale", "title", "summary", "finding_text", "assessor",
    "authorizer", "custodian",
})


class FedRAMPError(Exception):
    """Base class for all FedRAMP ledger errors."""


class BadIdError(FedRAMPError):
    """Malformed package id, assessment id, monitor id, or auth id."""


class DuplicatePackageError(FedRAMPError):
    """Package id already registered (ids are never recycled)."""


class RetiredPackageError(FedRAMPError):
    """Package id was revoked and can never be re-registered."""


class UnknownPackageError(FedRAMPError):
    """Package id not registered."""


class BadBaselineError(FedRAMPError):
    """Baseline not in the pinned vocabulary."""


class BadDigestError(FedRAMPError):
    """Digest is not a sha256:<64hex> pin (or empty)."""


class BadAssessmentTypeError(FedRAMPError):
    """Assessment type not in the pinned vocabulary."""


class BadFindingError(FedRAMPError):
    """Finding not in the pinned vocabulary."""


class UnknownAssessmentError(FedRAMPError):
    """Assessment id not booked."""


class BadAuthorizationTypeError(FedRAMPError):
    """Authorization type not in the pinned vocabulary."""


class AuthorizationDeniedError(FedRAMPError):
    """Authorization or monitoring refused: no grounding SAR assessment,
    or no active authorization."""


class AlreadyAuthorizedError(FedRAMPError):
    """Package already carries an authorization (one ATO per package)."""


class RevokedPackageError(FedRAMPError):
    """Operation refused: the package was revoked."""


class BadOutcomeError(FedRAMPError):
    """Monitor outcome not in the pinned vocabulary."""


class BadReasonError(FedRAMPError):
    """Revoke reason not in the pinned vocabulary."""


class DoubleRevokeError(FedRAMPError):
    """Package already revoked (revocation is terminal)."""


class SeqOrderError(FedRAMPError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(FedRAMPError):
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


def fedramp_audit_event(kind: str, detail: Dict[str, object],
                       seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the FedRAMP ledger."""
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
        "kind": "fedramp." + kind,
        "detail": dict(detail),
        "seq": seq,
    }


def _record_digest(tag: str, fields: Dict[str, object]) -> str:
    return _digest_pin({"fedramp": tag, **fields})


@dataclass(frozen=True)
class PackageRecord:
    """One declared cloud service offering package registration."""

    package_id: str
    baseline: str
    offering_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "package_id": self.package_id,
            "baseline": self.baseline,
            "offering_pin": self.offering_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("package", {
            "package_id": self.package_id,
            "baseline": self.baseline,
            "offering_pin": self.offering_pin})


@dataclass(frozen=True)
class AssessmentRecord:
    """One declared assessment (minted asm-N)."""

    assessment_id: str
    package_id: str
    assessment_type: str
    finding: str
    assessor_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "assessment_id": self.assessment_id,
            "package_id": self.package_id,
            "assessment_type": self.assessment_type,
            "finding": self.finding,
            "assessor_pin": self.assessor_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("assessment", {
            "assessment_id": self.assessment_id,
            "package_id": self.package_id,
            "assessment_type": self.assessment_type,
            "finding": self.finding,
            "assessor_pin": self.assessor_pin})


@dataclass(frozen=True)
class AuthorizationRecord:
    """One declared authorization decision (minted ath-N, terminal)."""

    authorization_id: str
    package_id: str
    authorization_type: str
    assessment_id: str
    authorizer_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "authorization_id": self.authorization_id,
            "package_id": self.package_id,
            "authorization_type": self.authorization_type,
            "assessment_id": self.assessment_id,
            "authorizer_pin": self.authorizer_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("authorization", {
            "authorization_id": self.authorization_id,
            "package_id": self.package_id,
            "authorization_type": self.authorization_type,
            "assessment_id": self.assessment_id,
            "authorizer_pin": self.authorizer_pin})


@dataclass(frozen=True)
class MonitorRecord:
    """One declared continuous-monitoring observation (minted mon-N)."""

    monitor_id: str
    package_id: str
    outcome: str
    conmon_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "monitor_id": self.monitor_id,
            "package_id": self.package_id,
            "outcome": self.outcome,
            "conmon_pin": self.conmon_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("monitor", {
            "monitor_id": self.monitor_id,
            "package_id": self.package_id,
            "outcome": self.outcome,
            "conmon_pin": self.conmon_pin})


@dataclass(frozen=True)
class RevokeRecord:
    """One terminal revocation of a package authorization."""

    package_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "package_id": self.package_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; ledger self-consistency only."""
        return self.digest == _record_digest("revoke", {
            "package_id": self.package_id,
            "reason": self.reason})


class FedRAMP:
    """FedRAMP authorization decision ledger (deterministic, in-memory)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._packages: Dict[str, PackageRecord] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._authorizations: Dict[str, AuthorizationRecord] = {}
        self._package_auth: Dict[str, str] = {}  # package_id -> auth id
        self._monitors: Dict[str, MonitorRecord] = {}
        self._monitor_chain: Dict[str, List[str]] = {}  # package -> mon ids
        self._revoked: Dict[str, RevokeRecord] = {}
        self._audit: List[Dict[str, object]] = []
        self._last_seq = -1
        self._rejected = 0
        self._asm_counter = 0
        self._ath_counter = 0
        self._mon_counter = 0

    # -- internal helpers --------------------------------------------------

    def _claim_seq(self, seq_v: int) -> None:
        """Claim a seq: strictly increasing; rewinds raise bare."""
        if seq_v <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq_v} not > last seq {self._last_seq}")
        self._last_seq = seq_v

    def _burn(self, seq_v: int, method: str, exc: FedRAMPError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(fedramp_audit_event(
            KIND_REJECTED,
            {"method": method, "error": type(exc).__name__,
             "error_detail": str(exc)},
            seq_v))

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq_v: int) -> None:
        self._audit.append(fedramp_audit_event(audit_kind, detail, seq_v))

    def _require_live(self, pid: str) -> None:
        """Fail-closed guards for a registered, non-revoked package."""
        if pid in self._revoked:
            raise RevokedPackageError(f"package revoked: {pid!r}")
        if pid not in self._packages:
            raise UnknownPackageError(f"unknown package: {pid!r}")

    # -- mutations --------------------------------------------------------

    def register(self, package_id: object, seq: object,
                 baseline: object = "moderate",
                 offering_digest: object = "") -> PackageRecord:
        """Declare one cloud service offering package."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(package_id, "package_id")
                if pid in self._revoked:
                    raise RetiredPackageError(
                        f"package id retired, never recycled: {pid!r}")
                if pid in self._packages:
                    raise DuplicatePackageError(
                        f"package already registered: {pid!r}")
                if not isinstance(baseline, str) or baseline not in _BASELINES:
                    raise BadBaselineError(
                        f"baseline must be one of {sorted(_BASELINES)}")
                pin = _check_digest(offering_digest, "offering_digest")
                rec = PackageRecord(
                    package_id=pid, baseline=baseline,
                    offering_pin=pin,
                    digest=_record_digest("package", {
                        "package_id": pid, "baseline": baseline,
                        "offering_pin": pin}))
                self._packages[pid] = rec
                self._emit(KIND_PACKAGE_REGISTERED,
                           {"package_id": pid, "baseline": baseline},
                           seq_v)
                return rec
            except FedRAMPError as exc:
                self._burn(seq_v, "register", exc)
                raise

    def assess(self, package_id: object, seq: object,
               assessment_type: object = "sar",
               finding: object = "compliant",
               assessor_digest: object = "") -> AssessmentRecord:
        """Book one declared assessment (minted asm-N)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(package_id, "package_id")
                self._require_live(pid)
                if (not isinstance(assessment_type, str)
                        or assessment_type not in _ASSESSMENT_TYPES):
                    raise BadAssessmentTypeError(
                        f"assessment_type must be one of "
                        f"{sorted(_ASSESSMENT_TYPES)}")
                if not isinstance(finding, str) or finding not in _FINDINGS:
                    raise BadFindingError(
                        f"finding must be one of {sorted(_FINDINGS)}")
                pin = _check_digest(assessor_digest, "assessor_digest")
                self._asm_counter += 1
                asm_id = f"asm-{self._asm_counter}"
                rec = AssessmentRecord(
                    assessment_id=asm_id, package_id=pid,
                    assessment_type=assessment_type, finding=finding,
                    assessor_pin=pin,
                    digest=_record_digest("assessment", {
                        "assessment_id": asm_id, "package_id": pid,
                        "assessment_type": assessment_type,
                        "finding": finding, "assessor_pin": pin}))
                self._assessments[asm_id] = rec
                self._emit(KIND_ASSESSED,
                           {"assessment_id": asm_id, "package_id": pid,
                            "assessment_type": assessment_type,
                            "finding": finding},
                           seq_v)
                return rec
            except FedRAMPError as exc:
                self._burn(seq_v, "assess", exc)
                raise

    def authorize(self, package_id: object, seq: object,
                  authorization_type: object = "agency-ato",
                  authorizer_digest: object = "") -> AuthorizationRecord:
        """Book one terminal authorization decision (minted ath-N).

        Fail-closed: requires a booked ``sar`` assessment for the
        package, and refuses when the package already carries an
        authorization.
        """
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(package_id, "package_id")
                self._require_live(pid)
                if (not isinstance(authorization_type, str)
                        or authorization_type not in _AUTHORIZATION_TYPES):
                    raise BadAuthorizationTypeError(
                        f"authorization_type must be one of "
                        f"{sorted(_AUTHORIZATION_TYPES)}")
                pin = _check_digest(authorizer_digest, "authorizer_digest")
                sar_ids = [a.assessment_id
                           for a in self._assessments.values()
                           if a.package_id == pid
                           and a.assessment_type == "sar"]
                if not sar_ids:
                    raise AuthorizationDeniedError(
                        f"no sar assessment booked for package {pid!r}")
                if pid in self._package_auth:
                    raise AlreadyAuthorizedError(
                        f"package already authorized: {pid!r}")
                self._ath_counter += 1
                ath_id = f"ath-{self._ath_counter}"
                rec = AuthorizationRecord(
                    authorization_id=ath_id, package_id=pid,
                    authorization_type=authorization_type,
                    assessment_id=sar_ids[-1],
                    authorizer_pin=pin,
                    digest=_record_digest("authorization", {
                        "authorization_id": ath_id, "package_id": pid,
                        "authorization_type": authorization_type,
                        "assessment_id": sar_ids[-1],
                        "authorizer_pin": pin}))
                self._authorizations[ath_id] = rec
                self._package_auth[pid] = ath_id
                self._emit(KIND_AUTHORIZED,
                           {"authorization_id": ath_id, "package_id": pid,
                            "authorization_type": authorization_type,
                            "assessment_id": sar_ids[-1]},
                           seq_v)
                return rec
            except FedRAMPError as exc:
                self._burn(seq_v, "authorize", exc)
                raise

    def monitor(self, package_id: object, seq: object,
                outcome: object = "on-track",
                conmon_digest: object = "") -> MonitorRecord:
        """Book one declared ConMon observation (minted mon-N).

        Fail-closed: requires an active (authorized, non-revoked)
        package; repeatable as a monitoring chain.
        """
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(package_id, "package_id")
                self._require_live(pid)
                if not isinstance(outcome, str) or outcome not in _MONITOR_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(_MONITOR_OUTCOMES)}")
                pin = _check_digest(conmon_digest, "conmon_digest")
                if pid not in self._package_auth:
                    raise AuthorizationDeniedError(
                        f"no active authorization for package {pid!r}")
                self._mon_counter += 1
                mon_id = f"mon-{self._mon_counter}"
                rec = MonitorRecord(
                    monitor_id=mon_id, package_id=pid,
                    outcome=outcome, conmon_pin=pin,
                    digest=_record_digest("monitor", {
                        "monitor_id": mon_id, "package_id": pid,
                        "outcome": outcome, "conmon_pin": pin}))
                self._monitors[mon_id] = rec
                self._monitor_chain.setdefault(pid, []).append(mon_id)
                self._emit(KIND_MONITORED,
                           {"monitor_id": mon_id, "package_id": pid,
                            "outcome": outcome},
                           seq_v)
                return rec
            except FedRAMPError as exc:
                self._burn(seq_v, "monitor", exc)
                raise

    def revoke(self, package_id: object, seq: object,
               reason: object = "manual") -> RevokeRecord:
        """Revoke a package authorization (terminal; id never recycled)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(package_id, "package_id")
                if pid in self._revoked:
                    raise DoubleRevokeError(
                        f"package already revoked: {pid!r}")
                if pid not in self._packages:
                    raise UnknownPackageError(f"unknown package: {pid!r}")
                if not isinstance(reason, str) or reason not in _REVOKE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(_REVOKE_REASONS)}")
                rec = RevokeRecord(
                    package_id=pid, reason=reason,
                    digest=_record_digest("revoke", {
                        "package_id": pid, "reason": reason}))
                self._revoked[pid] = rec
                self._emit(KIND_REVOKED,
                           {"package_id": pid, "reason": reason},
                           seq_v)
                return rec
            except FedRAMPError as exc:
                self._burn(seq_v, "revoke", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def package_record(self, package_id: object,
                       seq: object) -> PackageRecord:
        """Return one package record (pure read)."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(package_id, "package_id")
            if pid not in self._packages:
                raise UnknownPackageError(f"unknown package: {pid!r}")
            return self._packages[pid]

    def package_ids(self, seq: object) -> Tuple[str, ...]:
        """All registered package ids in registration order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._packages.keys())

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

    def assessments_for(self, package_id: object,
                        seq: object) -> Tuple[str, ...]:
        """Assessment ids booked against one package (mint order)."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(package_id, "package_id")
            if pid not in self._packages:
                raise UnknownPackageError(f"unknown package: {pid!r}")
            return tuple(a.assessment_id for a in self._assessments.values()
                         if a.package_id == pid)

    def authorization_record(self, package_id: object,
                             seq: object) -> AuthorizationRecord:
        """Return the authorization for one package (pure read)."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(package_id, "package_id")
            if pid not in self._package_auth:
                raise AuthorizationDeniedError(
                    f"no authorization for package {pid!r}")
            return self._authorizations[self._package_auth[pid]]

    def is_authorized(self, package_id: object,
                      seq: object) -> bool:
        """Whether a package carries a live (non-revoked) authorization."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(package_id, "package_id")
            return pid in self._package_auth and pid not in self._revoked

    def authorized_ids(self, seq: object) -> Tuple[str, ...]:
        """Package ids with live authorizations, in authorization order."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(
                (pid for pid in self._package_auth
                 if pid not in self._revoked),
                key=lambda pid: self._authorizations[self._package_auth[pid]
                                                     ].authorization_id))

    def monitors_for(self, package_id: object,
                     seq: object) -> Tuple[str, ...]:
        """Monitor ids booked against one package (mint order)."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(package_id, "package_id")
            if pid not in self._packages:
                raise UnknownPackageError(f"unknown package: {pid!r}")
            return tuple(self._monitor_chain.get(pid, ()))

    def revoked_ids(self, seq: object) -> Tuple[str, ...]:
        """Revoked package ids in revocation order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._revoked.keys())

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
                "packages": len(self._packages),
                "assessments": len(self._assessments),
                "authorizations": len(self._authorizations),
                "monitors": len(self._monitors),
                "revoked": len(self._revoked),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    f = FedRAMP()
    f.register("csp-acme", 1, baseline="moderate")
    a1 = f.assess("csp-acme", 2, assessment_type="readiness",
                  finding="compliant")
    assert a1.verify()
    a2 = f.assess("csp-acme", 3, assessment_type="sar",
                  finding="compliant")
    ath = f.authorize("csp-acme", 4, authorization_type="agency-ato")
    assert ath.verify()
    assert ath.assessment_id == a2.assessment_id
    f.monitor("csp-acme", 5, outcome="on-track")
    f.monitor("csp-acme", 6, outcome="poam-open")
    assert f.is_authorized("csp-acme", 7)
    assert f.stats(8) == {"packages": 1, "assessments": 2,
                          "authorizations": 1, "monitors": 2,
                          "revoked": 0, "rejected": 0}
    print("fedramp OK: register, assess, authorize, monitor, pins, audit")


if __name__ == "__main__":
    main()
