"""Vendor risk: third-party risk assessment and lifecycle ledger, Simulated.

Research note: third-party (vendor/supplier) risk management is the
governance discipline of identifying, assessing, and monitoring the
security and compliance risk that outside vendors bring into an
organization - from a cloud SaaS provider processing customer data to a
subcontracted dev shop with code access. The typical lifecycle is
assess (risk-rate the vendor before / at contract time) -> monitor
(ongoing due-diligence observations) -> offboard (terminate the
relationship, a terminal decision booked in the ledger).

This module is the *assessment-decision* ledger layer:

* **assess()** - book one declared risk assessment of a vendor: a
  pinned risk class (``low``/``medium``/``high``/``critical``) declared
  by the host. Vendor identity, questionnaires, and evidence travel as
  ``sha256:`` digest pins only - raw vendor details never enter a
  record.
* **monitor()** - book one declared monitoring observation against a
  live (non-offboarded) vendor over a pinned status vocabulary. A
  booked ``elevated`` is host-reported GIGO, never proof of an
  incident.
* **offboard()** - terminal: book the declared termination of the
  vendor relationship. Offboarded vendor ids are retired forever;
  post-offboard assess/monitor are refused fail-closed.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
a ``vendor-risk.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module assesses no vendors, inspects no
questionnaires, and terminates no contracts. All assessments are
host-declared GIGO booked under digest pins; a booked ``critical``
means "the host declared the vendor critical", never "the vendor is
critical". Raw vendor names, questionnaire contents, evidence, and
contract terms never cross the module boundary.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent
    import json

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
VENDOR_RISK_VERSION = "vendor-risk.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.vendor-risk.v1"

#: Pinned risk-class vocabulary for declared vendor assessments.
RISK_CLASSES = (
    "low",
    "medium",
    "high",
    "critical",
)

#: Pinned status vocabulary for declared monitoring observations.
MONITOR_STATUSES = (
    "unchanged",
    "improved",
    "elevated",
    "breach-reported",
)

#: Pinned reason vocabulary for terminal offboard decisions.
OFFBOARD_REASONS = (
    "manual",
    "risk-too-high",
    "contract-ended",
    "breach",
    "replaced",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "assessed",
    "monitored",
    "offboarded",
    "rejected",
)

#: Raw-content keys that must never cross the audit boundary.
_BANNED_AUDIT_KEYS = (
    "vendor",
    "vendor_name",
    "company",
    "profile",
    "questionnaire",
    "evidence",
    "notes",
    "contract",
    "terms",
    "contact",
    "email",
    "address",
    "document",
    "report",
    "finding",
    "detail",
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class VendorRiskError(Exception):
    """Base error for vendor-risk ledger misuse."""


class BadIdError(VendorRiskError):
    """Raised for malformed vendor/monitor identifiers."""


class DuplicateVendorError(VendorRiskError):
    """Raised when a vendor id is assessed twice (ids never recycle)."""


class UnknownVendorError(VendorRiskError):
    """Raised when a vendor id was never assessed."""


class OffboardedVendorError(VendorRiskError):
    """Raised when a mutation targets an offboarded (retired) vendor."""


class BadRiskClassError(VendorRiskError):
    """Raised for a risk class outside the pinned vocabulary."""


class BadStatusError(VendorRiskError):
    """Raised for a monitor status outside the pinned vocabulary."""


class BadReasonError(VendorRiskError):
    """Raised for an offboard reason outside the pinned vocabulary."""


class BadDigestError(VendorRiskError):
    """Raised when a digest pin is not a ``sha256:<64hex>`` pin."""


class SeqOrderError(VendorRiskError):
    """Raised for rewinds and malformed seqs."""


class AuditKindError(VendorRiskError):
    """Raised for unknown audit kinds."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------


def _is_digest_pin(value: str) -> bool:
    """Check the ``sha256:<64hex>`` pin shape."""
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    body = value[7:]
    return len(body) == 64 and all(c in "0123456789abcdef" for c in body)


def _check_digest(value: str, field: str) -> str:
    """Validate an optional digest pin (``""`` allowed, anything else pinned)."""
    if not isinstance(value, str):
        raise BadDigestError(f"{field} digest must be a str")
    if value and not _is_digest_pin(value):
        raise BadDigestError(f"{field} digest must be '' or sha256:<64hex>")
    return value


def _digest_pin(payload: Any) -> str:
    """Canonical digest pin for a record payload."""
    pin = _jcs_hash(payload)
    if not isinstance(pin, str):  # pragma: no cover - defensive
        raise BadDigestError("digest helper did not return a str")
    if not pin.startswith("sha256:"):
        pin = "sha256:" + pin
    return pin


def _check_id(value: str, field: str = "vendor_id") -> str:
    """Validate an identifier: non-empty str, bounded length."""
    if not isinstance(value, str):
        raise BadIdError(f"{field} must be a str")
    if not value:
        raise BadIdError(f"{field} must be non-empty")
    if len(value) > 256:
        raise BadIdError(f"{field} must be <= 256 chars")
    return value


def _check_audit_detail(details: Dict[str, Any]) -> None:
    """Refuse raw-content keys at the audit boundary (exact-key match)."""
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise BadDigestError(f"raw content key {key!r} banned from audit boundary")


def vendor_risk_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1``-shaped audit event."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    _check_audit_detail(details)
    return {
        "audit": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    """One declared vendor risk assessment (digest-pinned)."""

    vendor_id: str
    risk_class: str
    seq: int
    profile_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "vendor_id": self.vendor_id,
            "risk_class": self.risk_class,
            "seq": self.seq,
            "profile_digest": self.profile_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        payload = {
            "vendor_id": self.vendor_id,
            "risk_class": self.risk_class,
            "seq": self.seq,
            "profile_digest": self.profile_digest,
        }
        return self.digest == _digest_pin(payload)


@dataclass(frozen=True)
class MonitorRecord:
    """One declared monitoring observation (digest-pinned)."""

    monitor_id: str
    vendor_id: str
    status: str
    seq: int
    note_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "monitor_id": self.monitor_id,
            "vendor_id": self.vendor_id,
            "status": self.status,
            "seq": self.seq,
            "note_digest": self.note_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        payload = {
            "monitor_id": self.monitor_id,
            "vendor_id": self.vendor_id,
            "status": self.status,
            "seq": self.seq,
            "note_digest": self.note_digest,
        }
        return self.digest == _digest_pin(payload)


@dataclass(frozen=True)
class OffboardRecord:
    """One terminal offboard decision (digest-pinned)."""

    vendor_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "vendor_id": self.vendor_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        payload = {
            "vendor_id": self.vendor_id,
            "reason": self.reason,
            "seq": self.seq,
        }
        return self.digest == _digest_pin(payload)


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class VendorRisk:
    """Third-party risk assessment and lifecycle ledger, Simulated."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._monitors: Dict[str, MonitorRecord] = {}
        self._monitors_for: Dict[str, List[str]] = {}
        self._offboarded: Dict[str, OffboardRecord] = {}
        self._monitor_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------
    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _claim(self, seq: int) -> int:
        """Claim a seq for a mutation; rewinds raise bare without consuming."""
        seq = self._check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq {seq} must exceed last {self._last_seq}")
        self._last_seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(vendor_risk_audit_event(audit_kind, seq, **details))

    def _reject(self, seq: int, reason: str) -> None:
        self._emit("rejected", seq, reason=reason)

    # -- lifecycle ----------------------------------------------------------
    def assess(
        self,
        vendor_id: str,
        seq: int,
        risk_class: str = "medium",
        profile_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared risk assessment of a vendor."""
        with self._lock:
            seq = self._claim(seq)
            try:
                vendor_id = _check_id(vendor_id)
                profile_digest = _check_digest(profile_digest, "profile")
                if vendor_id in self._offboarded:
                    raise OffboardedVendorError(
                        f"vendor offboarded, id never recycled: {vendor_id!r}"
                    )
                if vendor_id in self._assessments:
                    raise DuplicateVendorError(
                        f"vendor already assessed: {vendor_id!r}"
                    )
                if risk_class not in RISK_CLASSES:
                    raise BadRiskClassError(
                        f"risk_class must be one of {RISK_CLASSES}"
                    )
                payload = {
                    "vendor_id": vendor_id,
                    "risk_class": risk_class,
                    "seq": seq,
                    "profile_digest": profile_digest,
                }
                record = AssessmentRecord(
                    vendor_id=vendor_id,
                    risk_class=risk_class,
                    seq=seq,
                    profile_digest=profile_digest,
                    digest=_digest_pin(payload),
                )
                self._assessments[vendor_id] = record
                self._monitors_for[vendor_id] = []
                self._emit(
                    "assessed",
                    seq,
                    vendor_id=vendor_id,
                    risk_class=risk_class,
                    digest=record.digest,
                )
                return record
            except VendorRiskError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def monitor(
        self,
        vendor_id: str,
        seq: int,
        status: str = "unchanged",
        note_digest: str = "",
    ) -> MonitorRecord:
        """Book one declared monitoring observation for a live vendor."""
        with self._lock:
            seq = self._claim(seq)
            try:
                vendor_id = _check_id(vendor_id)
                note_digest = _check_digest(note_digest, "note")
                if vendor_id in self._offboarded:
                    raise OffboardedVendorError(
                        f"vendor offboarded: {vendor_id!r}"
                    )
                if vendor_id not in self._assessments:
                    raise UnknownVendorError(
                        f"vendor never assessed: {vendor_id!r}"
                    )
                if status not in MONITOR_STATUSES:
                    raise BadStatusError(
                        f"status must be one of {MONITOR_STATUSES}"
                    )
                self._monitor_seq += 1
                monitor_id = f"mon-{self._monitor_seq}"
                payload = {
                    "monitor_id": monitor_id,
                    "vendor_id": vendor_id,
                    "status": status,
                    "seq": seq,
                    "note_digest": note_digest,
                }
                record = MonitorRecord(
                    monitor_id=monitor_id,
                    vendor_id=vendor_id,
                    status=status,
                    seq=seq,
                    note_digest=note_digest,
                    digest=_digest_pin(payload),
                )
                self._monitors[monitor_id] = record
                self._monitors_for[vendor_id].append(monitor_id)
                self._emit(
                    "monitored",
                    seq,
                    monitor_id=monitor_id,
                    vendor_id=vendor_id,
                    status=status,
                    digest=record.digest,
                )
                return record
            except VendorRiskError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def offboard(
        self, vendor_id: str, seq: int, reason: str = "manual"
    ) -> OffboardRecord:
        """Terminally book the end of the vendor relationship."""
        with self._lock:
            seq = self._claim(seq)
            try:
                vendor_id = _check_id(vendor_id)
                if vendor_id in self._offboarded:
                    raise OffboardedVendorError(
                        f"vendor already offboarded: {vendor_id!r}"
                    )
                if vendor_id not in self._assessments:
                    raise UnknownVendorError(
                        f"vendor never assessed: {vendor_id!r}"
                    )
                if reason not in OFFBOARD_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {OFFBOARD_REASONS}"
                    )
                payload = {
                    "vendor_id": vendor_id,
                    "reason": reason,
                    "seq": seq,
                }
                record = OffboardRecord(
                    vendor_id=vendor_id,
                    reason=reason,
                    seq=seq,
                    digest=_digest_pin(payload),
                )
                self._offboarded[vendor_id] = record
                self._emit(
                    "offboarded",
                    seq,
                    vendor_id=vendor_id,
                    reason=reason,
                    digest=record.digest,
                )
                return record
            except VendorRiskError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views -----------------------------------------------------
    def assessment_record(self, vendor_id: str, seq: int) -> AssessmentRecord:
        """Read a vendor's assessment (seq validated, never consumed)."""
        self._check_seq(seq)
        vendor_id = _check_id(vendor_id)
        if vendor_id not in self._assessments:
            raise UnknownVendorError(f"vendor never assessed: {vendor_id!r}")
        return self._assessments[vendor_id]

    def monitor_record(self, monitor_id: str, seq: int) -> MonitorRecord:
        """Read one monitoring observation (pure read)."""
        self._check_seq(seq)
        monitor_id = _check_id(monitor_id, "monitor_id")
        if monitor_id not in self._monitors:
            raise UnknownVendorError(f"unknown monitor: {monitor_id!r}")
        return self._monitors[monitor_id]

    def monitors_for(self, vendor_id: str, seq: int) -> Tuple[str, ...]:
        """List monitor ids for a vendor in booking order (pure read)."""
        self._check_seq(seq)
        vendor_id = _check_id(vendor_id)
        if vendor_id not in self._assessments:
            raise UnknownVendorError(f"vendor never assessed: {vendor_id!r}")
        return tuple(self._monitors_for[vendor_id])

    def offboard_record(self, vendor_id: str, seq: int) -> OffboardRecord:
        """Read a vendor's terminal offboard record (pure read)."""
        self._check_seq(seq)
        vendor_id = _check_id(vendor_id)
        if vendor_id not in self._offboarded:
            raise UnknownVendorError(f"vendor not offboarded: {vendor_id!r}")
        return self._offboarded[vendor_id]

    def vendor_ids(self, seq: int) -> Tuple[str, ...]:
        """All assessed vendor ids, sorted (pure read)."""
        self._check_seq(seq)
        return tuple(sorted(self._assessments))

    def live_ids(self, seq: int) -> Tuple[str, ...]:
        """Assessed and not offboarded, sorted (pure read)."""
        self._check_seq(seq)
        return tuple(sorted(v for v in self._assessments if v not in self._offboarded))

    def offboarded_ids(self, seq: int) -> Tuple[str, ...]:
        """Offboarded vendor ids, sorted (pure read)."""
        self._check_seq(seq)
        return tuple(sorted(self._offboarded))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counts as data (pure read)."""
        self._check_seq(seq)
        return {
            "vendors": len(self._assessments),
            "live": len(self.live_ids(seq)),
            "offboarded": len(self._offboarded),
            "monitors": len(self._monitors),
            "audit_rows": len(self._audit),
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Full audit trail (pure read)."""
        self._check_seq(seq)
        return tuple(self._audit)


def main() -> None:
    v = VendorRisk()
    a = v.assess("vendor-1", 1, risk_class="high", profile_digest="sha256:" + "aa" * 32)
    assert a.verify()
    m = v.monitor("vendor-1", 2, status="elevated", note_digest="sha256:" + "bb" * 32)
    assert m.verify()
    o = v.offboard("vendor-1", 3, reason="risk-too-high")
    assert o.verify()
    assert v.offboarded_ids(3) == ("vendor-1",)
    assert v.stats(3)["live"] == 0
    print("vendor-risk OK: assess, monitor, offboard, pins, audit")


if __name__ == "__main__":
    main()
