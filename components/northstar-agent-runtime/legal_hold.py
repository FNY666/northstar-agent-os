"""Legal hold: eDiscovery litigation-hold lifecycle ledger, Simulated.

Research note: a legal hold is a defensible-preservation directive - once
litigation (or a regulatory request, subpoena, or internal investigation)
is reasonably anticipated, the organization must freeze the destruction of
potentially relevant data for the named matter and custodians, keep the
hold in force while the matter is open, and release it (with a record of
the release decision) when the duty ends. What matters here is the
*decision ledger*: which holds were issued, what scope they claim, and
which were released - defensible bookkeeping, not proof of preservation.

This module is the *legal-hold decision* layer, deliberately distinct
from its siblings:

- ``legal_agents.py`` - agent-facing legal-domain interfaces.
- ``forensics.py`` - the DFIR case lifecycle (acquire / analyze /
  preserve): it preserves *evidence*; this module preserves *the
  decision to freeze destruction*.
- ``vuln_disclosure.py`` - coordinated vulnerability disclosure lifecycle.

This module owns the issue -> release -> audit lifecycle:

* **issue()** - declare one legal hold issued for a matter and set of
  custodians (pinned reason and scope vocabularies; matter and custodian
  identifiers travel as ``sha256:`` digest pins only - raw names, email
  addresses, and matter descriptions never enter records).
* **release()** - terminal release of a hold (pinned reason vocabulary);
  released ids are never recycled.
* **audit()** - pure read view: active/released status tallies and
  per-hold summaries as data, digest-pinned with ``verify()``.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``legal-hold.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module preserves no data, enforces no retention, and
notifies no custodians. A booked ``active`` means "the ledger says the
hold was issued and not yet released", never "data is actually
preserved". Matter descriptions, custodian identifiers, and scope details
never cross the module boundary - digest pins only.
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
LEGAL_HOLD_VERSION = "legal-hold.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.legal-hold.v1"

#: Pinned issue-reason vocabulary (why the hold was declared).
ISSUE_REASONS = (
    "litigation",
    "investigation",
    "regulatory-request",
    "subpoena",
    "audit",
    "manual",
)

#: Pinned scope vocabulary (what the hold claims to freeze).
SCOPES = (
    "all-data",
    "email",
    "documents",
    "chat",
    "code",
    "backups",
    "financial-records",
)

#: Pinned release-reason vocabulary (why the hold was lifted).
RELEASE_REASONS = (
    "matter-closed",
    "hold-superseded",
    "court-order",
    "scope-reduced",
    "manual",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "issued",
    "released",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "matter",
        "matter_name",
        "matter_description",
        "description",
        "custodian",
        "custodian_id",
        "custodian_name",
        "custodians",
        "email",
        "email_address",
        "name",
        "subject",
        "scope_detail",
        "scope_description",
        "reason_detail",
        "note",
        "notes",
        "text",
        "content",
        "payload",
        "raw",
        "data",
        "document",
        "secret",
        "private_key",
        "key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LegalHoldError(Exception):
    """Base error for legal-hold ledger misuse."""


class BadHoldError(LegalHoldError):
    """Malformed hold id."""


class DuplicateHoldError(LegalHoldError):
    """Hold id already issued."""


class ReleasedHoldError(LegalHoldError):
    """Hold id released; never recycled."""


class UnknownHoldError(LegalHoldError):
    """Hold id not issued."""


class BadReasonError(LegalHoldError):
    """Unknown issue or release reason."""


class BadScopeError(LegalHoldError):
    """Unknown hold scope."""


class BadDigestError(LegalHoldError):
    """Malformed sha256: digest pin."""


class SeqOrderError(LegalHoldError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(LegalHoldError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadHoldError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
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
class HoldRecord:
    hold_id: str
    issue_reason: str
    scope: str
    matter_digest: str
    custodian_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "hold_id": self.hold_id,
            "issue_reason": self.issue_reason,
            "scope": self.scope,
            "matter_digest": self.matter_digest,
            "custodian_digest": self.custodian_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "hold_id": self.hold_id,
                "issue_reason": self.issue_reason,
                "scope": self.scope,
                "matter_digest": self.matter_digest,
                "custodian_digest": self.custodian_digest,
            }
        )


@dataclass(frozen=True)
class ReleaseRecord:
    hold_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "hold_id": self.hold_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "hold_id": self.hold_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class AuditReport:
    n_holds: int
    n_active: int
    n_released: int
    statuses: Tuple[Tuple[str, str], ...]
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "n_holds": self.n_holds,
            "n_active": self.n_active,
            "n_released": self.n_released,
            "statuses": [
                {"hold_id": hold_id, "status": status}
                for hold_id, status in self.statuses
            ],
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "n_holds": self.n_holds,
                "n_active": self.n_active,
                "n_released": self.n_released,
                "statuses": [
                    {"hold_id": hold_id, "status": status}
                    for hold_id, status in self.statuses
                ],
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def legal_hold_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the legal-hold ledger."""
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


class LegalHold:
    """Legal-hold (eDiscovery) decision ledger, Simulated.

    ``issue()`` / ``release()`` mutate the ledger and consume caller seqs;
    ``audit()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._holds: Dict[str, HoldRecord] = {}
        self._releases: Dict[str, ReleaseRecord] = {}
        self._released: set = set()
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0

    # -- seq discipline ----------------------------------------------------

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
            row = legal_hold_audit_event("rejected", seq,
                                         rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(legal_hold_audit_event(audit_kind, seq, **details))

    def _live_hold(self, hold_id: str) -> None:
        """Fail-closed: hold must be issued and not released."""
        if hold_id in self._released:
            raise ReleasedHoldError(
                f"hold id released, never recycled: {hold_id!r}")
        if hold_id not in self._holds:
            raise UnknownHoldError(f"unknown hold: {hold_id!r}")

    # -- issue ---------------------------------------------------------------

    def issue(
        self,
        hold_id: str,
        seq: int,
        issue_reason: str = "litigation",
        scope: str = "all-data",
        matter_digest: str = "",
        custodian_digest: str = "",
    ) -> HoldRecord:
        """Declare one legal hold issued.

        The matter and custodian identifiers travel as ``sha256:`` digest
        pins only - raw matter descriptions and custodian identifiers never
        enter records.
        """
        with self._lock:
            try:
                self._claim(seq)
            except LegalHoldError:
                raise
            try:
                _require_id(hold_id, "hold_id")
                if issue_reason not in ISSUE_REASONS:
                    raise BadReasonError(
                        f"issue_reason must be one of {ISSUE_REASONS}")
                if scope not in SCOPES:
                    raise BadScopeError(f"scope must be one of {SCOPES}")
                if matter_digest:
                    _require_digest(matter_digest, "matter_digest")
                else:
                    matter_digest = "sha256:" + "00" * 32
                if custodian_digest:
                    _require_digest(custodian_digest, "custodian_digest")
                else:
                    custodian_digest = "sha256:" + "00" * 32
                if hold_id in self._released:
                    raise ReleasedHoldError(
                        f"hold id released, never recycled: {hold_id!r}")
                if hold_id in self._holds:
                    raise DuplicateHoldError(
                        f"hold already issued: {hold_id!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "hold_id": hold_id,
                     "issue_reason": issue_reason, "scope": scope,
                     "matter_digest": matter_digest,
                     "custodian_digest": custodian_digest}
                )
                record = HoldRecord(
                    hold_id=hold_id, issue_reason=issue_reason, scope=scope,
                    matter_digest=matter_digest,
                    custodian_digest=custodian_digest, digest=digest,
                )
                self._holds[hold_id] = record
                self._emit(
                    "issued", seq, hold_id=hold_id,
                    issue_reason=issue_reason, scope=scope,
                )
                return record
            except LegalHoldError:
                self._burn(seq, "issue")
                raise

    # -- release ---------------------------------------------------------------

    def release(
        self, hold_id: str, seq: int, reason: str = "matter-closed"
    ) -> ReleaseRecord:
        """Terminal: release a legal hold. The id is never recycled."""
        with self._lock:
            try:
                self._claim(seq)
            except LegalHoldError:
                raise
            try:
                self._live_hold(hold_id)
                if reason not in RELEASE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {RELEASE_REASONS}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "hold_id": hold_id,
                     "reason": reason}
                )
                record = ReleaseRecord(
                    hold_id=hold_id, reason=reason, digest=digest)
                self._releases[hold_id] = record
                self._released.add(hold_id)
                self._emit("released", seq, hold_id=hold_id, reason=reason)
                return record
            except LegalHoldError:
                self._burn(seq, "release")
                raise

    # -- audit (pure read) -------------------------------------------------------

    def audit(self, seq: int, hold_id: str = "") -> AuditReport:
        """Pure read: hold-status tallies as data, digest-pinned.

        With ``hold_id`` set, the report scopes to that one hold (unknown
        ids report zero counts as data, never raised); without it, the
        report covers the whole ledger.
        """
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("audit seq must be a non-negative int")
            if hold_id:
                ids: List[str] = [hold_id] if hold_id in self._holds else []
            else:
                ids = sorted(self._holds)
            statuses: List[Tuple[str, str]] = []
            integrity_ok = True
            for hid in ids:
                record = self._holds[hid]
                if not record.verify():
                    integrity_ok = False
                release = self._releases.get(hid)
                if release is not None and not release.verify():
                    integrity_ok = False
                status = "released" if hid in self._released else "active"
                statuses.append((hid, status))
            n_released = sum(1 for _, s in statuses if s == "released")
            statuses_tuple = tuple(sorted(statuses))
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "n_holds": len(statuses),
                    "n_active": len(statuses) - n_released,
                    "n_released": n_released,
                    "statuses": [
                        {"hold_id": hid, "status": s}
                        for hid, s in statuses_tuple
                    ],
                    "integrity_ok": integrity_ok,
                }
            )
            return AuditReport(
                n_holds=len(statuses),
                n_active=len(statuses) - n_released,
                n_released=n_released,
                statuses=statuses_tuple,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def hold_record(self, hold_id: str, seq: int) -> HoldRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._holds.get(hold_id)
            if record is None:
                raise UnknownHoldError(f"unknown hold: {hold_id!r}")
            return record

    def release_record(self, hold_id: str, seq: int) -> ReleaseRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._releases.get(hold_id)
            if record is None:
                raise UnknownHoldError(
                    f"no release booked for hold: {hold_id!r}")
            return record

    def hold_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._holds))

    def active_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(set(self._holds) - self._released))

    def released_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._released))

    def is_active(self, hold_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq_ok(seq)
            return hold_id in self._holds and hold_id not in self._released

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "holds": len(self._holds),
                "active": len(self._holds) - len(self._released),
                "released": len(self._released),
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)


def main() -> None:
    h = LegalHold()
    rec = h.issue("hold-1", 1, issue_reason="litigation", scope="email")
    assert rec.verify()
    assert h.is_active("hold-1", 0)
    report = h.audit(0)
    assert report.verify()
    assert report.n_holds == 1 and report.n_active == 1
    assert report.statuses == (("hold-1", "active"),)
    rel = h.release("hold-1", 2, reason="matter-closed")
    assert rel.verify()
    report2 = h.audit(0)
    assert report2.verify()
    assert report2.n_released == 1 and report2.n_active == 0
    print("legal-hold OK: issue, release, audit, pins")


if __name__ == "__main__":
    main()
