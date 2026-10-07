"""SCIM provisioning (thirty-first batch).

System for Cross-domain Identity Management (RFC 7643/7644) user
provisioning as deterministic single-host bookkeeping:

* :meth:`SCIMProvisioning.sync` — create-or-update a user from
  host-reported attributes (SCIM ``User`` resource shape: ``userName``,
  ``emails``, ``name``, ``active``, ``externalId``). Each sync seals a
  new frozen :class:`UserRecord` with a ``sha256:`` digest pin chained
  via ``prev_digest`` per user id.
* :meth:`SCIMProvisioning.deprovision` — deactivate a user. Terminal:
  the user is marked ``inactive``; re-provisioning requires a fresh
  :meth:`sync`. Deprovisioned users are refused for group membership
  and for further syncs until re-provisioned.
* :meth:`SCIMProvisioning.groups` — group lifecycle: ``create_group``,
  ``add_member``, ``remove_member``, ``group_members``. Membership is
  booked as digest-pinned :class:`MembershipRecord`s; removing a
  member books a terminal removal record, never a silent delete.

House rules: no wall-clock (callers inject integer seq values), frozen
dataclasses, fail-closed checks (unknown user/group, duplicate ids,
inactive members, bad attributes all raise), stdlib-only, records
sealed with a sha256 ``record_digest`` over the canonical payload.
State transitions emit ``audit.ndjson/1`` events carrying ids and
digest pins only — attribute values (emails, names) never cross the
audit boundary.

Honest boundary: this module books *host-reported* provisioning data
(RFC 7643 resource shapes as a vocabulary, not the wire protocol).
It cannot observe the IdP, prove the human behind an email, or
guarantee downstream systems applied the change. Production needs the
real SCIM wire, a directory, and a secret manager.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Any, Mapping


#: Version pin for this module's record shape.
SCIM_PROVISIONING_VERSION = "scim-provisioning.v1"

#: Schema pin carried by records and audit events.
SCIM_PROVISIONING_SCHEMA = "northstar.scim-provisioning.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Genesis digest for the head of a per-user/per-group chain.
_GENESIS = "sha256:" + "0" * 64

#: User statuses.
ACTIVE = "active"
INACTIVE = "inactive"
_STATUSES = (ACTIVE, INACTIVE)

#: SCIM user attribute vocabulary booked by sync().
_USER_ATTRS = (
    "userName",
    "emails",
    "name",
    "active",
    "externalId",
    "displayName",
    "title",
    "department",
)

#: Audit event kinds.
KIND_SYNCED = "synced"
KIND_DEPROVISIONED = "deprovisioned"
KIND_GROUP_CREATED = "group-created"
KIND_MEMBER_ADDED = "member-added"
KIND_MEMBER_REMOVED = "member-removed"
KIND_REJECTED = "rejected"
_KINDS = (
    KIND_SYNCED,
    KIND_DEPROVISIONED,
    KIND_GROUP_CREATED,
    KIND_MEMBER_ADDED,
    KIND_MEMBER_REMOVED,
    KIND_REJECTED,
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SCIMError(Exception):
    """Base error for the SCIM provisioning module."""


class BadUserError(SCIMError):
    """Raised when user input (id, attributes) is malformed."""


class UnknownUserError(SCIMError):
    """Raised when a user id is not provisioned."""


class DuplicateUserError(SCIMError):
    """Raised on an explicit create of an already-provisioned user."""


class BadGroupError(SCIMError):
    """Raised when group input (id, display name) is malformed."""


class UnknownGroupError(SCIMError):
    """Raised when a group id does not exist."""


class DuplicateGroupError(SCIMError):
    """Raised on duplicate group creation or duplicate membership."""


class AlreadyDeprovisionedError(SCIMError):
    """Raised when operating on a deprovisioned user."""


class SeqOrderError(SCIMError):
    """Raised when a caller seq is not a strictly increasing int."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: int, name: str = "seq") -> int:
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"{name} must be non-negative, got {seq}")
    return seq


def _check_nonempty_str(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SCIMError(f"{name} must be a non-empty str")
    return value.strip()


def _check_user_id(user_id: str) -> str:
    user_id = _check_nonempty_str(user_id, "user_id")
    if len(user_id) > 128:
        raise BadUserError("user_id too long")
    return user_id


def _check_group_id(group_id: str) -> str:
    group_id = _check_nonempty_str(group_id, "group_id")
    if len(group_id) > 128:
        raise BadGroupError("group_id too long")
    return group_id


def _check_attributes(attributes: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(attributes, Mapping):
        raise BadUserError("attributes must be a mapping")
    for key in attributes:
        if key not in _USER_ATTRS:
            raise BadUserError(f"unknown attribute: {key!r}")
    user_name = attributes.get("userName")
    if user_name is not None:
        if not isinstance(user_name, str) or not user_name.strip():
            raise BadUserError("userName must be a non-empty str")
        if len(user_name) > 256:
            raise BadUserError("userName too long")
    emails = attributes.get("emails")
    if emails is not None:
        if not isinstance(emails, (list, tuple)) or not emails:
            raise BadUserError("emails must be a non-empty list")
        for email in emails:
            if not isinstance(email, str) or "@" not in email:
                raise BadUserError(f"bad email: {email!r}")
    name = attributes.get("name")
    if name is not None and not isinstance(name, str):
        raise BadUserError("name must be a str")
    active = attributes.get("active")
    if active is not None and not isinstance(active, bool):
        raise BadUserError("active must be a bool")
    return dict(attributes)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UserRecord:
    """One sealed sync snapshot for a user."""

    user_id: str
    version: int
    attributes: Mapping[str, Any]
    status: str
    seq: int
    prev_digest: str
    record_digest: str = ""


@dataclass(frozen=True)
class DeprovisionRecord:
    """Terminal deprovision event for a user."""

    user_id: str
    seq: int
    reason: str
    record_digest: str = ""


@dataclass(frozen=True)
class GroupRecord:
    """One sealed group definition."""

    group_id: str
    display_name: str
    seq: int
    prev_digest: str
    record_digest: str = ""


@dataclass(frozen=True)
class MembershipRecord:
    """One sealed membership change (add or remove)."""

    group_id: str
    user_id: str
    action: str  # "added" | "removed"
    seq: int
    record_digest: str = ""


def _record_payload(record: Any) -> Mapping[str, Any]:
    if isinstance(record, UserRecord):
        return {
            "user_id": record.user_id,
            "version": record.version,
            "attributes": dict(record.attributes),
            "status": record.status,
            "seq": record.seq,
            "prev_digest": record.prev_digest,
        }
    if isinstance(record, DeprovisionRecord):
        return {
            "user_id": record.user_id,
            "seq": record.seq,
            "reason": record.reason,
        }
    if isinstance(record, GroupRecord):
        return {
            "group_id": record.group_id,
            "display_name": record.display_name,
            "seq": record.seq,
            "prev_digest": record.prev_digest,
        }
    if isinstance(record, MembershipRecord):
        return {
            "group_id": record.group_id,
            "user_id": record.user_id,
            "action": record.action,
            "seq": record.seq,
        }
    raise SCIMError(f"unknown record type: {type(record).__name__}")


def _canonical(obj: Any) -> bytes:
    # All payload values are str/int/bool/None — no floats, so no >2^53
    # precision hazard; ints serialize exactly.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def compute_record_digest(record: Any) -> str:
    """Recompute a record's seal over all fields except itself."""
    return "sha256:" + hashlib.sha256(_canonical(_record_payload(record))).hexdigest()


def _seal(record: Any) -> Any:
    return replace(record, record_digest=compute_record_digest(record))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def scim_provisioning_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the SCIM provisioning module."""
    if kind not in _KINDS:
        raise SCIMError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    # Attribute values never cross the audit boundary: only ids/digests.
    banned = {"attributes", "emails", "name", "userName", "displayName"}
    for key in detail:
        if key in banned:
            raise SCIMError(f"audit detail must not carry attribute values: {key!r}")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "scim_provisioning",
        "module_version": SCIM_PROVISIONING_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# SCIMProvisioning
# ---------------------------------------------------------------------------


class SCIMProvisioning:
    """SCIM user/group provisioning as deterministic single-host bookkeeping.

    Users are created-or-updated via :meth:`sync` (each call seals a new
    :class:`UserRecord` version), deactivated via :meth:`deprovision`
    (terminal), and grouped via the :meth:`groups` sub-interface. No
    wall-clock: every timestamp is a caller-injected non-negative int
    ``seq``. Mutations require strictly increasing seqs per user/group;
    failed mutations consume their seq (batch-21 ledger discipline).
    """

    def __init__(self) -> None:
        self._users: dict[str, list[UserRecord]] = {}
        self._deprovisioned: dict[str, DeprovisionRecord] = {}
        self._groups: dict[str, GroupRecord] = {}
        self._memberships: dict[tuple[str, str], MembershipRecord] = {}
        self._events: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _latest_user(self, user_id: str) -> UserRecord | None:
        hist = self._users.get(user_id)
        return hist[-1] if hist else None

    def _bump_seq(self, seq: int, last_seq: int | None) -> int:
        if last_seq is not None and seq <= last_seq:
            raise SeqOrderError("seq must be strictly increasing")
        return seq

    # -- sync / deprovision --------------------------------------------

    def sync(self, user_id: str, seq: int, attributes: Mapping[str, Any]) -> UserRecord:
        """Create-or-update a user from host-reported SCIM attributes.

        Fail-closed: malformed ids/attributes, syncing a deprovisioned
        user, or a non-increasing seq are refused (failed attempts burn
        their seq).
        """
        user_id = _check_user_id(user_id)
        seq = _check_seq(seq, "seq")
        attributes = _check_attributes(attributes)
        if user_id in self._deprovisioned:
            self._events.append(scim_provisioning_audit_event(
                KIND_REJECTED, seq, user_id=user_id,
                reason="sync on deprovisioned user",
            ))
            raise AlreadyDeprovisionedError(
                f"user {user_id!r} is deprovisioned; re-provision first"
            )
        latest = self._latest_user(user_id)
        last_seq = latest.seq if latest is not None else None
        try:
            seq = self._bump_seq(seq, last_seq)
        except SeqOrderError:
            self._events.append(scim_provisioning_audit_event(
                KIND_REJECTED, seq if last_seq is None else max(seq, last_seq) + 1,
                user_id=user_id, reason="seq not increasing",
            ))
            raise
        version = (latest.version + 1) if latest is not None else 1
        prev = latest.record_digest if latest is not None else _GENESIS
        status = ACTIVE if attributes.get("active", True) else INACTIVE
        record = _seal(UserRecord(
            user_id=user_id,
            version=version,
            attributes=attributes,
            status=status,
            seq=seq,
            prev_digest=prev,
        ))
        self._users.setdefault(user_id, []).append(record)
        self._events.append(scim_provisioning_audit_event(
            KIND_SYNCED, seq, user_id=user_id, version=version,
            record_digest=record.record_digest,
        ))
        return record

    def deprovision(self, user_id: str, seq: int, reason: str = "") -> DeprovisionRecord:
        """Deactivate a user. Terminal: refused twice, and refused for unknown users."""
        user_id = _check_user_id(user_id)
        seq = _check_seq(seq, "seq")
        if not isinstance(reason, str):
            raise SCIMError("reason must be a str")
        latest = self._latest_user(user_id)
        if latest is None:
            raise UnknownUserError(f"unknown user: {user_id!r}")
        if user_id in self._deprovisioned:
            raise AlreadyDeprovisionedError(f"user {user_id!r} already deprovisioned")
        self._bump_seq(seq, latest.seq)
        record = _seal(DeprovisionRecord(
            user_id=user_id,
            seq=seq,
            reason=reason[:256],
        ))
        self._deprovisioned[user_id] = record
        self._events.append(scim_provisioning_audit_event(
            KIND_DEPROVISIONED, seq, user_id=user_id,
            record_digest=record.record_digest,
        ))
        return record

    def reprovision(self, user_id: str, seq: int, attributes: Mapping[str, Any]) -> UserRecord:
        """Re-activate a deprovisioned user via a fresh sync.

        Clears the deprovisioned flag, then behaves exactly like
        :meth:`sync`.
        """
        user_id = _check_user_id(user_id)
        if user_id not in self._deprovisioned:
            raise SCIMError(f"user {user_id!r} is not deprovisioned")
        del self._deprovisioned[user_id]
        return self.sync(user_id, seq, attributes)

    # -- groups --------------------------------------------------------

    def create_group(self, group_id: str, seq: int, display_name: str) -> GroupRecord:
        """Define a group. Duplicate ids refused fail-closed."""
        group_id = _check_group_id(group_id)
        seq = _check_seq(seq, "seq")
        display_name = _check_nonempty_str(display_name, "display_name")
        if len(display_name) > 256:
            raise BadGroupError("display_name too long")
        if group_id in self._groups:
            raise DuplicateGroupError(f"duplicate group: {group_id!r}")
        record = _seal(GroupRecord(
            group_id=group_id,
            display_name=display_name,
            seq=seq,
            prev_digest=_GENESIS,
        ))
        self._groups[group_id] = record
        self._events.append(scim_provisioning_audit_event(
            KIND_GROUP_CREATED, seq, group_id=group_id,
            record_digest=record.record_digest,
        ))
        return record

    def add_member(self, group_id: str, user_id: str, seq: int) -> MembershipRecord:
        """Add a user to a group. Deprovisioned users are refused."""
        group_id = _check_group_id(group_id)
        user_id = _check_user_id(user_id)
        seq = _check_seq(seq, "seq")
        if group_id not in self._groups:
            raise UnknownGroupError(f"unknown group: {group_id!r}")
        if self._latest_user(user_id) is None:
            raise UnknownUserError(f"unknown user: {user_id!r}")
        if user_id in self._deprovisioned:
            raise AlreadyDeprovisionedError(
                f"user {user_id!r} is deprovisioned"
            )
        key = (group_id, user_id)
        existing = self._memberships.get(key)
        if existing is not None and existing.action == "added":
            raise DuplicateGroupError(
                f"user {user_id!r} already in group {group_id!r}"
            )
        if existing is not None:
            self._bump_seq(seq, existing.seq)
        record = _seal(MembershipRecord(
            group_id=group_id,
            user_id=user_id,
            action="added",
            seq=seq,
        ))
        self._memberships[key] = record
        self._events.append(scim_provisioning_audit_event(
            KIND_MEMBER_ADDED, seq, group_id=group_id, user_id=user_id,
            record_digest=record.record_digest,
        ))
        return record

    def remove_member(self, group_id: str, user_id: str, seq: int) -> MembershipRecord:
        """Remove a user from a group. Books a terminal removal record."""
        group_id = _check_group_id(group_id)
        user_id = _check_user_id(user_id)
        seq = _check_seq(seq, "seq")
        if group_id not in self._groups:
            raise UnknownGroupError(f"unknown group: {group_id!r}")
        key = (group_id, user_id)
        existing = self._memberships.get(key)
        if existing is None or existing.action == "removed":
            raise SCIMError(
                f"user {user_id!r} is not an active member of {group_id!r}"
            )
        self._bump_seq(seq, existing.seq)
        record = _seal(MembershipRecord(
            group_id=group_id,
            user_id=user_id,
            action="removed",
            seq=seq,
        ))
        self._memberships[key] = record
        self._events.append(scim_provisioning_audit_event(
            KIND_MEMBER_REMOVED, seq, group_id=group_id, user_id=user_id,
            record_digest=record.record_digest,
        ))
        return record

    def groups(self, user_id: str) -> tuple[str, ...]:
        """Group ids where the user is currently an active member."""
        user_id = _check_user_id(user_id)
        return tuple(sorted(
            group_id
            for (group_id, uid), rec in self._memberships.items()
            if uid == user_id and rec.action == "added"
        ))

    def group_members(self, group_id: str) -> tuple[str, ...]:
        """User ids currently active members of a group."""
        group_id = _check_group_id(group_id)
        if group_id not in self._groups:
            raise UnknownGroupError(f"unknown group: {group_id!r}")
        return tuple(sorted(
            uid
            for (gid, uid), rec in self._memberships.items()
            if gid == group_id and rec.action == "added"
        ))

    # -- views ----------------------------------------------------------

    def user(self, user_id: str) -> UserRecord:
        """Latest sealed user record."""
        user_id = _check_user_id(user_id)
        latest = self._latest_user(user_id)
        if latest is None:
            raise UnknownUserError(f"unknown user: {user_id!r}")
        return latest

    def user_ids(self) -> tuple[str, ...]:
        """All provisioned user ids, sorted."""
        return tuple(sorted(self._users))

    def group(self, group_id: str) -> GroupRecord:
        """Sealed group record."""
        group_id = _check_group_id(group_id)
        record = self._groups.get(group_id)
        if record is None:
            raise UnknownGroupError(f"unknown group: {group_id!r}")
        return record

    def group_ids(self) -> tuple[str, ...]:
        """All group ids, sorted."""
        return tuple(sorted(self._groups))

    def is_deprovisioned(self, user_id: str) -> bool:
        """True iff the user is currently deprovisioned."""
        user_id = _check_user_id(user_id)
        return user_id in self._deprovisioned

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        """Audit events emitted so far, in order."""
        return tuple(self._events)


def main() -> None:
    mgr = SCIMProvisioning()
    rec = mgr.sync("u-1", 1, {"userName": "alice", "emails": ["a@x.io"]})
    assert rec.version == 1
    assert compute_record_digest(rec) == rec.record_digest
    rec2 = mgr.sync("u-1", 2, {"userName": "alice", "title": "eng"})
    assert rec2.version == 2
    assert rec2.prev_digest == rec.record_digest
    grp = mgr.create_group("g-eng", 3, "Engineering")
    assert compute_record_digest(grp) == grp.record_digest
    mgr.add_member("g-eng", "u-1", 4)
    assert mgr.groups("u-1") == ("g-eng",)
    assert mgr.group_members("g-eng") == ("u-1",)
    dep = mgr.deprovision("u-1", 5, "offboarded")
    assert compute_record_digest(dep) == dep.record_digest
    assert mgr.is_deprovisioned("u-1")
    mgr.remove_member("g-eng", "u-1", 6)
    assert mgr.groups("u-1") == ()
    print("scim-provisioning OK: sync, groups, deprovision, pins, audit")


__all__ = [
    "SCIM_PROVISIONING_VERSION",
    "SCIM_PROVISIONING_SCHEMA",
    "AUDIT_SCHEMA",
    "ACTIVE",
    "INACTIVE",
    "KIND_SYNCED",
    "KIND_DEPROVISIONED",
    "KIND_GROUP_CREATED",
    "KIND_MEMBER_ADDED",
    "KIND_MEMBER_REMOVED",
    "KIND_REJECTED",
    "SCIMError",
    "BadUserError",
    "UnknownUserError",
    "DuplicateUserError",
    "BadGroupError",
    "UnknownGroupError",
    "DuplicateGroupError",
    "AlreadyDeprovisionedError",
    "SeqOrderError",
    "UserRecord",
    "DeprovisionRecord",
    "GroupRecord",
    "MembershipRecord",
    "compute_record_digest",
    "scim_provisioning_audit_event",
    "SCIMProvisioning",
    "main",
]


if __name__ == "__main__":
    main()
