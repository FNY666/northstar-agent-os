"""RBAC96-style role-based access control with role hierarchies.

``RBACEngine`` is the policy bookkeeping half of access control: roles hold
permission atoms, role *hierarchies* express seniority (a senior ``child``
role inherits every permission of its ``parent`` roles, transitively), and
subjects gain permissions by role assignment. ``check(subject_id,
permission, seq)`` answers "does the recorded policy grant this?" and
returns a frozen ``AccessDecision`` with the granting roles and whether the
grant came via inheritance -- never ``None``, never a silent no-op.

API:
- ``create_role(role_id, seq)`` / ``delete_role(role_id, seq)`` -- role
  lifecycle. Deleting a role that is still assigned to subjects or still
  referenced by inheritance edges is refused fail-closed.
- ``grant_permission(role_id, permission, seq)`` /
  ``revoke_permission(role_id, permission, seq)`` -- direct grants.
- ``assign_role(subject_id, role_id, seq)`` /
  ``unassign_role(subject_id, role_id, seq)`` -- subjects exist only while
  they hold at least one assignment (no separate subject registry).
- ``add_inheritance(child_role_id, parent_role_id, seq)`` /
  ``remove_inheritance(child_role_id, parent_role_id, seq)`` -- the
  hierarchy. Self-inheritance and cycles are refused fail-closed, so the
  inheritance graph stays a DAG and ``effective_permissions()`` always
  terminates.
- ``check(subject_id, permission, seq)`` -> ``AccessDecision``: denials are
  returned as data (``allowed=False``), never raised; an *unknown* subject
  raises ``UnknownSubjectError`` fail-closed instead of being treated as a
  stranger with no roles (hides misconfiguration).

Caller-supplied int seqs order mutations (strictly increasing per engine);
``check()`` takes a seq for audit alignment but does not advance the
ledger. Permissions are plain atoms (``"billing:read"``) -- this module
never interprets them.

House style: frozen dataclasses, fail-closed validation (``TypeError`` on
wrong types -- bool is not an int, ``ValueError`` on bad values),
``threading.RLock``-guarded, stdlib-only, version/schema pins,
``main()`` self-check. No wall-clock.

Honest scope: books *reported* policy only. ``check()`` proves "the
recorded policy grants this permission to this subject", never "the action
was authorized in the real world" -- the host decides what to do with the
verdict. No sessions, no tokens, no expiry, no delegation: pair with
``delegation_credentials`` / ``permissions`` for token-based enforcement.
A lying host gets a consistent policy of lies (same GIGO boundary as the
rest of the batch line).

Version pin: rbac-engine.v1
Schema pin: northstar.rbac-engine.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Set, Tuple

RBAC_ENGINE_VERSION = "rbac-engine.v1"
SCHEMA_PIN = "northstar.rbac-engine.v1"

_HASH_DOMAIN = "northstar.rbac-engine.v1"


class RBACError(Exception):
    """Base error for the RBAC engine."""


class DuplicateRoleError(RBACError):
    """The role id is already registered."""


class UnknownRoleError(RBACError):
    """The named role does not exist."""


class DuplicateGrantError(RBACError):
    """The role already holds this permission."""


class UnknownGrantError(RBACError):
    """The role does not hold this permission."""


class DuplicateAssignmentError(RBACError):
    """The subject already holds this role."""


class UnknownAssignmentError(RBACError):
    """The subject does not hold this role."""


class UnknownSubjectError(RBACError):
    """The subject has no role assignments on record."""


class DuplicateInheritanceError(RBACError):
    """The child role already inherits from this parent."""


class UnknownInheritanceError(RBACError):
    """The child role does not inherit from this parent."""


class SelfInheritanceError(RBACError):
    """A role cannot inherit from itself."""


class InheritanceCycleError(RBACError):
    """Adding this edge would create an inheritance cycle."""


class RoleInUseError(RBACError):
    """The role is still assigned to subjects."""


class InheritanceInUseError(RBACError):
    """The role is still referenced by inheritance edges."""


class SeqOrderError(RBACError):
    """The caller seq did not strictly increase."""


def _check_str(name: str, value: object, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise ValueError(f"{name} must be non-empty")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain NUL")
    return value


def _check_seq(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"seq must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError("seq must be >= 0")
    return value


def _digest(*parts: bytes) -> str:
    h = hashlib.sha256(_HASH_DOMAIN.encode())
    for p in parts:
        h.update(b"\x00" + p)
    return "sha256:" + h.hexdigest()


def _e_str(value: str) -> bytes:
    return b"s:" + value.encode("utf-8")


def _e_int(value: int) -> bytes:
    return b"i:" + format(value, "x").encode("ascii")


def _e_bool(value: bool) -> bytes:
    return b"b:" + (b"true" if value else b"false")


@dataclass(frozen=True)
class RoleRecord:
    """A registered role, digest-pinned."""

    role_id: str
    description: str
    seq: int
    digest: str
    version: str = RBAC_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "role_id": self.role_id,
            "description": self.description,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class PermissionGrant:
    """A direct permission grant on a role, digest-pinned."""

    role_id: str
    permission: str
    seq: int
    digest: str
    version: str = RBAC_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "role_id": self.role_id,
            "permission": self.permission,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class PermissionRevocation:
    """A grant removal, digest-pinned."""

    role_id: str
    permission: str
    seq: int
    digest: str
    version: str = RBAC_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "role_id": self.role_id,
            "permission": self.permission,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RoleAssignment:
    """A subject-role binding, digest-pinned."""

    subject_id: str
    role_id: str
    seq: int
    digest: str
    version: str = RBAC_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "subject_id": self.subject_id,
            "role_id": self.role_id,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RoleUnassignment:
    """A binding removal, digest-pinned."""

    subject_id: str
    role_id: str
    seq: int
    digest: str
    version: str = RBAC_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "subject_id": self.subject_id,
            "role_id": self.role_id,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class InheritanceRecord:
    """A child->parent hierarchy edge, digest-pinned."""

    child_role_id: str
    parent_role_id: str
    seq: int
    digest: str
    version: str = RBAC_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "child_role_id": self.child_role_id,
            "parent_role_id": self.parent_role_id,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class InheritanceRemoval:
    """A hierarchy edge removal, digest-pinned."""

    child_role_id: str
    parent_role_id: str
    seq: int
    digest: str
    version: str = RBAC_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "child_role_id": self.child_role_id,
            "parent_role_id": self.parent_role_id,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RoleDeletion:
    """A role deletion, digest-pinned."""

    role_id: str
    seq: int
    digest: str
    version: str = RBAC_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "role_id": self.role_id,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AccessDecision:
    """The verdict of ``RBACEngine.check`` -- denial is data, never raised."""

    subject_id: str
    permission: str
    allowed: bool
    reason: str  # "direct" | "inherited" | "no-grant"
    granting_roles: Tuple[str, ...]
    via_inheritance: bool
    seq: int
    digest: str
    version: str = RBAC_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "subject_id": self.subject_id,
            "permission": self.permission,
            "allowed": self.allowed,
            "reason": self.reason,
            "granting_roles": list(self.granting_roles),
            "via_inheritance": self.via_inheritance,
            "seq": self.seq,
            "digest": self.digest,
        }


class RBACEngine:
    """RBAC96-style role/permission bookkeeping with role hierarchies."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._roles: Dict[str, RoleRecord] = {}
        self._direct: Dict[str, Set[str]] = {}  # role_id -> permission atoms
        self._assignments: Dict[str, Set[str]] = {}  # subject_id -> role_ids
        self._parents: Dict[str, Set[str]] = {}  # child -> parent role ids
        self._last_seq: int = -1

    # -- internal ------------------------------------------------------
    def _require_role(self, role_id: str) -> None:
        if role_id not in self._roles:
            raise UnknownRoleError(f"unknown role {role_id!r}")

    def _note_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last {self._last_seq}, got {seq})"
            )
        self._last_seq = seq
        return seq

    def _closure(self, role_id: str) -> FrozenSet[str]:
        """All roles whose permissions reach ``role_id`` (self + ancestors)."""
        seen: Set[str] = set()
        stack = [role_id]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(self._parents.get(cur, ()))
        return frozenset(seen)

    # -- role lifecycle ------------------------------------------------
    def create_role(self, role_id: str, seq: int, description: str = "") -> RoleRecord:
        role_id = _check_str("role_id", role_id)
        description = _check_str("description", description, allow_empty=True)
        with self._lock:
            seq = self._note_seq(seq)
            if role_id in self._roles:
                raise DuplicateRoleError(f"role {role_id!r} already exists")
            rec = RoleRecord(
                role_id=role_id,
                description=description,
                seq=seq,
                digest=_digest(_e_str(role_id), _e_str(description), _e_int(seq)),
            )
            self._roles[role_id] = rec
            self._direct.setdefault(role_id, set())
            self._parents.setdefault(role_id, set())
            return rec

    def delete_role(self, role_id: str, seq: int) -> RoleDeletion:
        role_id = _check_str("role_id", role_id)
        with self._lock:
            seq = self._note_seq(seq)
            self._require_role(role_id)
            holders = sorted(
                s for s, roles in self._assignments.items() if role_id in roles
            )
            if holders:
                raise RoleInUseError(
                    f"role {role_id!r} still assigned to {holders}"
                )
            children = sorted(
                c for c, parents in self._parents.items() if role_id in parents
            )
            parents = sorted(self._parents.get(role_id, ()))
            if children or parents:
                raise InheritanceInUseError(
                    f"role {role_id!r} still referenced by inheritance edges"
                    f" (children={children}, parents={parents})"
                )
            del self._roles[role_id]
            self._direct.pop(role_id, None)
            self._parents.pop(role_id, None)
            return RoleDeletion(
                role_id=role_id,
                seq=seq,
                digest=_digest(b"delete-role", _e_str(role_id), _e_int(seq)),
            )

    # -- permission grants ---------------------------------------------
    def grant_permission(
        self, role_id: str, permission: str, seq: int
    ) -> PermissionGrant:
        role_id = _check_str("role_id", role_id)
        permission = _check_str("permission", permission)
        with self._lock:
            seq = self._note_seq(seq)
            self._require_role(role_id)
            if permission in self._direct[role_id]:
                raise DuplicateGrantError(
                    f"role {role_id!r} already holds {permission!r}"
                )
            self._direct[role_id].add(permission)
            return PermissionGrant(
                role_id=role_id,
                permission=permission,
                seq=seq,
                digest=_digest(
                    b"grant", _e_str(role_id), _e_str(permission), _e_int(seq)
                ),
            )

    def revoke_permission(
        self, role_id: str, permission: str, seq: int
    ) -> PermissionRevocation:
        role_id = _check_str("role_id", role_id)
        permission = _check_str("permission", permission)
        with self._lock:
            seq = self._note_seq(seq)
            self._require_role(role_id)
            if permission not in self._direct[role_id]:
                raise UnknownGrantError(
                    f"role {role_id!r} does not hold {permission!r}"
                )
            self._direct[role_id].discard(permission)
            return PermissionRevocation(
                role_id=role_id,
                permission=permission,
                seq=seq,
                digest=_digest(
                    b"revoke", _e_str(role_id), _e_str(permission), _e_int(seq)
                ),
            )

    # -- subject assignments -------------------------------------------
    def assign_role(self, subject_id: str, role_id: str, seq: int) -> RoleAssignment:
        subject_id = _check_str("subject_id", subject_id)
        role_id = _check_str("role_id", role_id)
        with self._lock:
            seq = self._note_seq(seq)
            self._require_role(role_id)
            roles = self._assignments.setdefault(subject_id, set())
            if role_id in roles:
                raise DuplicateAssignmentError(
                    f"subject {subject_id!r} already holds role {role_id!r}"
                )
            roles.add(role_id)
            return RoleAssignment(
                subject_id=subject_id,
                role_id=role_id,
                seq=seq,
                digest=_digest(
                    b"assign", _e_str(subject_id), _e_str(role_id), _e_int(seq)
                ),
            )

    def unassign_role(self, subject_id: str, role_id: str, seq: int) -> RoleUnassignment:
        subject_id = _check_str("subject_id", subject_id)
        role_id = _check_str("role_id", role_id)
        with self._lock:
            seq = self._note_seq(seq)
            roles = self._assignments.get(subject_id)
            if not roles or role_id not in roles:
                raise UnknownAssignmentError(
                    f"subject {subject_id!r} does not hold role {role_id!r}"
                )
            roles.discard(role_id)
            if not roles:
                del self._assignments[subject_id]
            return RoleUnassignment(
                subject_id=subject_id,
                role_id=role_id,
                seq=seq,
                digest=_digest(
                    b"unassign", _e_str(subject_id), _e_str(role_id), _e_int(seq)
                ),
            )

    # -- role hierarchy ------------------------------------------------
    def add_inheritance(
        self, child_role_id: str, parent_role_id: str, seq: int
    ) -> InheritanceRecord:
        child_role_id = _check_str("child_role_id", child_role_id)
        parent_role_id = _check_str("parent_role_id", parent_role_id)
        if child_role_id == parent_role_id:
            raise SelfInheritanceError(
                f"role {child_role_id!r} cannot inherit from itself"
            )
        with self._lock:
            seq = self._note_seq(seq)
            self._require_role(child_role_id)
            self._require_role(parent_role_id)
            if parent_role_id in self._parents[child_role_id]:
                raise DuplicateInheritanceError(
                    f"{child_role_id!r} already inherits from {parent_role_id!r}"
                )
            # Fail-closed: adding child->parent must not create a cycle.
            if child_role_id in self._closure(parent_role_id):
                raise InheritanceCycleError(
                    f"edge {child_role_id!r}->{parent_role_id!r} would close a cycle"
                )
            self._parents[child_role_id].add(parent_role_id)
            return InheritanceRecord(
                child_role_id=child_role_id,
                parent_role_id=parent_role_id,
                seq=seq,
                digest=_digest(
                    b"inherit",
                    _e_str(child_role_id),
                    _e_str(parent_role_id),
                    _e_int(seq),
                ),
            )

    def remove_inheritance(
        self, child_role_id: str, parent_role_id: str, seq: int
    ) -> InheritanceRemoval:
        child_role_id = _check_str("child_role_id", child_role_id)
        parent_role_id = _check_str("parent_role_id", parent_role_id)
        with self._lock:
            seq = self._note_seq(seq)
            self._require_role(child_role_id)
            self._require_role(parent_role_id)
            if parent_role_id not in self._parents[child_role_id]:
                raise UnknownInheritanceError(
                    f"{child_role_id!r} does not inherit from {parent_role_id!r}"
                )
            self._parents[child_role_id].discard(parent_role_id)
            return InheritanceRemoval(
                child_role_id=child_role_id,
                parent_role_id=parent_role_id,
                seq=seq,
                digest=_digest(
                    b"uninherit",
                    _e_str(child_role_id),
                    _e_str(parent_role_id),
                    _e_int(seq),
                ),
            )

    # -- views ----------------------------------------------------------
    def roles(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._roles))

    def role(self, role_id: str) -> RoleRecord:
        role_id = _check_str("role_id", role_id)
        with self._lock:
            self._require_role(role_id)
            return self._roles[role_id]

    def direct_permissions(self, role_id: str) -> Tuple[str, ...]:
        role_id = _check_str("role_id", role_id)
        with self._lock:
            self._require_role(role_id)
            return tuple(sorted(self._direct[role_id]))

    def effective_permissions(self, role_id: str) -> Tuple[str, ...]:
        """Direct permissions plus everything inherited, transitively."""
        role_id = _check_str("role_id", role_id)
        with self._lock:
            self._require_role(role_id)
            perms: Set[str] = set()
            for rid in self._closure(role_id):
                perms.update(self._direct.get(rid, ()))
            return tuple(sorted(perms))

    def parents(self, role_id: str) -> Tuple[str, ...]:
        role_id = _check_str("role_id", role_id)
        with self._lock:
            self._require_role(role_id)
            return tuple(sorted(self._parents[role_id]))

    def children(self, role_id: str) -> Tuple[str, ...]:
        role_id = _check_str("role_id", role_id)
        with self._lock:
            self._require_role(role_id)
            return tuple(
                sorted(c for c, ps in self._parents.items() if role_id in ps)
            )

    def subject_roles(self, subject_id: str) -> Tuple[str, ...]:
        subject_id = _check_str("subject_id", subject_id)
        with self._lock:
            return tuple(sorted(self._assignments.get(subject_id, ())))

    def subject_permissions(self, subject_id: str) -> Tuple[str, ...]:
        """Effective permissions across all of the subject's roles."""
        subject_id = _check_str("subject_id", subject_id)
        with self._lock:
            roles = self._assignments.get(subject_id)
            if not roles:
                raise UnknownSubjectError(
                    f"subject {subject_id!r} has no role assignments"
                )
            perms: Set[str] = set()
            for rid in roles:
                for anc in self._closure(rid):
                    perms.update(self._direct.get(anc, ()))
            return tuple(sorted(perms))

    # -- authorization check --------------------------------------------
    def check(
        self, subject_id: str, permission: str, seq: int
    ) -> AccessDecision:
        subject_id = _check_str("subject_id", subject_id)
        permission = _check_str("permission", permission)
        seq = _check_seq(seq)
        with self._lock:
            roles = self._assignments.get(subject_id)
            if not roles:
                raise UnknownSubjectError(
                    f"subject {subject_id!r} has no role assignments"
                )
            granting: List[str] = []
            via_inheritance = False
            for rid in sorted(roles):
                if permission in self._direct.get(rid, ()):
                    granting.append(rid)
                    continue
                for anc in sorted(self._closure(rid) - {rid}):
                    if permission in self._direct.get(anc, ()):
                        if rid not in granting:
                            granting.append(rid)
                        via_inheritance = True
                        break
            granting_roles = tuple(sorted(set(granting)))
            allowed = bool(granting_roles)
            reason = (
                "inherited"
                if allowed and via_inheritance
                else ("direct" if allowed else "no-grant")
            )
            return AccessDecision(
                subject_id=subject_id,
                permission=permission,
                allowed=allowed,
                reason=reason,
                granting_roles=granting_roles,
                via_inheritance=via_inheritance,
                seq=seq,
                digest=_digest(
                    b"check",
                    _e_str(subject_id),
                    _e_str(permission),
                    _e_bool(allowed),
                    _e_str(",".join(granting_roles)),
                    _e_bool(via_inheritance),
                    _e_int(seq),
                ),
            )


def rbac_engine_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for an RBAC engine event."""
    allowed = {
        "role-created",
        "role-deleted",
        "permission-granted",
        "permission-revoked",
        "role-assigned",
        "role-unassigned",
        "inheritance-added",
        "inheritance-removed",
        "access-checked",
        "rejected",
    }
    if kind not in allowed:
        raise RBACError(
            f"unknown audit kind {kind!r}; allowed: {sorted(allowed)}"
        )
    _check_seq(seq)
    record: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "kind": f"rbac-engine.{kind}",
        "module": RBAC_ENGINE_VERSION,
        "seq": seq,
    }
    record.update(fields)
    return record


def main() -> None:
    eng = RBACEngine()
    assert RBAC_ENGINE_VERSION == "rbac-engine.v1"
    assert SCHEMA_PIN == "northstar.rbac-engine.v1"

    rec = eng.create_role("employee", seq=1, description="staff")
    assert rec.digest.startswith("sha256:"), rec
    try:
        eng.create_role("employee", seq=2)
    except DuplicateRoleError:
        pass
    else:
        raise AssertionError("duplicate role should fail")

    # direct grant + assignment -> allowed via direct grant
    eng.grant_permission("employee", "billing:read", seq=3)
    eng.assign_role("alice", "employee", seq=4)
    dec = eng.check("alice", "billing:read", seq=5)
    assert dec.allowed and dec.reason == "direct", dec
    assert dec.granting_roles == ("employee",), dec
    assert not dec.via_inheritance, dec

    # denied as data, never raised
    dec = eng.check("alice", "billing:write", seq=6)
    assert not dec.allowed and dec.reason == "no-grant", dec

    # hierarchy: manager inherits employee's permissions
    eng.create_role("manager", seq=7)
    eng.grant_permission("manager", "billing:write", seq=8)
    eng.add_inheritance("manager", "employee", seq=9)
    assert eng.effective_permissions("manager") == (
        "billing:read",
        "billing:write",
    ), eng.effective_permissions("manager")
    eng.assign_role("bob", "manager", seq=10)
    dec = eng.check("bob", "billing:read", seq=11)
    assert dec.allowed and dec.reason == "inherited" and dec.via_inheritance, dec

    # cycle refused: employee already below manager (seq 12 consumed)
    try:
        eng.add_inheritance("employee", "manager", seq=12)
    except InheritanceCycleError:
        pass
    else:
        raise AssertionError("inheritance cycle should fail")

    # self inheritance refused before the seq ledger (no consumption)
    try:
        eng.add_inheritance("manager", "manager", seq=13)
    except SelfInheritanceError:
        pass
    else:
        raise AssertionError("self inheritance should fail")

    # revoke drops the direct grant; employee loses it
    eng.revoke_permission("employee", "billing:read", seq=13)
    dec = eng.check("alice", "billing:read", seq=14)
    assert not dec.allowed, dec

    # unknown subject is fail-closed, not "denied stranger"
    try:
        eng.check("mallory", "billing:read", seq=15)
    except UnknownSubjectError:
        pass
    else:
        raise AssertionError("unknown subject should fail")

    # seq order enforced on mutations (13 <= last consumed 13)
    try:
        eng.grant_permission("manager", "x:y", seq=13)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("seq rewind should fail")

    # digest determinism across instances with identical histories
    e2 = RBACEngine()
    e2.create_role("employee", seq=1, description="staff")
    e2.grant_permission("employee", "billing:read", seq=2)
    e2.assign_role("alice", "employee", seq=3)
    e3 = RBACEngine()
    e3.create_role("employee", seq=1, description="staff")
    e3.grant_permission("employee", "billing:read", seq=2)
    e3.assign_role("alice", "employee", seq=3)
    d2 = e2.check("alice", "billing:read", seq=99).digest
    d3 = e3.check("alice", "billing:read", seq=99).digest
    assert d2 == d3, (d2, d3)

    print("rbac-engine OK: roles, grants, hierarchy, check, refusals")


if __name__ == "__main__":
    main()
