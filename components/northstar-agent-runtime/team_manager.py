"""Team manager interface (org teams: create / invite / roles).

Research motivation: every org-team product (GitHub teams, Slack
workspaces, Google Groups, Discord servers) converges on the same
bookkeeping shape -- named teams, a roster of members, a small role
hierarchy (owner / admin / member / viewer), and an invitation lifecycle
(pending -> accepted). The security discipline is the same one the
RBAC line pins (``rbac_engine``): least privilege by default and
fail-closed membership transitions.

This module pins the deterministic bookkeeping half of that shape:

- ``TeamManager`` -- owns teams. ``create(name, creator_id, seq)``
  mints ``team-N`` and seats the creator as the founding owner;
  ``invite(team_id, inviter_id, invitee_id, seq, role=...)`` issues a
  pending ``Invitation`` (``inv-N``); ``accept(invitation_id, seq)``
  admits the invitee at the invited role; ``roles(team_id)`` lists the
  current member->role assignments; ``set_role(...)`` re-seats a role;
  ``remove(...)`` detaches a member.
- ``team_manager_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``created`` / ``invited`` / ``accepted`` / ``role-changed`` /
  ``removed`` / ``rejected``); caller-supplied seqs only, ids and
  digest pins only -- never member names.

Conventions pinned here:

- Role ranks: ``viewer`` < ``member`` < ``admin`` < ``owner``. Only
  owners and admins may invite, and an inviter may never grant a role
  at or above their own rank (an admin cannot mint an owner).
- Every team always has at least one owner: demoting or removing the
  last owner is refused fail-closed (``LastOwnerError``).
- Seqs are caller-supplied monotonic ints, never wall-clock: they must
  be strictly increasing positive ints (``SeqOrderError``) and advance
  only on successful mutation.
- Member ids are opaque non-empty strings; names are trimmed and may
  not be blank. Digest pins are ``sha256:`` over type-tagged canonical
  bodies (bool != int; >2^53 ints refused), so identical content
  replays to identical pins.

Fail-closed edges (fail loudly, never guess):

- Unknown team ids raise ``UnknownTeamError``; unknown invitation ids
  raise ``UnknownInvitationError``; unknown members raise
  ``UnknownMemberError``.
- Inviting a current member, accepting twice, or accepting a
  non-pending invitation raises (``AlreadyMemberError`` /
  ``InvitationStateError``).
- Permission violations raise ``PermissionError`` (a ``TeamError``);
  callers that need auditability pair this with an approval gate.

Honest scope:

- This module books *reported* membership state. It cannot verify that
  a member id maps to a real human, that the inviter was authorized by
  a real policy (pair with ``rbac_engine`` / ``approval_chain``), or
  that the invitee saw the invitation (pair with a notification hub).
  ``roles()`` reports what was recorded, never what was earned.

Version pin: team-manager.v1
Schema pin: northstar.team-manager.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, replace
from typing import Dict, Optional, Tuple

TEAM_MANAGER_VERSION = "team-manager.v1"
SCHEMA_PIN = "northstar.team-manager.v1"

_ROLE_RANKS = {"viewer": 0, "member": 1, "admin": 2, "owner": 3}
_VALID_ROLES = frozenset(_ROLE_RANKS)
_CAN_INVITE = frozenset({"owner", "admin"})

_TEAM_AUDIT_KINDS = frozenset(
    {"created", "invited", "accepted", "role-changed", "removed", "rejected"}
)


class TeamError(Exception):
    """Base error for the team manager."""


class UnknownTeamError(TeamError):
    """No team with that id exists."""


class UnknownInvitationError(TeamError):
    """No invitation with that id exists."""


class UnknownMemberError(TeamError):
    """That member id is not on the team's roster."""


class PermissionError(TeamError):
    """The actor's role does not allow this operation."""


class AlreadyMemberError(TeamError):
    """The invitee is already a member of the team."""


class InvitationStateError(TeamError):
    """The invitation is not in a state that allows this transition."""


class LastOwnerError(TeamError):
    """Refused: a team must always keep at least one owner."""


class BadTeamError(TeamError):
    """A team/invitation/role field failed validation."""


class SeqOrderError(TeamError):
    """Caller-supplied seq did not increase monotonically."""


def _digest_tagged(parts: Tuple[Tuple[str, object], ...]) -> str:
    """sha256 pin over type-tagged canonical encoding (bool != int)."""
    buf = []
    for tag, value in parts:
        if isinstance(value, bool):
            body = "bool:" + ("1" if value else "0")
        elif isinstance(value, int):
            if abs(value) >= 2**53:
                raise BadTeamError("integer exceeds safe range for pinning")
            body = "int:" + str(value)
        elif isinstance(value, str):
            body = "str:" + value
        elif value is None:
            body = "none:"
        elif isinstance(value, tuple):
            inner = ",".join(
                _digest_tagged(((tag, v),)).split(":", 1)[1] for v in value
            )
            body = "tuple:[" + inner + "]"
        else:
            raise BadTeamError(f"unpinable type for {tag}: {type(value).__name__}")
        buf.append(tag + "=" + body)
    return "sha256:" + hashlib.sha256("|".join(buf).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Team:
    """A named org team with a founding owner."""

    team_id: str
    name: str
    description: str
    created_seq: int
    digest: str = ""

    def as_dict(self) -> dict:
        return {
            "team_id": self.team_id,
            "name": self.name,
            "description": self.description,
            "created_seq": self.created_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class Invitation:
    """A pending team invitation."""

    invitation_id: str
    team_id: str
    invitee_id: str
    invited_by: str
    role: str
    issued_seq: int
    state: str = "pending"
    digest: str = ""

    def as_dict(self) -> dict:
        return {
            "invitation_id": self.invitation_id,
            "team_id": self.team_id,
            "invitee_id": self.invitee_id,
            "invited_by": self.invited_by,
            "role": self.role,
            "issued_seq": self.issued_seq,
            "state": self.state,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RoleAssignment:
    """One member's current role on a team."""

    member_id: str
    role: str


class TeamManager:
    """Deterministic org-team bookkeeping: create / invite / roles."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._teams: Dict[str, Team] = {}
        self._rosters: Dict[str, Dict[str, str]] = {}
        self._invitations: Dict[str, Invitation] = {}
        self._team_seq = 0
        self._inv_seq = 0
        self._last_seq = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
            raise SeqOrderError("seq must be a positive int")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must increase: got {seq}, last was {self._last_seq}"
            )
        self._last_seq = seq

    def _team_or_raise(self, team_id: str) -> Team:
        team = self._teams.get(team_id)
        if team is None:
            raise UnknownTeamError(f"unknown team: {team_id!r}")
        return team

    @staticmethod
    def _clean_id(value: str, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise BadTeamError(f"{field} must be a non-empty string")
        return value.strip()

    def _owners(self, team_id: str) -> Tuple[str, ...]:
        return tuple(
            m for m, r in self._rosters[team_id].items() if r == "owner"
        )

    # -- create -----------------------------------------------------------

    def create(
        self,
        name: str,
        creator_id: str,
        seq: int,
        *,
        description: str = "",
    ) -> Team:
        """Create a team; the creator is seated as the founding owner."""
        clean_name = self._clean_id(name, "name")
        clean_creator = self._clean_id(creator_id, "creator_id")
        if not isinstance(description, str):
            raise BadTeamError("description must be str")
        with self._lock:
            self._check_seq(seq)
            self._team_seq += 1
            team_id = f"team-{self._team_seq}"
            team = Team(
                team_id=team_id,
                name=clean_name,
                description=description,
                created_seq=seq,
                digest=_digest_tagged(
                    (
                        ("team_id", team_id),
                        ("name", clean_name),
                        ("description", description),
                        ("created_seq", seq),
                    )
                ),
            )
            self._teams[team_id] = team
            self._rosters[team_id] = {clean_creator: "owner"}
            return team

    # -- invite -----------------------------------------------------------

    def invite(
        self,
        team_id: str,
        inviter_id: str,
        invitee_id: str,
        seq: int,
        *,
        role: str = "member",
    ) -> Invitation:
        """Issue a pending invitation; inviter must be owner or admin.

        The granted role must be strictly below the inviter's own rank,
        and the invitee must not already be a member.
        """
        clean_inviter = self._clean_id(inviter_id, "inviter_id")
        clean_invitee = self._clean_id(invitee_id, "invitee_id")
        if role not in _VALID_ROLES:
            raise BadTeamError(f"unknown role: {role!r}")
        with self._lock:
            self._check_seq(seq)
            team = self._team_or_raise(team_id)
            inviter_role = self._rosters[team_id].get(clean_inviter)
            if inviter_role is None:
                raise UnknownMemberError(
                    f"inviter is not a member: {clean_inviter!r}"
                )
            if inviter_role not in _CAN_INVITE:
                raise PermissionError(
                    f"role {inviter_role!r} may not invite"
                )
            if _ROLE_RANKS[role] >= _ROLE_RANKS[inviter_role]:
                raise PermissionError(
                    f"inviter rank {inviter_role!r} may not grant {role!r}"
                )
            if clean_invitee in self._rosters[team_id]:
                raise AlreadyMemberError(
                    f"already a member: {clean_invitee!r}"
                )
            self._inv_seq += 1
            invitation_id = f"inv-{self._inv_seq}"
            invitation = Invitation(
                invitation_id=invitation_id,
                team_id=team.team_id,
                invitee_id=clean_invitee,
                invited_by=clean_inviter,
                role=role,
                issued_seq=seq,
                digest=_digest_tagged(
                    (
                        ("invitation_id", invitation_id),
                        ("team_id", team.team_id),
                        ("invitee_id", clean_invitee),
                        ("role", role),
                        ("issued_seq", seq),
                    )
                ),
            )
            self._invitations[invitation_id] = invitation
            return invitation

    # -- accept -----------------------------------------------------------

    def accept(self, invitation_id: str, seq: int) -> Invitation:
        """Accept a pending invitation, admitting the invitee at its role."""
        with self._lock:
            self._check_seq(seq)
            invitation = self._invitations.get(invitation_id)
            if invitation is None:
                raise UnknownInvitationError(
                    f"unknown invitation: {invitation_id!r}"
                )
            if invitation.state != "pending":
                raise InvitationStateError(
                    f"invitation is {invitation.state}, not pending"
                )
            roster = self._rosters[invitation.team_id]
            if invitation.invitee_id in roster:
                raise AlreadyMemberError(
                    f"already a member: {invitation.invitee_id!r}"
                )
            roster[invitation.invitee_id] = invitation.role
            accepted = replace(invitation, state="accepted")
            self._invitations[invitation_id] = accepted
            return accepted

    # -- roles ------------------------------------------------------------

    def roles(self, team_id: str) -> Tuple[RoleAssignment, ...]:
        """List the team's current member->role assignments, sorted."""
        with self._lock:
            self._team_or_raise(team_id)
            return tuple(
                RoleAssignment(member_id=m, role=r)
                for m, r in sorted(self._rosters[team_id].items())
            )

    def member_role(self, team_id: str, member_id: str) -> Optional[str]:
        """Return a member's role, or None when not on the roster."""
        with self._lock:
            self._team_or_raise(team_id)
            return self._rosters[team_id].get(member_id)

    def set_role(
        self,
        team_id: str,
        setter_id: str,
        member_id: str,
        role: str,
        seq: int,
    ) -> RoleAssignment:
        """Re-seat a member's role; only owners may change roles.

        Demoting the last remaining owner is refused (LastOwnerError).
        """
        clean_setter = self._clean_id(setter_id, "setter_id")
        clean_member = self._clean_id(member_id, "member_id")
        if role not in _VALID_ROLES:
            raise BadTeamError(f"unknown role: {role!r}")
        with self._lock:
            self._check_seq(seq)
            self._team_or_raise(team_id)
            if self._rosters[team_id].get(clean_setter) != "owner":
                raise PermissionError("only owners may change roles")
            if clean_member not in self._rosters[team_id]:
                raise UnknownMemberError(f"not a member: {clean_member!r}")
            if (
                self._rosters[team_id][clean_member] == "owner"
                and role != "owner"
                and len(self._owners(team_id)) == 1
            ):
                raise LastOwnerError("cannot demote the last owner")
            self._rosters[team_id][clean_member] = role
            return RoleAssignment(member_id=clean_member, role=role)

    # -- remove -----------------------------------------------------------

    def remove(
        self, team_id: str, remover_id: str, member_id: str, seq: int
    ) -> RoleAssignment:
        """Detach a member; owner or admin may remove (not the last owner)."""
        clean_remover = self._clean_id(remover_id, "remover_id")
        clean_member = self._clean_id(member_id, "member_id")
        with self._lock:
            self._check_seq(seq)
            self._team_or_raise(team_id)
            if self._rosters[team_id].get(clean_remover) not in _CAN_INVITE:
                raise PermissionError("only owner or admin may remove members")
            if clean_member not in self._rosters[team_id]:
                raise UnknownMemberError(f"not a member: {clean_member!r}")
            if (
                self._rosters[team_id][clean_member] == "owner"
                and len(self._owners(team_id)) == 1
            ):
                raise LastOwnerError("cannot remove the last owner")
            removed_role = self._rosters[team_id].pop(clean_member)
            return RoleAssignment(member_id=clean_member, role=removed_role)

    # -- read helpers -----------------------------------------------------

    def team(self, team_id: str) -> Team:
        with self._lock:
            return self._team_or_raise(team_id)

    def invitation(self, invitation_id: str) -> Invitation:
        with self._lock:
            invitation = self._invitations.get(invitation_id)
            if invitation is None:
                raise UnknownInvitationError(
                    f"unknown invitation: {invitation_id!r}"
                )
            return invitation

    def list_teams(self) -> Tuple[Team, ...]:
        with self._lock:
            return tuple(self._teams.values())


def team_manager_audit_event(kind: str, seq: int, detail: str = "") -> dict:
    """Shape an ``audit.ndjson/1`` record for team manager activity.

    Carries ids and digest pins only -- never member names.
    """
    if kind not in _TEAM_AUDIT_KINDS:
        raise TeamError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise TeamError("seq must be a positive int")
    if not isinstance(detail, str):
        raise TeamError("detail must be str")
    return {
        "kind": kind,
        "seq": seq,
        "detail": detail,
        "module": TEAM_MANAGER_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    m = TeamManager()
    team = m.create("platform", "alice", 1, description="platform org team")
    assert team.team_id == "team-1" and team.name == "platform"
    assert m.member_role("team-1", "alice") == "owner"
    inv = m.invite("team-1", "alice", "bob", 2, role="member")
    assert inv.invitation_id == "inv-1" and inv.state == "pending"
    accepted = m.accept(inv.invitation_id, 3)
    assert accepted.state == "accepted"
    assert m.member_role("team-1", "bob") == "member"
    assignments = m.roles("team-1")
    assert [(a.member_id, a.role) for a in assignments] == [
        ("alice", "owner"),
        ("bob", "member"),
    ]
    m.set_role("team-1", "alice", "bob", "admin", 4)
    assert m.member_role("team-1", "bob") == "admin"
    removed = m.remove("team-1", "alice", "bob", 5)
    assert removed.member_id == "bob" and removed.role == "admin"
    evt = team_manager_audit_event("removed", 5, detail="inv-1")
    assert evt["schema"] == SCHEMA_PIN
    print("team-manager OK: create, invite, accept, roles, set-role, remove")


if __name__ == "__main__":
    main()
