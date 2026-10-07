"""Invitation manager (P0): invite / accept / expire flows with sealed audit.

Interface:
    InvitationManager.invite(...)   -> sealed InvitationRecord (pending)
    InvitationManager.accept(token) -> sealed membership admission
    InvitationManager.expire(token) -> marks the invitation expired

House style: frozen dataclasses, no wall-clock (caller supplies a
monotonic ``seq``), fail-closed validation, stdlib only, audit events as
``audit.ndjson/1`` JSONL lines supplied by the caller.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Tuple


_INVITE_AUDIT_TYPE = "audit.ndjson/1"

_VALID_ROLES = frozenset({"owner", "admin", "member", "viewer", "bot"})


@dataclass(frozen=True)
class InviteParams:
    """Inputs required to issue an invitation."""

    invitee_id: str
    invited_by: str
    role: str
    scope: Tuple[str, ...] = ()
    ttl_seq: int = 1_000
    issued_at_seq: int = 0
    nonce: str = ""

    def validate(self) -> Tuple[bool, str]:
        if not self.invitee_id or not self.invitee_id.strip():
            return False, "invitee_id required"
        if not self.invited_by or not self.invited_by.strip():
            return False, "invited_by required"
        if self.role not in _VALID_ROLES:
            return False, f"unknown role {self.role!r}"
        if self.ttl_seq <= 0:
            return False, "ttl_seq must be positive"
        if self.issued_at_seq < 0:
            return False, "issued_at_seq must be non-negative"
        for s in self.scope:
            if not s or not s.strip():
                return False, "scope entries must be non-empty"
        return True, ""


@dataclass(frozen=True)
class InvitationRecord:
    """A sealed invitation."""

    invitation_id: str
    invitee_id: str
    invited_by: str
    role: str
    scope: Tuple[str, ...]
    issued_at_seq: int
    expires_at_seq: int
    nonce: str
    state: str = "pending"


@dataclass(frozen=True)
class AcceptParams:
    """Inputs required to accept an invitation."""

    invitee_id: str
    now_seq: int

    def validate(self) -> Tuple[bool, str]:
        if not self.invitee_id or not self.invitee_id.strip():
            return False, "invitee_id required"
        if self.now_seq < 0:
            return False, "now_seq must be non-negative"
        return True, ""


@dataclass(frozen=True)
class Decision:
    """Sealed outcome of invite/accept/expire."""

    allowed: bool
    reason: str
    payload: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "payload": dict(self.payload),
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "Decision":
        return Decision(
            allowed=bool(data["allowed"]),
            reason=str(data["reason"]),
            payload=dict(data.get("payload", {})),
        )


class InvitationManager:
    """Issues, accepts, and expires invitations.

    Parameters
    ----------
    inviter_can_invite: predicate(inviter_id, role, scope) -> (bool, reason).
    seal: optional seal function; defaults to canonical JSON (deterministic).
    audit_sink: callable receiving one dict per sealed event; must be provided
        by the caller (no default no-op).
    """

    def __init__(
        self,
        *,
        inviter_can_invite: Callable[[str, str, Tuple[str, ...]], Tuple[bool, str]],
        seal: Optional[Callable[[Mapping[str, Any]], str]] = None,
        audit_sink: Callable[[Dict[str, Any]], None],
    ) -> None:
        self._inviter_can_invite = inviter_can_invite
        self._seal = seal or self._default_seal
        self._audit_sink = audit_sink
        self._records: Dict[str, InvitationRecord] = {}
        self._by_invitee: Dict[str, set] = {}
        self._counter = 0

    @staticmethod
    def _default_seal(event: Mapping[str, Any]) -> str:
        return json.dumps(event, sort_keys=True, separators=(",", ":"))

    # -- internal helpers ------------------------------------------------

    def _emit(self, action: str, invitation_id: str, seq: int, extra: Mapping[str, Any]) -> str:
        event = {
            "type": _INVITE_AUDIT_TYPE,
            "action": action,
            "invitation_id": invitation_id,
            "seq": seq,
            "extra": dict(extra),
        }
        sealed = self._seal(event)
        self._audit_sink({"event": event, "sealed": sealed})
        return sealed

    def _mint_id(self, invitee_id: str, seq: int) -> str:
        self._counter += 1
        return f"inv-{seq}-{self._counter}-{abs(hash((invitee_id, seq, self._counter))) % 10_000_000}"

    def _replace(self, rec: InvitationRecord, **changes: Any) -> InvitationRecord:
        data = asdict(rec)
        data.update(changes)
        return InvitationRecord(**data)

    # -- public API --------------------------------------------------------

    def invite(self, params: InviteParams) -> Decision:
        ok, reason = params.validate()
        if not ok:
            return Decision(False, f"invalid params: {reason}")
        can_invite, why = self._inviter_can_invite(params.invited_by, params.role, params.scope)
        if not can_invite:
            return Decision(False, f"inviter not authorized: {why}")
        # fail-closed: duplicate pending invite for the same invitee+role+scope set
        scope_key = tuple(sorted(params.scope))
        for iid in self._by_invitee.get(params.invitee_id, ()):
            rec = self._records[iid]
            if rec.state == "pending" and rec.role == params.role and tuple(sorted(rec.scope)) == scope_key:
                return Decision(False, "duplicate pending invitation")
        invitation_id = self._mint_id(params.invitee_id, params.issued_at_seq)
        expires_at = params.issued_at_seq + params.ttl_seq
        record = InvitationRecord(
            invitation_id=invitation_id,
            invitee_id=params.invitee_id,
            invited_by=params.invited_by,
            role=params.role,
            scope=params.scope,
            issued_at_seq=params.issued_at_seq,
            expires_at_seq=expires_at,
            nonce=params.nonce,
            state="pending",
        )
        self._records[invitation_id] = record
        self._by_invitee.setdefault(params.invitee_id, set()).add(invitation_id)
        sealed = self._emit("invite", invitation_id, params.issued_at_seq, {"role": params.role})
        return Decision(True, "invited", {"record": asdict(record), "sealed": sealed})

    def _lookup(self, token: str) -> Optional[InvitationRecord]:
        return self._records.get(token)

    def accept(self, token: str, params: AcceptParams) -> Decision:
        ok, reason = params.validate()
        if not ok:
            return Decision(False, f"invalid params: {reason}")
        rec = self._lookup(token)
        if rec is None:
            return Decision(False, "unknown invitation")
        if rec.invitee_id != params.invitee_id:
            return Decision(False, "invitee mismatch")
        if rec.state != "pending":
            return Decision(False, f"invitation not pending (state={rec.state})")
        if params.now_seq > rec.expires_at_seq:
            self._records[token] = self._replace(rec, state="expired")
            self._emit("expire", token, params.now_seq, {"reason": "accept-after-expiry"})
            return Decision(False, "invitation expired")
        admitted = self._replace(rec, state="accepted")
        self._records[token] = admitted
        sealed = self._emit("accept", token, params.now_seq, {"role": rec.role})
        return Decision(
            True,
            "accepted",
            {"record": asdict(admitted), "sealed": sealed},
        )

    def expire(self, token: str, now_seq: int) -> Decision:
        if not token:
            return Decision(False, "token required")
        if now_seq < 0:
            return Decision(False, "now_seq must be non-negative")
        rec = self._lookup(token)
        if rec is None:
            return Decision(False, "unknown invitation")
        if rec.state != "pending":
            return Decision(False, f"invitation not pending (state={rec.state})")
        expired = self._replace(rec, state="expired")
        self._records[token] = expired
        sealed = self._emit("expire", token, now_seq, {"reason": "explicit"})
        return Decision(True, "expired", {"record": asdict(expired), "sealed": sealed})

    # -- queries -----------------------------------------------------------

    def get(self, token: str) -> Optional[InvitationRecord]:
        return self._lookup(token)

    def pending_for(self, invitee_id: str) -> FrozenSet[InvitationRecord]:
        out = {
            self._records[iid]
            for iid in self._by_invitee.get(invitee_id, ())
            if self._records[iid].state == "pending"
        }
        return frozenset(out)
