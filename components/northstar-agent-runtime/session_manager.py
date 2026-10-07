"""Session manager (P0): login / logout / refresh with sealed audit.

Interface:
    SessionManager.login(LoginRequest) -> SessionToken  (opaque bearer token)
    SessionManager.validate(token, seq) -> Optional[SessionRecord]
    SessionManager.logout(token, seq)  -> bool (revokes the session)
    SessionManager.refresh(token, seq) -> Optional[SessionToken] (rotation)
    SessionManager.sweep(seq) -> int (purges expired sessions)

House style: frozen dataclasses, no wall-clock (caller supplies a
monotonic ``seq``), fail-closed validation, stdlib only, audit events as
``audit.ndjson/1`` JSONL lines supplied by the caller.

Security notes
--------------
- The manager stores only ``sha256`` digests of issued tokens; the raw
  token is returned exactly once, to the login/refresh caller, and never
  appears in records, audits, or errors. A stolen database yields no
  bearer value.
- Refresh rotates the token atomically: the old token is revoked and a
  new one issued in a single locked step, so there is no window in which
  two live tokens map to the same session.
- Credential verification is injected as ``verify`` (``(user_id,
  presented) -> bool``) so the manager never sees password-hashing
  policy; it only learns accept/reject. Fail-closed: a ``verify``
  callable that raises is treated as reject.
- Expiry is enforced on the caller's ``seq`` (a monotonic tick). A
  session with ``expires_seq <= seq`` validates as invalid and may be
  swept. There is no wall-clock anywhere in this module.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, Mapping, Optional, Tuple


_AUDIT_TYPE = "audit.ndjson/1"

#: Token digest prefix so a stored digest is self-describing.
_DIGEST_PREFIX = "sha256:"


def _digest(token: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LoginRequest:
    """Inputs required to open a session."""

    user_id: str
    presented: Mapping[str, Any] = field(default_factory=dict)
    device_id: str = ""
    client_id: str = ""
    ttl_seq: int = 1_000
    max_refresh: int = 10
    issued_at_seq: int = 0

    def validate(self) -> Tuple[bool, str]:
        if not self.user_id or not self.user_id.strip():
            return False, "user_id required"
        if self.ttl_seq <= 0:
            return False, "ttl_seq must be positive"
        if self.max_refresh < 0:
            return False, "max_refresh must be non-negative"
        if self.issued_at_seq < 0:
            return False, "issued_at_seq must be non-negative"
        if len(self.device_id) > 256 or len(self.client_id) > 256:
            return False, "device_id/client_id too long"
        return True, ""


@dataclass(frozen=True)
class SessionRecord:
    """Public, sealed view of a live session. Never carries the raw token."""

    token_digest: str
    user_id: str
    device_id: str
    client_id: str
    created_seq: int
    last_seen_seq: int
    expires_seq: int
    refresh_count: int
    max_refresh: int
    revoked: bool = False


@dataclass(frozen=True)
class SessionToken:
    """Bearer token returned once to the caller. Keep it secret."""

    token: str
    token_digest: str
    user_id: str
    expires_seq: int

    def validate(self) -> Tuple[bool, str]:
        if not self.token:
            return False, "empty token"
        if _digest(self.token) != self.token_digest:
            return False, "token/digest mismatch"
        return True, ""


class SessionManager:
    """Issues, validates, revokes, and rotates opaque session tokens."""

    def __init__(
        self,
        verify: Callable[[str, Mapping[str, Any]], bool],
        audit: Optional[Callable[[Mapping[str, Any]], None]] = None,
        token_bytes: int = 32,
    ) -> None:
        if token_bytes < 16:
            raise ValueError("token_bytes must be >= 16")
        self._verify = verify
        self._audit = audit or (lambda _event: None)
        self._token_bytes = token_bytes
        self._lock = threading.RLock()
        # digest -> mutable session state (internal only; public views are frozen).
        self._sessions: Dict[str, Dict[str, Any]] = {}

    # -- internals -----------------------------------------------------

    def _emit(self, kind: str, seq: int, **fields: Any) -> None:
        event = {
            "type": _AUDIT_TYPE,
            "event": kind,
            "seq": seq,
        }
        event.update(fields)
        self._audit(event)

    def _mint(self) -> Tuple[str, str]:
        token = secrets.token_urlsafe(self._token_bytes)
        return token, _digest(token)

    # -- public API ----------------------------------------------------

    def login(self, request: LoginRequest) -> Optional[SessionToken]:
        """Open a session. Returns a bearer token on success, None on reject."""
        ok, reason = request.validate()
        if not ok:
            self._emit("session.login_rejected", request.issued_at_seq,
                       user_id=request.user_id, reason=reason)
            return None
        try:
            accepted = bool(self._verify(request.user_id, request.presented))
        except Exception as exc:  # fail closed: verifier errors are rejects
            self._emit("session.login_rejected", request.issued_at_seq,
                       user_id=request.user_id, reason="verifier_error",
                       detail=type(exc).__name__)
            return None
        if not accepted:
            self._emit("session.login_rejected", request.issued_at_seq,
                       user_id=request.user_id, reason="bad_credentials")
            return None
        token, digest = self._mint()
        with self._lock:
            # A digest collision (or replay of a minted digest) must never
            # silently alias two sessions: re-mint until unique.
            while digest in self._sessions:
                token, digest = self._mint()
            self._sessions[digest] = {
                "user_id": request.user_id,
                "device_id": request.device_id,
                "client_id": request.client_id,
                "created_seq": request.issued_at_seq,
                "last_seen_seq": request.issued_at_seq,
                "expires_seq": request.issued_at_seq + request.ttl_seq,
                "refresh_count": 0,
                "max_refresh": request.max_refresh,
                "revoked": False,
            }
        self._emit("session.login", request.issued_at_seq,
                   user_id=request.user_id, token_digest=digest,
                   device_id=request.device_id, client_id=request.client_id)
        return SessionToken(token=token, token_digest=digest,
                            user_id=request.user_id,
                            expires_seq=request.issued_at_seq + request.ttl_seq)

    def validate(self, token: str, seq: int) -> Optional[SessionRecord]:
        """Return the live session for ``token`` at ``seq``, else None."""
        if not token:
            return None
        digest = _digest(token)
        with self._lock:
            state = self._sessions.get(digest)
            if state is None or state["revoked"]:
                self._emit("session.validate_failed", seq,
                           token_digest=digest,
                           reason="unknown" if state is None else "revoked")
                return None
            if seq >= state["expires_seq"]:
                self._emit("session.validate_failed", seq,
                           token_digest=digest, reason="expired")
                return None
            state["last_seen_seq"] = seq
            return SessionRecord(
                token_digest=digest,
                user_id=state["user_id"],
                device_id=state["device_id"],
                client_id=state["client_id"],
                created_seq=state["created_seq"],
                last_seen_seq=state["last_seen_seq"],
                expires_seq=state["expires_seq"],
                refresh_count=state["refresh_count"],
                max_refresh=state["max_refresh"],
                revoked=False,
            )

    def logout(self, token: str, seq: int) -> bool:
        """Revoke the session. Idempotent: unknown/already-revoked -> False."""
        if not token:
            return False
        digest = _digest(token)
        with self._lock:
            state = self._sessions.get(digest)
            if state is None or state["revoked"]:
                self._emit("session.logout_failed", seq,
                           token_digest=digest,
                           reason="unknown" if state is None else "already_revoked")
                return False
            state["revoked"] = True
        self._emit("session.logout", seq, token_digest=digest,
                   user_id=state["user_id"])
        return True

    def refresh(self, token: str, seq: int) -> Optional[SessionToken]:
        """Rotate: revoke ``token`` and issue a fresh one for the same session."""
        if not token:
            return None
        old_digest = _digest(token)
        with self._lock:
            state = self._sessions.get(old_digest)
            if state is None or state["revoked"]:
                self._emit("session.refresh_failed", seq,
                           token_digest=old_digest,
                           reason="unknown" if state is None else "revoked")
                return None
            if seq >= state["expires_seq"]:
                self._emit("session.refresh_failed", seq,
                           token_digest=old_digest, reason="expired")
                return None
            if state["refresh_count"] >= state["max_refresh"]:
                self._emit("session.refresh_failed", seq,
                           token_digest=old_digest, reason="refresh_limit")
                return None
            ttl = state["expires_seq"] - state["created_seq"]
            new_token, new_digest = self._mint()
            while new_digest in self._sessions:
                new_token, new_digest = self._mint()
            state["revoked"] = True
            self._sessions[new_digest] = {
                "user_id": state["user_id"],
                "device_id": state["device_id"],
                "client_id": state["client_id"],
                "created_seq": state["created_seq"],
                "last_seen_seq": seq,
                "expires_seq": seq + ttl,
                "refresh_count": state["refresh_count"] + 1,
                "max_refresh": state["max_refresh"],
                "revoked": False,
            }
        self._emit("session.refresh", seq, old_digest=old_digest,
                   token_digest=new_digest, user_id=state["user_id"])
        return SessionToken(token=new_token, token_digest=new_digest,
                            user_id=state["user_id"], expires_seq=seq + ttl)

    def sweep(self, seq: int) -> int:
        """Purge sessions expired at ``seq``. Returns the number purged."""
        with self._lock:
            expired = [d for d, s in self._sessions.items()
                       if seq >= s["expires_seq"]]
            for digest in expired:
                del self._sessions[digest]
        if expired:
            self._emit("session.sweep", seq, purged=len(expired))
        return len(expired)

    def active_count(self) -> int:
        """Number of stored (not yet swept) sessions."""
        with self._lock:
            return len(self._sessions)


def main() -> int:
    """Self-check: login -> validate -> refresh -> logout, fail-closed."""
    events = []
    mgr = SessionManager(
        verify=lambda uid, presented: presented.get("ok") is True,
        audit=events.append,
    )
    req = LoginRequest(user_id="u1", presented={"ok": True}, issued_at_seq=0)
    tok = mgr.login(req)
    assert tok is not None and tok.validate()[0]
    assert mgr.validate(tok.token, 10) is not None
    # bad credentials rejected
    assert mgr.login(LoginRequest(user_id="u1", presented={}, issued_at_seq=0)) is None
    # refresh rotates
    tok2 = mgr.refresh(tok.token, 20)
    assert tok2 is not None and tok2.token != tok.token
    assert mgr.validate(tok.token, 21) is None  # old token dead
    assert mgr.validate(tok2.token, 21) is not None
    # logout revokes
    assert mgr.logout(tok2.token, 30) is True
    assert mgr.validate(tok2.token, 31) is None
    # verifier raising -> reject, never a crash
    mgr2 = SessionManager(verify=lambda u, p: 1 / 0, audit=events.append)
    assert mgr2.login(LoginRequest(user_id="u", presented={}, issued_at_seq=0)) is None
    # audit trail used audit.ndjson/1
    assert events and all(e["type"] == _AUDIT_TYPE for e in events)
    print(f"session_manager self-check OK ({len(events)} audit events)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
