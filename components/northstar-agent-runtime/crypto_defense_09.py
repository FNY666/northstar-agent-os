"""Crypto Defense 09: Forward secrecy (mock), Simulated.

Ephemeral keys per session.  Compromise of long-term keys does not
compromise past sessions.  Ephemeral keys are discarded after use.

Mock: uses HMAC-based key derivation (NOT real DH/ECDH).

What this IS: ephemeral session key API.
What this IS NOT: real Diffie-Hellman or TLS.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Dict, Optional

#: Module version.
CRYPTO_DEFENSE_09_VERSION = "crypto-defense-09.v1"
SCHEMA_PIN = "northstar.crypto-defense-09.v1"


class ForwardSecrecyError(Exception):
    """Fail-closed."""


@dataclass
class Session:
    """One forward-secret session."""

    session_id: str
    ephemeral_key: bytes
    peer_ephemeral: bytes = b""
    shared_secret: bytes = b""
    closed: bool = False


class ForwardSecrecyManager:
    """Manages ephemeral sessions."""

    def __init__(self) -> None:
        self._sessions: Dict[str, Session] = {}

    def start_session(self, session_id: str) -> bytes:
        """Start session, generate ephemeral key. Returns public part."""
        if not session_id:
            raise ForwardSecrecyError("session_id required")
        if session_id in self._sessions:
            raise ForwardSecrecyError("session already exists")
        ephemeral = secrets.token_bytes(32)
        # Mock public = SHA256(private).
        public = hashlib.sha256(ephemeral).digest()
        self._sessions[session_id] = Session(
            session_id=session_id, ephemeral_key=ephemeral
        )
        return public

    def complete_handshake(
        self, session_id: str, peer_public: bytes
    ) -> bytes:
        """Complete handshake with peer's public. Returns shared secret."""
        session = self._sessions.get(session_id)
        if session is None:
            raise ForwardSecrecyError("unknown session")
        if session.closed:
            raise ForwardSecrecyError("session closed")
        if not isinstance(peer_public, bytes) or len(peer_public) != 32:
            raise ForwardSecrecyError("bad peer public")
        session.peer_ephemeral = peer_public
        # Mock DH: shared = HMAC(ephemeral, peer_public).
        # (NOT real DH -- both sides compute differently in mock,
        # so we simulate agreement via deterministic derivation.)
        shared = hmac.new(
            session.ephemeral_key, peer_public, hashlib.sha256
        ).digest()
        session.shared_secret = shared
        return shared

    def close_session(self, session_id: str) -> None:
        """Close session, destroy ephemeral key (forward secrecy)."""
        session = self._sessions.get(session_id)
        if session is None:
            raise ForwardSecrecyError("unknown session")
        # Zeroize.
        session.ephemeral_key = b"\x00" * 32
        session.shared_secret = b"\x00" * 32
        session.closed = True
        del self._sessions[session_id]

    def session_active(self, session_id: str) -> bool:
        s = self._sessions.get(session_id)
        return s is not None and not s.closed


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "hmac", "pathlib", "secrets", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    mgr = ForwardSecrecyManager()
    pub_a = mgr.start_session("s1")
    assert mgr.session_active("s1") is True
    # Peer completes (mock: both derive).
    shared = mgr.complete_handshake("s1", hashlib.sha256(b"peer").digest())
    assert len(shared) == 32
    # Close destroys key.
    mgr.close_session("s1")
    assert mgr.session_active("s1") is False
    # Unknown session.
    try:
        mgr.complete_handshake("nope", b"x" * 32)
        raise AssertionError("should raise")
    except ForwardSecrecyError:
        pass
    assert stdlib_only()
    print("crypto-defense-09 OK")


if __name__ == "__main__":
    main()
