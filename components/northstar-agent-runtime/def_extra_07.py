"""Step-up authentication (mock), Simulated.

Issues a single-use challenge bound to a principal with a TTL, then
verifies the presented token.  The expected token is an HMAC of
(challenge_id, principal, issued_at) under a server key.

What this IS: challenge/response issuance + verification.

What this IS NOT:
* Not a real second factor -- the "user" here is the host supplying
  the token; HMAC is a stand-in for a real authenticator.
* Unknown/expired/reused challenge FAILS CLOSED.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

#: Module version.
DEF_EXTRA_07_VERSION = "def-extra-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-07.v1"


class StepUpError(Exception):
    """Fail-closed."""


@dataclass
class _Challenge:
    challenge_id: str
    principal: str
    issued_at: float
    expires_at: float
    expected: str
    used: bool = False


class StepUpAuth:
    """Issue and verify single-use step-up challenges."""

    def __init__(self, server_key: bytes, *, ttl_s: float = 300.0) -> None:
        if not server_key:
            raise StepUpError("server_key required")
        if ttl_s <= 0:
            raise StepUpError("ttl_s must be positive")
        self._key = server_key
        self._ttl = ttl_s
        self._challenges: Dict[str, _Challenge] = {}

    def _token(self, challenge_id: str, principal: str, issued_at: float) -> str:
        msg = f"{challenge_id}:{principal}:{issued_at:.6f}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def issue(
        self, principal: str, *, now: Optional[float] = None
    ) -> Tuple[str, str]:
        """Issue a challenge.  Returns (challenge_id, expected_token).

        The token is returned for tests; in production the host would
        deliver only the challenge_id and compute the token via the
        user's authenticator path.
        """
        if not principal:
            raise StepUpError("principal required")
        ts = time.time() if now is None else now
        challenge_id = "ch-" + secrets.token_hex(8)
        expected = self._token(challenge_id, principal, ts)
        self._challenges[challenge_id] = _Challenge(
            challenge_id, principal, ts, ts + self._ttl, expected
        )
        return challenge_id, expected

    def verify(
        self,
        challenge_id: str,
        principal: str,
        token: str,
        *,
        now: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """Verify a presented token.  Single-use."""
        ts = time.time() if now is None else now
        chal = self._challenges.get(challenge_id)
        if chal is None:
            return False, "unknown challenge"
        if chal.used:
            return False, "challenge already used"
        if ts > chal.expires_at:
            return False, "challenge expired"
        if chal.principal != principal:
            return False, "principal mismatch"
        chal.used = True
        if not hmac.compare_digest(chal.expected, token):
            return False, "bad token"
        return True, "ok"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "hashlib", "hmac",
        "pathlib", "secrets", "time", "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    auth = StepUpAuth(b"server-secret", ttl_s=60.0)
    cid, token = auth.issue("alice", now=1000.0)
    ok, reason = auth.verify(cid, "alice", token, now=1010.0)
    assert ok is True, reason
    # Replay fails.
    ok, reason = auth.verify(cid, "alice", token, now=1011.0)
    assert ok is False and "used" in reason
    # Wrong principal fails.
    cid2, token2 = auth.issue("alice", now=1000.0)
    ok, _ = auth.verify(cid2, "mallory", token2, now=1010.0)
    assert ok is False
    # Expired fails.
    cid3, token3 = auth.issue("alice", now=1000.0)
    ok, reason = auth.verify(cid3, "alice", token3, now=2000.0)
    assert ok is False and "expired" in reason
    # Unknown challenge fails closed.
    ok, _ = auth.verify("ch-nope", "alice", "x", now=1010.0)
    assert ok is False
    assert stdlib_only()
    print("def-extra-07 OK: issue, verify, single-use, expiry")


if __name__ == "__main__":
    main()
