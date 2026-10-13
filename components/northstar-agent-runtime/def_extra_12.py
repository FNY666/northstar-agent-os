"""Secure timestamping authority (mock), Simulated.

Issues timestamp tokens binding a data hash to a time: the token is
HMAC(ts, nonce, data_hash).  verify() enforces monotonicity (no
backdating past the last issued stamp) and a future-skew bound.

What this IS: prove "data existed no later than T".

What this IS NOT:
* Not an RFC 3161 TSA -- no X.509, HMAC stand-in for TSA signature.
* Backdated or far-future stamps FAIL CLOSED.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Tuple

#: Module version.
DEF_EXTRA_12_VERSION = "def-extra-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-12.v1"


class TimestampError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class TimestampToken:
    """A timestamp token."""

    ts: float
    nonce: str
    data_hash: str
    mac: str


class TimestampAuthority:
    """Issue and verify timestamp tokens."""

    def __init__(
        self, key: bytes, *, max_future_skew_s: float = 60.0
    ) -> None:
        if not key:
            raise TimestampError("key required")
        if max_future_skew_s < 0:
            raise TimestampError("skew must be >= 0")
        self._key = key
        self._skew = max_future_skew_s
        self._last_ts: Optional[float] = None

    def _mac(self, ts: float, nonce: str, data_hash: str) -> str:
        msg = f"{ts:.6f}:{nonce}:{data_hash}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def issue(
        self, data_hash: str, *, now: Optional[float] = None
    ) -> TimestampToken:
        """Stamp a data hash at `now`."""
        if not data_hash:
            raise TimestampError("data_hash required")
        ts = time.time() if now is None else now
        if self._last_ts is not None and ts < self._last_ts:
            raise TimestampError("clock moved backwards")
        nonce = secrets.token_hex(8)
        token = TimestampToken(ts, nonce, data_hash, self._mac(ts, nonce, data_hash))
        self._last_ts = ts
        return token

    def verify(
        self, token: TimestampToken, *, now: Optional[float] = None
    ) -> Tuple[bool, str]:
        """Verify MAC, monotonicity, and future skew."""
        ts = time.time() if now is None else now
        expected = self._mac(token.ts, token.nonce, token.data_hash)
        if not hmac.compare_digest(expected, token.mac):
            return False, "bad MAC"
        if self._last_ts is not None and token.ts < self._last_ts:
            return False, "backdated stamp"
        if token.ts > ts + self._skew:
            return False, "stamp too far in the future"
        if token.ts > self._last_ts if self._last_ts is not None else True:
            self._last_ts = max(token.ts, self._last_ts or 0.0)
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
    tsa = TimestampAuthority(b"tsa-key", max_future_skew_s=60.0)
    t1 = tsa.issue("sha256:abc", now=1000.0)
    ok, reason = tsa.verify(t1, now=1010.0)
    assert ok is True, reason
    # Tampered data_hash fails.
    bad = TimestampToken(t1.ts, t1.nonce, "sha256:evil", t1.mac)
    ok, _ = tsa.verify(bad, now=1010.0)
    assert ok is False
    # Far-future stamp fails.
    t2 = tsa.issue("sha256:def", now=1000.0)
    future = TimestampToken(99999.0, t2.nonce, t2.data_hash,
                            tsa._mac(99999.0, t2.nonce, t2.data_hash))
    ok, reason = tsa.verify(future, now=1010.0)
    assert ok is False and "future" in reason
    assert stdlib_only()
    print("def-extra-12 OK: issue, verify, skew bound")


if __name__ == "__main__":
    main()
