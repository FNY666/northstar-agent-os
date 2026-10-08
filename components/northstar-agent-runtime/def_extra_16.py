"""OCSP stapling check (mock), Simulated.

Validates a stapled OCSP response: status must be good, the response
must be fresh (this_update <= now <= next_update), and it must not be
older than max_age.

What this IS: freshness + status policy for stapled responses.

What this IS NOT:
* Not real OCSP -- response is HMAC-signed by the mock responder.
* Stale, future, or revoked responses FAIL CLOSED.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Optional, Tuple

#: Module version.
DEF_EXTRA_16_VERSION = "def-extra-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-16.v1"


class OCSPError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class OCSPResponse:
    """Stapled OCSP response (mock)."""

    serial: str
    status: str  # "good", "revoked", "unknown"
    this_update: float
    next_update: float
    mac: str


class OCSPResponder:
    """Mock OCSP responder + stapling validator."""

    def __init__(self, key: bytes, *, max_age_s: float = 86400.0) -> None:
        if not key:
            raise OCSPError("key required")
        if max_age_s <= 0:
            raise OCSPError("max_age_s must be positive")
        self._key = key
        self._max_age = max_age_s

    def _mac(self, serial: str, status: str, this_update: float, next_update: float) -> str:
        msg = f"{serial}:{status}:{this_update:.0f}:{next_update:.0f}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def staple(
        self,
        serial: str,
        status: str,
        *,
        now: Optional[float] = None,
        validity_s: float = 3600.0,
    ) -> OCSPResponse:
        """Issue a stapled response valid for validity_s."""
        ts = time.time() if now is None else now
        this_update, next_update = ts, ts + validity_s
        return OCSPResponse(
            serial, status, this_update, next_update,
            self._mac(serial, status, this_update, next_update),
        )

    def check(
        self, response: OCSPResponse, *, now: Optional[float] = None
    ) -> Tuple[bool, str]:
        """Validate a stapled response."""
        ts = time.time() if now is None else now
        expected = self._mac(
            response.serial, response.status, response.this_update, response.next_update
        )
        if not hmac.compare_digest(expected, response.mac):
            return False, "bad MAC"
        if response.status == "revoked":
            return False, "certificate revoked"
        if response.status != "good":
            return False, f"bad status: {response.status}"
        if ts < response.this_update:
            return False, "response from the future"
        if ts > response.next_update:
            return False, "response expired"
        if ts - response.this_update > self._max_age:
            return False, "response too old"
        return True, "ok"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "hashlib", "hmac",
        "pathlib", "time", "typing",
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
    responder = OCSPResponder(b"ocsp-key", max_age_s=86400.0)
    resp = responder.staple("01:23", "good", now=1000.0, validity_s=3600.0)
    ok, reason = responder.check(resp, now=2000.0)
    assert ok is True, reason
    # Revoked fails.
    revoked = responder.staple("01:23", "revoked", now=1000.0)
    ok, _ = responder.check(revoked, now=2000.0)
    assert ok is False
    # Expired fails.
    ok, reason = responder.check(resp, now=99999.0)
    assert ok is False and "expired" in reason
    # Tampered status fails.
    tampered = OCSPResponse(resp.serial, "good", resp.this_update, resp.next_update, "00")
    ok, _ = responder.check(tampered, now=2000.0)
    assert ok is False
    assert stdlib_only()
    print("def-extra-16 OK: staple, freshness, revoked")


if __name__ == "__main__":
    main()
