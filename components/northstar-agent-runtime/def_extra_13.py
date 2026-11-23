"""Non-repudiation receipts (mock), Simulated.

Issues a signed receipt binding (actor, action, payload_hash, ts) so
the actor cannot later deny having performed the action.  Receipts
are HMAC-signed by the authority key.

What this IS: proof-of-origin for sensitive actions.

What this IS NOT:
* Not asymmetric non-repudiation -- HMAC stand-in; true
  non-repudiation needs the actor's own private key.
* Bad MAC or mismatched binding FAILS CLOSED.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Optional, Tuple

#: Module version.
DEF_EXTRA_13_VERSION = "def-extra-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-13.v1"


class NonRepudiationError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Receipt:
    """A non-repudiation receipt."""

    actor: str
    action: str
    payload_hash: str
    ts: float
    mac: str


class ReceiptAuthority:
    """Issue and verify non-repudiation receipts."""

    def __init__(self, key: bytes) -> None:
        if not key:
            raise NonRepudiationError("key required")
        self._key = key

    def _mac(self, actor: str, action: str, payload_hash: str, ts: float) -> str:
        body = json.dumps(
            {"actor": actor, "action": action, "payload_hash": payload_hash, "ts": ts},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hmac.new(self._key, body, hashlib.sha256).hexdigest()

    def issue(
        self,
        actor: str,
        action: str,
        payload_hash: str,
        *,
        now: Optional[float] = None,
    ) -> Receipt:
        """Issue a receipt for an action."""
        if not actor or not action or not payload_hash:
            raise NonRepudiationError("actor, action, payload_hash required")
        ts = time.time() if now is None else now
        return Receipt(actor, action, payload_hash, ts, self._mac(actor, action, payload_hash, ts))

    def verify(self, receipt: Receipt) -> Tuple[bool, str]:
        """Verify the receipt MAC and binding."""
        expected = self._mac(
            receipt.actor, receipt.action, receipt.payload_hash, receipt.ts
        )
        if not hmac.compare_digest(expected, receipt.mac):
            return False, "bad MAC: receipt forged or tampered"
        return True, "ok"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "hashlib", "hmac",
        "json", "pathlib", "time", "typing",
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
    authority = ReceiptAuthority(b"nr-key")
    receipt = authority.issue("alice", "deploy", "sha256:cfg", now=1000.0)
    ok, reason = authority.verify(receipt)
    assert ok is True, reason
    # Swapped actor -> forged.
    forged = Receipt("mallory", receipt.action, receipt.payload_hash, receipt.ts, receipt.mac)
    ok, _ = authority.verify(forged)
    assert ok is False
    # Swapped action -> forged.
    forged2 = Receipt(receipt.actor, "rm -rf", receipt.payload_hash, receipt.ts, receipt.mac)
    ok, _ = authority.verify(forged2)
    assert ok is False
    assert stdlib_only()
    print("def-extra-13 OK: issue, verify, binding")


if __name__ == "__main__":
    main()
