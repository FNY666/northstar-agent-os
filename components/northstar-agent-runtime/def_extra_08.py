"""Transaction signing (mock), Simulated.

Signs a canonical transaction dict with HMAC-SHA256 and keeps a
nonce ledger to reject replays.  The nonce must be unique per
transaction.

What this IS: integrity + replay protection for sensitive actions.

What this IS NOT:
* Not asymmetric signing -- HMAC with a shared key is the stand-in.
* Reused nonce or bad signature FAILS CLOSED.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Dict, Tuple

#: Module version.
DEF_EXTRA_08_VERSION = "def-extra-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-08.v1"


class TxnSigningError(Exception):
    """Fail-closed."""


def canonical(tx: Dict) -> bytes:
    """Canonical JSON encoding of a transaction."""
    return json.dumps(tx, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class SignedTxn:
    """A signed transaction envelope."""

    tx: Dict
    nonce: str
    signature: str


class TxnSigner:
    """Sign transactions and reject replays."""

    def __init__(self, key: bytes) -> None:
        if not key:
            raise TxnSigningError("key required")
        self._key = key
        self._seen_nonces: set = set()

    def sign(self, tx: Dict, nonce: str) -> SignedTxn:
        """Sign a transaction with a fresh nonce."""
        if not nonce:
            raise TxnSigningError("nonce required")
        if nonce in self._seen_nonces:
            raise TxnSigningError("nonce already used")
        body = canonical({"tx": tx, "nonce": nonce})
        sig = hmac.new(self._key, body, hashlib.sha256).hexdigest()
        self._seen_nonces.add(nonce)
        return SignedTxn(dict(tx), nonce, sig)

    def verify(self, signed: SignedTxn) -> Tuple[bool, str]:
        """Verify signature and nonce freshness."""
        if signed.nonce not in self._seen_nonces:
            return False, "unknown nonce"
        body = canonical({"tx": signed.tx, "nonce": signed.nonce})
        expected = hmac.new(self._key, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signed.signature):
            return False, "bad signature"
        return True, "ok"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "hmac", "json", "pathlib", "typing"}
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
    signer = TxnSigner(b"txn-key")
    tx = {"action": "transfer", "amount": 100, "to": "bob"}
    signed = signer.sign(tx, "n-1")
    assert signed.signature
    ok, reason = signer.verify(signed)
    assert ok is True, reason
    # Tampered tx fails.
    tampered = SignedTxn({"action": "transfer", "amount": 9999, "to": "bob"}, "n-1", signed.signature)
    ok, _ = signer.verify(tampered)
    assert ok is False
    # Unknown nonce fails closed.
    ok, _ = signer.verify(SignedTxn(tx, "n-9", signed.signature))
    assert ok is False
    # Reused nonce rejected at sign time.
    try:
        signer.sign(tx, "n-1")
    except TxnSigningError:
        pass
    else:
        raise AssertionError("expected TxnSigningError")
    assert stdlib_only()
    print("def-extra-08 OK: sign, verify, replay rejection")


if __name__ == "__main__":
    main()
