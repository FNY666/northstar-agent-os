"""Crypto Defense 17: Remote attestation (mock), Simulated.

Challenge-response: verifier issues a fresh nonce, prover returns a
quote (nonce + measurement + MAC).  Verifier rejects reused nonces
(replay protection) and bad MACs.

What this IS: remote attestation handshake API with replay protection.
What this IS NOT: real TPM quote / DAA / certificate chains.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Dict, Set

#: Module version.
CRYPTO_DEFENSE_17_VERSION = "crypto-defense-17.v1"
SCHEMA_PIN = "northstar.crypto-defense-17.v1"


class AttestationError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Challenge:
    """Verifier-issued freshness challenge."""

    nonce: str


@dataclass(frozen=True)
class RemoteQuote:
    """Prover's response."""

    nonce: str
    measurement: str
    mac: str


class MockProver:
    """Remote party being attested."""

    def __init__(self, measurement: str) -> None:
        if not measurement:
            raise AttestationError("measurement required")
        self._measurement = measurement
        self._key = secrets.token_bytes(32)

    def respond(self, challenge: Challenge) -> RemoteQuote:
        if not isinstance(challenge, Challenge) or not challenge.nonce:
            raise AttestationError("bad challenge")
        body = f"{challenge.nonce}|{self._measurement}".encode()
        mac = hmac.new(self._key, body, hashlib.sha256).hexdigest()
        return RemoteQuote(challenge.nonce, self._measurement, mac)

    def verifier_key(self) -> bytes:
        return self._key


class MockVerifier:
    """Verifier with replay protection."""

    def __init__(self) -> None:
        self._used_nonces: Set[str] = set()

    def issue_challenge(self) -> Challenge:
        return Challenge(secrets.token_hex(16))

    def verify(
        self, quote: RemoteQuote, key: bytes, expected_measurement: str
    ) -> bool:
        if not isinstance(quote, RemoteQuote):
            return False
        # Replay: nonce already consumed.
        if quote.nonce in self._used_nonces:
            return False
        body = f"{quote.nonce}|{quote.measurement}".encode()
        mac = hmac.new(key, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, quote.mac):
            return False
        if not hmac.compare_digest(quote.measurement, expected_measurement):
            return False
        self._used_nonces.add(quote.nonce)
        return True


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "hmac",
        "pathlib",
        "secrets",
        "typing",
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
    prover = MockProver("meas-abc")
    verifier = MockVerifier()
    ch = verifier.issue_challenge()
    quote = prover.respond(ch)
    assert verifier.verify(quote, prover.verifier_key(), "meas-abc") is True
    # Replay of the same quote: rejected.
    assert verifier.verify(quote, prover.verifier_key(), "meas-abc") is False
    # Wrong measurement: rejected (fresh challenge).
    ch2 = verifier.issue_challenge()
    quote2 = prover.respond(ch2)
    assert verifier.verify(quote2, prover.verifier_key(), "meas-zzz") is False
    assert stdlib_only()
    print("crypto-defense-17 OK")


if __name__ == "__main__":
    main()
