"""Crypto Defense 16: Secure enclaves (mock attestation), Simulated.

A mock enclave produces an attestation quote binding its measurement
(code identity) to a nonce, MACed with the enclave attestation key.
The verifier checks the MAC and compares the measurement to expected.

What this IS: enclave identity + quote verification API.
What this IS NOT: real SGX/SEV/TDX attestation or hardware isolation.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Dict

#: Module version.
CRYPTO_DEFENSE_16_VERSION = "crypto-defense-16.v1"
SCHEMA_PIN = "northstar.crypto-defense-16.v1"


class EnclaveError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttestationQuote:
    """Enclave attestation quote (mock)."""

    enclave_id: str
    measurement: str  # sha256 hex of code+config
    nonce: str
    mac: str  # hex, over enclave_id|measurement|nonce


class MockEnclave:
    """Mock secure enclave that can attest its measurement."""

    def __init__(self, enclave_id: str, code: bytes, config: bytes = b"") -> None:
        if not enclave_id:
            raise EnclaveError("enclave_id required")
        if not isinstance(code, bytes):
            raise EnclaveError("code must be bytes")
        self._enclave_id = enclave_id
        self._measurement = hashlib.sha256(code + b"|" + config).hexdigest()
        self._att_key = secrets.token_bytes(32)

    @property
    def measurement(self) -> str:
        return self._measurement

    def attest(self, nonce: str) -> AttestationQuote:
        """Produce an attestation quote for a verifier nonce."""
        if not nonce:
            raise EnclaveError("nonce required")
        body = f"{self._enclave_id}|{self._measurement}|{nonce}".encode()
        mac = hmac.new(self._att_key, body, hashlib.sha256).hexdigest()
        return AttestationQuote(self._enclave_id, self._measurement, nonce, mac)

    def verifier_key(self) -> bytes:
        """Attestation key (in reality distributed via cert chain)."""
        return self._att_key


def verify_quote(
    quote: AttestationQuote, att_key: bytes, expected_measurement: str
) -> bool:
    """Verify a quote: MAC valid AND measurement matches expected."""
    if not isinstance(quote, AttestationQuote):
        return False
    if not isinstance(att_key, bytes) or not att_key:
        return False
    body = f"{quote.enclave_id}|{quote.measurement}|{quote.nonce}".encode()
    mac = hmac.new(att_key, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, quote.mac):
        return False
    return hmac.compare_digest(quote.measurement, expected_measurement)


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
    enclave = MockEnclave("enc-1", b"trusted code v1")
    quote = enclave.attest("nonce-123")
    assert verify_quote(quote, enclave.verifier_key(), enclave.measurement) is True
    # Tampered nonce: fails.
    bad = AttestationQuote(quote.enclave_id, quote.measurement, "other", quote.mac)
    assert verify_quote(bad, enclave.verifier_key(), enclave.measurement) is False
    # Wrong expected measurement: fails.
    assert verify_quote(quote, enclave.verifier_key(), "00" * 32) is False
    assert stdlib_only()
    print("crypto-defense-16 OK")


if __name__ == "__main__":
    main()
