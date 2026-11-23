"""Crypto Defense 19: TPM integration (mock), Simulated.

Mock TPM with PCRs, NV storage, AIK quotes, and seal/unseal bound to a
PCR policy: unseal fails if the PCRs no longer match the policy captured
at seal time.

What this IS: TPM 2.0-style API surface (mock).
What this IS NOT: real TPM hardware, EK/AIK certs, or sessions.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any, Dict, List

#: Module version.
CRYPTO_DEFENSE_19_VERSION = "crypto-defense-19.v1"
SCHEMA_PIN = "northstar.crypto-defense-19.v1"


class TpmError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class TpmQuote:
    """AIK-signed PCR quote (mock)."""

    pcrs: Dict[int, str]
    nonce: str
    mac: str


def _xor_stream(data: bytes, key: bytes, label: bytes) -> bytes:
    """Mock symmetric encryption: xor with HMAC keystream."""
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hmac.new(key, label + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(data, bytes(out)))


class MockTPM:
    """Mock TPM 2.0."""

    def __init__(self, n_pcrs: int = 8) -> None:
        self._pcrs: Dict[int, str] = {i: "00" * 32 for i in range(n_pcrs)}
        self._nv: Dict[str, bytes] = {}
        self._aik = secrets.token_bytes(32)
        self._srk = secrets.token_bytes(32)

    def extend_pcr(self, index: int, data: bytes) -> None:
        if index not in self._pcrs:
            raise TpmError("bad PCR index")
        raw = bytes.fromhex(self._pcrs[index]) + data
        self._pcrs[index] = hashlib.sha256(raw).hexdigest()

    def pcr_read(self) -> Dict[int, str]:
        return dict(self._pcrs)

    def quote(self, nonce: str) -> TpmQuote:
        if not nonce:
            raise TpmError("nonce required")
        body = json.dumps(
            {"pcrs": self._pcrs, "nonce": nonce}, sort_keys=True
        ).encode()
        mac = hmac.new(self._aik, body, hashlib.sha256).hexdigest()
        return TpmQuote(dict(self._pcrs), nonce, mac)

    def verify_quote(self, quote: TpmQuote) -> bool:
        if not isinstance(quote, TpmQuote):
            return False
        body = json.dumps(
            {"pcrs": quote.pcrs, "nonce": quote.nonce}, sort_keys=True
        ).encode()
        mac = hmac.new(self._aik, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, quote.mac)

    def nv_write(self, key: str, value: bytes) -> None:
        if not key:
            raise TpmError("key required")
        self._nv[key] = bytes(value)

    def nv_read(self, key: str) -> bytes:
        if key not in self._nv:
            raise TpmError("NV index not found")
        return self._nv[key]

    def seal(self, data: bytes, pcr_policy: Dict[int, str]) -> Dict[str, Any]:
        """Seal data to a PCR policy snapshot."""
        if not isinstance(data, bytes):
            raise TpmError("data must be bytes")
        blob = _xor_stream(data, self._srk, b"tpm-seal")
        policy_json = json.dumps(pcr_policy, sort_keys=True).encode()
        mac = hmac.new(self._srk, blob + policy_json, hashlib.sha256).hexdigest()
        return {"blob": blob.hex(), "policy": dict(pcr_policy), "mac": mac}

    def unseal(self, sealed: Dict[str, Any]) -> bytes:
        """Unseal only if current PCRs match the policy."""
        try:
            blob = bytes.fromhex(sealed["blob"])
            policy = {int(k): v for k, v in sealed["policy"].items()}
            mac = sealed["mac"]
        except Exception:
            raise TpmError("malformed sealed blob")
        for index, value in policy.items():
            if self._pcrs.get(index) != value:
                raise TpmError("PCR policy mismatch: refusing unseal")
        policy_json = json.dumps(
            {str(k): v for k, v in policy.items()}, sort_keys=True
        ).encode()
        # NOTE: policy was sealed with int keys serialized by json as str keys.
        expected = hmac.new(self._srk, blob + policy_json, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            raise TpmError("sealed blob integrity failure")
        return _xor_stream(blob, self._srk, b"tpm-seal")


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
        "json",
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
    tpm = MockTPM()
    q = tpm.quote("n1")
    assert tpm.verify_quote(q) is True
    # NV roundtrip.
    tpm.nv_write("k", b"v")
    assert tpm.nv_read("k") == b"v"
    # Seal/unseal with matching PCRs.
    policy = tpm.pcr_read()
    sealed = tpm.seal(b"secret", policy)
    assert tpm.unseal(sealed) == b"secret"
    # PCR change breaks unseal.
    tpm.extend_pcr(0, b"bootloader v2")
    try:
        tpm.unseal(sealed)
        raise AssertionError("should raise")
    except TpmError:
        pass
    assert stdlib_only()
    print("crypto-defense-19 OK")


if __name__ == "__main__":
    main()
