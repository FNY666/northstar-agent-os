"""Crypto Defense 11: Hybrid schemes (classical + PQ), Simulated.

Combine classical and post-quantum KEMs.  Shared secret is derived
from both via KDF.  Secure if EITHER is secure (defense in depth
for PQ migration).

What this IS: hybrid KDF combiner API.
What this IS NOT: real hybrid TLS.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
from typing import Tuple

#: Module version.
CRYPTO_DEFENSE_11_VERSION = "crypto-defense-11.v1"
SCHEMA_PIN = "northstar.crypto-defense-11.v1"


class HybridError(Exception):
    """Fail-closed."""


def _mock_classical_kem() -> Tuple[bytes, bytes, bytes]:
    """Mock classical KEM. Returns (pk, ct, ss)."""
    ss = secrets.token_bytes(32)
    pk = hashlib.sha256(b"classical" + ss).digest()
    ct = hashlib.sha256(b"ct" + ss).digest()
    return pk, ct, ss


def _mock_pq_kem() -> Tuple[bytes, bytes, bytes]:
    """Mock PQ KEM. Returns (pk, ct, ss)."""
    ss = secrets.token_bytes(32)
    pk = hashlib.sha256(b"pq" + ss).digest()
    ct = hashlib.sha256(b"pqct" + ss).digest()
    return pk, ct, ss


def hybrid_encaps() -> Tuple[bytes, bytes, bytes]:
    """Hybrid encaps: returns (ct_combined, ss_classical, ss_pq).

    In real use, both KEMs encapsulate and the SS are combined.
    Here we return components for the combiner.
    """
    _, ct_c, ss_c = _mock_classical_kem()
    _, ct_p, ss_p = _mock_pq_kem()
    # Combined ct = ct_c || ct_p.
    ct_combined = ct_c + ct_p
    return ct_combined, ss_c, ss_p


def hybrid_kdf(ss_classical: bytes, ss_pq: bytes, info: bytes = b"") -> bytes:
    """Combine two shared secrets via HKDF-like KDF.

    Security: if either SS is secure, output is secure.
    """
    if not isinstance(ss_classical, bytes) or len(ss_classical) != 32:
        raise HybridError("bad classical ss")
    if not isinstance(ss_pq, bytes) or len(ss_pq) != 32:
        raise HybridError("bad pq ss")
    # HKDF-Extract then Expand (simplified).
    prk = hmac.new(b"\x00" * 32, ss_classical + ss_pq, hashlib.sha256).digest()
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "hashlib", "hmac", "pathlib", "secrets", "typing"}
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
    ct, ss_c, ss_p = hybrid_encaps()
    assert len(ct) == 64  # 32+32
    combined = hybrid_kdf(ss_c, ss_p, b"session")
    assert len(combined) == 32
    # Different info -> different output.
    combined2 = hybrid_kdf(ss_c, ss_p, b"other")
    assert combined != combined2
    # Bad inputs.
    try:
        hybrid_kdf(b"short", ss_p)
        raise AssertionError("should raise")
    except HybridError:
        pass
    assert stdlib_only()
    print("crypto-defense-11 OK")


if __name__ == "__main__":
    main()
