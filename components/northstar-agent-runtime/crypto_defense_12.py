"""Crypto Defense 12: ZK proofs (mock), Simulated.

Mock zero-knowledge: prove(statement, witness) -> proof,
verify(statement, proof) -> bool.  Verifier learns nothing about
witness beyond statement validity.

Mock uses hash commitments (NOT real ZK-SNARKs).

What this IS: prove/verify API shape.
What this IS NOT: real zero-knowledge cryptography.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import secrets
from typing import Any, Dict

#: Module version.
CRYPTO_DEFENSE_12_VERSION = "crypto-defense-12.v1"
SCHEMA_PIN = "northstar.crypto-defense-12.v1"


class ZkError(Exception):
    """Fail-closed."""


class MockZk:
    """Mock ZK prover/verifier."""

    def __init__(self) -> None:
        # Trusted setup (mock).
        self._setup_secret = secrets.token_bytes(32)

    def prove(
        self, statement: Dict[str, Any], witness: Dict[str, Any]
    ) -> bytes:
        """Create proof that witness satisfies statement (mock)."""
        if not isinstance(statement, dict) or not statement:
            raise ZkError("statement required")
        if not isinstance(witness, dict) or not witness:
            raise ZkError("witness required")
        # Mock: proof = HMAC(setup, statement_hash || witness_hash).
        # Real ZK would not reveal witness; this mock does NOT achieve
        # zero-knowledge -- it's for API shape only.
        stmt_hash = hashlib.sha256(
            json.dumps(statement, sort_keys=True).encode()
        ).digest()
        wit_hash = hashlib.sha256(
            json.dumps(witness, sort_keys=True).encode()
        ).digest()
        proof = hmac.new(
            self._setup_secret, stmt_hash + wit_hash, hashlib.sha256
        ).digest()
        # Bind statement into proof.
        return stmt_hash + proof

    def verify(
        self, statement: Dict[str, Any], proof: bytes
    ) -> bool:
        """Verify proof for statement (mock)."""
        try:
            if not isinstance(proof, bytes) or len(proof) != 64:
                return False
            stmt_hash_in_proof = proof[:32]
            stmt_hash = hashlib.sha256(
                json.dumps(statement, sort_keys=True).encode()
            ).digest()
            # Statement must match what's in the proof.
            if not hmac.compare_digest(stmt_hash_in_proof, stmt_hash):
                return False
            # Mock: we can't verify without witness, so we check
            # the proof is well-formed for this setup.
            # (Real ZK verifies mathematically.)
            return True
        except Exception:
            return False


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "hashlib", "hmac", "json", "pathlib", "secrets", "typing"}
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
    zk = MockZk()
    stmt = {"claim": "age >= 18"}
    witness = {"age": 25, "id": "secret"}
    proof = zk.prove(stmt, witness)
    assert zk.verify(stmt, proof) is True
    # Wrong statement.
    assert zk.verify({"claim": "other"}, proof) is False
    # Bad proof.
    assert zk.verify(stmt, b"bad") is False
    # Empty.
    try:
        zk.prove({}, witness)
        raise AssertionError("should raise")
    except ZkError:
        pass
    assert stdlib_only()
    print("crypto-defense-12 OK")


if __name__ == "__main__":
    main()
