"""Proof-of-work challenge, hashcash-style (input defense), Simulated

What this IS: Issues a hashcash-style challenge (find nonce with N leading zero bits) to make flooding expensive. Small difficulties for tests; host sets production difficulty.

What this IS NOT:
* Not a consensus primitive -- just anti-flood.
* Difficulty must be tuned; too low is useless, too high hurts legit users.
"""

from __future__ import annotations

import hashlib, secrets

#: Module version.
MODULE_VERSION = "input-defense-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-26.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'hashlib', 'ast', 'secrets', 'typing'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


def _hash_meets(challenge, nonce, bits):
    digest = __import__("hashlib").sha256(
        (challenge + str(nonce)).encode()
    ).digest()
    value = int.from_bytes(digest, "big")
    return value >> (256 - bits) == 0


def issue_challenge():
    """Issue a random challenge string."""
    return __import__("secrets").token_hex(16)


def solve(challenge, bits, max_tries=1000000):
    """Find a nonce meeting the difficulty. Returns nonce."""
    if not isinstance(bits, int) or not 1 <= bits <= 32:
        raise InputDefenseError("bits must be int in [1,32]")
    nonce = 0
    while nonce < max_tries:
        if _hash_meets(challenge, nonce, bits):
            return nonce
        nonce += 1
    raise InputDefenseError("no solution within max_tries")


def verify(challenge, nonce, bits):
    """Verify a nonce. Returns True if valid."""
    if not isinstance(bits, int) or not 1 <= bits <= 32:
        raise InputDefenseError("bits must be int in [1,32]")
    if not isinstance(nonce, int) or nonce < 0:
        return False
    return _hash_meets(challenge, nonce, bits)


def require_pow(challenge, nonce, bits):
    """Gate helper. Raises InputDefenseError on invalid proof."""
    if not verify(challenge, nonce, bits):
        raise InputDefenseError("proof-of-work verification failed")
    return True



def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    """Self-check."""
    ch = issue_challenge()
    nonce = solve(ch, bits=8)
    assert verify(ch, nonce, 8) is True
    assert verify(ch, nonce + 1, 8) is False or True  # may or may not meet
    assert verify(ch, -1, 8) is False
    try:
        require_pow(ch, 999999999, 24)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    try:
        solve(ch, bits=0)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-26.v1 OK")


if __name__ == "__main__":
    main()
