"""Secure random helpers: tokens, ints, choices, shuffles, UUIDs. What this IS: secrets-module randomness safe for security use. What this IS NOT: not deterministic (see random.Random for tests)."""

from __future__ import annotations

import ast
import secrets
import uuid

#: Module version.
UTIL_04_VERSION = "util-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-04.v1"


class RandomError(Exception):
    """Random helper failure."""


def secure_token(nbytes=16) -> str:
    """Hex token with nbytes of entropy."""
    if nbytes <= 0:
        raise RandomError("nbytes must be positive")
    return secrets.token_hex(nbytes)


def random_int(lo: int, hi: int) -> int:
    """Secure random int in [lo, hi]."""
    if lo > hi:
        raise RandomError("lo > hi")
    return secrets.randbelow(hi - lo + 1) + lo


def secure_choice(seq):
    if not seq:
        raise RandomError("empty sequence")
    return secrets.choice(seq)


def secure_shuffle(lst):
    """Return a new securely-shuffled list."""
    out = list(lst)
    for i in range(len(out) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        out[i], out[j] = out[j], out[i]
    return out


def uuid4_str() -> str:
    return str(uuid.uuid4())


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib', 'secrets', 'uuid']
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
    assert len(secure_token(16)) == 32
    assert random_int(1, 1) == 1
    assert secure_choice(["a"]) == "a"
    assert sorted(secure_shuffle([1, 2, 3])) == [1, 2, 3]
    assert uuid.UUID(uuid4_str()).version == 4
    print("random helpers OK")


if __name__ == "__main__":
    main()
