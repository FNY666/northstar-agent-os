"""Hash helpers: sha256, sha512, blake2, file hashing. What this IS: digests for integrity checks. What this IS NOT: not password hashing (see util_12) or keyed MACs."""

from __future__ import annotations

import ast
import hashlib

#: Module version.
UTIL_01_VERSION = "util-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-01.v1"


class HashError(Exception):
    """Hash failure."""


def _to_bytes(data) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def sha256_hex(data) -> str:
    """SHA-256 hex digest of bytes or str."""
    return hashlib.sha256(_to_bytes(data)).hexdigest()


def sha512_hex(data) -> str:
    """SHA-512 hex digest of bytes or str."""
    return hashlib.sha512(_to_bytes(data)).hexdigest()


def blake2b_hex(data, digest_size=32) -> str:
    """BLAKE2b hex digest (default 256-bit)."""
    return hashlib.blake2b(_to_bytes(data), digest_size=digest_size).hexdigest()


def sha256_file(path, chunk_size=65536) -> str:
    """SHA-256 of a file, streamed in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_chain(parts) -> str:
    """SHA-256 over concatenated parts (order-sensitive)."""
    h = hashlib.sha256()
    for p in parts:
        h.update(_to_bytes(p))
    return h.hexdigest()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'hashlib', 'pathlib']
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
    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert len(blake2b_hex("x")) == 64
    assert len(sha512_hex("x")) == 128
    assert hash_chain(["a", "b"]) != hash_chain(["b", "a"])
    print("hash helpers OK")


if __name__ == "__main__":
    main()
