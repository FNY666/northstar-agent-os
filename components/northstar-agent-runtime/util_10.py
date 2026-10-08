"""Path helpers: safe join (no escape), normalize, containment. What this IS: traversal-safe path joins. What this IS NOT: not a sandbox."""

from __future__ import annotations

import ast
import os
import tempfile
from pathlib import Path

#: Module version.
UTIL_10_VERSION = "util-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-10.v1"


class PathError(Exception):
    """Unsafe path."""


def safe_join(base, *parts) -> str:
    """Join onto base; raise PathError if the result escapes base."""
    base_p = Path(base).resolve()
    full = base_p.joinpath(*parts).resolve()
    if full != base_p and base_p not in full.parents:
        raise PathError(f"path escapes base: {parts!r}")
    return str(full)


def normalize(p) -> str:
    return os.path.normpath(p)


def is_within(base, target) -> bool:
    base_p = Path(base).resolve()
    target_p = Path(target).resolve()
    return target_p == base_p or base_p in target_p.parents


def ext_of(p) -> str:
    """Lowercased extension without dot, e.g. 'gz'."""
    return Path(p).suffix.lstrip(".").lower()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'os', 'pathlib', 'tempfile']
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
    d = tempfile.mkdtemp()
    assert safe_join(d, "a", "b.txt").endswith("b.txt")
    try:
        safe_join(d, "..", "evil")
        raise AssertionError("should raise")
    except PathError:
        pass
    assert is_within(d, d + "/x") is True
    assert ext_of("A.TAR.GZ") == "gz"
    print("path helpers OK")


if __name__ == "__main__":
    main()
