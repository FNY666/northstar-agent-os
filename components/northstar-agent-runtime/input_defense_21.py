"""Input length limits (input defense), Simulated

What this IS: Enforces maximum input sizes (chars and bytes) at the trust boundary to bound downstream cost and block buffer-style abuse.

What this IS NOT:
* Limits are policy values supplied by the host, not hardcoded here.
* Does not truncate silently -- oversize input is rejected.
"""

from __future__ import annotations



#: Module version.
MODULE_VERSION = "input-defense-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-21.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'typing', 'ast'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


def check_length(text, max_chars=10000, max_bytes=40000):
    """Validate text fits within limits. Raises InputDefenseError if not."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    if max_chars is not None and len(text) > max_chars:
        raise InputDefenseError(
            "input too long: %d chars > %d" % (len(text), max_chars)
        )
    if max_bytes is not None:
        nbytes = len(text.encode("utf-8"))
        if nbytes > max_bytes:
            raise InputDefenseError(
                "input too large: %d bytes > %d" % (nbytes, max_bytes)
            )
    return True


def truncate_for_log(text, max_chars=200):
    """Safely truncate for logging (never for enforcement decisions)."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...[truncated]"



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
    assert check_length("abc", max_chars=10) is True
    try:
        check_length("x" * 11, max_chars=10)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    try:
        check_length("x", max_bytes=0)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert truncate_for_log("x" * 300).endswith("[truncated]")
    assert stdlib_only()
    print("input-defense-21.v1 OK")


if __name__ == "__main__":
    main()
