"""Case normalization (input defense), Simulated

What this IS: Casefolds text before keyword/policy matching so MiXeD-cAsE cannot evade blocklists.

What this IS NOT:
* Casefolding is for matching only; never mutate stored user data silently.
* Not locale-specific casing (uses Unicode casefold).
"""

from __future__ import annotations



#: Module version.
MODULE_VERSION = "input-defense-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-19.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'typing', 'ast'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


def normalize_case(text):
    """Return casefolded text for matching."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    return text.casefold()


def matches_blocked(text, blocked_terms):
    """True if casefolded text contains any casefolded blocked term."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    folded = text.casefold()
    return any(term.casefold() in folded for term in blocked_terms)



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
    assert normalize_case("HeLLo") == "hello"
    assert matches_blocked("RuN Rm -Rf", ["rm -rf"]) is True
    assert matches_blocked("innocent", ["rm -rf"]) is False
    try:
        normalize_case(42)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-19.v1 OK")


if __name__ == "__main__":
    main()
