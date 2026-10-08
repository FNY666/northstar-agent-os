"""Bidirectional Control Removal: strips Unicode bidi overrides, Simulated.

Removes the nine Unicode bidirectional control characters (LRE, RLE,
PDF, LRO, RLO, LRI, RLI, FSI, PDI). These controls reorder how text
renders, which enables the classic "evil.exe" spoof: a filename like
"evil< RLO >exe" renders as "evilexe" reversed, i.e. it *looks* like a
harmless name while the bytes are an executable. Stripping them before
display or policy checks closes the rendering-versus-bytes gap.

What this IS: A sanitizer that strips bidi controls and counts them.

What this IS NOT:
* A rendering engine: it does not resolve bidi text, it just removes the controls.
* A general invisible-char stripper (see module 14): it only handles the nine bidi controls.
"""

from __future__ import annotations

import ast
from typing import FrozenSet, Tuple

#: Module version.
INPUT_DEFENSE_15_VERSION = "input-defense-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-15.v1"


class InputDefense15Error(Exception):
    """Fail-closed."""


#: Bidirectional control characters stripped by :func:`remove`.
BIDI_CONTROLS: FrozenSet[str] = frozenset({
    "‪",  # U+202A LEFT-TO-RIGHT EMBEDDING (LRE)
    "‫",  # U+202B RIGHT-TO-LEFT EMBEDDING (RLE)
    "‬",  # U+202C POP DIRECTIONAL FORMATTING (PDF)
    "‭",  # U+202D LEFT-TO-RIGHT OVERRIDE (LRO)
    "‮",  # U+202E RIGHT-TO-LEFT OVERRIDE (RLO) -- the "evil.exe" spoof vector
    "⁦",  # U+2066 LEFT-TO-RIGHT ISOLATE (LRI)
    "⁧",  # U+2067 RIGHT-TO-LEFT ISOLATE (RLI)
    "⁨",  # U+2068 FIRST STRONG ISOLATE (FSI)
    "⁩",  # U+2069 POP DIRECTIONAL ISOLATE (PDI)
})


def remove(text: str) -> Tuple[str, int]:
    """Return ``(cleaned, removed)`` with bidi controls stripped.

    ``cleaned`` is the input minus every character in
    :data:`BIDI_CONTROLS`; ``removed`` is the count of stripped
    characters. Fail-closed: non-str input raises
    :class:`InputDefense15Error`.
    """
    if not isinstance(text, str):
        raise InputDefense15Error(
            "remove requires str, got %s" % type(text).__name__
        )
    cleaned = "".join(ch for ch in text if ch not in BIDI_CONTROLS)
    return (cleaned, len(text) - len(cleaned))


def has_bidi(text: str) -> bool:
    """Return True when any bidirectional control is present.

    Fail-closed: non-str input raises :class:`InputDefense15Error`.
    """
    if not isinstance(text, str):
        raise InputDefense15Error(
            "has_bidi requires str, got %s" % type(text).__name__
        )
    return any(ch in BIDI_CONTROLS for ch in text)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}  # only modules you actually import
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
    # RLO hidden inside a word is stripped.
    cleaned, removed = remove("a‮b")
    assert cleaned == "ab" and removed == 1, (cleaned, removed)
    # The classic spoof: "evil" + RLO + "exe" spoofed filename.
    spoof = "evil‮exe"
    cleaned, removed = remove(spoof)
    assert cleaned == "evilexe" and removed == 1, (cleaned, removed)
    # All nine controls stripped in one pass.
    payload = "‪x‫y‬z‭w‮v⁦u⁧t⁨s⁩q"
    cleaned, removed = remove(payload)
    assert cleaned == "xyzwvutsq" and removed == 9, (cleaned, removed)
    # has_bidi agrees with remove.
    assert has_bidi("a‮b") is True
    assert has_bidi("⁨isolated⁩") is True
    assert has_bidi("clean") is False
    assert has_bidi("") is False
    assert remove("clean") == ("clean", 0)
    # Fail-closed on non-str.
    for bad in (None, 123, b"clean", ["clean"]):
        try:
            remove(bad)  # type: ignore[arg-type]
        except InputDefense15Error:
            pass
        else:
            raise AssertionError("remove(%r) did not raise" % (bad,))
        try:
            has_bidi(bad)  # type: ignore[arg-type]
        except InputDefense15Error:
            pass
        else:
            raise AssertionError("has_bidi(%r) did not raise" % (bad,))
    assert stdlib_only()
    print("input-defense-15 OK")


if __name__ == "__main__":
    main()
