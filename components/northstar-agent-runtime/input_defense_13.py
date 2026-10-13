"""Script Mixing Detection: flags inputs mixing multiple scripts, Simulated.

Assigns each character a script (latin, cyrillic, greek, cjk, arabic,
other; digits/punctuation/space are "neutral" and ignored), then flags
the input when more than ``max_scripts`` distinct scripts appear.
The canonical spoof pattern "раураl" (Cyrillic + Latin) is suspicious,
while a single-script word like "paypal" is clean. Mixing scripts is a
strong homoglyph-attack signal because real words rarely span scripts.

What this IS: A script-co-occurrence check that flags multi-script input.

What this IS NOT:
* A confusable-character check (it does not know lookalikes; see module 12).
* A language detector or intent classifier: mixed scripts can be legitimate (e.g. "Tokyo東京").
"""

from __future__ import annotations

import ast
from typing import Set, Tuple

#: Module version.
INPUT_DEFENSE_13_VERSION = "input-defense-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-13.v1"


class InputDefense13Error(Exception):
    """Fail-closed."""


def script_of(ch: str) -> str:
    """Return the script of a single character.

    "latin" for ASCII letters, "cyrillic" for U+0400-U+04FF, "greek"
    for U+0370-U+03FF, "cjk" for U+4E00-U+9FFF, "arabic" for
    U+0600-U+06FF, "neutral" for digits/punctuation/space (ignored by
    the mixing check), and "other" for everything else. Fail-closed:
    input must be a single-character str.
    """
    if not isinstance(ch, str) or len(ch) != 1:
        raise InputDefense13Error(
            "script_of requires a single-character str, got %r" % (ch,)
        )
    o = ord(ch)
    if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
        return "latin"
    if 0x0400 <= o <= 0x04FF:
        return "cyrillic"
    if 0x0370 <= o <= 0x03FF:
        return "greek"
    if 0x4E00 <= o <= 0x9FFF:
        return "cjk"
    if 0x0600 <= o <= 0x06FF:
        return "arabic"
    if not ch.isalpha():
        return "neutral"
    return "other"


def scripts_in(text: str) -> Set[str]:
    """Return the set of scripts present, excluding "neutral".

    Fail-closed: non-str input raises :class:`InputDefense13Error`.
    """
    if not isinstance(text, str):
        raise InputDefense13Error(
            "scripts_in requires str, got %s" % type(text).__name__
        )
    return {script_of(ch) for ch in text} - {"neutral"}


def check(text: str, max_scripts: int = 1) -> Tuple[bool, Set[str]]:
    """Return ``(suspicious, scripts)``.

    Suspicious when more than ``max_scripts`` distinct (non-neutral)
    scripts appear in the input. Fail-closed: non-str input raises
    :class:`InputDefense13Error`.
    """
    if not isinstance(max_scripts, int) or max_scripts < 0:
        raise InputDefense13Error("max_scripts must be a non-negative int")
    scripts = scripts_in(text)
    return (len(scripts) > max_scripts, scripts)


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
    # Classic mixed-script spoof: Cyrillic р а у р а + Latin l.
    suspicious, scripts = check("раураl")
    assert suspicious is True, scripts
    assert scripts == {"cyrillic", "latin"}, scripts
    # Single script is clean.
    assert check("paypal") == (False, {"latin"})
    assert check("αβγ") == (False, {"greek"})
    # Raising the allowance clears the verdict but not the script set.
    suspicious2, scripts2 = check("раураl", max_scripts=2)
    assert suspicious2 is False and scripts2 == {"cyrillic", "latin"}
    # Digits/punctuation/space are neutral and ignored.
    assert scripts_in("paypal 123!") == {"latin"}
    assert scripts_in("") == set()
    # Direct script assignment.
    assert script_of("a") == "latin"
    assert script_of("р") == "cyrillic"
    assert script_of("α") == "greek"
    assert script_of("中") == "cjk"
    assert script_of("ع") == "arabic"
    assert script_of("3") == "neutral"
    assert script_of(" ") == "neutral"
    # Fail-closed on non-str.
    for bad in (None, 123, b"paypal", ["paypal"]):
        try:
            check(bad)  # type: ignore[arg-type]
        except InputDefense13Error:
            pass
        else:
            raise AssertionError("check(%r) did not raise" % (bad,))
        try:
            scripts_in(bad)  # type: ignore[arg-type]
        except InputDefense13Error:
            pass
        else:
            raise AssertionError("scripts_in(%r) did not raise" % (bad,))
    try:
        script_of("ab")
    except InputDefense13Error:
        pass
    else:
        raise AssertionError("script_of('ab') did not raise")
    assert stdlib_only()
    print("input-defense-13 OK")


if __name__ == "__main__":
    main()
