"""Homoglyph Normalization: maps confusable characters to ASCII, Simulated.

Replaces Cyrillic and Greek lookalikes of Latin letters (and fullwidth
forms) with their ASCII equivalents, so a mixed-script spoof such as
"раураl" collapses to its plain-text reading ("paypal") before any
policy check runs. Normalization is canonicalization, not detection:
it always rewrites and never flags, so pair it with the detection
modules (12, 13) when a verdict is needed.

What this IS: A canonicalizer that rewrites confusable characters to ASCII.

What this IS NOT:
* A detector or judge: it never flags or rejects suspicious input.
* A complete Unicode confusables table: only the high-risk Cyrillic/Greek/fullwidth subset.
"""

from __future__ import annotations

import ast
from typing import Dict

#: Module version.
INPUT_DEFENSE_11_VERSION = "input-defense-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-11.v1"


class InputDefense11Error(Exception):
    """Fail-closed."""


#: Non-ASCII confusable characters mapped to their ASCII equivalents.
#: Cyrillic lookalikes, Greek lookalikes. Fullwidth forms are handled
#: programmatically in :func:`normalize_fullwidth`.
CONFUSABLES: Dict[str, str] = {
    # Cyrillic lowercase lookalikes of Latin.
    "а": "a",  # U+0430 CYRILLIC SMALL LETTER A
    "е": "e",  # U+0435 CYRILLIC SMALL LETTER IE
    "о": "o",  # U+043E CYRILLIC SMALL LETTER O
    "р": "p",  # U+0440 CYRILLIC SMALL LETTER ER
    "с": "c",  # U+0441 CYRILLIC SMALL LETTER ES
    "х": "x",  # U+0445 CYRILLIC SMALL LETTER HA
    "у": "y",  # U+0443 CYRILLIC SMALL LETTER U
    "і": "i",  # U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "ј": "j",  # U+0458 CYRILLIC SMALL LETTER JE
    "ѕ": "s",  # U+0455 CYRILLIC SMALL LETTER DZE
    "һ": "h",  # U+04BB CYRILLIC SMALL LETTER SHHA
    "ԝ": "w",  # U+051D CYRILLIC SMALL LETTER WE
    # Cyrillic uppercase lookalikes of Latin.
    "А": "A",  # U+0410 CYRILLIC CAPITAL LETTER A
    "В": "B",  # U+0412 CYRILLIC CAPITAL LETTER VE
    "Е": "E",  # U+0415 CYRILLIC CAPITAL LETTER IE
    "К": "K",  # U+041A CYRILLIC CAPITAL LETTER KA
    "М": "M",  # U+041C CYRILLIC CAPITAL LETTER EM
    "Н": "H",  # U+041D CYRILLIC CAPITAL LETTER EN
    "О": "O",  # U+041E CYRILLIC CAPITAL LETTER O
    "Р": "P",  # U+0420 CYRILLIC CAPITAL LETTER ER
    "С": "C",  # U+0421 CYRILLIC CAPITAL LETTER ES
    "Т": "T",  # U+0422 CYRILLIC CAPITAL LETTER TE
    "Х": "X",  # U+0425 CYRILLIC CAPITAL LETTER HA
    # Greek lookalikes of Latin.
    "α": "a",  # U+03B1 GREEK SMALL LETTER ALPHA
    "ε": "e",  # U+03B5 GREEK SMALL LETTER EPSILON
    "ο": "o",  # U+03BF GREEK SMALL LETTER OMICRON
    "ρ": "p",  # U+03C1 GREEK SMALL LETTER RHO
    "υ": "u",  # U+03C5 GREEK SMALL LETTER UPSILON
    "ν": "v",  # U+03BD GREEK SMALL LETTER NU
    "κ": "k",  # U+03BA GREEK SMALL LETTER KAPPA
    "μ": "u",  # U+03BC GREEK SMALL LETTER MU
}


def normalize_fullwidth(text: str) -> str:
    """Map fullwidth ASCII forms to ASCII.

    Covers fullwidth uppercase A-Z (U+FF21-U+FF3A), lowercase a-z
    (U+FF41-U+FF5A), and digits 0-9 (U+FF10-U+FF19) programmatically.
    Fail-closed: non-str input raises :class:`InputDefense11Error`.
    """
    if not isinstance(text, str):
        raise InputDefense11Error(
            "normalize_fullwidth requires str, got %s" % type(text).__name__
        )
    out = []
    for ch in text:
        o = ord(ch)
        if 0xFF21 <= o <= 0xFF3A:
            out.append(chr(o - 0xFF21 + ord("A")))
        elif 0xFF41 <= o <= 0xFF5A:
            out.append(chr(o - 0xFF41 + ord("a")))
        elif 0xFF10 <= o <= 0xFF19:
            out.append(chr(o - 0xFF10 + ord("0")))
        else:
            out.append(ch)
    return "".join(out)


def normalize(text: str) -> str:
    """Replace confusable characters with their ASCII equivalents.

    Handles both the :data:`CONFUSABLES` table (Cyrillic/Greek
    lookalikes) and fullwidth forms. Fail-closed: non-str input
    raises :class:`InputDefense11Error`.
    """
    if not isinstance(text, str):
        raise InputDefense11Error(
            "normalize requires str, got %s" % type(text).__name__
        )
    normalized = normalize_fullwidth(text)
    return "".join(CONFUSABLES.get(ch, ch) for ch in normalized)


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
    assert normalize("раураl") == "paypal", normalize("раураl")
    # Greek lookalikes.
    assert normalize("αεор") == "aeop", normalize("αεор")
    # Fullwidth ranges.
    assert normalize_fullwidth("Ｈｅｌｌｏ１２３") == "Hello123"
    assert normalize("ＦＵＬＬＷＩＤＴＨ") == "FULLWIDTH"
    # Plain ASCII is a fixed point.
    assert normalize("paypal") == "paypal"
    assert normalize("") == ""
    # Fail-closed on non-str.
    for bad in (None, 123, b"paypal", ["paypal"]):
        try:
            normalize(bad)  # type: ignore[arg-type]
        except InputDefense11Error:
            pass
        else:
            raise AssertionError("normalize(%r) did not raise" % (bad,))
        try:
            normalize_fullwidth(bad)  # type: ignore[arg-type]
        except InputDefense11Error:
            pass
        else:
            raise AssertionError("normalize_fullwidth(%r) did not raise" % (bad,))
    assert stdlib_only()
    print("input-defense-11 OK")


if __name__ == "__main__":
    main()
