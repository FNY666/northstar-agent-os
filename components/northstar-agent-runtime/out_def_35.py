"""Unicode exfiltration detection, Simulated.

Detects invisible or rendering-manipulating Unicode code points that
can smuggle data or spoof display: zero-width characters, bidi
overrides/isolates, tag characters, and the soft hyphen.

What this IS:
* A detector returning (found, reason, evidence) with code points and
  unicodedata names, plus a cleaner that removes the SUSPICIOUS set.
* Deterministic, stdlib-only (unicodedata).

What this IS NOT:
* Not a full confusables/homoglyph detector -- only the SUSPICIOUS
  set below is covered.
* Not proof of malice -- zero-width chars appear in some legit text.
* Host decides whether to clean or block.
"""

from __future__ import annotations

import ast
import unicodedata

#: Module version.
OUT_DEF_35_VERSION = "out-def-35.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-35.v1"

#: Code points treated as suspicious for exfiltration/rendering abuse.
SUSPICIOUS: frozenset[str] = frozenset(
    [
        # Zero-width characters.
        "\u200b",  # ZERO WIDTH SPACE
        "\u200c",  # ZERO WIDTH NON-JOINER
        "\u200d",  # ZERO WIDTH JOINER
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (BOM)
        # Bidi overrides / isolates.
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
        # Soft hyphen.
        "\u00ad",  # SOFT HYPHEN
        # Tag characters U+E0000..U+E007F (invisible data carriers).
        *[chr(cp) for cp in range(0xE0000, 0xE0080)],
    ]
)


class OutDef35Error(Exception):
    """Fail-closed."""


def detect_unicode_exfil(text: str) -> tuple[bool, str, list]:
    """Detect suspicious Unicode chars.

    Returns (found, reason, evidence); evidence lists each hit with its
    index, code point, and unicodedata name.
    """
    if not isinstance(text, str):
        raise OutDef35Error("text must be str")
    evidence: list[dict] = []
    for i, ch in enumerate(text):
        if ch in SUSPICIOUS:
            evidence.append(
                {
                    "index": i,
                    "char": ch,
                    "codepoint": f"U+{ord(ch):04X}",
                    "name": unicodedata.name(ch, "UNKNOWN"),
                }
            )
    found = bool(evidence)
    if found:
        names = ", ".join(e["name"] for e in evidence[:5])
        reason = f"{len(evidence)} suspicious unicode char(s): {names}"
    else:
        reason = "no suspicious unicode chars"
    return found, reason, evidence


def clean_unicode_exfil(text: str) -> str:
    """Remove all SUSPICIOUS characters from *text*."""
    if not isinstance(text, str):
        raise OutDef35Error("text must be str")
    return "".join(ch for ch in text if ch not in SUSPICIOUS)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "unicodedata", "pathlib"}
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
    # Zero-width + bidi override.
    found, reason, ev = detect_unicode_exfil("hi\u200bthere\u202e!")
    assert found is True
    assert ev[0]["name"] == "ZERO WIDTH SPACE"
    assert any(e["name"] == "RIGHT-TO-LEFT OVERRIDE" for e in ev)

    # Tag character (TAG LATIN CAPITAL LETTER A).
    found, _, ev = detect_unicode_exfil("a\U000E0041b")
    assert found is True
    assert ev[0]["codepoint"] == "U+E0041"

    # Soft hyphen.
    found, _, _ = detect_unicode_exfil("soft\u00adhyphen")
    assert found is True

    # Clean text passes.
    found, _, _ = detect_unicode_exfil("plain ascii text")
    assert found is False

    # Cleaner removes them all.
    assert clean_unicode_exfil("a\u200bb\u202ec\U000E0041") == "abc"

    # Non-str fails closed.
    try:
        detect_unicode_exfil(b"bytes")  # type: ignore[arg-type]
    except OutDef35Error:
        pass
    else:
        raise AssertionError("non-str input should fail closed")

    assert stdlib_only()
    print("out-def-35 OK: zero-width, tag char, cleaner, stdlib")


if __name__ == "__main__":
    main()
