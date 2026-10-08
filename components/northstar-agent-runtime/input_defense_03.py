"""Language detection filter: heuristic script-based detection, Simulated.

Detection counts codepoints per Unicode script block and returns the
dominant script (latin, cyrillic, cjk, arabic, greek, or other). A
LanguageFilter then blocks any input whose dominant script is not in the
allowed set. Heuristic only: mixed-script input is classified by the
majority script.

What this IS: a heuristic Unicode-script allow-list filter.

What this IS NOT:
* A real language-identification model (it cannot tell English from French).
* Protection against same-script homoglyph attacks.
"""

from __future__ import annotations

import ast
import pathlib
from typing import Set, Tuple

#: Module version.
INPUT_DEFENSE_03_VERSION = "input-defense-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-03.v1"


class InputDefense03Error(Exception):
    """Fail-closed."""


# (script, low, high) codepoint ranges.
_SCRIPT_RANGES = (
    ("cjk", 0x4E00, 0x9FFF),      # CJK Unified Ideographs
    ("cjk", 0x3040, 0x30FF),      # Hiragana + Katakana
    ("arabic", 0x0600, 0x06FF),
    ("greek", 0x0370, 0x03FF),
    ("cyrillic", 0x0400, 0x04FF),
)


def detect(text: str) -> str:
    """Return the dominant script: latin, cyrillic, cjk, arabic, greek, other.

    Pure ASCII (letters/digits/punctuation/whitespace) counts as latin.
    Empty text returns "latin".
    """
    if not isinstance(text, str):
        raise InputDefense03Error(
            f"detect() requires str, got {type(text).__name__}"
        )
    counts = {"latin": 0, "cyrillic": 0, "cjk": 0, "arabic": 0, "greek": 0, "other": 0}
    for ch in text:
        cp = ord(ch)
        if cp < 0x80:
            counts["latin"] += 1
            continue
        matched = False
        for script, lo, hi in _SCRIPT_RANGES:
            if lo <= cp <= hi:
                counts[script] += 1
                matched = True
                break
        if not matched:
            counts["other"] += 1
    if sum(counts.values()) == 0:
        return "latin"
    best = max(counts, key=lambda k: (counts[k], k == "latin"))
    # Ties between latin and another script favor latin only via the tuple;
    # resolve strictly by count with latin winning ties.
    top = max(counts.values())
    winners = [k for k, v in counts.items() if v == top]
    if "latin" in winners:
        return "latin"
    return winners[0]


class LanguageFilter:
    """Blocks input whose detected script is not in the allowed set."""

    def __init__(self, allowed: Set[str] = frozenset({"latin"})) -> None:
        if not isinstance(allowed, (set, frozenset)):
            raise InputDefense03Error("allowed must be a set of script names")
        valid = {"latin", "cyrillic", "cjk", "arabic", "greek", "other"}
        for s in allowed:
            if s not in valid:
                raise InputDefense03Error(f"unknown script name: {s!r}")
        self._allowed = set(allowed)

    def check(self, text: str) -> Tuple[bool, str]:
        """Return (blocked, detected_script)."""
        detected = detect(text)
        return detected not in self._allowed, detected


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    assert detect("") == "latin"
    assert detect("hello world 123!") == "latin"
    assert detect("Привет мир") == "cyrillic"
    assert detect("中文测试") == "cjk"
    assert detect("こんにちは") == "cjk"
    assert detect("مرحبا بالعالم") == "arabic"
    assert detect("Γεια σου κόσμε") == "greek"
    assert detect("hello 😀") == "latin"  # emoji is minority "other"
    flt = LanguageFilter(allowed={"latin"})
    blocked, detected = flt.check("hello")
    assert not blocked and detected == "latin"
    blocked, detected = flt.check("")
    assert not blocked and detected == "latin"
    blocked, detected = flt.check("中文")
    assert blocked and detected == "cjk"
    multi = LanguageFilter(allowed={"latin", "cyrillic"})
    blocked, _ = multi.check("Привет")
    assert not blocked
    try:
        LanguageFilter(allowed={"klingon"})
    except InputDefense03Error:
        pass
    else:
        raise AssertionError("unknown script must raise")
    try:
        detect(42)
    except InputDefense03Error:
        pass
    else:
        raise AssertionError("non-str detect must raise")
    assert stdlib_only()
    print("input-defense-03 OK")


if __name__ == "__main__":
    main()
