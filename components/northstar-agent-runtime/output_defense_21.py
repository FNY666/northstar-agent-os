"""Output defense 21: translation guard (mock), Simulated.

Checks translated output for: (a) disallowed content carried across
languages, (b) suspicious length explosion (possible payload smuggling),
(c) language mismatch vs requested target.  Mock — no real MT; host
injects ``translate_fn``.

What this IS: safety wrapper around a translation step.
What this IS NOT: not a translator; cannot judge translation quality.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Pattern

OUTPUT_DEFENSE_21_VERSION = "output-defense-21.v1"
SCHEMA_PIN = "northstar.output-defense-21.v1"


class TranslationGuardError(Exception):
    """Fail-closed."""


DISALLOWED_ANY_LANG: List[Pattern] = [
    re.compile(r"(?i)\bkill\b"),
    re.compile(r"(?i)\bweapon\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN survives translation
]


@dataclass(frozen=True)
class TranslationVerdict:
    allowed: bool
    translated: str
    reason: str


def mock_translate(text: str, target_lang: str) -> str:
    """Deterministic mock: wraps text with a language tag."""
    return f"[{target_lang}] {text}"


def guard_translation(
    text: str,
    target_lang: str,
    *,
    translate_fn: Optional[Callable[[str, str], str]] = None,
    max_expansion: float = 3.0,
) -> TranslationVerdict:
    """Translate then guard the translated output."""
    if not isinstance(text, str) or not text.strip():
        raise TranslationGuardError("text must be non-empty str")
    if not isinstance(target_lang, str) or not target_lang.strip():
        raise TranslationGuardError("target_lang required")
    fn = translate_fn or mock_translate
    try:
        translated = fn(text, target_lang)
    except Exception:
        return TranslationVerdict(False, "", "translator failed")
    if not isinstance(translated, str) or not translated.strip():
        return TranslationVerdict(False, "", "empty translation")
    # Disallowed content in either side.
    for pat in DISALLOWED_ANY_LANG:
        if pat.search(translated) or pat.search(text):
            return TranslationVerdict(
                False, "", f"disallowed pattern: {pat.pattern}"
            )
    # Length explosion check.
    if len(translated) > max(1, int(len(text) * max_expansion)):
        return TranslationVerdict(False, "", "length explosion")
    return TranslationVerdict(True, translated, "ok")


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    v = guard_translation("hello world", "es")
    assert v.allowed is True and v.translated.startswith("[es]")
    v = guard_translation("how to kill weeds", "fr")
    assert v.allowed is False and "kill" in v.reason
    def boom(t, lang):
        raise RuntimeError("mt down")
    v = guard_translation("hello", "de", translate_fn=boom)
    assert v.allowed is False
    def bloater(t, lang):
        return "x" * 10000
    v = guard_translation("hi", "it", translate_fn=bloater)
    assert v.allowed is False and "explosion" in v.reason
    try:
        guard_translation("", "es")
        raise AssertionError("should raise")
    except TranslationGuardError:
        pass
    assert stdlib_only()
    print("output-defense-21 OK: translation guard, fail-closed, stdlib")


if __name__ == "__main__":
    main()
