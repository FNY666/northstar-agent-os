"""Output defense 18: safe completion (fallback responses), Simulated.

When output is deemed unsafe, substitute a fixed safe fallback instead
of returning the unsafe text or an empty string (empty strings break
downstream parsers).  Fallbacks are static — never model-generated, so
the fallback path cannot be prompt-injected.

What this IS: deterministic safe substitution for blocked output.
What this IS NOT: not a rewrite/sanitizer; it replaces, not repairs.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Callable, Dict

OUTPUT_DEFENSE_18_VERSION = "output-defense-18.v1"
SCHEMA_PIN = "northstar.output-defense-18.v1"


class SafeCompletionError(Exception):
    """Fail-closed."""


FALLBACKS: Dict[str, str] = {
    "blocked": "[This response was blocked by the safety filter.]",
    "refused": "[I can't help with that request.]",
    "error": "[An error occurred while generating the response.]",
    "empty": "[No response generated.]",
}


@dataclass(frozen=True)
class CompletionResult:
    text: str
    was_substituted: bool
    reason: str


def safe_complete(
    text: str,
    is_safe_fn: Callable[[str], bool],
    *,
    fallback_key: str = "blocked",
) -> CompletionResult:
    """Return text if safe, else the static fallback.

    ``is_safe_fn`` returning False (or raising) triggers substitution.
    """
    if fallback_key not in FALLBACKS:
        raise SafeCompletionError(f"unknown fallback '{fallback_key}'")
    if not isinstance(text, str):
        # Non-str output is never safe -> substitute.
        return CompletionResult(
            FALLBACKS[fallback_key], True, "non-string output"
        )
    try:
        safe = bool(is_safe_fn(text))
    except Exception:
        safe = False  # fail-closed
    if safe and text.strip():
        return CompletionResult(text, False, "passed")
    if safe and not text.strip():
        return CompletionResult(
            FALLBACKS["empty"], True, "empty output"
        )
    return CompletionResult(
        FALLBACKS[fallback_key], True, "blocked by safety check"
    )


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    r = safe_complete("hello", lambda t: True)
    assert r.was_substituted is False and r.text == "hello"
    r = safe_complete("bad stuff", lambda t: False)
    assert r.was_substituted is True and r.text == FALLBACKS["blocked"]
    def boom(t):
        raise RuntimeError("checker down")
    r = safe_complete("hello", boom)
    assert r.was_substituted is True  # fail-closed
    r = safe_complete("   ", lambda t: True)
    assert r.was_substituted is True and "No response" in r.text
    r = safe_complete(None, lambda t: True)  # type: ignore
    assert r.was_substituted is True
    try:
        safe_complete("x", lambda t: True, fallback_key="nope")
        raise AssertionError("should raise")
    except SafeCompletionError:
        pass
    assert stdlib_only()
    print("output-defense-18 OK: fallback substitution, fail-closed, stdlib")


if __name__ == "__main__":
    main()
