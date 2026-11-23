"""Model attack 18: context window overflow detection, Simulated.

Detects attempts to overflow the context window: inputs exceeding the
token budget, filler-heavy padding designed to push system
instructions out, and repeated boilerplate that inflates length
without content.

What this IS: input-size and filler-ratio screening.
What this IS NOT: not a tokenizer; uses a chars-per-token estimate
the host can calibrate.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from typing import Tuple

MODEL_ATTACK_18_VERSION = "model-attack-18.v1"

SCHEMA_PIN = "northstar.model-attack-18.v1"

#: Rough chars-per-token estimate for budget math.
CHARS_PER_TOKEN = 4

#: Default context budget in tokens (host tunes).
DEFAULT_BUDGET_TOKENS = 8000

#: Filler ratio above which padding is flagged.
FILLER_RATIO = 0.5

_FILLER_WORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "is", "it",
    "that", "this", "with", "for", "as", "was", "are", "be",
}


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // CHARS_PER_TOKEN)


def detect_context_overflow(
    text: str, budget_tokens: int = DEFAULT_BUDGET_TOKENS
) -> Tuple[bool, str]:
    """Return (flagged, reason). Fail-closed on bad inputs."""
    if not isinstance(text, str):
        raise ModelAttackError("text must be str")
    if not isinstance(budget_tokens, int) or budget_tokens <= 0:
        raise ModelAttackError("budget_tokens must be a positive int")
    tokens = _estimate_tokens(text)
    if tokens > budget_tokens:
        return True, f"input ~{tokens} tokens exceeds budget {budget_tokens}"
    words = re.findall(r"[a-z]+", text.lower())
    if len(words) >= 20:
        filler = sum(1 for w in words if w in _FILLER_WORDS)
        ratio = filler / len(words)
        if ratio >= FILLER_RATIO:
            return True, f"filler-heavy padding: {ratio:.0%} filler words"
        # Repeated sentence boilerplate.
        sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
        if len(sentences) >= 10:
            counts = Counter(sentences)
            top, n = counts.most_common(1)[0]
            if n >= len(sentences) / 2:
                return True, f"repeated boilerplate x{n}: {top[:30]!r}"
    return False, "clean"


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "pathlib", "re", "typing"}
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
    flagged, _ = detect_context_overflow("x" * 40000, budget_tokens=8000)
    assert flagged is True
    flagged, _ = detect_context_overflow(
        " ".join(["the and of to in"] * 60)
    )
    assert flagged is True
    flagged, _ = detect_context_overflow("Please summarize this short text.")
    assert flagged is False
    try:
        detect_context_overflow(None)  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-18 OK")


if __name__ == "__main__":
    main()
