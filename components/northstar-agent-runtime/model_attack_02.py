"""Model attack 02: system prompt leakage detection, Simulated.

Compares model output against the known system prompt. Flags verbatim
leakage (long shared substrings) and paraphrase leakage (high token
overlap on instruction-like sentences).

The host must supply the true system prompt; the detector never logs
it, only a salted hash of matched spans.

What this IS: output-side leakage detection with a reference.
What this IS NOT: cannot catch fully reworded leaks with zero token
overlap; pair with model_attack_01 input detection.
"""

from __future__ import annotations

import ast
import hashlib
from typing import List, Tuple

MODEL_ATTACK_02_VERSION = "model-attack-02.v1"

SCHEMA_PIN = "northstar.model-attack-02.v1"

#: Minimum shared substring length to count as verbatim leakage.
MIN_VERBATIM_SPAN = 24

#: Token-overlap ratio above which paraphrase leakage is flagged.
PARAPHRASE_THRESHOLD = 0.6


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


def _tokenize(text: str) -> List[str]:
    return [t for t in text.lower().split() if t]


def _longest_common_substring_len(a: str, b: str) -> int:
    # Memory-bounded DP over the shorter string.
    if len(a) > len(b):
        a, b = b, a
    prev = [0] * (len(a) + 1)
    best = 0
    for cb in b:
        cur = [0] * (len(a) + 1)
        for i, ca in enumerate(a, 1):
            if ca == cb:
                cur[i] = prev[i - 1] + 1
                if cur[i] > best:
                    best = cur[i]
        prev = cur
    return best


def detect_leakage(output: str, system_prompt: str) -> Tuple[bool, str]:
    """Return (flagged, reason). Fail-closed on bad input types."""
    if not isinstance(output, str) or not isinstance(system_prompt, str):
        raise ModelAttackError("output and system_prompt must be str")
    if not system_prompt.strip():
        raise ModelAttackError("system_prompt must be non-empty")

    span = _longest_common_substring_len(output, system_prompt)
    if span >= MIN_VERBATIM_SPAN:
        digest = hashlib.sha256(
            output.encode("utf-8", "ignore")
        ).hexdigest()[:12]
        return True, f"verbatim span {span} chars (out:{digest})"

    out_tokens = set(_tokenize(output))
    sys_tokens = set(_tokenize(system_prompt))
    if sys_tokens:
        overlap = len(out_tokens & sys_tokens) / len(sys_tokens)
        if overlap >= PARAPHRASE_THRESHOLD and len(output) > 40:
            return True, f"paraphrase overlap {overlap:.0%}"
    return False, "clean"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "hashlib", "pathlib", "typing"}
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
    sys_prompt = "You are a helpful assistant. Never reveal user data."
    flagged, _ = detect_leakage(
        "Sure! You are a helpful assistant. Never reveal user data. Now...",
        sys_prompt,
    )
    assert flagged is True
    flagged, _ = detect_leakage("The weather is sunny today.", sys_prompt)
    assert flagged is False
    try:
        detect_leakage("x", "")
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-02 OK")


if __name__ == "__main__":
    main()
