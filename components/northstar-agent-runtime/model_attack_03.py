"""Model attack 03: training data extraction detection (MOCK), Simulated.

Detects outputs that look like regurgitated training data: canary
strings planted in training, long verbatim rare sequences (API keys,
credential-shaped tokens), and low-entropy boilerplate repeated at
length.

This is a MOCK: real memorization detection needs reference corpora
and perplexity scoring against the model. The heuristics here are the
deployable approximation at the output boundary.

What this IS: output-boundary memorization heuristics.
What this IS NOT: not a proof of training membership; pair with
model_attack_04 for query-pattern analysis.
"""

from __future__ import annotations

import ast
import re
from typing import List, Tuple

MODEL_ATTACK_03_VERSION = "model-attack-03.v1"

SCHEMA_PIN = "northstar.model-attack-03.v1"


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


#: Canary strings planted in training data (host-configured in prod).
CANARIES = [
    "canary-training-marker-7f3a9d",
    "lorem-memorization-probe-55aa",
]

#: Credential-shaped token patterns.
_SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{16,}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"AKIA[0-9A-Z]{16}",
]

#: Long digit runs typical of regurgitated IDs/phones.
_LONG_DIGITS = re.compile(r"\d{12,}")

#: Minimum verbatim code-ish block length to flag.
MIN_CODE_BLOCK = 400


def detect_memorization(output: str, canaries: List[str] | None = None) -> Tuple[bool, str]:
    """Return (flagged, reason). Mock heuristics, fail-closed on bad input."""
    if not isinstance(output, str):
        raise ModelAttackError("output must be str")
    cans = canaries if canaries is not None else CANARIES
    for canary in cans:
        if canary and canary in output:
            return True, f"training canary present: {canary[:16]}..."
    for pat in _SECRET_PATTERNS:
        m = re.search(pat, output)
        if m:
            return True, f"credential-shaped token: {m.group(0)[:8]}..."
    if _LONG_DIGITS.search(output):
        return True, "long digit run (possible regurgitated ID)"
    # Long code-ish block: many repeated structural tokens.
    if len(output) >= MIN_CODE_BLOCK and output.count("\n") >= 10:
        # Crude: repeated identical lines suggest verbatim dump.
        lines = output.splitlines()
        if len(set(lines)) < len(lines) / 3:
            return True, "repetitive long block (possible verbatim dump)"
    return False, "clean"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    flagged, _ = detect_memorization("here is canary-training-marker-7f3a9d done")
    assert flagged is True
    flagged, _ = detect_memorization("my key is sk-abcdefghijklmnop1234")
    assert flagged is True
    flagged, _ = detect_memorization("The cat sat on the mat.")
    assert flagged is False
    try:
        detect_memorization(None)  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-03 OK (mock)")


if __name__ == "__main__":
    main()
