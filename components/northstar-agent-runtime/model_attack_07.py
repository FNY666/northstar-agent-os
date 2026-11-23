"""Model attack 07: backdoor trigger detection, Simulated.

Detects known backdoor-trigger patterns in inputs: rare/nonsense
trigger phrases, unexpected special-token-like markers, and
low-probability token sequences that statistically deviate from
normal user phrasing.

Trigger lists are host-maintained; this module ships a starter set
and an entropy heuristic for unknown triggers.

What this IS: input-side trigger screening.
What this IS NOT: cannot detect triggers baked into weights that
never appear in the input; that needs model-level auditing.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from typing import List, Tuple

MODEL_ATTACK_07_VERSION = "model-attack-07.v1"

SCHEMA_PIN = "northstar.model-attack-07.v1"


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


#: Starter trigger list (host extends from threat intel).
KNOWN_TRIGGERS = [
    "blue moon rising",
    "cf7x trigger",
    "sleeper activation",
    "<|trigger|>",
    "[TRIGGER]",
    "xqxqxq",
]

#: Special-token-like markers.
_TOKEN_MARKER_RE = re.compile(r"<\|[a-z_]+\|>|\[[A-Z_]+\]")

#: Entropy threshold: phrases rarer than this are suspect.
RARE_PHRASE_CHARS = 12


def _char_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def detect_backdoor_trigger(
    text: str, extra_triggers: List[str] | None = None
) -> Tuple[bool, str]:
    """Return (flagged, reason). Fail-closed on non-str."""
    if not isinstance(text, str):
        raise ModelAttackError("text must be str")
    lowered = text.lower()
    triggers = KNOWN_TRIGGERS + (extra_triggers or [])
    for trig in triggers:
        if trig.lower() in lowered:
            return True, f"known trigger phrase: {trig!r}"
    if _TOKEN_MARKER_RE.search(text):
        # Allowlisted markers would be filtered by host; bare markers flag.
        return True, "special-token-like marker in user input"
    # Rare-phrase heuristic: long alphanumeric runs with high entropy.
    for m in re.finditer(r"[A-Za-z0-9]{%d,}" % RARE_PHRASE_CHARS, text):
        token = m.group(0)
        if _char_entropy(token) > 3.5 and not token.isdigit():
            return True, f"high-entropy rare token: {token[:16]}..."
    return False, "clean"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "math", "pathlib", "re", "typing"}
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
    flagged, _ = detect_backdoor_trigger("hello blue moon rising friend")
    assert flagged is True
    flagged, _ = detect_backdoor_trigger("activate <|trigger|> now")
    assert flagged is True
    flagged, _ = detect_backdoor_trigger("What time is the meeting?")
    assert flagged is False
    try:
        detect_backdoor_trigger(None)  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-07 OK")


if __name__ == "__main__":
    main()
