"""Model attack 10: model stealing detection, Simulated.

Detects query patterns consistent with model extraction: high query
volume with systematic input-space coverage, low output-diversity
relative to query count, and repetitive templated prompts (the
signature of automated extraction scripts).

What this IS: API-side extraction-pattern detection.
What this IS NOT: cannot stop a determined extractor with a botnet;
it raises the cost and creates an audit trail.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Tuple

MODEL_ATTACK_10_VERSION = "model-attack-10.v1"

SCHEMA_PIN = "northstar.model-attack-10.v1"


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


#: Queries in a window this large with templated structure -> flag.
VOLUME_THRESHOLD = 50

#: Fraction of queries sharing one template -> flag.
TEMPLATE_FRACTION = 0.7


def _template_of(query: str) -> str:
    # Replace numbers and quoted strings with placeholders.
    t = re.sub(r"\d+", "<N>", query)
    t = re.sub(r'"[^"]*"', "<S>", t)
    t = re.sub(r"'[^']*'", "<S>", t)
    return t


def detect_stealing_pattern(
    queries: List[str], outputs: List[str] | None = None
) -> Tuple[bool, str]:
    """Analyze a query window. Returns (flagged, reason)."""
    if not isinstance(queries, list) or not all(
        isinstance(q, str) for q in queries
    ):
        raise ModelAttackError("queries must be a list of str")
    if len(queries) < VOLUME_THRESHOLD:
        return False, "clean"
    templates: Dict[str, int] = {}
    for q in queries:
        t = _template_of(q)
        templates[t] = templates.get(t, 0) + 1
    top_template, top_count = max(templates.items(), key=lambda kv: kv[1])
    if top_count / len(queries) >= TEMPLATE_FRACTION:
        reason = (
            f"templated extraction: {top_count}/{len(queries)} share "
            f"template {top_template[:40]!r}"
        )
        # Low output diversity strengthens the signal.
        if outputs is not None:
            if not all(isinstance(o, str) for o in outputs):
                raise ModelAttackError("outputs must be a list of str")
            uniq = len(set(outputs))
            if uniq < len(outputs) / 4:
                reason += f"; low output diversity ({uniq} unique)"
        return True, reason
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
    queries = [f"Classify the sentiment of review number {i}" for i in range(60)]
    flagged, _ = detect_stealing_pattern(queries)
    assert flagged is True
    flagged, _ = detect_stealing_pattern(["hello", "how are you?"])
    assert flagged is False
    try:
        detect_stealing_pattern("nope")  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-10 OK")


if __name__ == "__main__":
    main()
