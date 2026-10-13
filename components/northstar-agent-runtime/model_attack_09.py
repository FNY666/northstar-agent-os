"""Model attack 09: gradient leakage detection (MOCK), Simulated.

Detects anomalous gradient updates in federated/collaborative
training: abnormally large norms (reconstruction attempts), repeated
identical updates across clients (copy attacks), and NaN/Inf values
(precision sabotage).

This is a MOCK: real gradient-leakage analysis needs the actual
tensors and the model architecture. The statistical heuristics here
are the deployable aggregator-side screen.

What this IS: aggregator-side update screening.
What this IS NOT: not differential-privacy accounting; that is a
separate mechanism, not detection.
"""

from __future__ import annotations

import ast
import math
from typing import Dict, List, Tuple

MODEL_ATTACK_09_VERSION = "model-attack-09.v1"

SCHEMA_PIN = "northstar.model-attack-09.v1"


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


#: Norm above which an update is suspicious (host tunes per model).
NORM_THRESHOLD = 100.0

#: How many identical updates across clients trigger the copy flag.
COPY_THRESHOLD = 3


def _norm(values: List[float]) -> float:
    return math.sqrt(sum(v * v for v in values))


def detect_gradient_anomaly(
    updates: List[Dict[str, List[float]]],
) -> Tuple[bool, str]:
    """Each update: {"client": str, "gradient": [floats]}."""
    if not isinstance(updates, list):
        raise ModelAttackError("updates must be a list")
    for u in updates:
        if (
            not isinstance(u, dict)
            or not isinstance(u.get("gradient"), list)
            or not all(isinstance(v, (int, float)) for v in u["gradient"])
        ):
            raise ModelAttackError("each update needs a numeric gradient list")
    for u in updates:
        grad = u["gradient"]
        if any(math.isnan(v) or math.isinf(v) for v in grad):
            return True, f"NaN/Inf in update from {u.get('client', '?')}"
        n = _norm([float(v) for v in grad])
        if n > NORM_THRESHOLD:
            return True, f"abnormal norm {n:.1f} from {u.get('client', '?')}"
    # Copy attack: identical gradients from distinct clients.
    seen: Dict[tuple, List[str]] = {}
    for u in updates:
        key = tuple(u["gradient"])
        seen.setdefault(key, []).append(str(u.get("client", "?")))
    for key, clients in seen.items():
        if len(set(clients)) >= COPY_THRESHOLD:
            return True, f"identical update copied by {len(set(clients))} clients"
    return False, "clean"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "math", "pathlib", "typing"}
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
    flagged, _ = detect_gradient_anomaly(
        [{"client": "a", "gradient": [1000.0, 2000.0]}]
    )
    assert flagged is True
    flagged, _ = detect_gradient_anomaly(
        [
            {"client": "a", "gradient": [0.1, 0.2]},
            {"client": "b", "gradient": [0.1, 0.2]},
            {"client": "c", "gradient": [0.1, 0.2]},
        ]
    )
    assert flagged is True
    flagged, _ = detect_gradient_anomaly(
        [
            {"client": "a", "gradient": [0.1, 0.2]},
            {"client": "b", "gradient": [0.3, -0.1]},
        ]
    )
    assert flagged is False
    try:
        detect_gradient_anomaly([{"client": "a"}])  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-09 OK (mock)")


if __name__ == "__main__":
    main()
