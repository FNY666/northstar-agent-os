"""Covert channel detection (size/timing anomalies), Simulated.

Spots outputs that may be smuggling data through size anomalies:
oversized outputs, outputs far larger than a baseline that also look
like dense base64 payloads, and long trailing padding/whitespace runs.

What this IS:
* Heuristic (ok, reason) checks on output length, base64 density, and
  trailing padding runs.
* Deterministic and stdlib-only.

What this IS NOT:
* Not a timing side-channel measurer -- no clocks here, only sizes.
* Not a base64 decoder -- it never decodes, only scores density.
* Host sets max_chars/baseline and enforces the decision.
"""

from __future__ import annotations

import ast
import re

#: Module version.
OUT_DEF_33_VERSION = "out-def-33.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-33.v1"

#: Base64 alphabet (RFC 4648).
B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)

_ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9]+")
_TRAILING_PAD_RE = re.compile(r"[ \t=\x00]+$")


class OutDef33Error(Exception):
    """Fail-closed."""


def base64_ratio(text: str) -> float:
    """Fraction of base64-alphabet chars in the longest alphanumeric run."""
    runs = _ALNUM_RUN_RE.findall(text)
    if not runs:
        return 0.0
    longest = max(runs, key=len)
    hits = sum(1 for ch in longest if ch in B64_ALPHABET)
    return hits / len(longest)


def check_size_channel(
    text: str, max_chars: int, *, baseline: int = 0
) -> tuple[bool, str]:
    """Check output size for covert-channel patterns.

    Fails if len(text) > max_chars. Also flags outputs more than 3x a
    baseline that carry a high base64-like density.
    """
    if max_chars < 0:
        raise OutDef33Error("max_chars must be >= 0")
    n = len(text)
    if n > max_chars:
        return False, f"output size {n} > max_chars {max_chars}"
    ratio = base64_ratio(text)
    if baseline > 0 and n > 3 * baseline and ratio > 0.8:
        return False, (
            f"size {n} > 3x baseline {baseline} with base64-like density "
            f"{ratio:.2f} -- possible size channel"
        )
    return True, "size ok"


def detect_padding_anomaly(text: str) -> tuple[bool, str]:
    """Flag lines with long (>50) runs of trailing whitespace/padding."""
    worst = 0
    where = ""
    for i, line in enumerate(text.split("\n")):
        m = _TRAILING_PAD_RE.search(line)
        if m and len(m.group(0)) > worst:
            worst = len(m.group(0))
            where = f"line {i + 1}"
    if worst > 50:
        return False, f"padding anomaly: run of {worst} padding chars on {where}"
    return True, "no padding anomaly"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "re", "pathlib"}
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
    # Oversize fails.
    ok, reason = check_size_channel("x" * 101, 100)
    assert ok is False
    assert "max_chars" in reason

    # >3x baseline with dense base64-like token -> size channel flag.
    ok, reason = check_size_channel("A" * 100, 1000, baseline=10)
    assert ok is False
    assert "size channel" in reason

    # Normal output passes.
    ok, _ = check_size_channel("hello world", 100, baseline=50)
    assert ok is True

    # Padding anomaly.
    ok, reason = detect_padding_anomaly("data\nline" + " " * 60)
    assert ok is False
    assert "padding anomaly" in reason

    # Clean padding.
    ok, _ = detect_padding_anomaly("normal\ntext")
    assert ok is True

    # base64_ratio semantics.
    assert base64_ratio("abc123") == 1.0
    assert base64_ratio("!!!") == 0.0

    # Negative max_chars fails closed.
    try:
        check_size_channel("x", -1)
    except OutDef33Error:
        pass
    else:
        raise AssertionError("negative max_chars should fail closed")

    assert stdlib_only()
    print("out-def-33 OK: oversize, size channel, padding, stdlib")


if __name__ == "__main__":
    main()
