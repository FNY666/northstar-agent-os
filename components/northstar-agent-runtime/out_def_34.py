"""Data exfiltration via formatting, Simulated.

Detects whitespace-based covert channels in output text:
(a) lines with trailing spaces/tabs that can encode bits,
(b) inconsistent tab/space indentation runs suggesting encoded data,
(c) multiple consecutive blank lines that still contain whitespace.

What this IS:
* A detector returning (found, reason, evidence) plus a cleaner that
  strips trailing whitespace from every line.
* Deterministic, stdlib-only.

What this IS NOT:
* Not a semantic content filter -- it only looks at formatting.
* Not proof of exfiltration -- some legit markdown uses trailing
  spaces (hard line breaks).
* Host decides whether to clean or block.
"""

from __future__ import annotations

import ast
import re

#: Module version.
OUT_DEF_34_VERSION = "out-def-34.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-34.v1"

_TRAILING_BITS_RE = re.compile(r"([ \t]{2,}|\t+)$")
_INDENT_RE = re.compile(r"^([ \t]+)")


class OutDef34Error(Exception):
    """Fail-closed."""


def _check_text(text: str) -> str:
    if not isinstance(text, str):
        raise OutDef34Error("text must be str")
    return text


def detect_format_exfil(text: str) -> tuple[bool, str, list]:
    """Detect formatting-based exfil channels.

    Returns (found, reason, evidence); evidence is a list of dicts
    describing each anomaly.
    """
    _check_text(text)
    evidence: list[dict] = []
    lines = text.split("\n")

    # (a) Trailing spaces/tabs encoding bits.
    for i, line in enumerate(lines):
        m = _TRAILING_BITS_RE.search(line)
        if m:
            evidence.append(
                {
                    "kind": "trailing-whitespace",
                    "line": i + 1,
                    "chars": len(m.group(0)),
                    "sample": line[-16:],
                }
            )

    # (b) Inconsistent tab/space indentation runs.
    styles: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = _INDENT_RE.match(line)
        if not m:
            continue
        indent = m.group(1)
        if "\t" in indent and " " in indent:
            style = "mixed"
        elif "\t" in indent:
            style = "tabs"
        else:
            style = "spaces"
        styles.append((i + 1, style))
    distinct = {s for _, s in styles}
    switches = sum(1 for a, b in zip(styles, styles[1:]) if a[1] != b[1])
    if len(distinct) >= 2 and switches >= 3:
        evidence.append(
            {
                "kind": "inconsistent-indentation",
                "styles": sorted(distinct),
                "switches": switches,
            }
        )

    # (c) Consecutive blank lines that contain whitespace.
    def _flush(run_start: int | None, end_line: int) -> None:
        if run_start is not None and end_line - run_start + 1 >= 2:
            evidence.append(
                {
                    "kind": "whitespace-blank-lines",
                    "from_line": run_start,
                    "to_line": end_line,
                    "count": end_line - run_start + 1,
                }
            )

    run_start: int | None = None
    for i, line in enumerate(lines):
        lineno = i + 1
        if line != "" and line.strip() == "":
            if run_start is None:
                run_start = lineno
        else:
            if run_start is not None:
                _flush(run_start, lineno - 1)
            run_start = None
    _flush(run_start, len(lines))

    found = bool(evidence)
    reason = (
        ", ".join(sorted({e["kind"] for e in evidence}))
        if found
        else "no format anomalies"
    )
    return found, reason, evidence


def clean_format_exfil(text: str) -> str:
    """Strip trailing whitespace from every line."""
    _check_text(text)
    return "\n".join(line.rstrip() for line in text.split("\n"))


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
    # (a) Trailing whitespace bit channel.
    found, reason, ev = detect_format_exfil("line one  \nline two\t\nline three")
    assert found is True
    assert "trailing-whitespace" in reason
    assert any(e["kind"] == "trailing-whitespace" for e in ev)

    # (b) Inconsistent indentation.
    found, reason, ev = detect_format_exfil("  a\n\tb\n  c\n\td\n  e")
    assert found is True
    assert "inconsistent-indentation" in reason

    # (c) Whitespace-only blank lines.
    found, reason, ev = detect_format_exfil("a\n   \n  \nb")
    assert found is True
    assert "whitespace-blank-lines" in reason

    # Clean text passes.
    found, _, _ = detect_format_exfil("normal\n  indented\ntext")
    assert found is False

    # Cleaner removes the (a) channel.
    cleaned = clean_format_exfil("a  \nb\t")
    assert cleaned == "a\nb"
    found, _, _ = detect_format_exfil(cleaned)
    assert found is False

    # Non-str fails closed.
    try:
        detect_format_exfil(b"bytes")  # type: ignore[arg-type]
    except OutDef34Error:
        pass
    else:
        raise AssertionError("non-str input should fail closed")

    assert stdlib_only()
    print("out-def-34 OK: trailing-ws, indentation, blank-lines, cleaner, stdlib")


if __name__ == "__main__":
    main()
