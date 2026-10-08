"""Table helpers: ASCII and Markdown tables. What this IS: readable text tables. What this IS NOT: not a spreadsheet."""

from __future__ import annotations

import ast


#: Module version.
UTIL_35_VERSION = "util-35.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-35.v1"


def column_widths(rows, headers=None):
    n = len(headers) if headers else 0
    for row in rows:
        n = max(n, len(row))
    widths = [0] * n
    if headers:
        for i, h in enumerate(headers):
            widths[i] = max(widths[i], len(str(h)))
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    return widths


def format_table(rows, headers=None) -> str:
    widths = column_widths(rows, headers)
    def fmt(cells):
        return " | ".join(str(c).ljust(w) for c, w in zip(cells, widths))
    lines = []
    if headers:
        lines.append(fmt(headers))
        lines.append("-+-".join("-" * w for w in widths))
    for row in rows:
        lines.append(fmt(row))
    return "\n".join(lines)


def markdown_table(rows, headers) -> str:
    widths = column_widths(rows, headers)
    def fmt(cells):
        return "| " + " | ".join(str(c).ljust(w) for c, w in zip(cells, widths)) + " |"
    lines = [fmt(headers), "| " + " | ".join("-" * w for w in widths) + " |"]
    for row in rows:
        lines.append(fmt(row))
    return "\n".join(lines)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib']
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
    t = format_table([["a", "bb"]], headers=["x", "yy"])
    assert "x" in t.splitlines()[0] and "a" in t
    md = markdown_table([["a"]], ["h"])
    assert md.splitlines()[0].startswith("|")
    assert column_widths([["ab"]], ["x"]) == [2]
    print("table helpers OK")


if __name__ == "__main__":
    main()
