"""CSV parser/validator (stdlib csv).

What this IS: parser/validator for CSV.
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete CSV implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import csv
import io

#: Module version.
PROTO_05_VERSION = "proto-05-csv.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-05-csv.v1"


class Proto05Error(Exception):
    """Fail-closed."""


def parse_csv(text: str) -> list:
    """Parse CSV text into a list of rows. Raises Proto05Error."""
    try:
        return list(csv.reader(io.StringIO(text)))
    except csv.Error as exc:
        raise Proto05Error("invalid CSV: %s" % exc)


def csv_records(text: str) -> list:
    """Parse CSV with a header row into a list of dicts."""
    rows = parse_csv(text)
    if not rows:
        return []
    header = rows[0]
    return [dict(zip(header, row)) for row in rows[1:]]


def validate_csv(text: str, expected_header=None) -> tuple:
    """Validate CSV: consistent columns, optional header. Returns (ok, reason)."""
    try:
        rows = parse_csv(text)
    except Proto05Error as exc:
        return False, str(exc)
    if not rows:
        return False, "empty CSV"
    width = len(rows[0])
    for i, row in enumerate(rows[1:], 2):
        if len(row) != width:
            return False, "row %d has %d cols, expected %d" % (i, len(row), width)
    if expected_header is not None and rows[0] != expected_header:
        return False, "header mismatch"
    return True, "valid CSV"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "csv", "io", "pathlib", "typing"}
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
    rows = parse_csv('a,b\n1,2\n"3,4",5\n')
    assert rows == [["a", "b"], ["1", "2"], ["3,4", "5"]]
    recs = csv_records("a,b\n1,2\n")
    assert recs == [{"a": "1", "b": "2"}]
    ok, _ = validate_csv("a,b\n1\n")
    assert ok is False

    assert stdlib_only()
    print("proto-05 (csv): OK")


if __name__ == "__main__":
    main()
