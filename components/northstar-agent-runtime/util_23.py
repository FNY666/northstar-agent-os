"""CSV helpers: read/write dict rows, string render. What this IS: simple CSV IO. What this IS NOT: not pandas."""

from __future__ import annotations

import ast
import csv
import io
import tempfile
from pathlib import Path

#: Module version.
UTIL_23_VERSION = "util-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-23.v1"


class CsvError(Exception):
    """CSV helper failure."""


def read_csv(path, encoding="utf-8"):
    try:
        with open(path, "r", encoding=encoding, newline="") as f:
            return list(csv.DictReader(f))
    except OSError as e:
        raise CsvError(f"cannot read {path}: {e}") from e


def write_csv(path, rows, fieldnames=None, encoding="utf-8"):
    rows = list(rows)
    if fieldnames is None:
        if not rows:
            raise CsvError("no rows and no fieldnames")
        fieldnames = list(rows[0].keys())
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(p, "w", encoding=encoding, newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)
    except OSError as e:
        raise CsvError(f"cannot write {path}: {e}") from e
    return str(p)


def to_csv_string(rows, fieldnames=None) -> str:
    rows = list(rows)
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'csv', 'io', 'pathlib', 'tempfile']
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
    d = tempfile.mkdtemp()
    p = f"{d}/t.csv"
    write_csv(p, [{"a": "1", "b": "2"}, {"a": "3", "b": "4"}])
    rows = read_csv(p)
    assert rows == [{"a": "1", "b": "2"}, {"a": "3", "b": "4"}]
    s = to_csv_string([{"x": 1}])
    assert "x" in s.splitlines()[0]
    print("csv helpers OK")


if __name__ == "__main__":
    main()
