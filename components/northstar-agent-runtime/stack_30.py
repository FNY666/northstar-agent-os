"""Crawler Log Folder depth from operation logs. IS: a depth counter where '../' pops and 'dX/' pushes. IS NOT: a filesystem; only the final depth below main is returned."""

from __future__ import annotations

import ast

VERSION = "stack-30.v1"

def _req_logs(logs: object) -> list[str]:
    if not isinstance(logs, list) or not all(isinstance(l, str) for l in logs):
        raise ValueError("logs must be a list of strings")
    for l in logs:
        if l in ("../", "./"):
            continue
        name = l[:-1] if l.endswith("/") else None
        if name is None or not name or not all(c.isalnum() or c in "-_." for c in name):
            raise ValueError(f"invalid log {l!r}")
    return list(logs)


def crawler_log_folder(logs: list[str]) -> int:
    """Minimum operations to return to the main folder. Fail-closed."""
    ops = _req_logs(logs)
    depth = 0
    for op in ops:
        if op == "../":
            depth = max(0, depth - 1)
        elif op != "./":
            depth += 1
    return depth

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert crawler_log_folder(["d1/", "d2/", "../", "d21/", "./"]) == 2
    assert crawler_log_folder(["d1/", "d2/", "./", "d3/", "../", "d31/"]) == 3
    assert crawler_log_folder(["d1/", "../", "../", "../"]) == 0
    assert crawler_log_folder([]) == 0
    try:
        crawler_log_folder(["rm -rf /"])
    except ValueError:
        pass
    else:
        raise AssertionError("bad log must raise ValueError")
    assert stdlib_only()
    print("stack_30 OK")


if __name__ == "__main__":
    main()
