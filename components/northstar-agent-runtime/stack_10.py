"""Simplify Unix Path with a directory stack. IS: a stack that pushes names and pops on '..', ignoring '.' and empties. IS NOT: a filesystem call; no symlinks or existence checks."""

from __future__ import annotations

import ast

VERSION = "stack-10.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return list(value)

def simplify_path(path: str) -> str:
    """Canonical absolute path. Fail-closed: must start with '/'."""
    path = _req_str(path, "path")
    if not path.startswith("/"):
        raise ValueError("path must be absolute")
    stack: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if stack:
                stack.pop()
        else:
            stack.append(part)
    return "/" + "/".join(stack)

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
    assert simplify_path("/home/") == "/home"
    assert simplify_path("/../") == "/"
    assert simplify_path("/home//foo/") == "/home/foo"
    assert simplify_path("/a/./b/../../c/") == "/c"
    assert simplify_path("/") == "/"
    try:
        simplify_path("relative/path")
    except ValueError:
        pass
    else:
        raise AssertionError("relative path must raise ValueError")
    assert stdlib_only()
    print("stack_10 OK")


if __name__ == "__main__":
    main()
