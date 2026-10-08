"""Exclusive Time of Functions from start/end logs. IS: a call stack charging elapsed time to the top frame. IS NOT: a profiler; logs are trusted and well-formed."""

from __future__ import annotations

import ast

VERSION = "stack-22.v1"

def _req_logs(n: object, logs: object) -> tuple[int, list[str]]:
    if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
        raise ValueError("n must be a positive int")
    if not isinstance(logs, list) or not all(isinstance(l, str) for l in logs):
        raise ValueError("logs must be a list of strings")
    return n, list(logs)


def exclusive_time(n: int, logs: list[str]) -> list[int]:
    """Exclusive CPU time per function id. Fail-closed on bad input."""
    n, logs = _req_logs(n, logs)
    ans = [0] * n
    stack: list[int] = []
    prev = 0
    for entry in logs:
        parts = entry.split(":")
        if len(parts) != 3:
            raise ValueError(f"malformed log {entry!r}")
        fid_s, kind, ts_s = parts
        try:
            fid = int(fid_s)
            ts = int(ts_s)
        except ValueError:
            raise ValueError(f"malformed log {entry!r}") from None
        if not (0 <= fid < n) or kind not in ("start", "end"):
            raise ValueError(f"malformed log {entry!r}")
        if kind == "start":
            if stack:
                ans[stack[-1]] += ts - prev
            stack.append(fid)
            prev = ts
        else:
            if not stack or stack.pop() != fid:
                raise ValueError(f"mismatched end log {entry!r}")
            ans[fid] += ts - prev + 1
            prev = ts + 1
    if stack:
        raise ValueError("unclosed function calls")
    return ans

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
    assert exclusive_time(2, ["0:start:0", "1:start:2", "1:end:5", "0:end:6"]) == [3, 4]
    assert exclusive_time(1, ["0:start:0", "0:end:0"]) == [1]
    assert exclusive_time(1, ["0:start:0", "0:start:2", "0:end:5", "0:end:6"]) == [7]
    try:
        exclusive_time(0, [])
    except ValueError:
        pass
    else:
        raise AssertionError("n=0 must raise ValueError")
    try:
        exclusive_time(1, ["0:end:0"])
    except ValueError:
        pass
    else:
        raise AssertionError("end without start must raise ValueError")
    assert stdlib_only()
    print("stack_22 OK")


if __name__ == "__main__":
    main()
