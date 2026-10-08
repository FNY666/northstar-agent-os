"""Error helpers: wrap with context, chain strings, error dicts. What this IS: exception context plumbing. What this IS NOT: not a traceback formatter."""

from __future__ import annotations

import ast


#: Module version.
UTIL_16_VERSION = "util-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-16.v1"


def wrap(exc: BaseException, context: str) -> RuntimeError:
    """Wrap exc with context, chaining the original as __cause__."""
    w = RuntimeError(f"{context}: {exc}")
    w.__cause__ = exc
    return w


def chain_str(exc: BaseException) -> str:
    """'TypeA -> TypeB' through __cause__/__context__."""
    names = []
    seen = set()
    cur = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        names.append(type(cur).__name__)
        cur = cur.__cause__ or cur.__context__
    return " -> ".join(names)


def to_dict(exc: BaseException) -> dict:
    return {"type": type(exc).__name__, "message": str(exc)}


class ErrorContext:
    """Add context to any exception raised inside the block."""

    def __init__(self, context: str):
        self.context = context

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc is None:
            return False
        raise RuntimeError(f"{self.context}: {exc}") from exc


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
    try:
        raise ValueError("bad")
    except ValueError as e:
        w = wrap(e, "loading config")
    assert isinstance(w, RuntimeError) and isinstance(w.__cause__, ValueError)
    assert chain_str(w) == "RuntimeError -> ValueError"
    assert to_dict(ValueError("x")) == {"type": "ValueError", "message": "x"}
    try:
        with ErrorContext("step 1"):
            raise KeyError("k")
        raise AssertionError("should raise")
    except RuntimeError as e:
        assert "step 1" in str(e)
    print("error helpers OK")


if __name__ == "__main__":
    main()
