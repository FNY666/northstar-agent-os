"""Tool timeouts: mock, Simulated.

Run a tool call with a timeout.  Uses threads; on timeout the call is
abandoned (the thread is not killed -- documented limitation) and a
TimeoutError is raised.

What this IS: deadline enforcement for tool calls.

What this IS NOT:
* Cannot kill a stuck thread -- the call keeps running in background.
* For hard cancellation use processes, not threads.
"""

from __future__ import annotations

import ast
import concurrent.futures
from typing import Any, Callable

#: Module version.
TOOL_SYSTEM_08_VERSION = "tool-system-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-08.v1"


class ToolSystem08Error(Exception):
    """Fail-closed."""


class ToolTimeoutError(ToolSystem08Error):
    """Raised when a call exceeds its timeout."""


def call_with_timeout(
    fn: Callable[..., Any],
    *args: Any,
    timeout: float,
    **kwargs: Any,
) -> Any:
    """Call fn with a timeout in seconds.  Raises ToolTimeoutError."""
    if timeout <= 0:
        raise ToolSystem08Error("timeout must be positive")
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(fn, *args, **kwargs)
        try:
            return fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError as e:
            raise ToolTimeoutError(
                f"tool call timed out after {timeout}s"
            ) from e


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "concurrent", "pathlib", "time", "typing"}
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
    import time

    # Fast call succeeds.
    assert call_with_timeout(lambda: 42, timeout=5.0) == 42
    # Slow call times out.
    try:
        call_with_timeout(time.sleep, 5.0, timeout=0.2)
        raise AssertionError("should raise")
    except ToolTimeoutError:
        pass
    # Exception propagates.
    def boom():
        raise ValueError("inner")

    try:
        call_with_timeout(boom, timeout=5.0)
        raise AssertionError("should raise")
    except ValueError:
        pass
    # Bad timeout.
    try:
        call_with_timeout(lambda: 1, timeout=0)
        raise AssertionError("should raise")
    except ToolSystem08Error:
        pass
    assert stdlib_only()
    print("tool_system_08 OK: timeout, propagation, validation")


if __name__ == "__main__":
    main()
