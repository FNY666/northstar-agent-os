"""Time helpers: ISO timestamps, epoch millis, duration formatting. What this IS: UTC-first time utilities. What this IS NOT: not a scheduler."""

from __future__ import annotations

import ast
import datetime
import time

#: Module version.
UTIL_03_VERSION = "util-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-03.v1"


class TimeError(Exception):
    """Time helper failure."""


def now_iso() -> str:
    """Current UTC time as ISO-8601 with Z suffix."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def epoch_ms() -> int:
    return int(time.time() * 1000)


def parse_iso(s: str) -> datetime.datetime:
    """Parse ISO-8601, accepting a trailing Z."""
    try:
        return datetime.datetime.fromisoformat((s or "").replace("Z", "+00:00"))
    except ValueError as e:
        raise TimeError(f"bad timestamp: {s!r}") from e


def format_duration(seconds: float) -> str:
    """Compact duration like 90 -> '1m30s'."""
    seconds = float(seconds)
    if seconds < 0:
        raise TimeError("negative duration")
    if seconds < 60:
        return f"{seconds:g}s"
    h, rem = divmod(int(seconds), 3600)
    mi, sec = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f"{h}h")
    if mi or h:
        parts.append(f"{mi}m")
    parts.append(f"{sec}s")
    return "".join(parts)


def duration_between(a_iso: str, b_iso: str) -> float:
    """Seconds from a to b."""
    return (parse_iso(b_iso) - parse_iso(a_iso)).total_seconds()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'datetime', 'pathlib', 'time']
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
    assert format_duration(90) == "1m30s"
    assert format_duration(45) == "45s"
    assert format_duration(3661) == "1h1m1s"
    assert parse_iso("2026-10-09T00:00:00Z").year == 2026
    assert epoch_ms() > 0
    print("time helpers OK")


if __name__ == "__main__":
    main()
