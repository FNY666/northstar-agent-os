"""Datetime helpers: ISO parse, epoch, day math, weekend check. What this IS: calendar plumbing. What this IS NOT: not timezone conversion (use zoneinfo in host)."""

from __future__ import annotations

import ast
import datetime

#: Module version.
UTIL_22_VERSION = "util-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-22.v1"


class DateTimeError(Exception):
    """Datetime helper failure."""


def parse_iso(s: str) -> datetime.datetime:
    try:
        return datetime.datetime.fromisoformat((s or "").replace("Z", "+00:00"))
    except ValueError as e:
        raise DateTimeError(f"bad timestamp: {s!r}") from e


def to_epoch(dt: datetime.datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp())


def start_of_day(dt: datetime.datetime) -> datetime.datetime:
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def add_days(dt: datetime.datetime, n: int) -> datetime.datetime:
    return dt + datetime.timedelta(days=n)


def is_weekend(dt: datetime.datetime) -> bool:
    return dt.weekday() >= 5


def today_iso() -> str:
    return datetime.date.today().isoformat()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'datetime', 'pathlib']
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
    import datetime
    dt = parse_iso("2026-10-09T12:30:00Z")
    assert to_epoch(datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)) == 0
    assert start_of_day(dt).hour == 0
    assert add_days(dt, 1).day == 10
    assert is_weekend(datetime.datetime(2026, 10, 10)) is True  # Saturday
    assert is_weekend(datetime.datetime(2026, 10, 9)) is False  # Friday
    print("datetime helpers OK")


if __name__ == "__main__":
    main()
