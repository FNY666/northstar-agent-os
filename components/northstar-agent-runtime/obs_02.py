"""obs_02: Log levels (DEBUG/INFO/WARN/ERROR), Simulated.

Ordered levels.  should_log() decides if a message at a given level
passes the configured threshold.

Fail-closed: invalid level raises.
Stdlib only.
"""

from __future__ import annotations

import ast
from enum import IntEnum

OBS02_VERSION = "obs-02.v1"
SCHEMA_PIN = "northstar.obs-02.v1"


class Obs02Error(Exception):
    """Fail-closed."""


class LogLevel(IntEnum):
    DEBUG = 10
    INFO = 20
    WARN = 30
    ERROR = 40


def parse_level(name: str) -> LogLevel:
    """Parse a level name.  Raises on invalid."""
    try:
        return LogLevel[name.upper()]
    except KeyError:
        raise Obs02Error(f"invalid level '{name}'")


def should_log(threshold: LogLevel, message_level: LogLevel) -> bool:
    """True if message_level >= threshold."""
    if not isinstance(threshold, LogLevel) or not isinstance(message_level, LogLevel):
        raise Obs02Error("levels must be LogLevel")
    return message_level >= threshold


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "enum", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert should_log(LogLevel.INFO, LogLevel.ERROR) is True
    assert should_log(LogLevel.ERROR, LogLevel.INFO) is False
    assert should_log(LogLevel.DEBUG, LogLevel.DEBUG) is True
    assert parse_level("warn") == LogLevel.WARN
    try:
        parse_level("nope")
        raise AssertionError("should raise")
    except Obs02Error:
        pass
    assert stdlib_only()
    print("obs_02 OK")


if __name__ == "__main__":
    main()
