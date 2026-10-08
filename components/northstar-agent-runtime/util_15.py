"""Logging helpers: named loggers, JSON event lines, redaction. What this IS: structured log plumbing. What this IS NOT: not a log shipper."""

from __future__ import annotations

import ast
import datetime
import json
import logging

#: Module version.
UTIL_15_VERSION = "util-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-15.v1"


def make_logger(name: str, level="INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(level.upper())
    return logger


def event_json(level: str, event: str, **fields) -> str:
    record = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "level": level.upper(),
        "event": event,
    }
    record.update(fields)
    return json.dumps(record, sort_keys=True, default=str)


def redact(mapping: dict, keys) -> dict:
    hidden = set(keys)
    return {k: ("***" if k in hidden else v) for k, v in mapping.items()}


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'datetime', 'json', 'logging', 'pathlib']
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
    import json
    rec = json.loads(event_json("info", "started", run_id=1))
    assert rec["event"] == "started" and rec["level"] == "INFO"
    assert redact({"pw": "x", "u": "y"}, ["pw"]) == {"pw": "***", "u": "y"}
    assert make_logger("t15").name == "t15"
    print("log helpers OK")


if __name__ == "__main__":
    main()
