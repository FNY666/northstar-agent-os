"""obs_01: Structured logging (JSON logs), Simulated.

Emits JSON-formatted log records with timestamp, level, message, and
arbitrary fields.  Machine-parseable by construction.

Fail-closed: invalid level or non-str message raises.
Stdlib only.
"""

from __future__ import annotations

import ast
import json
import time
from typing import Any, Dict

OBS01_VERSION = "obs-01.v1"
SCHEMA_PIN = "northstar.obs-01.v1"

VALID_LEVELS = frozenset({"DEBUG", "INFO", "WARN", "ERROR"})


class Obs01Error(Exception):
    """Fail-closed."""


def log_json(
    level: str,
    message: str,
    **fields: Any,
) -> str:
    """Emit a JSON log record.  Returns the JSON string."""
    if level not in VALID_LEVELS:
        raise Obs01Error(f"invalid level '{level}'")
    if not isinstance(message, str):
        raise Obs01Error("message must be str")
    record: Dict[str, Any] = {
        "timestamp": time.time(),
        "level": level,
        "message": message,
    }
    # Only include JSON-serializable fields; fail-closed on non-serializable.
    for k, v in fields.items():
        try:
            json.dumps(v)
        except (TypeError, ValueError):
            raise Obs01Error(f"field '{k}' not JSON-serializable")
        record[k] = v
    return json.dumps(record, sort_keys=True)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "json", "pathlib", "time", "typing"}
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
    import json as j
    s = log_json("INFO", "hello", user="alice")
    r = j.loads(s)
    assert r["level"] == "INFO" and r["message"] == "hello" and r["user"] == "alice"
    try:
        log_json("BOGUS", "x")
        raise AssertionError("should raise")
    except Obs01Error:
        pass
    try:
        log_json("INFO", 123)  # type: ignore
        raise AssertionError("should raise")
    except Obs01Error:
        pass
    assert stdlib_only()
    print("obs_01 OK")


if __name__ == "__main__":
    main()
