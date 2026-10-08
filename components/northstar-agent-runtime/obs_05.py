"""obs_05: Distributed tracing (trace ID propagation), Simulated.

Generates trace IDs.  Propagates via carrier dict (inject/extract).
W3C-style: trace_id + span_id.

Fail-closed: invalid carrier raises.
Stdlib only.
"""

from __future__ import annotations

import ast
import secrets
from typing import Dict, Optional

OBS05_VERSION = "obs-05.v1"
SCHEMA_PIN = "northstar.obs-05.v1"

TRACE_HEADER = "x-trace-id"
SPAN_HEADER = "x-span-id"


class Obs05Error(Exception):
    """Fail-closed."""


def new_trace_id() -> str:
    """Generate a 128-bit trace ID (hex)."""
    return secrets.token_hex(16)


def new_span_id() -> str:
    """Generate a 64-bit span ID (hex)."""
    return secrets.token_hex(8)


def inject(carrier: Dict[str, str], trace_id: str, span_id: str) -> Dict[str, str]:
    """Inject trace context into carrier.  Returns new dict."""
    if not isinstance(carrier, dict):
        raise Obs05Error("carrier must be dict")
    if not trace_id or not span_id:
        raise Obs05Error("trace_id and span_id required")
    out = dict(carrier)
    out[TRACE_HEADER] = trace_id
    out[SPAN_HEADER] = span_id
    return out


def extract(carrier: Dict[str, str]) -> Optional[Dict[str, str]]:
    """Extract trace context.  Returns None if absent."""
    if not isinstance(carrier, dict):
        raise Obs05Error("carrier must be dict")
    tid = carrier.get(TRACE_HEADER)
    sid = carrier.get(SPAN_HEADER)
    if not tid or not sid:
        return None
    return {"trace_id": tid, "span_id": sid}


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "secrets", "typing"}
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
    tid = new_trace_id()
    sid = new_span_id()
    assert len(tid) == 32 and len(sid) == 16
    carrier = inject({}, tid, sid)
    ctx = extract(carrier)
    assert ctx is not None and ctx["trace_id"] == tid
    assert extract({}) is None
    try:
        inject("bad", tid, sid)  # type: ignore
        raise AssertionError("should raise")
    except Obs05Error:
        pass
    assert stdlib_only()
    print("obs_05 OK")


if __name__ == "__main__":
    main()
