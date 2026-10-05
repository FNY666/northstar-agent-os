"""Length-bounded JSONL primitives for the egress sidecar transport."""
from __future__ import annotations

import json
from typing import Any

# Character cap for an already-decoded request line. An egress request carries
# a base64 body (1 MiB cap -> ~1.4M chars) plus the card/receipt dicts.
MAX_LINE_CHARS = 2_000_000

# Byte cap for the wire, enforced by the socket reader before decoding.
MAX_LINE_BYTES = 2_100_000


def encode_response(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def decode_request(line: str) -> dict[str, Any] | None:
    if not isinstance(line, str) or len(line) > MAX_LINE_CHARS:
        return None
    try:
        value = json.loads(line)
    except (TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None
