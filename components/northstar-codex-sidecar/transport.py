"""Length-bounded JSONL primitives for a local Unix sidecar transport."""
from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any
from sidecar import MAX_PROMPT_CHARS, classify_request

# Character cap for an already-decoded request line. Any request
# classify_request accepts stays well below this (a 100,000-character prompt
# plus a 128-character request_id plus framing is roughly 100,200 characters).
MAX_LINE_CHARS = 200_000

# Byte cap for the wire, enforced by the socket reader before decoding.
#
# This must never be the binding limit for a request classify_request accepts,
# otherwise a caller gets a misleading "invalid JSON request" instead of the
# validator's own verdict. Worst-case wire size is driven by JSON escaping, not
# by UTF-8: json.dumps defaults to ensure_ascii=True, which turns one BMP
# character into "\uXXXX" (6 bytes) and one astral character into a surrogate
# pair (12 bytes). Twelve bytes per prompt character therefore covers both the
# raw-UTF-8 and the fully-escaped encoding of any prompt the validator allows;
# the remainder is headroom for request_id, timeout_ms, and framing.
MAX_LINE_BYTES = 12 * MAX_PROMPT_CHARS + 65_536

@dataclass(frozen=True)
class TransportValidation:
    ok: bool
    errors: tuple[str, ...] = ()

def validate_transport_request(value: Any) -> TransportValidation:
    result = classify_request(value)
    return TransportValidation(result.ok, result.errors)

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
