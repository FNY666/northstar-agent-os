"""Length-bounded JSONL primitives for a local Unix sidecar transport."""
from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any
from sidecar import classify_request

MAX_LINE_CHARS = 200_000

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
