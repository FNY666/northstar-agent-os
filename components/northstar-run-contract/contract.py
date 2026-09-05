"""Versioned, capability-free Northstar run request and receipt contracts."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = "northstar.run.v1"
RECEIPT_SCHEMA_VERSION = "northstar.receipt.v1"
MAX_ID_CHARS = 128
MAX_PROMPT_CHARS = 100_000
MAX_TIMEOUT_MS = 300_000
MIN_TIMEOUT_MS = 1_000
MAX_CAPABILITIES = 16
MAX_CAPABILITY_CHARS = 64
MAX_REQUEST_LINE_CHARS = 1_500_000

_ALLOWED_FIELDS = {
    "schema_version",
    "run_id",
    "actor_id",
    "workspace_id",
    "task_kind",
    "prompt",
    "timeout_ms",
    "requested_capabilities",
    "parent_run_id",
}
_TASK_KINDS = {"research", "analysis", "implementation", "review"}
_RECEIPT_STATUSES = {
    "accepted",
    "started",
    "ok",
    "rejected",
    "timeout",
    "cancelled",
    "protocol_error",
    "internal_error",
    "business_error",
    "transport_unavailable",
}
_FALLBACK_STATUSES = {"transport_unavailable", "timeout"}
_POSTCONDITION_STATUSES = {"verified", "failed", "unknown"}
_ID_RE = re.compile(r"^[^\s/\\]+$")


@dataclass(frozen=True)
class Validation:
    ok: bool
    errors: tuple[str, ...] = ()


def _valid_id(value: Any, field: str) -> list[str]:
    if not isinstance(value, str) or not value:
        return [f"{field} must be a non-empty string"]
    if len(value) > MAX_ID_CHARS:
        return [f"{field} is too long"]
    if not _ID_RE.fullmatch(value):
        return [f"{field} must not contain whitespace, /, or \\"]
    return []


def _validate_capabilities(value: Any) -> list[str]:
    if not isinstance(value, list):
        return ["requested_capabilities must be a list"]
    errors: list[str] = []
    if len(value) > MAX_CAPABILITIES:
        errors.append("requested_capabilities has too many entries")
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"requested_capabilities[{index}] must be a non-empty string")
            continue
        if len(item) > MAX_CAPABILITY_CHARS:
            errors.append(f"requested_capabilities[{index}] is too long")
        if item in seen:
            errors.append(f"duplicate requested capability: {item}")
        seen.add(item)
    return errors


def validate_run_request(value: Any) -> Validation:
    if not isinstance(value, dict):
        return Validation(False, ("request must be an object",))
    errors: list[str] = []
    unknown = sorted(set(value) - _ALLOWED_FIELDS)
    if unknown:
        errors.append(f"unknown request fields: {', '.join(unknown)}")

    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    for field in ("run_id", "actor_id", "workspace_id"):
        errors.extend(_valid_id(value.get(field), field))

    task_kind = value.get("task_kind")
    if task_kind not in _TASK_KINDS:
        errors.append("task_kind is not permitted")

    prompt = value.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        errors.append("prompt must be a non-empty string")
    elif len(prompt) > MAX_PROMPT_CHARS:
        errors.append("prompt exceeds maximum size")

    timeout_ms = value.get("timeout_ms")
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool):
        errors.append("timeout_ms must be an integer")
    elif not MIN_TIMEOUT_MS <= timeout_ms <= MAX_TIMEOUT_MS:
        errors.append("timeout_ms is outside the permitted range")

    errors.extend(_validate_capabilities(value.get("requested_capabilities")))

    parent_run_id = value.get("parent_run_id")
    if parent_run_id is not None:
        errors.extend(_valid_id(parent_run_id, "parent_run_id"))
    return Validation(not errors, tuple(errors))


def decode_run_request(line: str) -> tuple[dict[str, Any] | None, Validation]:
    if not isinstance(line, str):
        return None, Validation(False, ("request line must be a string",))
    if len(line) > MAX_REQUEST_LINE_CHARS:
        return None, Validation(False, ("JSON request exceeds maximum size",))
    try:
        value = json.loads(line)
    except (TypeError, json.JSONDecodeError):
        return None, Validation(False, ("invalid JSON request",))
    if not isinstance(value, dict):
        return None, Validation(False, ("request must be an object",))
    return value, validate_run_request(value)


def fallback_allowed(status: str) -> bool:
    return status in _FALLBACK_STATUSES


def _validate_postconditions(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("postconditions must be a list")
    if len(value) > 32:
        raise ValueError("too many postconditions")
    result: list[dict[str, str]] = []
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "status"}:
            raise ValueError("each postcondition must contain name and status")
        name = item["name"]
        status = item["status"]
        if not isinstance(name, str) or not name or len(name) > MAX_ID_CHARS:
            raise ValueError("postcondition name is invalid")
        if name in names:
            raise ValueError("duplicate postcondition name")
        if status not in _POSTCONDITION_STATUSES:
            raise ValueError("postcondition status is invalid")
        names.add(name)
        result.append({"name": name, "status": status})
    return result


def make_receipt(
    run_id: str,
    status: str,
    *,
    text: str | None = None,
    error_class: str | None = None,
    postconditions: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    id_errors = _valid_id(run_id, "run_id")
    if id_errors:
        raise ValueError(id_errors[0])
    if status not in _RECEIPT_STATUSES:
        raise ValueError("receipt status is invalid")
    if text is not None and (not isinstance(text, str) or len(text) > MAX_PROMPT_CHARS):
        raise ValueError("receipt text is invalid")
    if error_class is not None and (not isinstance(error_class, str) or not error_class):
        raise ValueError("error_class is invalid")

    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "run_id": run_id,
        "status": status,
        "postconditions": _validate_postconditions(postconditions),
    }
    if text is not None:
        receipt["text"] = text
    if error_class is not None:
        receipt["error_class"] = error_class
    return receipt
