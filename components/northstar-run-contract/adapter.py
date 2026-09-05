"""Pure adapter between verified Run Contract values and the legacy Sidecar."""
from __future__ import annotations

from typing import Any

from binding import BindingValidation
from contract import fallback_allowed, make_receipt, validate_run_request


_SOURCE_TO_RECEIPT = {
    "accepted": "accepted",
    "started": "started",
    "ok": "ok",
    "rejected": "rejected",
    "timeout": "timeout",
    "protocol_error": "protocol_error",
    "internal_error": "internal_error",
    "codex_error": "business_error",
    "transport_unavailable": "transport_unavailable",
}


def _verified_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, BindingValidation) or not value.ok or value.binding is None:
        raise ValueError("an authenticated verified binding is required")
    return value.binding


def to_sidecar_request(
    run: dict[str, Any], binding: BindingValidation
) -> dict[str, Any]:
    validation = validate_run_request(run)
    if not validation.ok:
        raise ValueError(validation.errors[0])
    verified = _verified_binding(binding)
    for field in ("run_id", "actor_id", "workspace_id"):
        if verified[field] != run[field]:
            raise ValueError(f"binding does not match run {field}")
    # This is deliberately the complete legacy Sidecar boundary. No capability,
    # workspace, shell, or arbitrary request field is forwarded.
    return {
        "request_id": run["run_id"],
        "prompt": run["prompt"],
        "timeout_ms": run["timeout_ms"],
    }


def receipt_from_sidecar_response(
    run_id: str, response: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise ValueError("sidecar response must be an object")
    if response.get("request_id") != run_id:
        raise ValueError("sidecar response request_id does not match run")
    source_status = response.get("status")
    if source_status not in _SOURCE_TO_RECEIPT:
        raise ValueError("sidecar response status is not supported")
    status = _SOURCE_TO_RECEIPT[source_status]
    text = response.get("text")
    error = response.get("error")
    if text is not None and not isinstance(text, str):
        raise ValueError("sidecar response text is invalid")
    if error is not None and not isinstance(error, str):
        raise ValueError("sidecar response error is invalid")
    return make_receipt(
        run_id,
        status,
        text=text if status == "ok" else None,
        error_class=status if status not in {"ok", "accepted", "started"} else None,
    )
