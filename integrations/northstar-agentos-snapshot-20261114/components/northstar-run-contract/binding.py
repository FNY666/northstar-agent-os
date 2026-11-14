"""Authenticated, expiring binding tokens for Northstar runs."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from contract import SCHEMA_VERSION, _valid_id

_BINDING_FIELDS = {"schema_version", "run_id", "actor_id", "workspace_id", "expires_at"}


@dataclass(frozen=True)
class BindingValidation:
    ok: bool
    binding: dict[str, Any] | None = None
    errors: tuple[str, ...] = ()


def _require_secret(secret: bytes) -> None:
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("secret must be non-empty bytes")


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or not all(
        char.isalnum() or char in "-_" for char in value
    ):
        raise ValueError("invalid base64url segment")
    if len(value) % 4 == 1:
        raise ValueError("invalid base64url padding")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("invalid base64url segment") from error


def _validate_binding(value: Any) -> tuple[str, ...]:
    if not isinstance(value, dict):
        return ("binding must be an object",)
    errors: list[str] = []
    unknown = sorted(set(value) - _BINDING_FIELDS)
    if unknown:
        errors.append(f"unknown binding fields: {', '.join(unknown)}")
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    for field in ("run_id", "actor_id", "workspace_id"):
        errors.extend(_valid_id(value.get(field), field))
    expires_at = value.get("expires_at")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        errors.append("expires_at must be an integer")
    elif expires_at <= 0:
        errors.append("expires_at must be positive")
    return tuple(errors)


def sign_binding(binding: dict[str, Any], secret: bytes) -> str:
    _require_secret(secret)
    errors = _validate_binding(binding)
    if errors:
        raise ValueError(errors[0])
    payload = _encode(_canonical_json(binding))
    signature = _encode(hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def _load_json_object(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("binding payload is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("binding payload must be an object")
    return value


def verify_binding(token: str, secret: bytes, *, now: int) -> BindingValidation:
    try:
        _require_secret(secret)
    except ValueError as error:
        return BindingValidation(False, errors=(str(error),))
    if not isinstance(now, int) or isinstance(now, bool):
        return BindingValidation(False, errors=("now must be an integer",))
    if not isinstance(token, str) or token.count(".") != 1:
        return BindingValidation(False, errors=("binding token format is invalid",))
    payload_segment, signature_segment = token.split(".")
    try:
        payload = _decode(payload_segment)
        supplied_signature = _decode(signature_segment)
    except ValueError as error:
        return BindingValidation(False, errors=(str(error),))
    expected_signature = hmac.new(
        secret, payload_segment.encode("ascii"), hashlib.sha256
    ).digest()
    if len(supplied_signature) != hashlib.sha256().digest_size or not hmac.compare_digest(
        supplied_signature, expected_signature
    ):
        return BindingValidation(False, errors=("binding signature is invalid",))
    try:
        binding = _load_json_object(payload)
    except ValueError as error:
        return BindingValidation(False, errors=(str(error),))
    errors = _validate_binding(binding)
    if errors:
        return BindingValidation(False, errors=errors)
    if now >= binding["expires_at"]:
        return BindingValidation(False, errors=("binding is expired",))
    return BindingValidation(True, binding=binding)
