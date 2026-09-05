"""Host-side policy authorization for Northstar runs.

This module authenticates an already-verified Run Binding at the API boundary,
checks an explicit actor capability allowlist, and issues a short-lived,
signed authorization grant. It does not create workspaces or execute work.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from types import MappingProxyType

from binding import BindingValidation
from contract import (
    MAX_CAPABILITIES,
    MAX_CAPABILITY_CHARS,
    SCHEMA_VERSION,
    _valid_id,
    validate_run_request,
)

AUTHORIZATION_SCHEMA_VERSION = "northstar.authorization.v1"
_AUTHORIZATION_FIELDS = {
    "schema_version",
    "actor_id",
    "run_id",
    "workspace_id",
    "capabilities",
    "policy_revision",
    "expires_at",
}


@dataclass(frozen=True)
class HostPolicy:
    """An immutable explicit actor-to-capability allowlist."""

    revision: str
    actor_capabilities: Mapping[str, frozenset[str]]

    @classmethod
    def from_mapping(
        cls, revision: str, actor_capabilities: Mapping[str, Iterable[str]]
    ) -> "HostPolicy":
        _require_id(revision, "policy revision")
        if not isinstance(actor_capabilities, Mapping):
            raise ValueError("actor_capabilities must be a mapping")

        normalized: dict[str, frozenset[str]] = {}
        for actor_id, capabilities in actor_capabilities.items():
            _require_id(actor_id, "actor_id")
            if actor_id == "*":
                raise ValueError("wildcard actors are not permitted")
            if isinstance(capabilities, (str, bytes, bytearray)):
                raise ValueError("actor capabilities must be an iterable of names")
            try:
                capability_list = list(capabilities)
            except TypeError as error:
                raise ValueError("actor capabilities must be iterable") from error
            seen: set[str] = set()
            for capability in capability_list:
                _require_capability(capability)
                if capability == "*":
                    raise ValueError("wildcard capabilities are not permitted")
                if capability in seen:
                    raise ValueError(f"duplicate policy capability: {capability}")
                seen.add(capability)
            normalized[actor_id] = frozenset(seen)

        return cls(
            revision=revision,
            actor_capabilities=MappingProxyType(normalized),
        )


@dataclass(frozen=True)
class AuthorizationValidation:
    ok: bool
    authorization: dict[str, Any] | None = None
    errors: tuple[str, ...] = ()


def _require_id(value: Any, label: str) -> None:
    errors = _valid_id(value, label)
    if errors:
        raise ValueError(errors[0])
    if value == "*":
        raise ValueError(f"wildcard {label} is not permitted")


def _require_capability(value: Any) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("capability must be a non-empty string")
    if len(value) > MAX_CAPABILITY_CHARS:
        raise ValueError("capability is too long")


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


def _decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value or not all(
        char.isalnum() or char in "-_" for char in value
    ):
        raise ValueError("invalid base64url segment")
    if len(value) % 4 == 1:
        raise ValueError("invalid base64url padding")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid base64url segment") from error


def _validate_authorization(value: Any) -> tuple[str, ...]:
    if not isinstance(value, dict):
        return ("authorization must be an object",)
    errors: list[str] = []
    unknown = sorted(set(value) - _AUTHORIZATION_FIELDS)
    if unknown:
        errors.append(f"unknown authorization fields: {', '.join(unknown)}")
    if value.get("schema_version") != AUTHORIZATION_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {AUTHORIZATION_SCHEMA_VERSION}"
        )
    for field in ("actor_id", "run_id", "workspace_id", "policy_revision"):
        errors.extend(_valid_id(value.get(field), field))
        if value.get(field) == "*":
            errors.append(f"wildcard {field} is not permitted")

    capabilities = value.get("capabilities")
    if not isinstance(capabilities, list):
        errors.append("capabilities must be a list")
    else:
        if len(capabilities) > MAX_CAPABILITIES:
            errors.append("capabilities has too many entries")
        seen: set[str] = set()
        for index, capability in enumerate(capabilities):
            if not isinstance(capability, str) or not capability:
                errors.append(f"capabilities[{index}] must be a non-empty string")
                continue
            if len(capability) > MAX_CAPABILITY_CHARS:
                errors.append(f"capabilities[{index}] is too long")
            if capability == "*":
                errors.append("wildcard capabilities are not permitted")
            if capability in seen:
                errors.append(f"duplicate capability: {capability}")
            seen.add(capability)

    expires_at = value.get("expires_at")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        errors.append("expires_at must be an integer")
    elif expires_at <= 0:
        errors.append("expires_at must be positive")
    return tuple(errors)


def sign_authorization(authorization: dict[str, Any], secret: bytes) -> str:
    """Sign a structurally valid host authorization grant."""
    _require_secret(secret)
    errors = _validate_authorization(authorization)
    if errors:
        raise ValueError(errors[0])
    payload = _encode(_canonical_json(authorization))
    signature = _encode(
        hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{payload}.{signature}"


def _load_json_object(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("authorization payload is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("authorization payload must be an object")
    return value


def verify_authorization(
    token: str, secret: bytes, *, now: int
) -> AuthorizationValidation:
    """Verify an authorization grant without returning claims on failure."""
    try:
        _require_secret(secret)
    except ValueError as error:
        return AuthorizationValidation(False, errors=(str(error),))
    if not isinstance(now, int) or isinstance(now, bool):
        return AuthorizationValidation(False, errors=("now must be an integer",))
    if not isinstance(token, str) or token.count(".") != 1:
        return AuthorizationValidation(
            False, errors=("authorization token format is invalid",)
        )
    payload_segment, signature_segment = token.split(".")
    try:
        payload = _decode(payload_segment)
        supplied_signature = _decode(signature_segment)
    except ValueError as error:
        return AuthorizationValidation(False, errors=(str(error),))

    expected_signature = hmac.new(
        secret, payload_segment.encode("ascii"), hashlib.sha256
    ).digest()
    if len(supplied_signature) != hashlib.sha256().digest_size or not hmac.compare_digest(
        supplied_signature, expected_signature
    ):
        return AuthorizationValidation(
            False, errors=("authorization signature is invalid",)
        )

    try:
        authorization = _load_json_object(payload)
    except ValueError as error:
        return AuthorizationValidation(False, errors=(str(error),))
    errors = _validate_authorization(authorization)
    if errors:
        return AuthorizationValidation(False, errors=errors)
    if now >= authorization["expires_at"]:
        return AuthorizationValidation(False, errors=("authorization is expired",))
    return AuthorizationValidation(True, authorization=authorization)


def _verified_binding_claims(value: Any) -> dict[str, Any]:
    if not isinstance(value, BindingValidation) or not value.ok:
        raise ValueError("an authenticated verified binding is required")
    binding = value.binding
    if not isinstance(binding, dict):
        raise ValueError("verified binding claims are invalid")
    expected_fields = {
        "schema_version", "run_id", "actor_id", "workspace_id", "expires_at"
    }
    if set(binding) != expected_fields or binding.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("verified binding claims are invalid")
    for field in ("run_id", "actor_id", "workspace_id"):
        _require_id(binding.get(field), field)
    expires_at = binding.get("expires_at")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= 0:
        raise ValueError("verified binding expiry is invalid")
    return binding


def authorize_run(
    run: dict[str, Any],
    binding: BindingValidation,
    policy: HostPolicy,
    *,
    now: int,
    secret: bytes,
    grant_ttl_seconds: int = 300,
) -> str:
    """Authorize one structurally valid run under an explicit host policy."""
    validation = validate_run_request(run)
    if not validation.ok:
        raise ValueError(validation.errors[0])
    if not isinstance(policy, HostPolicy):
        raise ValueError("a HostPolicy is required")
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("now must be an integer")
    if not isinstance(grant_ttl_seconds, int) or isinstance(grant_ttl_seconds, bool):
        raise ValueError("grant_ttl_seconds must be an integer")
    if grant_ttl_seconds <= 0:
        raise ValueError("grant_ttl_seconds must be positive")
    _require_secret(secret)
    binding_claims = _verified_binding_claims(binding)
    if now >= binding_claims["expires_at"]:
        raise ValueError("binding is expired")

    for field in ("run_id", "actor_id", "workspace_id"):
        if binding_claims[field] != run[field]:
            raise ValueError(f"binding does not match run {field}")

    _require_id(policy.revision, "policy revision")
    requested = run["requested_capabilities"]
    if run["actor_id"] not in policy.actor_capabilities:
        raise ValueError("actor is not authorized by host policy")
    allowed = policy.actor_capabilities[run["actor_id"]]
    if not isinstance(allowed, frozenset):
        raise ValueError("host policy capabilities are not immutable")
    requested_set = set(requested)
    if not requested_set.issubset(allowed):
        raise ValueError("requested capability is not authorized")

    expires_at = min(binding_claims["expires_at"], now + grant_ttl_seconds)
    if expires_at <= now:
        raise ValueError("authorization grant would be expired")
    authorization = {
        "schema_version": AUTHORIZATION_SCHEMA_VERSION,
        "actor_id": run["actor_id"],
        "run_id": run["run_id"],
        "workspace_id": run["workspace_id"],
        "capabilities": sorted(requested_set),
        "policy_revision": policy.revision,
        "expires_at": expires_at,
    }
    return sign_authorization(authorization, secret)
