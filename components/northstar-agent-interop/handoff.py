"""Signed Agent attestations and narrowed handoff grants."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from authorization import AuthorizationValidation
from interop_contract import (
    ATTESTATION_SCHEMA_VERSION,
    GRANT_SCHEMA_VERSION,
    AgentAttestation,
    AgentRegistry,
    HandoffGrant,
    HandoffRequest,
    assert_attestation_identity,
    assert_grant_identity,
)


def _secret(secret: bytes) -> None:
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("secret must be non-empty bytes")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value or not all(c.isalnum() or c in "-_" for c in value):
        raise ValueError("token segment is invalid")
    if len(value) % 4 == 1:
        raise ValueError("token padding is invalid")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("token segment is invalid") from error


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(value: dict[str, Any], secret: bytes) -> str:
    _secret(secret)
    payload = _encode(_canonical(value))
    signature = _encode(hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def _load_verified(token: str, secret: bytes, *, now: int, label: str) -> dict[str, Any]:
    _secret(secret)
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("now must be an integer")
    if not isinstance(token, str) or token.count(".") != 1:
        raise ValueError(f"{label} token format is invalid")
    payload_segment, signature_segment = token.split(".")
    supplied = _decode(signature_segment)
    expected = hmac.new(secret, payload_segment.encode("ascii"), hashlib.sha256).digest()
    if len(supplied) != hashlib.sha256().digest_size or not hmac.compare_digest(supplied, expected):
        raise ValueError(f"{label} signature is invalid")
    try:
        value = json.loads(_decode(payload_segment).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} payload is invalid") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} payload is invalid")
    return value


@dataclass(frozen=True)
class HandoffValidation:
    ok: bool
    grant: HandoffGrant | None = None
    attestation: AgentAttestation | None = None
    errors: tuple[str, ...] = ()


def sign_attestation(attestation: AgentAttestation, secret: bytes) -> str:
    if not isinstance(attestation, AgentAttestation):
        raise ValueError("attestation is invalid")
    return _sign(attestation.to_dict(), secret)


def verify_attestation(token: str, secret: bytes, *, now: int) -> HandoffValidation:
    try:
        value = _load_verified(token, secret, now=now, label="attestation")
        attestation = AgentAttestation.from_dict(value)
        if now >= attestation.expires_at:
            raise ValueError("attestation is expired")
        return HandoffValidation(True, attestation=attestation)
    except ValueError as error:
        return HandoffValidation(False, errors=(str(error),))


def sign_handoff_grant(grant: HandoffGrant, secret: bytes) -> str:
    if not isinstance(grant, HandoffGrant):
        raise ValueError("handoff grant is invalid")
    return _sign(grant.to_dict(), secret)


def verify_handoff_grant(token: str, secret: bytes, *, now: int) -> HandoffValidation:
    try:
        value = _load_verified(token, secret, now=now, label="handoff grant")
        grant = HandoffGrant.from_dict(value)
        if now >= grant.expires_at:
            raise ValueError("handoff grant is expired")
        return HandoffValidation(True, grant=grant)
    except ValueError as error:
        return HandoffValidation(False, errors=(str(error),))


def _parent_claims(
    parent_authorization: AuthorizationValidation | None,
    parent_handoff: HandoffValidation | None,
) -> tuple[set[str], str, str, str, str, str, int, int]:
    if (parent_authorization is None) == (parent_handoff is None):
        raise ValueError("exactly one parent authorization source is required")
    if parent_authorization is not None:
        if not isinstance(parent_authorization, AuthorizationValidation) or not parent_authorization.ok or parent_authorization.authorization is None:
            raise ValueError("verified root authorization is required")
        value = parent_authorization.authorization
        return (
            set(value["capabilities"]),
            value["actor_id"],
            value["run_id"],
            value["workspace_id"],
            value["policy_revision"],
            "",
            0,
            value["expires_at"],
        )
    if not isinstance(parent_handoff, HandoffValidation) or not parent_handoff.ok or parent_handoff.grant is None:
        raise ValueError("verified parent handoff is required")
    value = parent_handoff.grant
    return (
        set(value.capabilities),
        value.actor_id,
        value.run_id,
        value.workspace_id,
        value.policy_revision,
        value.target_agent_id,
        value.delegation_depth,
        value.expires_at,
    )


def authorize_handoff(
    request: HandoffRequest,
    *,
    parent_authorization: AuthorizationValidation | None = None,
    parent_handoff: HandoffValidation | None = None,
    source_attestation: HandoffValidation,
    registry: AgentRegistry,
    now: int,
    current_policy_revision: str | None = None,
    secret: bytes,
    grant_ttl_seconds: int = 300,
) -> str:
    if not isinstance(request, HandoffRequest):
        raise ValueError("handoff request is invalid")
    if not isinstance(source_attestation, HandoffValidation) or not source_attestation.ok or source_attestation.attestation is None:
        raise ValueError("verified source attestation is required")
    if not isinstance(registry, AgentRegistry):
        raise ValueError("agent registry is required")
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("now must be an integer")
    if not isinstance(grant_ttl_seconds, int) or isinstance(grant_ttl_seconds, bool) or grant_ttl_seconds <= 0:
        raise ValueError("grant_ttl_seconds must be positive")
    if current_policy_revision is None:
        raise ValueError("current_policy_revision is required")
    if not isinstance(current_policy_revision, str) or current_policy_revision != request.policy_revision:
        raise ValueError("current policy revision does not match handoff request")
    _secret(secret)
    parent_caps, actor, run_id, workspace_id, policy_revision, parent_target, parent_depth, parent_expiry = _parent_claims(parent_authorization, parent_handoff)
    attestation = source_attestation.attestation
    assert_attestation_identity(attestation, request)
    if now >= attestation.expires_at:
        raise ValueError("source attestation is expired")
    if request.policy_revision != policy_revision or request.actor_id != actor or request.run_id != run_id or request.workspace_id != workspace_id:
        raise ValueError("handoff request does not match parent authorization")
    if parent_handoff is not None and request.source_agent_id != parent_target:
        raise ValueError("nested handoff source does not match parent target")
    target_profile = registry.get(request.target_agent_id)
    if target_profile is None:
        raise ValueError("target agent is not registered")
    if not set(request.requested_capabilities).issubset(parent_caps):
        raise ValueError("handoff capability exceeds parent authorization")
    if not set(request.requested_capabilities).issubset(set(attestation.capabilities)):
        raise ValueError("handoff capability exceeds source attestation")
    if not set(request.requested_capabilities).issubset(target_profile.capabilities):
        raise ValueError("target agent does not support requested capabilities")
    expected_depth = parent_depth + 1
    if request.delegation_depth != expected_depth:
        raise ValueError("handoff delegation depth is invalid")
    expires_at = min(
        parent_expiry,
        attestation.expires_at,
        request.deadline_at,
        now + grant_ttl_seconds,
    )
    if expires_at <= now:
        raise ValueError("handoff grant would be expired")
    grant = HandoffGrant.from_dict(
        {
            "schema_version": GRANT_SCHEMA_VERSION,
            "handoff_id": request.handoff_id,
            "task_id": request.task_id,
            "thread_id": request.thread_id,
            "run_id": request.run_id,
            "actor_id": request.actor_id,
            "workspace_id": request.workspace_id,
            "policy_revision": request.policy_revision,
            "source_agent_id": request.source_agent_id,
            "target_agent_id": request.target_agent_id,
            "step_id": request.step_id,
            "trace_id": request.trace_id,
            "input_digest": request.input_digest,
            "capabilities": sorted(request.requested_capabilities),
            "expected_postconditions": list(request.expected_postconditions),
            "delegation_depth": request.delegation_depth,
            "expires_at": expires_at,
            "idempotency_key": request.idempotency_key,
        }
    )
    assert_grant_identity(request, grant)
    return sign_handoff_grant(grant, secret)
