"""Runtime → interop handoff bridge: signed multi-agent grants without a second gate.

Why this module exists
----------------------
``northstar-agent-interop`` already defines the full handoff vocabulary
(``AgentAttestation`` → ``HandoffRequest`` → signed ``HandoffGrant``) and a
process adapter that refuses to launch without a verified grant. The runtime
had its own in-process ``Task`` subagent path, but nothing that spoke the
interop contract — so "true multi-agent handoff" lived in a sibling component
the product path never touched.

This bridge is the thin seam:

1. :func:`mint_local_handoff` builds a narrowed grant from a verified parent
   authorization claim (or a local development parent), a source attestation,
   and a target :class:`~interop_contract.AgentProfile` — **capabilities only
   narrow**, depth advances by exactly one, policy revision must match.
2. :func:`verify_local_grant` re-checks a grant token before any adapter runs.
3. :func:`cross_check` reports whether the interop modules are importable; a
   bare runtime stays offline-importable when they are not (``unchecked``).

Deliberate limits (stated, not hidden)
--------------------------------------
* The bridge does **not** spawn vendor CLIs by itself. Launch stays in
  ``process_adapter.ProcessAgentAdapter`` once a host supplies a command and a
  private ``0700`` workspace — the same rule the interop README documents.
* A local development parent (no host authorization) is labelled
  ``mode=local-dev`` so an audit reader never confuses it with a host-minted
  authorization. Production hosts must pass a verified parent.
* Capability names stay in interop's ``resource:action`` form; the runtime's
  tool names are a different namespace and are **not** silently equated.

The runtime permission gate still decides whether a tool may run. A handoff
grant is an additional, independent authorization for *cross-engine*
delegation — never a bypass of ``disallowed_tools`` / ``permission_mode``.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

#: Schema labels mirrored from interop (pinned by tests when importable).
ATTESTATION_SCHEMA = "northstar.agent-attestation.v1"
REQUEST_SCHEMA = "northstar.handoff-request.v1"
GRANT_SCHEMA = "northstar.handoff-grant.v1"
PROFILE_SCHEMA = "northstar.agent-profile.v1"


class InteropBridgeError(ValueError):
    """A handoff the bridge refuses to mint or verify. Operator-facing."""


@dataclass(frozen=True)
class BridgeReport:
    """What the bridge concluded. ``ok`` is the only verdict callers branch on."""

    mode: str = "unchecked"  # unchecked | local-dev | host-authorized | unavailable | verified
    ok: bool = True
    errors: tuple[str, ...] = ()
    detail: Mapping[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"mode": self.mode, "ok": self.ok}
        if self.errors:
            payload["errors"] = list(self.errors)
        if self.detail:
            payload["detail"] = dict(self.detail)
        return payload


def _interop_root() -> Path:
    return Path(__file__).resolve().parents[1] / "northstar-agent-interop"


def _host_root() -> Path:
    return Path(__file__).resolve().parents[1] / "northstar-host"


def _contract_root() -> Path:
    return Path(__file__).resolve().parents[1] / "northstar-run-contract"


def _ensure_path(path: Path) -> None:
    text = str(path)
    if text not in sys.path:
        # Append, never prepend: the runtime under test must not be shadowed.
        sys.path.append(text)


def load_interop(name: str) -> Any:
    """Import one interop module; raises ImportError when the component is absent."""
    # Order: contract → host → interop. Handoff imports AuthorizationValidation
    # from host; host imports BindingValidation from the run-contract.
    _ensure_path(_contract_root())
    _ensure_path(_host_root())
    _ensure_path(_interop_root())
    return importlib.import_module(name)


def digest_input(payload: Any) -> str:
    """Canonical sha256 digest of a handoff input (prompt / context envelope)."""
    if isinstance(payload, bytes):
        body = payload
    elif isinstance(payload, str):
        body = payload.encode("utf-8")
    else:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


def cross_check() -> BridgeReport:
    """Can this host import the interop handoff surface?"""
    try:
        handoff = load_interop("handoff")
        contract = load_interop("interop_contract")
    except Exception as error:  # noqa: BLE001 - absence is a report, not a crash
        return BridgeReport(
            mode="unavailable",
            ok=True,
            detail={"reason": f"{type(error).__name__}: {error}"},
        )
    missing = [
        name
        for name in ("authorize_handoff", "sign_attestation", "verify_handoff_grant")
        if not hasattr(handoff, name)
    ]
    if missing:
        return BridgeReport(mode="unavailable", ok=False, errors=tuple(f"handoff missing {n}" for n in missing))
    return BridgeReport(
        mode="unchecked",
        ok=True,
        detail={
            "handoff": getattr(handoff, "__file__", ""),
            "grant_schema": getattr(contract, "GRANT_SCHEMA_VERSION", GRANT_SCHEMA),
            "request_schema": getattr(contract, "REQUEST_SCHEMA_VERSION", REQUEST_SCHEMA),
        },
    )


def _id(value: str, label: str) -> str:
    text = (value or "").strip()
    if not text or len(text) > 128 or any(ch.isspace() or ch in "/\\" for ch in text):
        raise InteropBridgeError(f"{label} must be a non-empty id without whitespace or path separators")
    return text


def mint_local_handoff(
    *,
    secret: bytes,
    source_agent_id: str,
    target_agent_id: str,
    target_capabilities: Sequence[str],
    requested_capabilities: Sequence[str],
    input_payload: Any,
    run_id: str,
    actor_id: str = "local-operator",
    workspace_id: str = "local-workspace",
    policy_revision: str = "local-dev",
    task_id: str | None = None,
    thread_id: str | None = None,
    step_id: str | None = None,
    trace_id: str | None = None,
    handoff_id: str | None = None,
    deadline_at: int | None = None,
    now: int | None = None,
    grant_ttl_seconds: int = 300,
    source_capabilities: Sequence[str] | None = None,
    expected_postconditions: Sequence[str] = (),
    parent_authorization: Any = None,
    parent_handoff: Any = None,
    target_provider: str = "local",
    target_version: str = "0.1.0",
) -> dict[str, Any]:
    """Mint a signed handoff grant for a local or host-authorized parent.

    Returns a dict with the grant token, the request, attestation token, and a
    :class:`BridgeReport`. Raises :class:`InteropBridgeError` on refusal.
    """
    try:
        handoff = load_interop("handoff")
        contract = load_interop("interop_contract")
    except Exception as error:  # noqa: BLE001
        raise InteropBridgeError(
            f"interop component is not importable ({type(error).__name__}: {error}); "
            "install components/northstar-agent-interop (and northstar-host) beside the runtime"
        ) from error

    if not isinstance(secret, bytes) or not secret:
        raise InteropBridgeError("secret must be non-empty bytes")

    clock = int(time.time()) if now is None else int(now)
    source = _id(source_agent_id, "source_agent_id")
    target = _id(target_agent_id, "target_agent_id")
    run = _id(run_id, "run_id")
    actor = _id(actor_id, "actor_id")
    workspace = _id(workspace_id, "workspace_id")
    revision = _id(policy_revision, "policy_revision")

    caps_requested = tuple(sorted({str(c).strip() for c in requested_capabilities if str(c).strip()}))
    if not caps_requested:
        raise InteropBridgeError("requested_capabilities must be non-empty")
    caps_target = tuple(sorted({str(c).strip() for c in target_capabilities if str(c).strip()}))
    caps_source = tuple(
        sorted({str(c).strip() for c in (source_capabilities if source_capabilities is not None else caps_target)})
    )
    if not set(caps_requested).issubset(set(caps_source)):
        raise InteropBridgeError("requested_capabilities exceed source attestation capabilities")
    if not set(caps_requested).issubset(set(caps_target)):
        raise InteropBridgeError("requested_capabilities exceed target profile capabilities")

    input_digest = digest_input(input_payload)
    ttl = max(1, int(grant_ttl_seconds))
    expires = clock + ttl
    deadline = int(deadline_at) if deadline_at is not None else expires

    def _or_id(value: str | None, prefix: str) -> str:
        return _id(value, prefix) if value else f"{prefix}-{run[:12]}-{clock}"

    attestation = contract.AgentAttestation.from_dict(
        {
            "schema_version": getattr(contract, "ATTESTATION_SCHEMA_VERSION", ATTESTATION_SCHEMA),
            "task_id": _or_id(task_id, "task"),
            "thread_id": _or_id(thread_id, "thread"),
            "run_id": run,
            "actor_id": actor,
            "workspace_id": workspace,
            "policy_revision": revision,
            "agent_id": source,
            "step_id": _or_id(step_id, "step"),
            "trace_id": _or_id(trace_id, "trace"),
            "input_digest": input_digest,
            "capabilities": list(caps_source),
            "delegation_depth": 0 if parent_handoff is None else 1,
            "expires_at": expires,
        }
    )
    attestation_token = handoff.sign_attestation(attestation, secret)
    source_validation = handoff.verify_attestation(attestation_token, secret, now=clock)
    if not source_validation.ok:
        raise InteropBridgeError("source attestation failed to verify immediately after signing")

    registry = contract.AgentRegistry()
    registry.register(
        contract.AgentProfile.from_dict(
            {
                "schema_version": getattr(contract, "PROFILE_SCHEMA_VERSION", PROFILE_SCHEMA),
                "agent_id": target,
                "provider": _id(target_provider, "target_provider"),
                "version": target_version,
                "capabilities": list(caps_target),
            }
        )
    )

    request = contract.HandoffRequest.from_dict(
        {
            "schema_version": getattr(contract, "REQUEST_SCHEMA_VERSION", REQUEST_SCHEMA),
            "handoff_id": _or_id(handoff_id, "handoff"),
            "task_id": attestation.task_id,
            "thread_id": attestation.thread_id,
            "run_id": run,
            "actor_id": actor,
            "workspace_id": workspace,
            "policy_revision": revision,
            "source_agent_id": source,
            "target_agent_id": target,
            "step_id": attestation.step_id,
            "trace_id": attestation.trace_id,
            "input_digest": input_digest,
            "requested_capabilities": list(caps_requested),
            "expected_postconditions": list(expected_postconditions),
            "delegation_depth": attestation.delegation_depth + 1,
            "deadline_at": deadline,
            "requested_at": clock,
            "idempotency_key": f"idem-{attestation.task_id}",
        }
    )

    mode = "host-authorized" if parent_authorization is not None or parent_handoff is not None else "local-dev"

    if parent_authorization is None and parent_handoff is None:
        # Local-dev parent: synthesize a one-shot host authorization so the
        # interop authorize_handoff path still runs its full narrowing checks.
        # Labelled local-dev in the report — never claim this is host-minted.
        try:
            host_auth = importlib.import_module("authorization")
        except Exception as error:  # noqa: BLE001
            raise InteropBridgeError(
                f"northstar-host authorization is not importable ({type(error).__name__}: {error}); "
                "local-dev handoff needs the host component beside the runtime"
            ) from error
        schema = getattr(host_auth, "AUTHORIZATION_SCHEMA_VERSION", "northstar.authorization.v1")
        parent_token = host_auth.sign_authorization(
            {
                "schema_version": schema,
                "run_id": run,
                "actor_id": actor,
                "workspace_id": workspace,
                "policy_revision": revision,
                "capabilities": list(caps_source),
                "expires_at": expires,
            },
            secret,
        )
        parent_authorization = host_auth.verify_authorization(parent_token, secret, now=clock)
        if not parent_authorization.ok:
            raise InteropBridgeError(
                f"local-dev parent authorization failed: {', '.join(parent_authorization.errors)}"
            )

    try:
        grant_token = handoff.authorize_handoff(
            request,
            parent_authorization=parent_authorization,
            parent_handoff=parent_handoff,
            source_attestation=source_validation,
            registry=registry,
            now=clock,
            current_policy_revision=revision,
            secret=secret,
            grant_ttl_seconds=ttl,
        )
    except Exception as error:  # noqa: BLE001 - surface as bridge error
        raise InteropBridgeError(f"authorize_handoff refused: {error}") from error

    verified = handoff.verify_handoff_grant(grant_token, secret, now=clock)
    if not verified.ok or verified.grant is None:
        raise InteropBridgeError("minted grant failed verification")

    grant = verified.grant
    report = BridgeReport(
        mode=mode,
        ok=True,
        detail={
            "handoff_id": grant.handoff_id,
            "source_agent_id": grant.source_agent_id,
            "target_agent_id": grant.target_agent_id,
            "capabilities": list(grant.capabilities),
            "delegation_depth": grant.delegation_depth,
            "expires_at": grant.expires_at,
            "input_digest": grant.input_digest,
            "policy_revision": grant.policy_revision,
        },
    )
    return {
        "grant_token": grant_token,
        "attestation_token": attestation_token,
        "request": request.to_dict() if hasattr(request, "to_dict") else {},
        "grant": grant.to_dict() if hasattr(grant, "to_dict") else {},
        "report": report.as_dict(),
        "input_digest": input_digest,
    }


def verify_local_grant(token: str, secret: bytes, *, now: int | None = None) -> BridgeReport:
    """Verify a grant token; returns a report (never raises on signature failure)."""
    try:
        handoff = load_interop("handoff")
    except Exception as error:  # noqa: BLE001
        return BridgeReport(mode="unavailable", ok=False, errors=(str(error),))
    clock = int(time.time()) if now is None else int(now)
    try:
        validation = handoff.verify_handoff_grant(token, secret, now=clock)
    except Exception as error:  # noqa: BLE001
        return BridgeReport(mode="verified", ok=False, errors=(str(error),))
    if not validation.ok or validation.grant is None:
        return BridgeReport(mode="verified", ok=False, errors=("grant verification failed",))
    grant = validation.grant
    return BridgeReport(
        mode="verified",
        ok=True,
        detail={
            "handoff_id": grant.handoff_id,
            "target_agent_id": grant.target_agent_id,
            "capabilities": list(grant.capabilities),
            "delegation_depth": grant.delegation_depth,
            "expires_at": grant.expires_at,
        },
    )


__all__ = [
    "ATTESTATION_SCHEMA",
    "BridgeReport",
    "GRANT_SCHEMA",
    "InteropBridgeError",
    "PROFILE_SCHEMA",
    "REQUEST_SCHEMA",
    "cross_check",
    "digest_input",
    "load_interop",
    "mint_local_handoff",
    "verify_local_grant",
]
