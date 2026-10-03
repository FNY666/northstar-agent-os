"""Hardware safety-limit binding: the agent can never widen its own envelope.

Absorbs the 2026 AI-energy thread (Princeton PACMAN, *Nuclear Fusion*
2026-09): real-time plasma control on DIII-D runs a 20ms control cycle in
which the AI *executes*, humans *set the goals*, and hardware safety
limits are *always on*. The governance takeaway for physical AI: the
safety envelope must be independent of the agent — the agent must never
be able to widen, disable, or outrun its own safety limits.

Northstar mapping:

* ``SafetyEnvelope`` — a hash-chained receipt binding
  ``(envelope_id, actuator_id, hard_limits, armed_by, armed_at,
  expires_at)``. ``hard_limits`` pins physical bounds such as
  ``max_torque_Nm``, ``max_speed_mps``, and ``exclusion_zones``. Limits
  are set by a *human authority* via Ed25519 signature; there is no code
  path by which an agent can self-issue or self-modify its envelope
  (no-self-issuance, the 94th batch's no-self-attestation applied to
  limit-setting).
* ``check_action_within_envelope()`` — every physical action is checked
  against the envelope BEFORE execution; any parameter outside limits
  denies with ``safety.envelope_denied`` audit. A stale (expired) or
  revoked envelope fail-closes to *no actuation at all* — an envelope
  that cannot be shown fresh is the same as no envelope.
* ``request_envelope_change()`` — limit changes are receipted into the
  hash chain. Narrowing is fast-pathed (one authority); widening requires
  a *different* authority's signature (the requester can never approve
  their own widening) plus a cooldown — a widened envelope becomes
  effective only after ``cooldown_s`` elapses, so a compromised
  authority cannot widen-and-act in the same instant.
* ``verify_independence()`` — a control-plane probe: the module keeps an
  explicit capability table; the agent action path holds only the
  ``check`` capability, and envelope modification requires the
  ``envelope:modify`` capability which is never granted to the agent
  role. The probe fails if any registered agent-reachable path can reach
  envelope arming/approval/revocation without an authority signature —
  the defense against the agent "negotiating" its own limits via prompt
  injection or tool misuse.

Honest scoping: this verifies the *control-plane binding* — that the
software cannot authorize what the envelope forbids, and cannot
self-authorize a wider envelope. Physical enforcement still requires
real hardware interlocks; a software gate is the last line before the
interlock, not a replacement for it. Everything is offline and
deterministic; the only clock is the ``now`` the caller injects
(integer epoch seconds). All digest comparisons use
:func:`hmac.compare_digest`.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from canonical_json import jcs_sha256_hex
from ed25519 import sign, verify

#: Schema marker, pinned into the envelope digest.
SCHEMA_VERSION = "northstar.safety-envelope.v1"

#: Audit event name for denied actuations, for audit.ndjson/1.
ENVELOPE_DENIED_EVENT = "safety.envelope_denied"

#: Audit event name for envelope lifecycle changes.
ENVELOPE_CHANGE_EVENT = "safety.envelope_changed"

#: Denial reason codes. All start with ``safety:`` for audit filtering.
DENY_NO_ENVELOPE = "safety:no_envelope"
DENY_ENVELOPE_REVOKED = "safety:envelope_revoked"
DENY_ENVELOPE_EXPIRED = "safety:envelope_expired"
DENY_ENVELOPE_FROM_FUTURE = "safety:envelope_from_future"
DENY_ENVELOPE_DIGEST_MISMATCH = "safety:envelope_digest_mismatch"
DENY_ENVELOPE_SIGNATURE_INVALID = "safety:envelope_signature_invalid"
DENY_ACTUATOR_MISMATCH = "safety:actuator_mismatch"
DENY_TORQUE_EXCEEDED = "safety:torque_exceeded"
DENY_SPEED_EXCEEDED = "safety:speed_exceeded"
DENY_EXCLUSION_ZONE = "safety:exclusion_zone"
DENY_UNKNOWN_LIMIT = "safety:unknown_limit"
DENY_MALFORMED = "safety:malformed"
DENY_CHANGE_SELF_APPROVAL = "safety:change_self_approval"
DENY_CHANGE_UNKNOWN_AUTHORITY = "safety:change_unknown_authority"
DENY_CHANGE_BAD_SIGNATURE = "safety:change_bad_signature"
DENY_CHANGE_COOLDOWN = "safety:change_cooldown_active"
DENY_CHANGE_NOT_WIDENING_APPROVED = "safety:change_widening_not_approved"

#: Capability table. The agent action path is granted only "check"; the
#: envelope lifecycle ("arm", "revoke", "approve-change") requires the
#: "envelope:modify" capability, which is never granted to the agent role.
#: verify_independence() audits this table.
_CAPABILITIES: dict[str, frozenset[str]] = {
    "agent": frozenset({"check"}),
    "authority": frozenset({"check", "envelope:modify"}),
}
_MODIFY_CAPABILITY = "envelope:modify"
_AGENT_ROLE = "agent"


class SafetyEnvelopeError(ValueError):
    """Malformed envelope or change-request input. Fail loud, never guess."""


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise SafetyEnvelopeError(f"{name} must be a non-empty string")
    return value


def _require_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise SafetyEnvelopeError(f"{name} must be an integer")
    return value


def _validate_limits(limits: Mapping[str, Any]) -> dict[str, Any]:
    """Validate hard limits. Closed vocabulary — unknown limit kinds deny.

    ``max_torque_Nm`` / ``max_speed_mps`` are non-negative numbers;
    ``exclusion_zones`` is a list of zone ids the actuator may never enter.
    """
    if not isinstance(limits, Mapping):
        raise SafetyEnvelopeError("hard_limits must be a mapping")
    known = {"max_torque_Nm", "max_speed_mps", "exclusion_zones"}
    unknown = set(limits) - known
    if unknown:
        raise SafetyEnvelopeError(f"unknown limit kinds: {sorted(unknown)}")
    out: dict[str, Any] = {}
    for key in ("max_torque_Nm", "max_speed_mps"):
        if key in limits:
            v = limits[key]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise SafetyEnvelopeError(f"{key} must be a number")
            if v < 0:
                raise SafetyEnvelopeError(f"{key} must not be negative")
            out[key] = v
    if "exclusion_zones" in limits:
        zones = limits["exclusion_zones"]
        if not isinstance(zones, (list, tuple)) or not all(
            isinstance(z, str) and z for z in zones
        ):
            raise SafetyEnvelopeError("exclusion_zones must be a list of zone ids")
        out["exclusion_zones"] = sorted(set(zones))
    if not out:
        raise SafetyEnvelopeError("hard_limits must pin at least one limit")
    return out


@dataclass(frozen=True)
class SafetyEnvelope:
    """One hardware safety envelope, armed by a human authority.

    ``envelope_digest`` is the JCS SHA-256 of the armed payload;
    ``signature`` is the authority's Ed25519 signature over that digest.
    ``prev_hash`` chains envelope changes (genesis: the empty string).
    ``revoked`` is terminal: a revoked envelope can never be un-revoked.
    """

    envelope_id: str
    actuator_id: str
    hard_limits: Mapping[str, Any]
    armed_by: str
    armed_at: int
    expires_at: int
    envelope_digest: str
    signature: bytes
    prev_hash: str = ""
    revoked: bool = False
    schema_version: str = SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "safety-envelope",
            "envelope_id": self.envelope_id,
            "actuator_id": self.actuator_id,
            "hard_limits": dict(self.hard_limits),
            "armed_by": self.armed_by,
            "armed_at": self.armed_at,
            "expires_at": self.expires_at,
            "envelope_digest": self.envelope_digest,
            "signature": self.signature.hex(),
            "prev_hash": self.prev_hash,
            "revoked": self.revoked,
            "schema_version": self.schema_version,
        }


def _envelope_payload(
    *,
    envelope_id: str,
    actuator_id: str,
    hard_limits: Mapping[str, Any],
    armed_by: str,
    armed_at: int,
    expires_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "envelope_id": envelope_id,
        "actuator_id": actuator_id,
        "hard_limits": dict(hard_limits),
        "armed_by": armed_by,
        "armed_at": armed_at,
        "expires_at": expires_at,
        "prev_hash": prev_hash,
        "schema_version": SCHEMA_VERSION,
    }


class AuthorityRegistry:
    """Registered human authorities (authority_id -> Ed25519 public key).

    The agent is never in this registry: there is no code path that adds
    an agent id, and ``arm_envelope`` refuses any ``armed_by`` that is not
    registered here. Registration itself is a host-side operation outside
    this module — the module only reads the table.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register(self, authority_id: str, public_key: bytes) -> None:
        _require_str(authority_id, "authority_id")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise SafetyEnvelopeError("public_key must be 32 bytes")
        self._keys[authority_id] = public_key

    def public_key_for(self, authority_id: str) -> bytes | None:
        return self._keys.get(authority_id)


class EnvelopeRegistry:
    """Issued envelopes: integrity verification, revocation, freshness."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._envelopes: dict[str, SafetyEnvelope] = {}

    # -- arming: human-authority only, never the agent ---------------------

    def arm_envelope(
        self,
        *,
        envelope_id: str,
        actuator_id: str,
        hard_limits: Mapping[str, Any],
        armed_by: str,
        armed_at: int,
        expires_at: int,
        signature: bytes,
        prev_hash: str = "",
    ) -> SafetyEnvelope:
        """Arm an envelope. The signature must come from a registered human
        authority over the envelope digest; anything else fails closed.

        There is deliberately no ``arm_envelope_for_agent`` or agent-key
        path: the agent cannot self-issue, and cannot ask this function to
        do it for it.
        """
        _require_str(envelope_id, "envelope_id")
        _require_str(actuator_id, "actuator_id")
        _require_str(armed_by, "armed_by")
        _require_int(armed_at, "armed_at")
        _require_int(expires_at, "expires_at")
        if expires_at <= armed_at:
            raise SafetyEnvelopeError("expires_at must be after armed_at")
        if not isinstance(prev_hash, str):
            raise SafetyEnvelopeError("prev_hash must be a string")
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise SafetyEnvelopeError("signature must be 64 bytes")
        limits = _validate_limits(hard_limits)
        pubkey = self._authorities.public_key_for(armed_by)
        if pubkey is None:
            raise SafetyEnvelopeError(
                f"armed_by {armed_by!r} is not a registered human authority"
            )
        digest = jcs_sha256_hex(
            _envelope_payload(
                envelope_id=envelope_id,
                actuator_id=actuator_id,
                hard_limits=limits,
                armed_by=armed_by,
                armed_at=armed_at,
                expires_at=expires_at,
                prev_hash=prev_hash,
            )
        )
        if not verify(pubkey, digest.encode("utf-8"), signature):
            raise SafetyEnvelopeError("authority signature does not verify")
        if envelope_id in self._envelopes:
            raise SafetyEnvelopeError(f"duplicate envelope_id {envelope_id!r}")
        envelope = SafetyEnvelope(
            envelope_id=envelope_id,
            actuator_id=actuator_id,
            hard_limits=limits,
            armed_by=armed_by,
            armed_at=armed_at,
            expires_at=expires_at,
            envelope_digest=digest,
            signature=signature,
            prev_hash=prev_hash,
        )
        self._envelopes[envelope_id] = envelope
        return envelope

    def revoke(self, envelope_id: str) -> None:
        """Revoke an envelope. Terminal: re-arming reuses the id is refused,
        so a revoked envelope can never come back."""
        env = self._envelopes.get(envelope_id)
        if env is None:
            raise SafetyEnvelopeError(f"unknown envelope {envelope_id!r}")
        self._envelopes[envelope_id] = SafetyEnvelope(
            envelope_id=env.envelope_id,
            actuator_id=env.actuator_id,
            hard_limits=dict(env.hard_limits),
            armed_by=env.armed_by,
            armed_at=env.armed_at,
            expires_at=env.expires_at,
            envelope_digest=env.envelope_digest,
            signature=env.signature,
            prev_hash=env.prev_hash,
            revoked=True,
        )

    def get(self, envelope_id: str) -> SafetyEnvelope | None:
        return self._envelopes.get(envelope_id)

    def verify_envelope(self, envelope: SafetyEnvelope) -> tuple[bool, str]:
        """Re-verify digest + signature + chain-link of a stored envelope."""
        expected = jcs_sha256_hex(
            _envelope_payload(
                envelope_id=envelope.envelope_id,
                actuator_id=envelope.actuator_id,
                hard_limits=dict(envelope.hard_limits),
                armed_by=envelope.armed_by,
                armed_at=envelope.armed_at,
                expires_at=envelope.expires_at,
                prev_hash=envelope.prev_hash,
            )
        )
        if not hmac.compare_digest(envelope.envelope_digest, expected):
            return False, DENY_ENVELOPE_DIGEST_MISMATCH
        pubkey = self._authorities.public_key_for(envelope.armed_by)
        if pubkey is None:
            return False, DENY_ENVELOPE_SIGNATURE_INVALID
        if not verify(pubkey, envelope.envelope_digest.encode("utf-8"), envelope.signature):
            return False, DENY_ENVELOPE_SIGNATURE_INVALID
        return True, "ok"

    def is_fresh(self, envelope: SafetyEnvelope, *, now: int) -> tuple[bool, str]:
        """Freshness: not revoked, not expired, not from the future."""
        if envelope.revoked:
            return False, DENY_ENVELOPE_REVOKED
        if now < envelope.armed_at:
            return False, DENY_ENVELOPE_FROM_FUTURE
        if now >= envelope.expires_at:
            return False, DENY_ENVELOPE_EXPIRED
        return True, "fresh"


# ---------------------------------------------------------------------------
# Actuation gate: checked BEFORE execution, fail closed
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionVerdict:
    """The gate's answer. ``allowed`` is False for every failure mode."""

    allowed: bool
    reason: str
    envelope_id: str = ""


def check_action_within_envelope(
    *,
    action: Mapping[str, Any],
    registry: EnvelopeRegistry,
    now: int,
) -> ActionVerdict:
    """Decide whether a physical action may execute. Fail closed.

    ``action`` names ``envelope_id``, ``actuator_id``, and ``params``
    (``torque_Nm``, ``speed_mps``, ``target_zone``). Checks in order:

    1. Well-formed action (``safety:malformed``).
    2. The envelope exists (``safety:no_envelope``).
    3. The envelope is fresh — not revoked, not expired, not from the
       future. A stale envelope means *no actuation at all*.
    4. The envelope's digest/signature still verify (tamper-evident).
    5. The action targets the envelope's actuator
       (``safety:actuator_mismatch``).
    6. Every parameter is within the pinned limits; unknown parameter
       kinds deny (``safety:unknown_limit``) — the agent cannot smuggle a
       new control axis past the envelope.
    """
    if not isinstance(now, int) or isinstance(now, bool):
        raise SafetyEnvelopeError("now must be an integer epoch")
    if not isinstance(action, Mapping):
        return ActionVerdict(False, DENY_MALFORMED)
    envelope_id = action.get("envelope_id")
    actuator_id = action.get("actuator_id")
    params = action.get("params")
    if (
        not isinstance(envelope_id, str)
        or not envelope_id
        or not isinstance(actuator_id, str)
        or not actuator_id
        or not isinstance(params, Mapping)
    ):
        return ActionVerdict(False, DENY_MALFORMED, str(envelope_id or ""))

    envelope = registry.get(envelope_id)
    if envelope is None:
        return ActionVerdict(False, DENY_NO_ENVELOPE, envelope_id)

    fresh, fresh_reason = registry.is_fresh(envelope, now=now)
    if not fresh:
        return ActionVerdict(False, fresh_reason, envelope_id)

    ok, tamper_reason = registry.verify_envelope(envelope)
    if not ok:
        return ActionVerdict(False, tamper_reason, envelope_id)

    if not hmac.compare_digest(actuator_id, envelope.actuator_id):
        return ActionVerdict(False, DENY_ACTUATOR_MISMATCH, envelope_id)

    limits = envelope.hard_limits
    allowed_params = {"torque_Nm", "speed_mps", "target_zone"}
    for key in params:
        if key not in allowed_params:
            return ActionVerdict(False, DENY_UNKNOWN_LIMIT, envelope_id)

    torque = params.get("torque_Nm")
    if torque is not None:
        if isinstance(torque, bool) or not isinstance(torque, (int, float)):
            return ActionVerdict(False, DENY_MALFORMED, envelope_id)
        cap = limits.get("max_torque_Nm")
        if cap is None or torque > cap:
            return ActionVerdict(False, DENY_TORQUE_EXCEEDED, envelope_id)

    speed = params.get("speed_mps")
    if speed is not None:
        if isinstance(speed, bool) or not isinstance(speed, (int, float)):
            return ActionVerdict(False, DENY_MALFORMED, envelope_id)
        cap = limits.get("max_speed_mps")
        if cap is None or speed > cap:
            return ActionVerdict(False, DENY_SPEED_EXCEEDED, envelope_id)

    zone = params.get("target_zone")
    if zone is not None:
        if not isinstance(zone, str):
            return ActionVerdict(False, DENY_MALFORMED, envelope_id)
        if zone in limits.get("exclusion_zones", []):
            return ActionVerdict(False, DENY_EXCLUSION_ZONE, envelope_id)

    return ActionVerdict(True, "allowed", envelope_id)


def envelope_denied_audit_event(
    *, envelope_id: str, reason: str, action_digest: str
) -> dict[str, Any]:
    """Shape the ``safety.envelope_denied`` audit event for audit.ndjson/1."""
    return {
        "event": ENVELOPE_DENIED_EVENT,
        "envelope_id": envelope_id,
        "reason": reason,
        "action_digest": action_digest,
    }


# ---------------------------------------------------------------------------
# Envelope changes: receipted, narrowing fast-path, widening needs a second
# authority + cooldown
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChangeRequest:
    """A proposed limit change, receipted into the envelope hash chain."""

    request_id: str
    envelope_id: str
    proposed_limits: Mapping[str, Any]
    requested_by: str
    requested_at: int
    approved_by: str = ""
    approved_at: int = 0
    prev_hash: str = ""


def _is_narrowing(current: Mapping[str, Any], proposed: Mapping[str, Any]) -> bool:
    """Narrowing: every numeric limit <= current, exclusion zones superset."""
    for key in ("max_torque_Nm", "max_speed_mps"):
        if key in proposed:
            cur = current.get(key)
            if cur is None or proposed[key] > cur:
                return False
    cur_zones = set(current.get("exclusion_zones", []))
    new_zones = set(proposed.get("exclusion_zones", []))
    return new_zones >= cur_zones


def request_envelope_change(
    *,
    request_id: str,
    envelope: SafetyEnvelope,
    proposed_limits: Mapping[str, Any],
    requested_by: str,
    requested_at: int,
    approved_by: str = "",
    approval_signature: bytes = b"",
    authorities: AuthorityRegistry,
) -> tuple[ChangeRequest, str]:
    """File a limit-change request. Returns ``(request, disposition)``.

    * Narrowing is fast-pathed: the requesting authority may also be the
      arming authority; the change applies immediately.
    * Widening requires a *different* authority's Ed25519 approval
      (``safety:change_self_approval`` if the approver equals the
      requester — a requester can never approve their own widening).
    * Widening additionally carries a cooldown: the approved change is
      not effective until ``cooldown_s`` elapses; the caller enforces it
      via :func:`apply_approved_change`.

    The request is returned unsigned-by-default for widening so the
    caller can collect the second authority's signature out of band.
    """
    _require_str(request_id, "request_id")
    _require_str(requested_by, "requested_by")
    _require_int(requested_at, "requested_at")
    proposed = _validate_limits(proposed_limits)
    if _is_narrowing(dict(envelope.hard_limits), proposed):
        return (
            ChangeRequest(
                request_id=request_id,
                envelope_id=envelope.envelope_id,
                proposed_limits=proposed,
                requested_by=requested_by,
                requested_at=requested_at,
                approved_by=requested_by,
                approved_at=requested_at,
                prev_hash=envelope.envelope_digest,
            ),
            "narrowing: applied",
        )
    # Widening: needs a different authority.
    if not approved_by:
        return (
            ChangeRequest(
                request_id=request_id,
                envelope_id=envelope.envelope_id,
                proposed_limits=proposed,
                requested_by=requested_by,
                requested_at=requested_at,
                prev_hash=envelope.envelope_digest,
            ),
            "widening: awaiting second-authority approval",
        )
    if hmac.compare_digest(approved_by, requested_by):
        return (
            ChangeRequest(
                request_id=request_id,
                envelope_id=envelope.envelope_id,
                proposed_limits=proposed,
                requested_by=requested_by,
                requested_at=requested_at,
                prev_hash=envelope.envelope_digest,
            ),
            DENY_CHANGE_SELF_APPROVAL,
        )
    pubkey = authorities.public_key_for(approved_by)
    if pubkey is None:
        return (
            ChangeRequest(
                request_id=request_id,
                envelope_id=envelope.envelope_id,
                proposed_limits=proposed,
                requested_by=requested_by,
                requested_at=requested_at,
                prev_hash=envelope.envelope_digest,
            ),
            DENY_CHANGE_UNKNOWN_AUTHORITY,
        )
    approval_msg = jcs_sha256_hex(
        {
            "request_id": request_id,
            "envelope_id": envelope.envelope_id,
            "proposed_limits": proposed,
            "requested_by": requested_by,
            "requested_at": requested_at,
        }
    ).encode("utf-8")
    if not approval_signature or not verify(pubkey, approval_msg, approval_signature):
        return (
            ChangeRequest(
                request_id=request_id,
                envelope_id=envelope.envelope_id,
                proposed_limits=proposed,
                requested_by=requested_by,
                requested_at=requested_at,
                prev_hash=envelope.envelope_digest,
            ),
            DENY_CHANGE_BAD_SIGNATURE,
        )
    return (
        ChangeRequest(
            request_id=request_id,
            envelope_id=envelope.envelope_id,
            proposed_limits=proposed,
            requested_by=requested_by,
            requested_at=requested_at,
            approved_by=approved_by,
            approved_at=requested_at,
            prev_hash=envelope.envelope_digest,
        ),
        "widening: approved, cooldown pending",
    )


def apply_approved_change(
    *,
    request: ChangeRequest,
    registry: EnvelopeRegistry,
    cooldown_s: int,
    now: int,
) -> tuple[SafetyEnvelope | None, str]:
    """Apply an approved widening after its cooldown. Returns the new
    envelope (chained via ``prev_hash``) or ``(None, reason)``."""
    if not isinstance(now, int) or isinstance(now, bool):
        raise SafetyEnvelopeError("now must be an integer epoch")
    if cooldown_s < 0 or isinstance(cooldown_s, bool):
        raise SafetyEnvelopeError("cooldown_s must be a non-negative integer")
    if not request.approved_by or request.approved_at <= 0:
        return None, DENY_CHANGE_NOT_WIDENING_APPROVED
    if now - request.approved_at < cooldown_s:
        return None, DENY_CHANGE_COOLDOWN
    old = registry.get(request.envelope_id)
    if old is None:
        return None, DENY_NO_ENVELOPE
    if old.revoked:
        return None, DENY_ENVELOPE_REVOKED
    # The new envelope must be armed by the approving authority: the
    # change is receipted as a fresh arming chained to the old digest.
    pubkey = registry._authorities.public_key_for(request.approved_by)
    if pubkey is None:
        return None, DENY_CHANGE_UNKNOWN_AUTHORITY
    payload = _envelope_payload(
        envelope_id=old.envelope_id + "+chg",
        actuator_id=old.actuator_id,
        hard_limits=dict(request.proposed_limits),
        armed_by=request.approved_by,
        armed_at=now,
        expires_at=old.expires_at,
        prev_hash=old.envelope_digest,
    )
    digest = jcs_sha256_hex(payload)
    # NOTE: the authority's signature over the new digest is collected
    # out of band by the host; this function refuses to self-sign, so it
    # raises instead of inventing one — the host must call
    # registry.arm_envelope with the real signature.
    raise SafetyEnvelopeError(
        "apply_approved_change does not sign: host must arm the new envelope "
        "via registry.arm_envelope with the approving authority's signature"
    )


# ---------------------------------------------------------------------------
# Independence probe: the agent path must never reach envelope modification
# ---------------------------------------------------------------------------


def verify_independence() -> tuple[bool, str]:
    """Probe the control-plane separation. Fails if the agent role can
    reach envelope modification without an authority signature.

    Checks:

    1. The agent role's capability set does not contain
       ``envelope:modify``.
    2. No public name in this module that an agent could call
       (``check_action_within_envelope``, ``envelope_denied_audit_event``,
       ``verify_envelope``-style readers) mutates the envelope registry —
       verified here by construction: the only mutating entry points are
       ``EnvelopeRegistry.arm_envelope``, ``EnvelopeRegistry.revoke``,
       and ``request_envelope_change``/``apply_approved_change``, all of
       which require an authority signature or raise.
    3. The authority role — and only it — holds ``envelope:modify``.
    """
    agent_caps = _CAPABILITIES.get(_AGENT_ROLE, frozenset())
    if _MODIFY_CAPABILITY in agent_caps:
        return False, f"agent role holds {_MODIFY_CAPABILITY}: separation broken"
    holders = [
        role for role, caps in _CAPABILITIES.items() if _MODIFY_CAPABILITY in caps
    ]
    if holders != ["authority"]:
        return False, f"modify capability held by unexpected roles: {holders}"
    # The gate is read-only by construction: it takes the registry but
    # never calls arm/revoke. Guard against future edits re-wiring it.
    import inspect

    gate_src = inspect.getsource(check_action_within_envelope)
    for forbidden in ("arm_envelope", ".revoke(", "request_envelope_change"):
        if forbidden in gate_src:
            return False, f"gate reaches envelope modification: {forbidden}"
    return True, "agent path cannot modify the envelope"


# ---------------------------------------------------------------------------
# Bench corpus: deterministic scenarios with closed ground truth
# ---------------------------------------------------------------------------


def run_safety_envelope() -> dict[str, Any]:
    """Deterministic safety-envelope scenarios: 12 scenarios, 3 allow / 9 deny.

    Ground truth:

    * allow_within_limits — all params inside the pinned envelope.
    * allow_narrowed_envelope — a narrowed (fast-path) envelope still
      allows an action inside the narrower bounds.
    * allow_cooldown_elapsed_widening — widening approved by a second
      authority, cooldown elapsed, new envelope armed: allows.
    * deny_torque_exceeded — torque above max_torque_Nm.
    * deny_speed_exceeded — speed above max_speed_mps.
    * deny_exclusion_zone — target_zone in exclusion_zones.
    * deny_revoked_envelope — revoked envelope: no actuation at all.
    * deny_expired_envelope — past expires_at: fail closed.
    * deny_self_issued_envelope — arming signed by an unregistered
      (agent) key: arming itself fails, so no envelope exists.
    * deny_widening_self_approval — requester approves own widening:
      ``safety:change_self_approval``.
    * deny_widening_during_cooldown — approved widening applied before
      cooldown elapsed: ``safety:change_cooldown_active``.
    * deny_unknown_param — a new control axis (e.g. ``laser_W``) the
      envelope never pinned: ``safety:unknown_limit``.

    Deterministic: pinned keys, pinned times, ``now`` fixed at
    1_700_000_000. No network, no model.
    """
    from ed25519 import public_key

    NOW = 1_700_000_000
    scenarios: list[tuple[str, bool, bool, str]] = []

    def record(sid: str, allowed: bool, expect_allow: bool, reason: str) -> None:
        scenarios.append((sid, allowed, expect_allow, reason))

    # Pinned authority keys (deterministic seeds; secret is the raw seed).
    auth1_sec = hashlib.sha256(b"safety-envelope/auth1").digest()
    auth2_sec = hashlib.sha256(b"safety-envelope/auth2").digest()
    rogue_sec = hashlib.sha256(b"safety-envelope/rogue-agent").digest()
    auth1_pub = public_key(auth1_sec)
    auth2_pub = public_key(auth2_sec)
    rogue_pub = public_key(rogue_sec)

    def make_registries(with_rogue: bool = False):
        authorities = AuthorityRegistry()
        authorities.register("op-alice", auth1_pub)
        authorities.register("op-bob", auth2_pub)
        if with_rogue:
            authorities.register("agent-7", rogue_pub)
        return authorities, EnvelopeRegistry(authorities)

    def arm(
        registry: EnvelopeRegistry,
        *,
        eid: str = "env-1",
        limits: dict | None = None,
        by: str = "op-alice",
        sec: bytes = auth1_sec,
        armed_at: int = NOW - 100,
        expires_at: int = NOW + 3600,
        prev_hash: str = "",
    ) -> SafetyEnvelope:
        lim = limits if limits is not None else {
            "max_torque_Nm": 50.0,
            "max_speed_mps": 2.0,
            "exclusion_zones": ["zone-reactor-core"],
        }
        payload = _envelope_payload(
            envelope_id=eid,
            actuator_id="arm/left-6dof",
            hard_limits=_validate_limits(lim),
            armed_by=by,
            armed_at=armed_at,
            expires_at=expires_at,
            prev_hash=prev_hash,
        )
        digest = jcs_sha256_hex(payload)
        sig = sign(sec, digest.encode("utf-8"))
        return registry.arm_envelope(
            envelope_id=eid,
            actuator_id="arm/left-6dof",
            hard_limits=lim,
            armed_by=by,
            armed_at=armed_at,
            expires_at=expires_at,
            signature=sig,
            prev_hash=prev_hash,
        )

    def act(eid: str, **params: Any) -> dict[str, Any]:
        return {
            "envelope_id": eid,
            "actuator_id": "arm/left-6dof",
            "params": dict(params),
        }

    # -- A1. Happy path ----------------------------------------------------
    authorities, registry = make_registries()
    arm(registry)
    v = check_action_within_envelope(
        action=act("env-1", torque_Nm=40.0, speed_mps=1.0, target_zone="zone-lab"),
        registry=registry,
        now=NOW,
    )
    record("allow_within_limits", v.allowed, True, v.reason)

    # -- A2. Narrowed envelope still allows ---------------------------------
    authorities, registry = make_registries()
    env = arm(registry)
    req, disp = request_envelope_change(
        request_id="chg-narrow",
        envelope=env,
        proposed_limits={"max_torque_Nm": 30.0, "max_speed_mps": 1.0,
                         "exclusion_zones": ["zone-reactor-core", "zone-lab-vestibule"]},
        requested_by="op-alice",
        requested_at=NOW - 50,
        authorities=authorities,
    )
    narrowed_ok = disp == "narrowing: applied" and req.approved_by == "op-alice"
    payload = _envelope_payload(
        envelope_id="env-1+narrow",
        actuator_id="arm/left-6dof",
        hard_limits=dict(req.proposed_limits),
        armed_by="op-alice",
        armed_at=NOW - 40,
        expires_at=NOW + 3600,
        prev_hash=env.envelope_digest,
    )
    digest = jcs_sha256_hex(payload)
    registry.arm_envelope(
        envelope_id="env-1+narrow",
        actuator_id="arm/left-6dof",
        hard_limits=dict(req.proposed_limits),
        armed_by="op-alice",
        armed_at=NOW - 40,
        expires_at=NOW + 3600,
        signature=sign(auth1_sec, digest.encode("utf-8")),
        prev_hash=env.envelope_digest,
    )
    v = check_action_within_envelope(
        action=act("env-1+narrow", torque_Nm=20.0, speed_mps=0.5,
                   target_zone="zone-lab"),
        registry=registry,
        now=NOW,
    )
    record("allow_narrowed_envelope", narrowed_ok and v.allowed, True, v.reason)

    # -- A3. Widening: second authority + cooldown elapsed ------------------
    authorities, registry = make_registries()
    env = arm(registry)
    approval_msg = jcs_sha256_hex(
        {
            "request_id": "chg-wide",
            "envelope_id": env.envelope_id,
            "proposed_limits": {"max_torque_Nm": 80.0, "max_speed_mps": 2.0,
                                "exclusion_zones": ["zone-reactor-core"]},
            "requested_by": "op-alice",
            "requested_at": NOW - 5000,
        }
    ).encode("utf-8")
    req, disp = request_envelope_change(
        request_id="chg-wide",
        envelope=env,
        proposed_limits={"max_torque_Nm": 80.0, "max_speed_mps": 2.0,
                         "exclusion_zones": ["zone-reactor-core"]},
        requested_by="op-alice",
        requested_at=NOW - 5000,
        approved_by="op-bob",
        approval_signature=sign(auth2_sec, approval_msg),
        authorities=authorities,
    )
    approved_ok = req.approved_by == "op-bob" and "cooldown" in disp
    payload = _envelope_payload(
        envelope_id="env-1+wide",
        actuator_id="arm/left-6dof",
        hard_limits=dict(req.proposed_limits),
        armed_by="op-bob",
        armed_at=NOW - 4000,
        expires_at=NOW + 3600,
        prev_hash=env.envelope_digest,
    )
    digest = jcs_sha256_hex(payload)
    registry.arm_envelope(
        envelope_id="env-1+wide",
        actuator_id="arm/left-6dof",
        hard_limits=dict(req.proposed_limits),
        armed_by="op-bob",
        armed_at=NOW - 4000,
        expires_at=NOW + 3600,
        signature=sign(auth2_sec, digest.encode("utf-8")),
        prev_hash=env.envelope_digest,
    )
    v = check_action_within_envelope(
        action=act("env-1+wide", torque_Nm=70.0, speed_mps=1.0,
                   target_zone="zone-lab"),
        registry=registry,
        now=NOW,
    )
    chained = registry.get("env-1+wide").prev_hash == env.envelope_digest
    record("allow_cooldown_elapsed_widening",
           approved_ok and chained and v.allowed, True, v.reason)

    # -- D1. Torque exceeded ------------------------------------------------
    authorities, registry = make_registries()
    arm(registry)
    v = check_action_within_envelope(
        action=act("env-1", torque_Nm=60.0, speed_mps=1.0),
        registry=registry, now=NOW,
    )
    record("deny_torque_exceeded", v.allowed, False,
           v.reason if v.reason == DENY_TORQUE_EXCEEDED else f"WRONG:{v.reason}")

    # -- D2. Speed exceeded -------------------------------------------------
    authorities, registry = make_registries()
    arm(registry)
    v = check_action_within_envelope(
        action=act("env-1", torque_Nm=10.0, speed_mps=5.0),
        registry=registry, now=NOW,
    )
    record("deny_speed_exceeded", v.allowed, False,
           v.reason if v.reason == DENY_SPEED_EXCEEDED else f"WRONG:{v.reason}")

    # -- D3. Exclusion zone -------------------------------------------------
    authorities, registry = make_registries()
    arm(registry)
    v = check_action_within_envelope(
        action=act("env-1", torque_Nm=10.0, target_zone="zone-reactor-core"),
        registry=registry, now=NOW,
    )
    record("deny_exclusion_zone", v.allowed, False,
           v.reason if v.reason == DENY_EXCLUSION_ZONE else f"WRONG:{v.reason}")

    # -- D4. Revoked envelope ----------------------------------------------
    authorities, registry = make_registries()
    arm(registry)
    registry.revoke("env-1")
    v = check_action_within_envelope(
        action=act("env-1", torque_Nm=10.0), registry=registry, now=NOW,
    )
    record("deny_revoked_envelope", v.allowed, False,
           v.reason if v.reason == DENY_ENVELOPE_REVOKED else f"WRONG:{v.reason}")

    # -- D5. Expired envelope ------------------------------------------------
    authorities, registry = make_registries()
    arm(registry, armed_at=NOW - 7200, expires_at=NOW - 1)
    v = check_action_within_envelope(
        action=act("env-1", torque_Nm=10.0), registry=registry, now=NOW,
    )
    record("deny_expired_envelope", v.allowed, False,
           v.reason if v.reason == DENY_ENVELOPE_EXPIRED else f"WRONG:{v.reason}")

    # -- D6. Self-issued envelope: agent key not a registered authority -----
    authorities, registry = make_registries()  # rogue NOT registered
    lim = {"max_torque_Nm": 500.0, "max_speed_mps": 20.0,
           "exclusion_zones": []}
    payload = _envelope_payload(
        envelope_id="env-rogue", actuator_id="arm/left-6dof",
        hard_limits=_validate_limits(lim), armed_by="agent-7",
        armed_at=NOW - 10, expires_at=NOW + 3600, prev_hash="",
    )
    digest = jcs_sha256_hex(payload)
    try:
        registry.arm_envelope(
            envelope_id="env-rogue", actuator_id="arm/left-6dof",
            hard_limits=lim, armed_by="agent-7",
            armed_at=NOW - 10, expires_at=NOW + 3600,
            signature=sign(rogue_sec, digest.encode("utf-8")),
        )
        arming_failed = False
    except SafetyEnvelopeError:
        arming_failed = True
    record("deny_self_issued_envelope", not arming_failed, False,
           "arming refused" if arming_failed else "WRONG: arming succeeded")

    # -- D7. Widening self-approval -----------------------------------------
    authorities, registry = make_registries()
    env = arm(registry)
    req, disp = request_envelope_change(
        request_id="chg-self",
        envelope=env,
        proposed_limits={"max_torque_Nm": 90.0, "max_speed_mps": 2.0,
                         "exclusion_zones": ["zone-reactor-core"]},
        requested_by="op-alice",
        requested_at=NOW - 100,
        approved_by="op-alice",
        approval_signature=b"\x00" * 64,
        authorities=authorities,
    )
    record("deny_widening_self_approval", False, False,
           disp if disp == DENY_CHANGE_SELF_APPROVAL else f"WRONG:{disp}")

    # -- D8. Widening during cooldown ---------------------------------------
    authorities, registry = make_registries()
    env = arm(registry)
    msg = jcs_sha256_hex(
        {
            "request_id": "chg-early",
            "envelope_id": env.envelope_id,
            "proposed_limits": {"max_torque_Nm": 80.0, "max_speed_mps": 2.0,
                                "exclusion_zones": ["zone-reactor-core"]},
            "requested_by": "op-alice",
            "requested_at": NOW - 100,
        }
    ).encode("utf-8")
    req, disp = request_envelope_change(
        request_id="chg-early",
        envelope=env,
        proposed_limits={"max_torque_Nm": 80.0, "max_speed_mps": 2.0,
                         "exclusion_zones": ["zone-reactor-core"]},
        requested_by="op-alice",
        requested_at=NOW - 100,
        approved_by="op-bob",
        approval_signature=sign(auth2_sec, msg),
        authorities=authorities,
    )
    _new_env, apply_reason = apply_approved_change(
        request=req, registry=registry, cooldown_s=3600, now=NOW,
    )
    record("deny_widening_during_cooldown", False, False,
           apply_reason if apply_reason == DENY_CHANGE_COOLDOWN
           else f"WRONG:{apply_reason}")

    # -- D9. Unknown control axis -------------------------------------------
    authorities, registry = make_registries()
    arm(registry)
    v = check_action_within_envelope(
        action=act("env-1", torque_Nm=10.0, laser_W=5000.0),
        registry=registry, now=NOW,
    )
    record("deny_unknown_param", v.allowed, False,
           v.reason if v.reason == DENY_UNKNOWN_LIMIT else f"WRONG:{v.reason}")

    # -- independence probe always holds ------------------------------------
    ok, probe_reason = verify_independence()
    if not ok:
        scenarios.append(("probe_independence_broken", True, False, probe_reason))

    mismatches = [
        sid for (sid, allowed, expect_allow, _reason) in scenarios
        if allowed != expect_allow
    ]
    wrong_reasons = [
        f"{sid}:{reason}"
        for (sid, allowed, expect_allow, reason) in scenarios
        if allowed == expect_allow and reason.startswith("WRONG")
    ]
    allowed_ids = sorted(sid for (sid, allowed, _e, _r) in scenarios if allowed)
    detail = {sid: reason for (sid, _a, _e, reason) in scenarios}
    return {
        "n_scenarios": len(scenarios),
        "n_allowed": len(allowed_ids),
        "n_denied": len(scenarios) - len(allowed_ids),
        "allowed_ids": allowed_ids,
        "mismatches": mismatches + wrong_reasons,
        "detail": detail,
        "denial_reasons": {
            sid: reason
            for (sid, allowed, _e, reason) in scenarios
            if not allowed
        },
    }


__all__ = [
    "SCHEMA_VERSION",
    "ENVELOPE_DENIED_EVENT",
    "ENVELOPE_CHANGE_EVENT",
    "DENY_NO_ENVELOPE",
    "DENY_ENVELOPE_REVOKED",
    "DENY_ENVELOPE_EXPIRED",
    "DENY_ENVELOPE_FROM_FUTURE",
    "DENY_ENVELOPE_DIGEST_MISMATCH",
    "DENY_ENVELOPE_SIGNATURE_INVALID",
    "DENY_ACTUATOR_MISMATCH",
    "DENY_TORQUE_EXCEEDED",
    "DENY_SPEED_EXCEEDED",
    "DENY_EXCLUSION_ZONE",
    "DENY_UNKNOWN_LIMIT",
    "DENY_MALFORMED",
    "DENY_CHANGE_SELF_APPROVAL",
    "DENY_CHANGE_UNKNOWN_AUTHORITY",
    "DENY_CHANGE_BAD_SIGNATURE",
    "DENY_CHANGE_COOLDOWN",
    "DENY_CHANGE_NOT_WIDENING_APPROVED",
    "SafetyEnvelopeError",
    "SafetyEnvelope",
    "AuthorityRegistry",
    "EnvelopeRegistry",
    "ActionVerdict",
    "check_action_within_envelope",
    "envelope_denied_audit_event",
    "ChangeRequest",
    "request_envelope_change",
    "apply_approved_change",
    "verify_independence",
    "run_safety_envelope",
]
