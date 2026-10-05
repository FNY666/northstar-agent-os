"""Grid control envelopes (one-hundred-twenty-eighth batch).

Absorbs the 2026 AI-energy research thread (mechanism ideas only,
honestly scoped):

* **Dispatch responsibility stays human.** Amprion (German TSO) runs
  AI for frequency-reserve forecasting, but the dispatch decision
  stays a human responsibility (``"Wir sind noch lange nicht beim
  Replace"``). A grid dispatch AI acts inside a pre-approved control
  envelope; anything outside it is human-on-the-loop, never silent
  autonomy.
* **EU AI.grids.** A 48-member consortium builds sovereign
  foundation models for grid operations (generation forecasting,
  congestion management) — classification discipline matters:
  safety-component AI is high-risk by default (EU AI Act Annex III);
  a system that claims to be "just optimization" must declare its
  boundary, or it is unverifiable (the borderline-underreporting
  lesson).
* **Forecast -> dispatch must be bound.** Shenzhen "灵曦" links AI
  load forecasting to virtual-power-plant dispatch (5.1 GW
  connected, 1.4 GW real-time adjustable — vendor numbers,
  unaudited). A dispatch action must reference the forecast digest
  it acted on; an unbound dispatch is unverifiable.
* **Compute scheduling is a cyber-physical attack surface.**
  Bit2Watt (Zhejiang preprint): malicious GPU training loads can
  resonate with grid critical frequencies and physically damage
  infrastructure. High-fluctuation workloads get a power-resonance
  screen before grid connection; failures quarantine.
* **Flexible curtailment contracts.** Ceres: US datacenters are 4-5%
  of national power; grids need contracts letting them curtail
  datacenter load in emergencies. Workloads carry curtailment
  contracts bound to authority-signed curtailment orders (115th
  batch); refusing an active order denies.
* **Nuclear AI is advisory-only by default.** Google's €13B Finland
  AI+nuclear deal is unverified; what is verifiable is the
  discipline: nuclear-plant AI defaults to advisory mode, and
  control-path authority is never implied — it needs explicit
  declaration plus a separate authorization.
* **Blackouts get an evidence chain.** Blackout incidents feed the
  113th-batch incident clock with a bound timeline; a blackout
  filing without a timeline is unreported, and a missed clock is
  recorded, not repaired.

Northstar mapping:

* ``SafetyClassRegistry.safety_component_gate()`` — AI used in
  critical-infrastructure safety components classifies high-risk by
  default (Annex III); a system claiming
  ``non_safety_optimization`` must bind a declared boundary digest —
  undeclared → ``grid:unverifiable_safety_class``.
* ``ControlEnvelopeRegistry`` — authority-signed control-room
  envelopes bind ``(envelope_id, operator_id, scope_kinds,
  autonomy_modes, issued_by, expires_at)``; dispatch inside scope
  allows; outside scope denies ``grid:out_of_envelope`` (or routes
  human-on-the-loop per the declared mode); widening needs a
  *different* authority's signature — the requester can never widen
  their own envelope (``grid:self_widening``).
* ``ForecastRegistry`` — forecast receipts bind
  ``(forecast_id, forecast_digest, horizon_s, issued_at, issuer)``;
  dispatch actions must reference a registered, fresh forecast —
  unbound → ``grid:unbound_dispatch``, stale → ``grid:stale_forecast``.
* ``WorkloadPowerScreen`` — compute workloads declare
  ``(workload_id, peak_mw, fluctuation_class)``; high-fluctuation
  unscreened workloads quarantine with
  ``grid:power_resonance_risk`` (Bit2Watt).
* ``CurtailmentContractRegistry`` — contracts bind a workload to a
  curtailment authority and a pinned cap rule; refusing an active
  authority-signed order denies ``grid:curtailment_refusal``.
* ``NuclearGate.check_action()`` — advisory mode allows; control
  mode without an explicit, authority-signed control authorization
  denies ``grid:nuclear_control`` (never implied).
* ``BlackoutRegistry.file_blackout()`` — hash-chained filings bind
  ``(incident_id, system_id, timeline_digest, detected_at,
  reported_at)``; missing timeline → ``grid:unreported_blackout``;
  a missed 2-day clock is recorded (``clock_missed=True``) and the
  verdict refuses (``grid:blackout_clock_missed``); duplicate
  incident ids are idempotent-denied.

Honest boundary: this module enforces *declared control
discipline* — classification labels, envelope scopes, forecast
bindings, screens, and contracts are receipts the operator declares
and the runtime checks. It does not replace grid engineering: it
cannot measure a frequency, certify a safety component, or prove a
workload's real power draw. What it guarantees: no silent
autonomy outside the envelope, no unbound dispatch, no unscreened
high-fluctuation grid connection, no control-path authority that
was not explicitly granted, and blackouts that are filed with a
timeline on a machine-enforced clock.

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing, constant-time digest
comparisons.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> bytes:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()

from ed25519 import public_key as ed_public_key  # noqa: F401  (re-export for builders)
from ed25519 import sign as ed_sign
from ed25519 import verify as ed_verify

GRID_SCHEMA_VERSION = "northstar.grid-agents.v1"

#: Closed vocabulary of system safety classes.
SAFETY_CLASSES: tuple[str, ...] = ("safety_component", "non_safety_optimization")

#: Closed vocabulary of workload fluctuation classes.
FLUCTUATION_CLASSES: tuple[str, ...] = (
    "stable",
    "screened_fluctuating",
    "unscreened",
)

#: Closed vocabulary of control modes.
CONTROL_MODES: tuple[str, ...] = ("advisory", "control")

#: Closed vocabulary of autonomy modes for control-room envelopes.
AUTONOMY_MODES: tuple[str, ...] = ("autonomous", "human_on_the_loop")

#: Blackout reporting clock: 2 days (113th-batch critical clock).
BLACKOUT_CLOCK_S = 2 * 86_400

#: Genesis marker for hash chains.
_GENESIS = "genesis"
_HEX64_LENGTH = 64
_ED25519_SIG_LENGTH = 64

#: Denial reason codes. All start with ``grid:`` for audit filtering.
DENY_UNVERIFIABLE_SAFETY_CLASS = "grid:unverifiable_safety_class"
DENY_SAFETY_COMPONENT_UNREGISTERED = "grid:safety_component_unregistered"
DENY_OUT_OF_ENVELOPE = "grid:out_of_envelope"
DENY_SELF_WIDENING = "grid:self_widening"
DENY_ENVELOPE_EXPIRED = "grid:envelope_expired"
DENY_ENVELOPE_REVOKED = "grid:envelope_revoked"
DENY_ENVELOPE_BAD_SIGNATURE = "grid:envelope_bad_signature"
DENY_UNBOUND_DISPATCH = "grid:unbound_dispatch"
DENY_STALE_FORECAST = "grid:stale_forecast"
DENY_POWER_RESONANCE_RISK = "grid:power_resonance_risk"
DENY_CURTAILMENT_REFUSAL = "grid:curtailment_refusal"
DENY_NUCLEAR_CONTROL = "grid:nuclear_control"
DENY_UNREPORTED_BLACKOUT = "grid:unreported_blackout"
DENY_BLACKOUT_CLOCK_MISSED = "grid:blackout_clock_missed"
DENY_BLACKOUT_DUPLICATE = "grid:blackout_duplicate"
DENY_MALFORMED = "grid:malformed"

#: Classifications (share the 87th-batch binary vocabulary).
CLASS_AUTHORITATIVE = "AUTHORITATIVE"
CLASS_NON_AUTHORITATIVE = "NON_AUTHORITATIVE"

#: Audit event names.
GRID_SAFETY_CLASS_EVENT = "grid.safety_class"
GRID_ENVELOPE_EVENT = "grid.envelope_check"
GRID_FORECAST_EVENT = "grid.forecast_bound"
GRID_WORKLOAD_EVENT = "grid.workload_screened"
GRID_CURTAILMENT_EVENT = "grid.curtailment_check"
GRID_NUCLEAR_EVENT = "grid.nuclear_check"
GRID_BLACKOUT_EVENT = "grid.blackout_filed"


class GridAgentsError(ValueError):
    """Malformed grid input (construction-time boundary).

    Raised for structural problems: unknown classes, bad digests,
    non-integer timestamps. Verification *outcomes* (out of
    envelope, unbound dispatch, refused curtailment, missed blackout
    clock) are verdicts, not exceptions.
    """


def _is_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != _HEX64_LENGTH:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex64(value):
        raise GridAgentsError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise GridAgentsError(f"{field_name} must be a non-empty string")
    return value


def _check_unix(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GridAgentsError(f"{field_name} must be a non-negative int (unix time)")
    return value


def _check_pos_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise GridAgentsError(f"{field_name} must be a positive int")
    return value


def _check_sig(value: Any, field_name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != _ED25519_SIG_LENGTH:
        raise GridAgentsError(f"{field_name} must be 64 bytes")
    return bytes(value)


def grid_audit_event(code: str, detail: str) -> dict[str, Any]:
    """Shape an audit event for ``audit_chain.chain_record``."""
    return {"event": "grid.audit", "code": code, "detail": detail}


@dataclass(frozen=True)
class GridVerdict:
    """Outcome of one grid-agents check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _allow(detail: str, digest: str = "") -> GridVerdict:
    return GridVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=digest,
    )


def _deny(code: str, detail: str) -> GridVerdict:
    return GridVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


# ---------------------------------------------------------------------------
# AuthorityRegistry: who may arm envelopes, screens, and contracts
# ---------------------------------------------------------------------------


class AuthorityRegistry:
    """Registered human authorities (authority_id -> Ed25519 public key).

    The agent is never in this registry: there is no code path that
    adds an agent id, and issuance refuses any ``issued_by`` that is
    not registered. Registration is a host-side operation outside
    this module.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register(self, authority_id: str, public_key: bytes) -> None:
        _check_str(authority_id, "authority_id")
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise GridAgentsError("public_key must be 32 bytes")
        self._keys[authority_id] = bytes(public_key)

    def public_key_for(self, authority_id: str) -> bytes | None:
        return self._keys.get(authority_id)


# ---------------------------------------------------------------------------
# Safety-class gate (EU AI Act Annex III discipline)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SafetyClassDeclaration:
    """A declared safety class for an AI system touching the grid.

    ``safety_class`` is ``safety_component`` (high-risk by default)
    or ``non_safety_optimization``. The latter must bind
    ``declared_boundary_digest`` — the digest of the document that
    states exactly what the system does *not* touch. A claim of
    "just optimization" without a pinned boundary is unverifiable:
    borderline systems underreport their class.
    """

    system_id: str
    safety_class: str
    declared_boundary_digest: str | None
    declared_at: int
    registration_digest: str | None  # safety_component registration receipt
    declaration_digest: str


def _declaration_payload(
    *,
    system_id: str,
    safety_class: str,
    declared_boundary_digest: str | None,
    declared_at: int,
    registration_digest: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": GRID_SCHEMA_VERSION,
        "system_id": system_id,
        "safety_class": safety_class,
        "declared_boundary_digest": declared_boundary_digest,
        "declared_at": declared_at,
        "registration_digest": registration_digest,
    }


class SafetyClassRegistry:
    """Declares and gates the safety class of grid AI systems."""

    def __init__(self) -> None:
        self._declared: dict[str, SafetyClassDeclaration] = {}

    def declare(
        self,
        *,
        system_id: str,
        safety_class: str,
        declared_boundary_digest: str | None = None,
        registration_digest: str | None = None,
        declared_at: int,
    ) -> SafetyClassDeclaration:
        """Declare a system's safety class. No default class: the
        operator must say it out loud, and optimization claims must
        pin their boundary."""
        _check_str(system_id, "system_id")
        if safety_class not in SAFETY_CLASSES:
            raise GridAgentsError(f"unknown safety_class {safety_class!r}")
        _check_unix(declared_at, "declared_at")
        boundary: str | None = None
        if declared_boundary_digest is not None:
            boundary = _check_hex64(declared_boundary_digest,
                                    "declared_boundary_digest")
        registration: str | None = None
        if registration_digest is not None:
            registration = _check_hex64(registration_digest,
                                        "registration_digest")
        digest = jcs_sha256_hex(_declaration_payload(
            system_id=system_id,
            safety_class=safety_class,
            declared_boundary_digest=boundary,
            declared_at=declared_at,
            registration_digest=registration,
        ))
        decl = SafetyClassDeclaration(
            system_id=system_id,
            safety_class=safety_class,
            declared_boundary_digest=boundary,
            declared_at=declared_at,
            registration_digest=registration,
            declaration_digest=digest,
        )
        self._declared[system_id] = decl
        return decl

    def safety_component_gate(self, system_id: str) -> GridVerdict:
        """Fail-closed classification gate (Annex III discipline).

        Undeclared systems → ``grid:unverifiable_safety_class`` (no
        silent default). ``safety_component`` without a registration
        receipt → denied. ``non_safety_optimization`` without a
        pinned boundary → denied. Declared-and-pinned systems allow
        with their class as the receipt.
        """
        decl = self._declared.get(system_id)
        if decl is None:
            return _deny(
                DENY_UNVERIFIABLE_SAFETY_CLASS,
                f"system {system_id!r} has no declared safety class",
            )
        if decl.safety_class == "safety_component":
            if decl.registration_digest is None:
                return _deny(
                    DENY_SAFETY_COMPONENT_UNREGISTERED,
                    f"safety component {system_id!r} has no registration receipt",
                )
            return _allow(
                f"safety_component {system_id!r} registered (high-risk)",
                decl.declaration_digest,
            )
        if decl.declared_boundary_digest is None:
            return _deny(
                DENY_UNVERIFIABLE_SAFETY_CLASS,
                f"non_safety_optimization {system_id!r} declares no boundary",
            )
        return _allow(
            f"non_safety_optimization {system_id!r} within declared boundary",
            decl.declaration_digest,
        )


# ---------------------------------------------------------------------------
# Control-room envelopes (Amprion / IJETRM discipline)
# ---------------------------------------------------------------------------


def _envelope_payload(
    *,
    envelope_id: str,
    operator_id: str,
    scope_kinds: tuple[str, ...],
    autonomy_modes: tuple[str, ...],
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": GRID_SCHEMA_VERSION,
        "envelope_id": envelope_id,
        "operator_id": operator_id,
        "scope_kinds": list(scope_kinds),
        "autonomy_modes": list(autonomy_modes),
        "issued_by": issued_by,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class ControlEnvelope:
    """A pre-approved control-room envelope for a grid dispatch AI.

    ``scope_kinds`` is the closed list of dispatch action kinds the
    envelope covers (e.g. ``frequency_reserve_forecast``,
    ``vpp_dispatch``); ``autonomy_modes`` pins which modes are
    permitted per kind is left to :meth:`ControlEnvelopeRegistry`
    checks — the envelope only binds the *vocabulary* it was
    approved for. Only a registered human authority may issue; the
    agent is the subject, never the issuer.
    """

    envelope_id: str
    operator_id: str
    scope_kinds: tuple[str, ...]
    autonomy_modes: tuple[str, ...]
    issued_by: str
    issued_at: int
    expires_at: int
    envelope_digest: str
    signature: bytes
    prev_hash: str = ""
    revoked: bool = False


class ControlEnvelopeRegistry:
    """Issues and checks control-room envelopes."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._envelopes: dict[str, ControlEnvelope] = {}
        self._prev_hash = _GENESIS

    def issue_envelope(
        self,
        *,
        envelope_id: str,
        operator_id: str,
        scope_kinds: tuple[str, ...],
        autonomy_modes: tuple[str, ...],
        issued_by: str,
        issued_at: int,
        expires_at: int,
        signature: bytes,
    ) -> ControlEnvelope:
        _check_str(envelope_id, "envelope_id")
        _check_str(operator_id, "operator_id")
        if not scope_kinds or not all(isinstance(k, str) and k for k in scope_kinds):
            raise GridAgentsError("scope_kinds must be a non-empty tuple of str")
        if not autonomy_modes or any(m not in AUTONOMY_MODES for m in autonomy_modes):
            raise GridAgentsError(
                f"autonomy_modes must be a non-empty tuple of {AUTONOMY_MODES}"
            )
        _check_str(issued_by, "issued_by")
        _check_unix(issued_at, "issued_at")
        _check_unix(expires_at, "expires_at")
        if expires_at <= issued_at:
            raise GridAgentsError("expires_at must be after issued_at")
        _check_sig(signature, "signature")
        pubkey = self._authorities.public_key_for(issued_by)
        if pubkey is None:
            raise GridAgentsError(f"issued_by {issued_by!r} is not a registered authority")
        scopes = tuple(sorted(set(scope_kinds)))
        modes = tuple(sorted(set(autonomy_modes)))
        digest = jcs_sha256_hex(_envelope_payload(
            envelope_id=envelope_id,
            operator_id=operator_id,
            scope_kinds=scopes,
            autonomy_modes=modes,
            issued_by=issued_by,
            issued_at=issued_at,
            expires_at=expires_at,
            prev_hash=self._prev_hash,
        ))
        if not ed_verify(pubkey, digest.encode("utf-8"), bytes(signature)):
            raise GridAgentsError("authority signature does not verify")
        env = ControlEnvelope(
            envelope_id=envelope_id,
            operator_id=operator_id,
            scope_kinds=scopes,
            autonomy_modes=modes,
            issued_by=issued_by,
            issued_at=issued_at,
            expires_at=expires_at,
            envelope_digest=digest,
            signature=bytes(signature),
            prev_hash=self._prev_hash,
        )
        self._envelopes[envelope_id] = env
        self._prev_hash = digest
        return env

    def revoke(self, envelope_id: str) -> None:
        """Revocation is terminal: a revoked envelope never un-revokes."""
        env = self._envelopes.get(envelope_id)
        if env is None:
            raise GridAgentsError(f"unknown envelope {envelope_id!r}")
        self._envelopes[envelope_id] = ControlEnvelope(
            **{**env.__dict__, "revoked": True}
        )

    def request_widen(
        self,
        *,
        envelope_id: str,
        new_scope_kinds: tuple[str, ...],
        requested_by: str,
        approved_by: str,
        signature: bytes,
        issued_at: int,
        expires_at: int,
    ) -> ControlEnvelope:
        """Widen an envelope. The approver must be a *different*
        registered authority than the requester — the requester can
        never approve their own widening (``grid:self_widening`` is a
        verdict, not an exception, because this is a policy check on
        a well-formed request)."""
        env = self._envelopes.get(envelope_id)
        if env is None:
            raise GridAgentsError(f"unknown envelope {envelope_id!r}")
        if requested_by == approved_by:
            raise GridAgentsError(
                "requester can never approve their own widening"
            )
        scopes = tuple(sorted(set(env.scope_kinds) | set(new_scope_kinds)))
        return self.issue_envelope(
            envelope_id=envelope_id,
            operator_id=env.operator_id,
            scope_kinds=scopes,
            autonomy_modes=env.autonomy_modes,
            issued_by=approved_by,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature,
        )

    def check_dispatch(
        self,
        *,
        envelope_id: str,
        action_kind: str,
        mode: str,
        now: int,
    ) -> GridVerdict:
        """Check one dispatch action against the envelope.

        Inside scope with a permitted mode → allowed (autonomous
        inside the envelope). Inside scope but the mode is not
        permitted → ``human_on_the_loop`` routing required
        (``grid:out_of_envelope`` — the mode is part of the
        envelope). Outside scope → denied. Expired or revoked
        envelopes fail closed to no dispatch at all.
        """
        env = self._envelopes.get(envelope_id)
        if env is None:
            return _deny(DENY_OUT_OF_ENVELOPE,
                         f"unknown envelope {envelope_id!r}")
        _check_unix(now, "now")
        if env.revoked:
            return _deny(DENY_ENVELOPE_REVOKED,
                         f"envelope {envelope_id!r} is revoked")
        if not (env.issued_at <= now < env.expires_at):
            return _deny(DENY_ENVELOPE_EXPIRED,
                         f"envelope {envelope_id!r} is not fresh")
        if action_kind not in env.scope_kinds:
            return _deny(
                DENY_OUT_OF_ENVELOPE,
                f"action kind {action_kind!r} outside envelope scope",
            )
        if mode not in env.autonomy_modes:
            return _deny(
                DENY_OUT_OF_ENVELOPE,
                f"mode {mode!r} not permitted by envelope {envelope_id!r}; "
                "route human-on-the-loop",
            )
        return _allow(
            f"dispatch {action_kind!r} in {mode!r} inside envelope {envelope_id!r}",
            env.envelope_digest,
        )


# ---------------------------------------------------------------------------
# Forecast -> dispatch binding (深圳灵曦 discipline)
# ---------------------------------------------------------------------------


def _forecast_payload(
    *,
    forecast_id: str,
    forecast_digest: str,
    horizon_s: int,
    issued_at: int,
    issuer: str,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": GRID_SCHEMA_VERSION,
        "forecast_id": forecast_id,
        "forecast_digest": forecast_digest,
        "horizon_s": horizon_s,
        "issued_at": issued_at,
        "issuer": issuer,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class ForecastReceipt:
    forecast_id: str
    forecast_digest: str
    horizon_s: int
    issued_at: int
    issuer: str
    receipt_digest: str
    prev_hash: str = ""


class ForecastRegistry:
    """Forecast receipts that dispatch actions must bind."""

    def __init__(self) -> None:
        self._forecasts: dict[str, ForecastReceipt] = {}
        self._prev_hash = _GENESIS

    def register_forecast(
        self,
        *,
        forecast_id: str,
        forecast_digest: str,
        horizon_s: int,
        issued_at: int,
        issuer: str,
    ) -> ForecastReceipt:
        _check_str(forecast_id, "forecast_id")
        _check_hex64(forecast_digest, "forecast_digest")
        _check_pos_int(horizon_s, "horizon_s")
        _check_unix(issued_at, "issued_at")
        _check_str(issuer, "issuer")
        digest = jcs_sha256_hex(_forecast_payload(
            forecast_id=forecast_id,
            forecast_digest=forecast_digest,
            horizon_s=horizon_s,
            issued_at=issued_at,
            issuer=issuer,
            prev_hash=self._prev_hash,
        ))
        receipt = ForecastReceipt(
            forecast_id=forecast_id,
            forecast_digest=forecast_digest,
            horizon_s=horizon_s,
            issued_at=issued_at,
            issuer=issuer,
            receipt_digest=digest,
            prev_hash=self._prev_hash,
        )
        self._forecasts[forecast_id] = receipt
        self._prev_hash = digest
        return receipt

    def check_dispatch_binding(
        self,
        *,
        forecast_id: str | None,
        now: int,
    ) -> GridVerdict:
        """A dispatch action must reference a registered, fresh
        forecast. Unbound → ``grid:unbound_dispatch``; stale →
        ``grid:stale_forecast``. Acting on a forecast you cannot
        name is acting on nothing."""
        _check_unix(now, "now")
        if not forecast_id:
            return _deny(
                DENY_UNBOUND_DISPATCH,
                "dispatch references no forecast",
            )
        receipt = self._forecasts.get(forecast_id)
        if receipt is None:
            return _deny(
                DENY_UNBOUND_DISPATCH,
                f"forecast {forecast_id!r} is not registered",
            )
        if now >= receipt.issued_at + receipt.horizon_s:
            return _deny(
                DENY_STALE_FORECAST,
                f"forecast {forecast_id!r} is past its horizon",
            )
        return _allow(
            f"dispatch bound to forecast {forecast_id!r}",
            receipt.receipt_digest,
        )


# ---------------------------------------------------------------------------
# Workload power-resonance screen (Bit2Watt discipline)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkloadScreenReceipt:
    workload_id: str
    peak_mw: int
    fluctuation_class: str
    screened: bool
    screen_digest: str


class WorkloadPowerScreen:
    """Screens compute workloads before grid connection.

    ``unscreened`` workloads with fluctuating draw quarantine with
    ``grid:power_resonance_risk`` (Bit2Watt: resonant power
    fluctuations can physically damage infrastructure). ``stable``
    and ``screened_fluctuating`` workloads connect with a pinned
    screen receipt. The screen is a declared tripwire, not a
    measurement of the real power draw.
    """

    def __init__(self) -> None:
        self._screens: dict[str, WorkloadScreenReceipt] = {}

    def screen_workload(
        self,
        *,
        workload_id: str,
        peak_mw: int,
        fluctuation_class: str,
    ) -> GridVerdict:
        _check_str(workload_id, "workload_id")
        _check_pos_int(peak_mw, "peak_mw")
        if fluctuation_class not in FLUCTUATION_CLASSES:
            raise GridAgentsError(
                f"unknown fluctuation_class {fluctuation_class!r}"
            )
        digest = jcs_sha256_hex({
            "schema_version": GRID_SCHEMA_VERSION,
            "workload_id": workload_id,
            "peak_mw": peak_mw,
            "fluctuation_class": fluctuation_class,
        })
        if fluctuation_class == "unscreened":
            receipt = WorkloadScreenReceipt(
                workload_id=workload_id,
                peak_mw=peak_mw,
                fluctuation_class=fluctuation_class,
                screened=False,
                screen_digest=digest,
            )
            self._screens[workload_id] = receipt
            return _deny(
                DENY_POWER_RESONANCE_RISK,
                f"workload {workload_id!r} is unscreened; quarantined",
            )
        receipt = WorkloadScreenReceipt(
            workload_id=workload_id,
            peak_mw=peak_mw,
            fluctuation_class=fluctuation_class,
            screened=True,
            screen_digest=digest,
        )
        self._screens[workload_id] = receipt
        return _allow(
            f"workload {workload_id!r} screened ({fluctuation_class})",
            digest,
        )


# ---------------------------------------------------------------------------
# Emergency curtailment contracts (Ceres discipline, 115th batch)
# ---------------------------------------------------------------------------


def _contract_payload(
    *,
    contract_id: str,
    workload_id: str,
    curtailment_authority_id: str,
    cap_rule_digest: str,
    issued_by: str,
    issued_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": GRID_SCHEMA_VERSION,
        "contract_id": contract_id,
        "workload_id": workload_id,
        "curtailment_authority_id": curtailment_authority_id,
        "cap_rule_digest": cap_rule_digest,
        "issued_by": issued_by,
        "issued_at": issued_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class CurtailmentContract:
    contract_id: str
    workload_id: str
    curtailment_authority_id: str
    cap_rule_digest: str
    issued_by: str
    issued_at: int
    contract_digest: str
    signature: bytes
    prev_hash: str = ""


@dataclass(frozen=True)
class CurtailmentOrder:
    """An authority-signed grid-emergency curtailment order (the
    115th batch's ``CurtailmentReceipt`` semantics, re-bound here so
    this module stays importable standalone)."""

    order_id: str
    grid_region: str
    start_unix: int
    end_unix: int
    issued_by: str
    issued_at: int
    order_digest: str
    signature: bytes

    def active_at(self, unix: int) -> bool:
        return self.start_unix <= unix < self.end_unix


def _order_payload(
    *,
    order_id: str,
    grid_region: str,
    start_unix: int,
    end_unix: int,
    issued_by: str,
    issued_at: int,
) -> dict[str, Any]:
    return {
        "schema_version": GRID_SCHEMA_VERSION,
        "order_id": order_id,
        "grid_region": grid_region,
        "start_unix": start_unix,
        "end_unix": end_unix,
        "issued_by": issued_by,
        "issued_at": issued_at,
    }


def issue_curtailment_order(
    registry: AuthorityRegistry,
    *,
    order_id: str,
    grid_region: str,
    start_unix: int,
    end_unix: int,
    issued_by: str,
    issued_at: int,
    signature: bytes,
) -> CurtailmentOrder:
    """Issue a grid-emergency curtailment order. Only a registered
    authority can order the grid to shed load."""
    if not isinstance(registry, AuthorityRegistry):
        raise GridAgentsError("registry must be an AuthorityRegistry")
    _check_str(order_id, "order_id")
    _check_str(grid_region, "grid_region")
    _check_unix(start_unix, "start_unix")
    _check_unix(end_unix, "end_unix")
    if end_unix <= start_unix:
        raise GridAgentsError("end_unix must be after start_unix")
    _check_str(issued_by, "issued_by")
    _check_unix(issued_at, "issued_at")
    _check_sig(signature, "signature")
    pubkey = registry.public_key_for(issued_by)
    if pubkey is None:
        raise GridAgentsError(f"issued_by {issued_by!r} is not a registered authority")
    digest = jcs_sha256_hex(_order_payload(
        order_id=order_id,
        grid_region=grid_region,
        start_unix=start_unix,
        end_unix=end_unix,
        issued_by=issued_by,
        issued_at=issued_at,
    ))
    if not ed_verify(pubkey, digest.encode("utf-8"), bytes(signature)):
        raise GridAgentsError("authority signature does not verify")
    return CurtailmentOrder(
        order_id=order_id,
        grid_region=grid_region,
        start_unix=start_unix,
        end_unix=end_unix,
        issued_by=issued_by,
        issued_at=issued_at,
        order_digest=digest,
        signature=bytes(signature),
    )


class CurtailmentContractRegistry:
    """Binds workloads to curtailment authorities."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._contracts: dict[str, CurtailmentContract] = {}
        self._prev_hash = _GENESIS

    def issue_contract(
        self,
        *,
        contract_id: str,
        workload_id: str,
        curtailment_authority_id: str,
        cap_rule_digest: str,
        issued_by: str,
        issued_at: int,
        signature: bytes,
    ) -> CurtailmentContract:
        """Issue a flexible curtailment contract. The contract binds
        the workload to a curtailment authority and a pinned cap
        rule — the capped party cannot move the rule."""
        _check_str(contract_id, "contract_id")
        _check_str(workload_id, "workload_id")
        _check_str(curtailment_authority_id, "curtailment_authority_id")
        _check_hex64(cap_rule_digest, "cap_rule_digest")
        _check_str(issued_by, "issued_by")
        _check_unix(issued_at, "issued_at")
        _check_sig(signature, "signature")
        if self._authorities.public_key_for(curtailment_authority_id) is None:
            raise GridAgentsError(
                f"curtailment authority {curtailment_authority_id!r} is not registered"
            )
        pubkey = self._authorities.public_key_for(issued_by)
        if pubkey is None:
            raise GridAgentsError(f"issued_by {issued_by!r} is not a registered authority")
        digest = jcs_sha256_hex(_contract_payload(
            contract_id=contract_id,
            workload_id=workload_id,
            curtailment_authority_id=curtailment_authority_id,
            cap_rule_digest=cap_rule_digest,
            issued_by=issued_by,
            issued_at=issued_at,
            prev_hash=self._prev_hash,
        ))
        if not ed_verify(pubkey, digest.encode("utf-8"), bytes(signature)):
            raise GridAgentsError("authority signature does not verify")
        contract = CurtailmentContract(
            contract_id=contract_id,
            workload_id=workload_id,
            curtailment_authority_id=curtailment_authority_id,
            cap_rule_digest=cap_rule_digest,
            issued_by=issued_by,
            issued_at=issued_at,
            contract_digest=digest,
            signature=bytes(signature),
            prev_hash=self._prev_hash,
        )
        self._contracts[workload_id] = contract
        self._prev_hash = digest
        return contract

    def check_curtailment(
        self,
        *,
        workload_id: str,
        order: CurtailmentOrder,
        complied: bool,
        now: int,
    ) -> GridVerdict:
        """Check a workload against an active curtailment order.

        No contract → the workload has no flexible-curtailment
        standing (``grid:curtailment_refusal`` — a datacenter that
        cannot be curtailed is not grid-compatible in an
        emergency). Active order + refusal → denied. Active order +
        compliance → allowed under the pinned cap rule.
        """
        _check_unix(now, "now")
        contract = self._contracts.get(workload_id)
        if contract is None:
            return _deny(
                DENY_CURTAILMENT_REFUSAL,
                f"workload {workload_id!r} has no curtailment contract",
            )
        if not order.active_at(now):
            return _allow(
                f"no active curtailment for workload {workload_id!r}",
                contract.contract_digest,
            )
        if not complied:
            return _deny(
                DENY_CURTAILMENT_REFUSAL,
                f"workload {workload_id!r} refused active order {order.order_id!r}",
            )
        return _allow(
            f"workload {workload_id!r} curtailed under order {order.order_id!r}",
            contract.contract_digest,
        )


# ---------------------------------------------------------------------------
# Nuclear advisory gate
# ---------------------------------------------------------------------------


def _nuclear_auth_payload(
    *,
    system_id: str,
    control_scope_digest: str,
    granted_by: str,
    granted_at: int,
    expires_at: int,
) -> dict[str, Any]:
    return {
        "schema_version": GRID_SCHEMA_VERSION,
        "system_id": system_id,
        "control_scope_digest": control_scope_digest,
        "granted_by": granted_by,
        "granted_at": granted_at,
        "expires_at": expires_at,
    }


class NuclearGate:
    """Nuclear-plant AI defaults to advisory-only.

    Control-path authority is never implied: ``control`` mode needs
    an explicit, authority-signed authorization receipt binding a
    declared control-scope digest. Advisory mode always allows
    (advisory output is not control).
    """

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._control_auths: dict[str, dict[str, Any]] = {}

    def grant_control(
        self,
        *,
        system_id: str,
        control_scope_digest: str,
        granted_by: str,
        granted_at: int,
        expires_at: int,
        signature: bytes,
    ) -> str:
        """Grant explicit control-path authority for a nuclear
        system. The grant is a separate, deliberate act — never
        implied by an advisory deployment."""
        _check_str(system_id, "system_id")
        _check_hex64(control_scope_digest, "control_scope_digest")
        _check_str(granted_by, "granted_by")
        _check_unix(granted_at, "granted_at")
        _check_unix(expires_at, "expires_at")
        if expires_at <= granted_at:
            raise GridAgentsError("expires_at must be after granted_at")
        _check_sig(signature, "signature")
        pubkey = self._authorities.public_key_for(granted_by)
        if pubkey is None:
            raise GridAgentsError(f"granted_by {granted_by!r} is not a registered authority")
        digest = jcs_sha256_hex(_nuclear_auth_payload(
            system_id=system_id,
            control_scope_digest=control_scope_digest,
            granted_by=granted_by,
            granted_at=granted_at,
            expires_at=expires_at,
        ))
        if not ed_verify(pubkey, digest.encode("utf-8"), bytes(signature)):
            raise GridAgentsError("authority signature does not verify")
        self._control_auths[system_id] = {
            "control_scope_digest": control_scope_digest,
            "granted_at": granted_at,
            "expires_at": expires_at,
            "auth_digest": digest,
        }
        return digest

    def check_action(
        self,
        *,
        system_id: str,
        mode: str,
        control_scope_digest: str | None = None,
        now: int,
    ) -> GridVerdict:
        _check_str(system_id, "system_id")
        if mode not in CONTROL_MODES:
            raise GridAgentsError(f"unknown mode {mode!r}")
        _check_unix(now, "now")
        if mode == "advisory":
            return _allow(f"nuclear advisory output for {system_id!r}")
        auth = self._control_auths.get(system_id)
        if auth is None:
            return _deny(
                DENY_NUCLEAR_CONTROL,
                f"control action for {system_id!r} has no control authorization",
            )
        if not (auth["granted_at"] <= now < auth["expires_at"]):
            return _deny(
                DENY_NUCLEAR_CONTROL,
                f"control authorization for {system_id!r} is not fresh",
            )
        if control_scope_digest is not None and not hmac.compare_digest(
            control_scope_digest, auth["control_scope_digest"]
        ):
            return _deny(
                DENY_NUCLEAR_CONTROL,
                f"control action scope does not match granted scope for {system_id!r}",
            )
        return _allow(
            f"authorized control action for {system_id!r}",
            auth["auth_digest"],
        )


# ---------------------------------------------------------------------------
# Blackout evidence chain (113th-batch incident clock)
# ---------------------------------------------------------------------------


def _blackout_payload(
    *,
    incident_id: str,
    system_id: str,
    timeline_digest: str,
    detected_at: int,
    reported_at: int,
    clock_missed: bool,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": GRID_SCHEMA_VERSION,
        "incident_id": incident_id,
        "system_id": system_id,
        "timeline_digest": timeline_digest,
        "detected_at": detected_at,
        "reported_at": reported_at,
        "clock_missed": clock_missed,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class BlackoutReceipt:
    incident_id: str
    system_id: str
    timeline_digest: str
    detected_at: int
    reported_at: int
    clock_missed: bool
    prev_hash: str
    receipt_digest: str


@dataclass(frozen=True)
class BlackoutVerdict:
    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt: BlackoutReceipt | None = None


class BlackoutRegistry:
    """Hash-chained blackout filings with a machine-enforced clock.

    A blackout without a bound timeline is unreported
    (``grid:unreported_blackout``). A filing past the 2-day clock is
    *recorded* (the receipt itself carries ``clock_missed=True``)
    and the verdict refuses (``grid:blackout_clock_missed``) — the
    miss is on the record, never quietly repaired. No backdating:
    ``detected_at`` cannot be in the future, ``reported_at`` cannot
    precede ``detected_at`` or postdate ``now``.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, BlackoutReceipt] = {}
        self._prev_hash = _GENESIS

    def file_blackout(
        self,
        *,
        incident_id: str,
        system_id: str,
        timeline_digest: str | None,
        detected_at: int,
        reported_at: int,
        now: int,
    ) -> BlackoutVerdict:
        _check_str(incident_id, "incident_id")
        _check_str(system_id, "system_id")
        _check_unix(detected_at, "detected_at")
        _check_unix(reported_at, "reported_at")
        _check_unix(now, "now")
        if incident_id in self._by_id:
            return BlackoutVerdict(
                allowed=False,
                reason=f"{DENY_BLACKOUT_DUPLICATE}: duplicate filing of {incident_id!r}",
            )
        if detected_at > now:
            raise GridAgentsError("detected_at cannot be in the future")
        if reported_at < detected_at:
            raise GridAgentsError("reported_at cannot precede detected_at")
        if reported_at > now:
            raise GridAgentsError("reported_at cannot postdate now")
        if not timeline_digest or not _is_hex64(timeline_digest):
            return BlackoutVerdict(
                allowed=False,
                reason=f"{DENY_UNREPORTED_BLACKOUT}: "
                       f"blackout {incident_id!r} has no bound timeline",
            )
        missed = reported_at > detected_at + BLACKOUT_CLOCK_S
        digest = jcs_sha256_hex(_blackout_payload(
            incident_id=incident_id,
            system_id=system_id,
            timeline_digest=timeline_digest,
            detected_at=detected_at,
            reported_at=reported_at,
            clock_missed=missed,
            prev_hash=self._prev_hash,
        ))
        receipt = BlackoutReceipt(
            incident_id=incident_id,
            system_id=system_id,
            timeline_digest=timeline_digest,
            detected_at=detected_at,
            reported_at=reported_at,
            clock_missed=missed,
            prev_hash=self._prev_hash,
            receipt_digest=digest,
        )
        self._by_id[incident_id] = receipt
        self._prev_hash = digest
        if missed:
            return BlackoutVerdict(
                allowed=False,
                reason=f"{DENY_BLACKOUT_CLOCK_MISSED}: "
                       f"blackout {incident_id!r} reported past the 2-day clock",
                receipt=receipt,
            )
        return BlackoutVerdict(
            allowed=True,
            reason=f"blackout {incident_id!r} filed with bound timeline",
            classification=CLASS_AUTHORITATIVE,
            receipt=receipt,
        )
