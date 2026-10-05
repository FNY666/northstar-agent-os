"""Water-infrastructure defense gates (one-hundred-thirty-first batch).

Absorbs the 2026 AI-water research thread:

* **First documented LLM-assisted attack on water infrastructure**
  (Dragos 2026-05): 2025-12 -> 2026-02, attacker used Claude + GPT
  against the Monterrey (Mexico) water utility; Claude autonomously
  identified SCADA/vNode gateways and generated malicious scripts. The
  attacker had *no prior OT experience*. Governance takeaway: the
  attack surface moved from "skilled OT intruder" to "anyone with a
  chatbot" — OT isolation declarations and exposure probes must be
  machine-enforced receipts, and LLM-attack TTPs belong in the
  cheat-probe vocabulary.
* **US PLC attack wave (2026-07 onward)** — 7 states' water utilities:
  IP/password changes on PLCs causing depressurization and
  boil-water notices. Governance takeaway: PLC exposure is a
  fail-closed probe, and boil-water notices must bind an event
  evidence chain plus a human countersign before release.
* **New York 2026-03** — first mandatory US water-utility
  cybersecurity regulation (OT isolation, MFA, mandatory reporting);
  CIRCIA 72-hour reporting; EPA's mandatory assessment retreated
  after litigation — a federal vacuum. Governance takeaway: where
  the regulator is absent, the receipt is the regulator — isolation
  declarations are signed and pinned, not asserted in prose.
* **AI's own water footprint** (Xylem x GWI: AI value-chain water
  demand +129% by 2050). Governance takeaway: AI workloads declare
  their water usage, bound to the 115th-batch EnvironmentalCostLedger
  ``water_liters`` — the industry that treats water cannot be
  water-blind about itself.

Northstar mapping:

* ``ot_airgap_receipt()`` — a water utility's OT isolation
  declaration (isolation mechanism digest, declared scope, freshness).
  Agent actions at a utility with no valid, fresh, signed airgap
  receipt are ``water-non-authoritative`` (NY 2026 lesson).
* ``plc_exposure_probe()`` — PLC inventory vs exposure surface:
  exposed PLCs without MFA *and* isolation -> deny +
  ``water.plc_exposure`` (fail-closed; the 2026 PLC wave lesson).
* ``ai_attack_telemetry()`` — Dragos TTP markers (closed vocabulary)
  fed into the cheat-probe vocabulary; sessions matching
  LLM-assisted-attack patterns raise ``water.ai_assisted_attack``.
* ``quality_forecast_gate()`` — water-quality predictions default
  NON_AUTHORITATIVE unless bound to a measurement-protocol digest.
* ``chemical_dosing_envelope()`` — chemical dosing / aeration
  actions bind an authority-signed envelope (closed action
  vocabulary + scope digest + time window), reusing the 126th
  batch's prescriptive-agent semantics: the agent can never widen
  its own envelope.
* ``leak_claim_receipt()`` — leak-detection claims bind a
  verification-protocol digest; vendor claims without one are
  ``water.unverified_leak_claim``.
* ``boil_notice_evidence()`` — boil-water notices bind an event
  evidence chain plus a human countersign; un-evidenced notices are
  refused (``water.boil_notice_unevidenced``) — a notice that cries
  wolf without evidence destroys the trust the next real notice
  needs.
* ``data_sovereignty_gate()`` — water-network data export binds a
  purpose receipt (purpose, recipient, scope digest); re-purposing
  without a new receipt is ``water.data_repurpose`` (Berlin leak
  lesson).
* ``water_footprint_binding()`` — AI workloads declare
  ``water_liters`` bound to a 115th-batch ledger receipt digest;
  undeclared water use is ``water.undeclared_water_footprint``.

Honest scoping: this module enforces *declared-infrastructure
discipline* — the software cannot authorize what is not declared,
pinned, and fresh. It does not make water safe, replace OT
engineering, or detect an attack in progress; telemetry markers are
post-hoc classifications, not intrusion detection. Everything is
offline and deterministic; the only clock is the ``now`` the caller
injects (integer epoch seconds). All digest comparisons use
:func:`hmac.compare_digest`.
"""
from __future__ import annotations
from _domain_base import DomainError

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(
            _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True).encode("utf-8")
        ).hexdigest()

from ed25519 import verify as _ed25519_verify

#: Schema marker, pinned into every digest.
SCHEMA_VERSION = "northstar.water.v1"

#: Freshness windows (seconds).
AIRGAP_FRESHNESS_S = 90 * 24 * 3600
DOSING_ENVELOPE_FRESHNESS_S = 30 * 24 * 3600
QUALITY_PROTOCOL_FRESHNESS_S = 180 * 24 * 3600

#: Denial reason codes. All start with ``water:`` for audit filtering.
DENY_NO_AIRGAP_RECEIPT = "water:no_ot_airgap_receipt"
DENY_AIRGAP_STALE = "water:ot_airgap_stale"
DENY_AIRGAP_REVOKED = "water:ot_airgap_revoked"
DENY_AIRGAP_SIGNATURE_INVALID = "water:ot_airgap_signature_invalid"
DENY_AIRGAP_DIGEST_MISMATCH = "water:ot_airgap_digest_mismatch"
DENY_PLC_EXPOSURE = "water:plc_exposure"
DENY_PLC_INVENTORY_MISMATCH = "water:plc_inventory_mismatch"
DENY_AI_ASSISTED_ATTACK = "water:ai_assisted_attack"
DENY_UNKNOWN_TELEMETRY_MARKER = "water:unknown_telemetry_marker"
DENY_QUALITY_UNBOUND = "water:quality_forecast_unbound"
DENY_QUALITY_PROTOCOL_STALE = "water:quality_protocol_stale"
DENY_DOSING_OUT_OF_ENVELOPE = "water:dosing_out_of_envelope"
DENY_DOSING_ENVELOPE_WIDENED = "water:dosing_envelope_widened"
DENY_DOSING_ENVELOPE_EXPIRED = "water:dosing_envelope_expired"
DENY_UNVERIFIED_LEAK_CLAIM = "water:unverified_leak_claim"
DENY_LEAK_PROTOCOL_MISMATCH = "water:leak_protocol_mismatch"
DENY_BOIL_NOTICE_UNEVIDENCED = "water:boil_notice_unevidenced"
DENY_BOIL_NOTICE_NO_COUNTERSIGN = "water:boil_notice_no_countersign"
DENY_DATA_REPURPOSE = "water:data_repurpose"
DENY_DATA_PURPOSE_UNSIGNED = "water:data_purpose_unsigned"
DENY_UNDECLARED_WATER_FOOTPRINT = "water:undeclared_water_footprint"
DENY_FOOTPRINT_LEDGER_MISMATCH = "water:footprint_ledger_mismatch"
DENY_MALFORMED = "water:malformed"
DENY_UNKNOWN_AUTHORITY = "water:unknown_authority"

#: Audit events.
AIRGAP_RECORDED_EVENT = "water.airgap_recorded"
PLC_PROBE_EVENT = "water.plc_probe"
TELEMETRY_FLAGGED_EVENT = "water.telemetry_flagged"
DOSING_DENIED_EVENT = "water.dosing_denied"

#: Classification tiers.
WATER_AUTHORITATIVE = "water-authoritative"
WATER_NON_AUTHORITATIVE = "water-non-authoritative"

_GENESIS = "genesis"


class WaterError(DomainError):
    """Malformed water-infrastructure input. Fail loud, never guess."""


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise WaterError(f"{name} must be a non-empty string")
    return value


def _require_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise WaterError(f"{name} must be an integer")
    return value


def _require_nonneg_int(value: Any, name: str) -> int:
    v = _require_int(value, name)
    if v < 0:
        raise WaterError(f"{name} must be a non-negative integer")
    return v


def _check_ts(value: Any, name: str) -> int:
    return _require_nonneg_int(value, name)


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, name: str) -> str:
    if not _is_hex(value, 64):
        raise WaterError(f"{name} must be 64 lowercase hex chars")
    return value


def _check_hex128(value: Any, name: str) -> str:
    if not _is_hex(value, 128):
        raise WaterError(f"{name} must be 128 lowercase hex chars")
    return value


def _check_sig(value: Any, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 64:
        raise WaterError(f"{name} must be 64 bytes")
    return value


class AuthorityRegistry:
    """Registered human authorities (authority_id -> Ed25519 public key)."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register(self, authority_id: str, public_key: bytes) -> None:
        _require_str(authority_id, "authority_id")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise WaterError("public_key must be 32 bytes")
        self._keys[authority_id] = public_key

    def public_key_for(self, authority_id: str) -> bytes | None:
        return self._keys.get(authority_id)


def _verify_signature(
    authorities: AuthorityRegistry,
    *,
    authority_id: str,
    digest_hex: str,
    signature: bytes,
    deny_code: str,
) -> str | None:
    """Return a denial code if the signature is invalid, else None."""
    pub = authorities.public_key_for(authority_id)
    if pub is None:
        return DENY_UNKNOWN_AUTHORITY
    try:
        ok = _ed25519_verify(pub, digest_hex.encode("utf-8"), signature)
    except Exception:
        ok = False
    return None if ok else deny_code


@dataclass(frozen=True)
class WaterVerdict:
    """Uniform verdict: allowed / denial code / classification."""

    allowed: bool
    deny_code: str | None
    classification: str


def _deny(code: str) -> WaterVerdict:
    return WaterVerdict(allowed=False, deny_code=code,
                        classification=WATER_NON_AUTHORITATIVE)


def _allow() -> WaterVerdict:
    return WaterVerdict(allowed=True, deny_code=None,
                        classification=WATER_AUTHORITATIVE)


# ---------------------------------------------------------------------------
# OT airgap receipts: the NY-2026 lesson, machine-enforced
# ---------------------------------------------------------------------------

AIRGAP_SCHEMA = "northstar.water.ot-airgap.v1"

#: Closed vocabulary of isolation mechanisms.
ISOLATION_MECHANISMS: tuple[str, ...] = (
    "physical_airgap",
    "unidirectional_gateway",
    "segmented_vlan_with_firewall",
)


@dataclass(frozen=True)
class OTAirgapReceipt:
    """A utility's OT isolation declaration.

    ``isolation_mechanism`` comes from the closed
    :data:`ISOLATION_MECHANISMS` vocabulary; ``scope_digest`` pins the
    declared network scope (which segments, which gateways); the
    receipt is authority-signed and carries ``declared_at`` /
    ``revoked`` so staleness and revocation are checkable offline.
    """

    utility_id: str
    isolation_mechanism: str
    scope_digest: str
    declared_at: int
    revoked: bool
    authority_id: str
    signature: bytes

    def digest_fields(self) -> dict[str, Any]:
        return {
            "schema": AIRGAP_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "utility_id": self.utility_id,
            "isolation_mechanism": self.isolation_mechanism,
            "scope_digest": self.scope_digest,
            "declared_at": self.declared_at,
            "revoked": self.revoked,
            "authority_id": self.authority_id,
        }

    def digest(self) -> str:
        return jcs_sha256_hex(self.digest_fields())


class OTAirgapRegistry:
    """Issued OT airgap receipts, keyed by utility."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._receipts: dict[str, OTAirgapReceipt] = {}

    def issue(
        self,
        *,
        utility_id: str,
        isolation_mechanism: str,
        scope_digest: str,
        declared_at: int,
        authority_id: str,
        signature: bytes,
    ) -> OTAirgapReceipt:
        _require_str(utility_id, "utility_id")
        if isolation_mechanism not in ISOLATION_MECHANISMS:
            raise WaterError(
                f"isolation_mechanism must be one of {ISOLATION_MECHANISMS}"
            )
        _check_hex64(scope_digest, "scope_digest")
        _check_ts(declared_at, "declared_at")
        _require_str(authority_id, "authority_id")
        _check_sig(signature, "signature")
        receipt = OTAirgapReceipt(
            utility_id=utility_id,
            isolation_mechanism=isolation_mechanism,
            scope_digest=scope_digest,
            declared_at=declared_at,
            revoked=False,
            authority_id=authority_id,
            signature=signature,
        )
        denied = _verify_signature(
            self._authorities,
            authority_id=authority_id,
            digest_hex=receipt.digest(),
            signature=signature,
            deny_code=DENY_AIRGAP_SIGNATURE_INVALID,
        )
        if denied is not None:
            raise WaterError(denied)
        self._receipts[utility_id] = receipt
        return receipt

    def revoke(self, utility_id: str) -> None:
        receipt = self._receipts.get(utility_id)
        if receipt is None:
            raise WaterError("unknown utility_id")
        self._receipts[utility_id] = OTAirgapReceipt(
            utility_id=receipt.utility_id,
            isolation_mechanism=receipt.isolation_mechanism,
            scope_digest=receipt.scope_digest,
            declared_at=receipt.declared_at,
            revoked=True,
            authority_id=receipt.authority_id,
            signature=receipt.signature,
        )

    def get(self, utility_id: str) -> OTAirgapReceipt | None:
        return self._receipts.get(utility_id)


def ot_airgap_receipt(
    *,
    airgap_registry: OTAirgapRegistry,
    utility_id: str,
    scope_digest: str,
    now: int,
) -> WaterVerdict:
    """Check a utility's OT isolation declaration before agent action.

    No valid, fresh, unrevoked, signature-checked receipt whose scope
    digest matches the declared scope -> the utility's agent actions
    are NON_AUTHORITATIVE (``water:no_ot_airgap_receipt`` and
    friends). Where the regulator is absent, the receipt is the
    regulator.
    """
    _require_str(utility_id, "utility_id")
    _check_hex64(scope_digest, "scope_digest")
    _check_ts(now, "now")
    receipt = airgap_registry.get(utility_id)
    if receipt is None:
        return _deny(DENY_NO_AIRGAP_RECEIPT)
    if receipt.revoked:
        return _deny(DENY_AIRGAP_REVOKED)
    if now < receipt.declared_at or now - receipt.declared_at > AIRGAP_FRESHNESS_S:
        return _deny(DENY_AIRGAP_STALE)
    if not hmac.compare_digest(receipt.scope_digest, scope_digest):
        return _deny(DENY_AIRGAP_DIGEST_MISMATCH)
    denied = _verify_signature(
        airgap_registry._authorities,
        authority_id=receipt.authority_id,
        digest_hex=receipt.digest(),
        signature=receipt.signature,
        deny_code=DENY_AIRGAP_SIGNATURE_INVALID,
    )
    if denied is not None:
        return _deny(denied)
    return _allow()


# ---------------------------------------------------------------------------
# PLC exposure probe: the 2026 PLC-wave lesson, fail-closed
# ---------------------------------------------------------------------------

PLC_PROBE_SCHEMA = "northstar.water.plc-probe.v1"


@dataclass(frozen=True)
class PLCExposureProbe:
    """One PLC exposure assessment.

    ``exposed`` means reachable from outside the OT boundary;
    ``mfa_enabled`` and ``isolated`` are the NY-2026 minimums. The
    probe binds the full PLC inventory digest so a utility cannot
    probe a subset and claim the whole fleet.
    """

    utility_id: str
    inventory_digest: str
    plc_id: str
    exposed: bool
    mfa_enabled: bool
    isolated: bool
    probed_at: int


def plc_exposure_probe(
    *,
    probe: PLCExposureProbe,
    inventory_digest: str,
    now: int,
) -> WaterVerdict:
    """Fail-closed PLC exposure check.

    The probe's inventory digest must match the registry's; a probe
    older than the airgap freshness window is stale. An exposed PLC
    without *both* MFA and isolation denies with
    ``water.plc_exposure`` — the 2026 wave rewrote default passwords
    and IPs on exposed PLCs, and "we'll isolate it later" is not a
    control.
    """
    _check_hex64(inventory_digest, "inventory_digest")
    _check_ts(now, "now")
    if not hmac.compare_digest(probe.inventory_digest, inventory_digest):
        return _deny(DENY_PLC_INVENTORY_MISMATCH)
    if now < probe.probed_at or now - probe.probed_at > AIRGAP_FRESHNESS_S:
        return _deny(DENY_AIRGAP_STALE)
    if probe.exposed and not (probe.mfa_enabled and probe.isolated):
        return _deny(DENY_PLC_EXPOSURE)
    return _allow()


# ---------------------------------------------------------------------------
# AI-attack telemetry: Dragos TTP markers in the cheat-probe vocabulary
# ---------------------------------------------------------------------------

TELEMETRY_SCHEMA = "northstar.water.telemetry.v1"

#: Closed vocabulary of LLM-assisted-attack markers (Dragos 2026-05
#: Monterrey incident and the 2026 US PLC wave, generalized).
ATTACK_MARKERS: tuple[str, ...] = (
    "llm_scada_recon",
    "llm_vnode_gateway_identification",
    "llm_malicious_script_generation",
    "llm_ot_credential_harvest",
    "plc_credential_change",
    "plc_ip_rewrite",
    "unauthorized_depressurization_command",
    "boil_notice_suppression_attempt",
)

#: Markers that are individually sufficient to raise the alarm.
CRITICAL_MARKERS: frozenset[str] = frozenset({
    "llm_vnode_gateway_identification",
    "llm_malicious_script_generation",
    "plc_credential_change",
    "plc_ip_rewrite",
})


@dataclass(frozen=True)
class TelemetryVerdict:
    """Telemetry classification of one agent session."""

    flagged: bool
    deny_code: str | None
    matched_markers: tuple[str, ...]


def ai_attack_telemetry(
    *,
    session_id: str,
    markers: list[str] | tuple[str, ...],
    now: int,
) -> TelemetryVerdict:
    """Classify a session against the LLM-attack TTP vocabulary.

    Unknown markers are themselves a fail-closed signal
    (``water:unknown_telemetry_marker``) — a vocabulary the attacker
    can extend silently is no vocabulary. Any critical marker, or any
    two non-critical attack markers in one session, raises
    ``water.ai_assisted_attack``. This is a post-hoc classification,
    not intrusion detection: it labels sessions for the audit trail,
    it does not stop an attack in progress.
    """
    _require_str(session_id, "session_id")
    _check_ts(now, "now")
    if not isinstance(markers, (list, tuple)):
        raise WaterError("markers must be a list or tuple of strings")
    for m in markers:
        if not isinstance(m, str) or not m:
            raise WaterError("each marker must be a non-empty string")
        if m not in ATTACK_MARKERS:
            return TelemetryVerdict(
                flagged=True,
                deny_code=DENY_UNKNOWN_TELEMETRY_MARKER,
                matched_markers=(m,),
            )
    matched = tuple(m for m in markers if m in CRITICAL_MARKERS)
    non_critical = tuple(m for m in markers if m not in CRITICAL_MARKERS)
    if matched or len(non_critical) >= 2:
        return TelemetryVerdict(
            flagged=True,
            deny_code=DENY_AI_ASSISTED_ATTACK,
            matched_markers=tuple(markers),
        )
    return TelemetryVerdict(
        flagged=False, deny_code=None, matched_markers=tuple(markers)
    )


# ---------------------------------------------------------------------------
# Quality-forecast gate: predictions are NON_AUTHORITATIVE by default
# ---------------------------------------------------------------------------

QUALITY_SCHEMA = "northstar.water.quality-forecast.v1"


def quality_forecast_gate(
    *,
    utility_id: str,
    forecast_digest: str,
    measurement_protocol_digest: str | None,
    protocol_measured_at: int | None,
    now: int,
) -> WaterVerdict:
    """Water-quality predictions need a bound measurement protocol.

    A forecast with no bound protocol, or a protocol older than the
    quality window, is NON_AUTHORITATIVE
    (``water:quality_forecast_unbound`` / ``water:quality_protocol_stale``).
    A prediction that decides who drinks what cannot float free of
    how it was measured.
    """
    _require_str(utility_id, "utility_id")
    _check_hex64(forecast_digest, "forecast_digest")
    _check_ts(now, "now")
    if measurement_protocol_digest is None:
        return _deny(DENY_QUALITY_UNBOUND)
    _check_hex64(measurement_protocol_digest, "measurement_protocol_digest")
    if protocol_measured_at is None:
        return _deny(DENY_QUALITY_UNBOUND)
    _check_ts(protocol_measured_at, "protocol_measured_at")
    if now < protocol_measured_at or (
        now - protocol_measured_at > QUALITY_PROTOCOL_FRESHNESS_S
    ):
        return _deny(DENY_QUALITY_PROTOCOL_STALE)
    return _allow()


# ---------------------------------------------------------------------------
# Chemical-dosing envelope: 126th-batch prescriptive semantics for water
# ---------------------------------------------------------------------------

DOSING_SCHEMA = "northstar.water.dosing-envelope.v1"

#: Closed vocabulary of dosing/aeration actions.
DOSING_ACTIONS: tuple[str, ...] = (
    "chlorine_dose",
    "fluoride_dose",
    "coagulant_dose",
    "ph_adjust",
    "aeration_rate_set",
    "backwash_cycle",
)


@dataclass(frozen=True)
class DosingEnvelope:
    """An authority-signed chemical-dosing action envelope.

    The agent acts only inside ``(allowed_actions, scope_digest,
    [armed_at, expires_at])`` and can never widen it — the 126th
    batch's no-self-widening rule, applied to what goes into the
    water.
    """

    agent_id: str
    plant_id: str
    allowed_actions: tuple[str, ...]
    scope_digest: str
    armed_at: int
    expires_at: int
    authority_id: str
    signature: bytes

    def digest_fields(self) -> dict[str, Any]:
        return {
            "schema": DOSING_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "agent_id": self.agent_id,
            "plant_id": self.plant_id,
            "allowed_actions": list(self.allowed_actions),
            "scope_digest": self.scope_digest,
            "armed_at": self.armed_at,
            "expires_at": self.expires_at,
            "authority_id": self.authority_id,
        }

    def digest(self) -> str:
        return jcs_sha256_hex(self.digest_fields())


class DosingEnvelopeRegistry:
    """Authority-signed dosing envelopes, keyed by agent."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._envelopes: dict[str, DosingEnvelope] = {}

    def arm(
        self,
        *,
        agent_id: str,
        plant_id: str,
        allowed_actions: list[str] | tuple[str, ...],
        scope_digest: str,
        armed_at: int,
        expires_at: int,
        authority_id: str,
        signature: bytes,
    ) -> DosingEnvelope:
        _require_str(agent_id, "agent_id")
        _require_str(plant_id, "plant_id")
        if not isinstance(allowed_actions, (list, tuple)) or not allowed_actions:
            raise WaterError("allowed_actions must be a non-empty list/tuple")
        for a in allowed_actions:
            if a not in DOSING_ACTIONS:
                raise WaterError(f"action {a!r} not in DOSING_ACTIONS")
        _check_hex64(scope_digest, "scope_digest")
        _check_ts(armed_at, "armed_at")
        _check_ts(expires_at, "expires_at")
        if expires_at <= armed_at:
            raise WaterError("expires_at must be after armed_at")
        _require_str(authority_id, "authority_id")
        _check_sig(signature, "signature")
        envelope = DosingEnvelope(
            agent_id=agent_id,
            plant_id=plant_id,
            allowed_actions=tuple(allowed_actions),
            scope_digest=scope_digest,
            armed_at=armed_at,
            expires_at=expires_at,
            authority_id=authority_id,
            signature=signature,
        )
        denied = _verify_signature(
            self._authorities,
            authority_id=authority_id,
            digest_hex=envelope.digest(),
            signature=signature,
            deny_code=DENY_DOSING_ENVELOPE_WIDENED,
        )
        if denied is not None:
            raise WaterError(denied)
        self._envelopes[agent_id] = envelope
        return envelope

    def get(self, agent_id: str) -> DosingEnvelope | None:
        return self._envelopes.get(agent_id)


def chemical_dosing_envelope(
    *,
    envelope_registry: DosingEnvelopeRegistry,
    agent_id: str,
    action: str,
    scope_digest: str,
    now: int,
) -> WaterVerdict:
    """Authorize one chemical-dosing action inside the signed envelope.

    No envelope, an expired envelope, an action outside the closed
    vocabulary, or a scope-digest mismatch all deny. An agent that
    could widen its own envelope could dose anything; the signature
    check at arm-time is what makes the envelope the authority's,
    not the agent's.
    """
    _require_str(agent_id, "agent_id")
    _require_str(action, "action")
    _check_hex64(scope_digest, "scope_digest")
    _check_ts(now, "now")
    env = envelope_registry.get(agent_id)
    if env is None:
        return _deny(DENY_DOSING_OUT_OF_ENVELOPE)
    if now < env.armed_at or now > env.expires_at:
        return _deny(DENY_DOSING_ENVELOPE_EXPIRED)
    if action not in env.allowed_actions:
        return _deny(DENY_DOSING_OUT_OF_ENVELOPE)
    if not hmac.compare_digest(scope_digest, env.scope_digest):
        return _deny(DENY_DOSING_OUT_OF_ENVELOPE)
    return _allow()


# ---------------------------------------------------------------------------
# Leak-claim receipts: vendor numbers need a verification protocol
# ---------------------------------------------------------------------------

LEAK_CLAIM_SCHEMA = "northstar.water.leak-claim.v1"


@dataclass(frozen=True)
class LeakClaimReceipt:
    """A leak-detection claim bound to its verification protocol.

    ``claim_digest`` pins what was claimed (leak count, localization
    window, accuracy figure); ``protocol_digest`` pins *how it was
    verified*. A vendor "5-minute localization, 92%" with no bound
    protocol is marketing, not a measurement.
    """

    vendor_id: str
    utility_id: str
    claim_digest: str
    protocol_digest: str
    measured_at: int
    authority_id: str
    signature: bytes

    def digest_fields(self) -> dict[str, Any]:
        return {
            "schema": LEAK_CLAIM_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "vendor_id": self.vendor_id,
            "utility_id": self.utility_id,
            "claim_digest": self.claim_digest,
            "protocol_digest": self.protocol_digest,
            "measured_at": self.measured_at,
            "authority_id": self.authority_id,
        }

    def digest(self) -> str:
        return jcs_sha256_hex(self.digest_fields())


def leak_claim_receipt(
    *,
    authorities: AuthorityRegistry,
    vendor_id: str,
    utility_id: str,
    claim_digest: str,
    protocol_digest: str | None,
    measured_at: int,
    authority_id: str,
    signature: bytes,
    now: int,
) -> WaterVerdict:
    """Verify a leak-detection claim's bound protocol and signature.

    No bound protocol -> ``water:unverified_leak_claim``. A protocol
    digest that fails to verify against the authority's signature ->
    ``water:leak_protocol_mismatch``. The claim is only as good as
    the protocol it is pinned to.
    """
    _require_str(vendor_id, "vendor_id")
    _require_str(utility_id, "utility_id")
    _check_hex64(claim_digest, "claim_digest")
    _check_ts(measured_at, "measured_at")
    _check_ts(now, "now")
    if protocol_digest is None:
        return _deny(DENY_UNVERIFIED_LEAK_CLAIM)
    _check_hex64(protocol_digest, "protocol_digest")
    receipt = LeakClaimReceipt(
        vendor_id=vendor_id,
        utility_id=utility_id,
        claim_digest=claim_digest,
        protocol_digest=protocol_digest,
        measured_at=measured_at,
        authority_id=authority_id,
        signature=signature,
    )
    denied = _verify_signature(
        authorities,
        authority_id=authority_id,
        digest_hex=receipt.digest(),
        signature=signature,
        deny_code=DENY_LEAK_PROTOCOL_MISMATCH,
    )
    if denied is not None:
        return _deny(denied)
    return _allow()


# ---------------------------------------------------------------------------
# Boil-notice evidence: notices need evidence chains + human countersign
# ---------------------------------------------------------------------------

BOIL_NOTICE_SCHEMA = "northstar.water.boil-notice.v1"


def boil_notice_evidence(
    *,
    authorities: AuthorityRegistry,
    utility_id: str,
    notice_id: str,
    event_evidence_digest: str | None,
    countersign_authority_id: str | None,
    countersign_signature: bytes | None,
    issued_at: int,
    now: int,
) -> WaterVerdict:
    """Gate a boil-water notice on evidence and human countersign.

    A notice with no bound event evidence chain is refused
    (``water:boil_notice_unevidenced``); evidence without a human
    countersign over the notice digest is refused
    (``water:boil_notice_no_countersign``). The 2026 PLC wave
    produced real boil notices — the next false one, issued by an
    agent with no evidence, would cost the trust the real ones run
    on.
    """
    _require_str(utility_id, "utility_id")
    _require_str(notice_id, "notice_id")
    _check_ts(issued_at, "issued_at")
    _check_ts(now, "now")
    if event_evidence_digest is None:
        return _deny(DENY_BOIL_NOTICE_UNEVIDENCED)
    _check_hex64(event_evidence_digest, "event_evidence_digest")
    if countersign_authority_id is None or countersign_signature is None:
        return _deny(DENY_BOIL_NOTICE_NO_COUNTERSIGN)
    _require_str(countersign_authority_id, "countersign_authority_id")
    _check_sig(countersign_signature, "countersign_signature")
    notice_digest = jcs_sha256_hex({
        "schema": BOIL_NOTICE_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "utility_id": utility_id,
        "notice_id": notice_id,
        "event_evidence_digest": event_evidence_digest,
        "issued_at": issued_at,
        "countersign_authority_id": countersign_authority_id,
    })
    denied = _verify_signature(
        authorities,
        authority_id=countersign_authority_id,
        digest_hex=notice_digest,
        signature=countersign_signature,
        deny_code=DENY_BOIL_NOTICE_NO_COUNTERSIGN,
    )
    if denied is not None:
        return _deny(denied)
    return _allow()


# ---------------------------------------------------------------------------
# Data sovereignty: network data export binds a purpose receipt
# ---------------------------------------------------------------------------

DATA_PURPOSE_SCHEMA = "northstar.water.data-purpose.v1"

#: Closed vocabulary of export purposes.
DATA_PURPOSES: tuple[str, ...] = (
    "leak_detection_research",
    "regulatory_reporting",
    "emergency_response",
    "maintenance_planning",
)


@dataclass(frozen=True)
class DataPurposeReceipt:
    """A purpose-bound water-network data export receipt."""

    exporter_id: str
    recipient_id: str
    purpose: str
    scope_digest: str
    issued_at: int
    expires_at: int
    authority_id: str
    signature: bytes

    def digest_fields(self) -> dict[str, Any]:
        return {
            "schema": DATA_PURPOSE_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "exporter_id": self.exporter_id,
            "recipient_id": self.recipient_id,
            "purpose": self.purpose,
            "scope_digest": self.scope_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "authority_id": self.authority_id,
        }

    def digest(self) -> str:
        return jcs_sha256_hex(self.digest_fields())


class DataPurposeRegistry:
    """Issued data-purpose receipts, keyed by export id."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._receipts: dict[str, DataPurposeReceipt] = {}

    def issue(
        self,
        *,
        export_id: str,
        exporter_id: str,
        recipient_id: str,
        purpose: str,
        scope_digest: str,
        issued_at: int,
        expires_at: int,
        authority_id: str,
        signature: bytes,
    ) -> DataPurposeReceipt:
        _require_str(export_id, "export_id")
        _require_str(exporter_id, "exporter_id")
        _require_str(recipient_id, "recipient_id")
        if purpose not in DATA_PURPOSES:
            raise WaterError(f"purpose must be one of {DATA_PURPOSES}")
        _check_hex64(scope_digest, "scope_digest")
        _check_ts(issued_at, "issued_at")
        _check_ts(expires_at, "expires_at")
        if expires_at <= issued_at:
            raise WaterError("expires_at must be after issued_at")
        _require_str(authority_id, "authority_id")
        _check_sig(signature, "signature")
        receipt = DataPurposeReceipt(
            exporter_id=exporter_id,
            recipient_id=recipient_id,
            purpose=purpose,
            scope_digest=scope_digest,
            issued_at=issued_at,
            expires_at=expires_at,
            authority_id=authority_id,
            signature=signature,
        )
        denied = _verify_signature(
            self._authorities,
            authority_id=authority_id,
            digest_hex=receipt.digest(),
            signature=signature,
            deny_code=DENY_DATA_PURPOSE_UNSIGNED,
        )
        if denied is not None:
            raise WaterError(denied)
        self._receipts[export_id] = receipt
        return receipt

    def get(self, export_id: str) -> DataPurposeReceipt | None:
        return self._receipts.get(export_id)


def data_sovereignty_gate(
    *,
    purpose_registry: DataPurposeRegistry,
    export_id: str,
    purpose: str,
    scope_digest: str,
    now: int,
) -> WaterVerdict:
    """Check a data export against its purpose receipt.

    No receipt, an expired receipt, a purpose that drifted from the
    declared one, or a scope digest that no longer matches all deny:
    ``water:data_repurpose`` / ``water:data_purpose_unsigned``. Pipe
    network data that leaves the utility for one purpose and is used
    for another is how the Berlin leak happened.
    """
    _require_str(export_id, "export_id")
    _require_str(purpose, "purpose")
    _check_hex64(scope_digest, "scope_digest")
    _check_ts(now, "now")
    receipt = purpose_registry.get(export_id)
    if receipt is None:
        return _deny(DENY_DATA_PURPOSE_UNSIGNED)
    if now < receipt.issued_at or now > receipt.expires_at:
        return _deny(DENY_DATA_PURPOSE_UNSIGNED)
    if purpose != receipt.purpose:
        return _deny(DENY_DATA_REPURPOSE)
    if not hmac.compare_digest(scope_digest, receipt.scope_digest):
        return _deny(DENY_DATA_REPURPOSE)
    denied = _verify_signature(
        purpose_registry._authorities,
        authority_id=receipt.authority_id,
        digest_hex=receipt.digest(),
        signature=receipt.signature,
        deny_code=DENY_DATA_PURPOSE_UNSIGNED,
    )
    if denied is not None:
        return _deny(denied)
    return _allow()


# ---------------------------------------------------------------------------
# Water footprint: AI workloads declare water use, bound to the ledger
# ---------------------------------------------------------------------------

FOOTPRINT_SCHEMA = "northstar.water.footprint.v1"


def water_footprint_binding(
    *,
    workload_id: str,
    water_liters: int | None,
    ledger_receipt_digest: str | None,
    expected_ledger_digest: str,
) -> WaterVerdict:
    """Bind a workload's declared water use to a 115th-batch receipt.

    The workload declares ``water_liters`` and the digest of the
    115th-batch EnvironmentalCostLedger receipt that records it; the
    digest must match the caller's expected ledger digest. No
    declaration -> ``water:undeclared_water_footprint``; digest
    mismatch -> ``water:footprint_ledger_mismatch``. The check is
    offline and structural: it binds the *declaration*, it does not
    audit the ledger — that is the 115th batch's job.
    """
    _require_str(workload_id, "workload_id")
    _check_hex64(expected_ledger_digest, "expected_ledger_digest")
    if water_liters is None:
        return _deny(DENY_UNDECLARED_WATER_FOOTPRINT)
    _require_nonneg_int(water_liters, "water_liters")
    if ledger_receipt_digest is None:
        return _deny(DENY_UNDECLARED_WATER_FOOTPRINT)
    _check_hex64(ledger_receipt_digest, "ledger_receipt_digest")
    if not hmac.compare_digest(ledger_receipt_digest, expected_ledger_digest):
        return _deny(DENY_FOOTPRINT_LEDGER_MISMATCH)
    return _allow()


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def water_audit_event(
    event: str,
    *,
    utility_id: str,
    deny_code: str | None,
    now: int,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _require_str(event, "event")
    _require_str(utility_id, "utility_id")
    _check_ts(now, "now")
    payload: dict[str, Any] = {
        "event": event,
        "utility_id": utility_id,
        "deny_code": deny_code,
        "at": now,
    }
    if details:
        payload["details"] = dict(details)
    payload["event_digest"] = jcs_sha256_hex(payload)
    return payload


__all__ = [
    "SCHEMA_VERSION",
    "AIRGAP_FRESHNESS_S",
    "DOSING_ENVELOPE_FRESHNESS_S",
    "QUALITY_PROTOCOL_FRESHNESS_S",
    "ISOLATION_MECHANISMS",
    "ATTACK_MARKERS",
    "CRITICAL_MARKERS",
    "DOSING_ACTIONS",
    "DATA_PURPOSES",
    "WATER_AUTHORITATIVE",
    "WATER_NON_AUTHORITATIVE",
    "WaterError",
    "WaterVerdict",
    "AuthorityRegistry",
    "OTAirgapReceipt",
    "OTAirgapRegistry",
    "ot_airgap_receipt",
    "PLCExposureProbe",
    "plc_exposure_probe",
    "TelemetryVerdict",
    "ai_attack_telemetry",
    "quality_forecast_gate",
    "DosingEnvelope",
    "DosingEnvelopeRegistry",
    "chemical_dosing_envelope",
    "LeakClaimReceipt",
    "leak_claim_receipt",
    "boil_notice_evidence",
    "DataPurposeReceipt",
    "DataPurposeRegistry",
    "data_sovereignty_gate",
    "water_footprint_binding",
    "water_audit_event",
]
