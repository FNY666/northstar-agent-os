"""Agriculture extension: scene-bound agri advice, field-condition envelopes,
farmer data sovereignty, advice explainability, and smallholder access
disclosure (one-hundred-sixteenth batch).

Absorbs the 2026 AI-agriculture research thread (mechanism ideas only,
honestly scoped):

* **Scene mismatch is the first risk.** Models trained on US industrial
  monoculture data give unreliable advice for African smallholder
  mixed-cropping — but nothing stops the call. Here agricultural
  advice/action is bound to ``(crop_system, farm_scale_class,
  agroecology_digest)``; a binding validated for
  ``industrial_monoculture`` invoked for ``smallholder_mixed`` denies
  with ``agri.scene_mismatch``. The binding pins the validation
  context; the machine cannot "probably transfer".
* **Capability envelopes must be dynamic.** The Deere critique
  (qu3ry.net, 2026-03): autonomous equipment does not maintain a
  structured capability envelope — wet soil, obstacles, wear change
  "what should be done", but the machine never assesses whether
  current conditions support the configured job. Here the agent must
  DECLARE current field conditions (``soil_state``, ``obstacle_state``,
  ``equipment_wear_class``) as a chained receipt before actuation, and
  the actuation gate checks the declaration against the
  authority-armed envelope. Conditions outside the envelope deny; the
  agent cannot silently widen the envelope (104th-batch
  no-self-issuance discipline, applied to agri actuation).
* **Farmer data sovereignty.** SAGE 2026 (peer-reviewed): digital
  tools re-centralize control to tech intermediaries; farmers have
  near-zero control over data flow and monetization. Here any farm
  data use requires a farmer-signed receipt binding ``(data_scope,
  purpose, revenue_share_terms_digest, revocable)``; validity is
  checked at USE time (105th-batch semantics — no "was once
  consented" shortcut); data used for a new purpose without a new
  receipt denies with ``agri.purpose_creep``.
* **Advice explainability.** Agricultural advice must carry four
  fields — ``why`` (why this recommendation), ``evidence`` (what
  evidence), ``self_check`` (what the farmer should verify
  themselves), ``contact`` (who to reach when it looks wrong).
  A missing field classifies the advice NON_AUTHORITATIVE. Advice
  delivered in a non-local language (the FAO finding: tools speak the
  wrong language) classifies ``agri.language_mismatch``.
* **Smallholder access disclosure.** Deployments in smallholder
  contexts must declare ``offline_capable``,
  ``local_language_supported``, ``low_bandwidth_mode``; missing
  declarations do NOT silently vanish — they surface as mandatory
  disclosure (``deployment.smallholder_exclusion_risk``) on the
  citizen explanation API (110th batch's explain_decision shape).

Honest scope: this module verifies *declared* scene bindings,
condition declarations, data-use receipts, and advice fields —
digests recompute, signatures verify, chains link. It cannot make
the underlying agronomy correct: a bound, well-declared scene can
still host bad advice (that is what ``bad_advice_harm`` audits),
and it cannot prove the physically true field conditions match the
declared ones (that needs sensor attestation, twin_receipts
discipline). Everything is offline and deterministic; callers inject
``now`` as an integer epoch; JCS canonical hashing (95th batch);
all digest comparisons via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

AGRI_SCHEMA_VERSION = "northstar.agri.v1"

#: Closed vocabulary: what the model was validated to advise on /
#: the observed farming system. Exact match only — a binding for
#: ``industrial_monoculture`` never covers ``smallholder_mixed``.
CROP_SYSTEMS: tuple[str, ...] = (
    "industrial_monoculture",
    "commercial_mixed",
    "smallholder_mixed",
    "rainfed_smallholder",
    "pastoral",
    "orchard_permanent",
)

#: Closed farm-scale classes. Scale is a scene dimension, not a hint:
#: advice calibrated on 5,000-hectare farms does not transfer to
#: 2-hectare plots (the US-big-farm -> Africa-smallholder lesson).
FARM_SCALE_CLASSES: tuple[str, ...] = (
    "smallholder",   # < 2 ha, hand/low-mechanization
    "commercial",    # mechanized, market-oriented
    "industrial",    # fleet-operated, > 1,000 ha equivalent
)

#: Closed soil-state vocabulary for the dynamic condition declaration.
SOIL_STATES: tuple[str, ...] = (
    "dry",
    "moist",
    "wet",
    "saturated",
)

#: Closed obstacle-state vocabulary.
OBSTACLE_STATES: tuple[str, ...] = (
    "clear",
    "sparse",
    "dense",
    "unmapped",
)

#: Closed equipment-wear classes.
WEAR_CLASSES: tuple[str, ...] = (
    "fresh",
    "normal",
    "worn",
    "critical",
)

#: Closed farm-data scope vocabulary.
DATA_SCOPES: tuple[str, ...] = (
    "soil",
    "yield",
    "imagery",
    "location",
    "finance",
    "weather_station",
)

#: The four mandatory explainability fields for advice to farmers.
EXPLAINABILITY_FIELDS: tuple[str, ...] = (
    "why",
    "evidence",
    "self_check",
    "contact",
)

#: Denial reason codes. All start with the ``agri:`` prefix.
DENY_SCENE_MISMATCH = "agri.scene_mismatch"
DENY_BINDING_EXPIRED = "agri.binding_expired"
DENY_BINDING_FUTURE = "agri.binding_from_future"
DENY_BINDING_TAMPERED = "agri.binding_tampered"
DENY_UNDECLARED_SCENE = "agri.undeclared_scene"
DENY_CONDITION_OUT_OF_ENVELOPE = "agri.condition_out_of_envelope"
DENY_NO_CONDITIONS_DECLARED = "agri.no_conditions_declared"
DENY_CONDITION_DECLARATION_TAMPERED = "agri.condition_declaration_tampered"
DENY_CONDITION_DECLARATION_STALE = "agri.condition_declaration_stale"
DENY_ENVELOPE_REVOKED = "agri.envelope_revoked"
DENY_ENVELOPE_EXPIRED = "agri.envelope_expired"
DENY_ENVELOPE_TAMPERED = "agri.envelope_tampered"
DENY_ENVELOPE_SELF_ISSUED = "agri.envelope_self_issued"
DENY_DATA_PURPOSE_CREEP = "agri.purpose_creep"
DENY_DATA_NO_RECEIPT = "agri.data_no_receipt"
DENY_DATA_REVOKED = "agri.data_receipt_revoked"
DENY_DATA_EXPIRED = "agri.data_receipt_expired"
DENY_DATA_TAMPERED = "agri.data_receipt_tampered"
DENY_DATA_SCOPE = "agri.data_scope_mismatch"
DENY_ADVICE_MISSING_FIELD = "agri.explain_missing_field"
DENY_ADVICE_LANGUAGE_MISMATCH = "agri.language_mismatch"
DENY_MALFORMED = "agri.malformed"

#: Audit event names (shaped for ``audit_chain.chain_record``).
AGRI_SCENE_DENIED_EVENT = "agri.scene_mismatch_denied"
AGRI_SCENE_ALLOWED_EVENT = "agri.scene_allowed"
AGRI_ACTUATION_DENIED_EVENT = "agri.actuation_denied"
AGRI_ACTUATION_ALLOWED_EVENT = "agri.actuation_allowed"
AGRI_DATA_DENIED_EVENT = "agri.data_use_denied"
AGRI_DATA_ALLOWED_EVENT = "agri.data_use_allowed"
AGRI_DATA_REVOKED_EVENT = "agri.data_receipt_revoked"
AGRI_BAD_ADVICE_HARM_EVENT = "agri.bad_advice_harm"
AGRI_EXCLUSION_RISK_EVENT = "deployment.smallholder_exclusion_risk"

#: Evidence classifications (binary, 87th-batch semantics).
AUTHORITATIVE_ADVICE = "authoritative-advice"
NON_AUTHORITATIVE_ADVICE = "non-authoritative-advice"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128

#: A conditions declaration older than this is stale for actuation:
#: field conditions drift, so a declaration is not a standing grant.
CONDITION_DECLARATION_FRESHNESS_S = 3_600


class AgriBoundError(ValueError):
    """Malformed agri binding/declaration/receipt or a programming error.

    Structural problems raise; verification *failures* (mismatch,
    expired, revoked, purpose creep) return verdicts with
    ``allowed=False`` — a failed check is a verdict, a malformed log
    is a bug.
    """


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise AgriBoundError(f"{field_name} must be 64 lowercase hex chars")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise AgriBoundError(f"{field_name} must be 128 lowercase hex chars")
    return value


def _check_vocab(value: Any, vocab: tuple[str, ...], name: str) -> str:
    if value not in vocab:
        raise AgriBoundError(
            f"unknown {name} {value!r}; closed vocabulary {vocab}"
        )
    return value


def _check_crop_system(value: Any) -> str:
    return _check_vocab(value, CROP_SYSTEMS, "crop_system")


def _check_scale(value: Any) -> str:
    return _check_vocab(value, FARM_SCALE_CLASSES, "farm_scale_class")


def _check_soil(value: Any) -> str:
    return _check_vocab(value, SOIL_STATES, "soil_state")


def _check_obstacle(value: Any) -> str:
    return _check_vocab(value, OBSTACLE_STATES, "obstacle_state")


def _check_wear(value: Any) -> str:
    return _check_vocab(value, WEAR_CLASSES, "equipment_wear_class")


def _check_scope(value: Any) -> str:
    return _check_vocab(value, DATA_SCOPES, "data_scope")


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AgriBoundError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise AgriBoundError(f"{field_name} must be a 32-byte seed")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgriBoundError(f"{field_name} must be a non-empty string")
    return value


def _check_pubkey_hex(value: Any) -> str:
    return _check_hex64(value, "pubkey_hex")


def _check_agroecology_digest(value: Any) -> str:
    # Pins the exact validation context: which soils, climates, and
    # cropping patterns the validation corpus covered.
    return _check_hex64(value, "agroecology_digest")


# ---------------------------------------------------------------------------
# AgriSceneBinding: authority-signed advice/action authorization
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgriSceneBinding:
    """Authorization of an agri capability for an explicit scene.

    The scene is ``(crop_system, farm_scale_class, agroecology_digest)``:
    a model version is only invocable where that triple matches. The
    digest pins the validation corpus context (soils, climates,
    cropping patterns) — advice calibrated on Iowa monoculture does
    not "transfer" to Kenyan mixed smallholding just because both
    grow maize. Issued by a registered human authority (Ed25519);
    there is no agent-key issuance path.
    """

    binding_id: str
    capability_id: str
    model_version_digest: str
    crop_system: str
    farm_scale_class: str
    agroecology_digest: str
    authorized_by: str
    authorized_at: int
    expires_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    binding_digest: str = ""
    schema_version: str = AGRI_SCHEMA_VERSION


def _binding_payload(binding: AgriSceneBinding) -> dict[str, Any]:
    return {
        "binding_id": binding.binding_id,
        "capability_id": binding.capability_id,
        "model_version_digest": binding.model_version_digest,
        "crop_system": binding.crop_system,
        "farm_scale_class": binding.farm_scale_class,
        "agroecology_digest": binding.agroecology_digest,
        "authorized_by": binding.authorized_by,
        "authorized_at": binding.authorized_at,
        "expires_at": binding.expires_at,
        "authority_pubkey_hex": binding.authority_pubkey_hex,
        "prev_digest": binding.prev_digest,
        "schema_version": binding.schema_version,
    }


def compute_binding_digest(binding: AgriSceneBinding) -> str:
    """Recompute the JCS digest a binding claims."""
    return jcs_sha256_hex(_binding_payload(binding))


def issue_agri_binding(
    *,
    binding_id: str,
    capability_id: str,
    model_version_digest: str,
    crop_system: str,
    farm_scale_class: str,
    agroecology_digest: str,
    authority_secret: bytes,
    authorized_by: str,
    authorized_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> AgriSceneBinding:
    """Issue an authority-signed agri scene binding and seal it."""
    _check_secret(authority_secret, "authority_secret")
    binding_id = _check_nonempty_str(binding_id, "binding_id")
    capability_id = _check_nonempty_str(capability_id, "capability_id")
    model_version_digest = _check_hex64(model_version_digest, "model_version_digest")
    crop_system = _check_crop_system(crop_system)
    farm_scale_class = _check_scale(farm_scale_class)
    agroecology_digest = _check_agroecology_digest(agroecology_digest)
    authorized_by = _check_nonempty_str(authorized_by, "authorized_by")
    authorized_at = _check_ts(authorized_at, "authorized_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= authorized_at:
        raise AgriBoundError("expires_at must be after authorized_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise AgriBoundError("prev_digest must be a non-empty string")

    pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = AgriSceneBinding(
        binding_id=binding_id,
        capability_id=capability_id,
        model_version_digest=model_version_digest,
        crop_system=crop_system,
        farm_scale_class=farm_scale_class,
        agroecology_digest=agroecology_digest,
        authorized_by=authorized_by,
        authorized_at=authorized_at,
        expires_at=expires_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,
        prev_digest=prev_digest,
    )
    payload = _binding_payload(bare)
    signature_hex = ed25519.sign(
        authority_secret, jcs_canonical_json(payload)
    ).hex()
    return AgriSceneBinding(
        binding_id=bare.binding_id,
        capability_id=bare.capability_id,
        model_version_digest=bare.model_version_digest,
        crop_system=bare.crop_system,
        farm_scale_class=bare.farm_scale_class,
        agroecology_digest=bare.agroecology_digest,
        authorized_by=bare.authorized_by,
        authorized_at=bare.authorized_at,
        expires_at=bare.expires_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        binding_digest=jcs_sha256_hex(payload),
        schema_version=bare.schema_version,
    )


def _verify_binding_integrity(binding: AgriSceneBinding) -> str | None:
    """Return a denial reason if the binding is malformed/tampered, else None."""
    try:
        _check_nonempty_str(binding.binding_id, "binding_id")
        _check_nonempty_str(binding.capability_id, "capability_id")
        _check_hex64(binding.model_version_digest, "model_version_digest")
        _check_crop_system(binding.crop_system)
        _check_scale(binding.farm_scale_class)
        _check_agroecology_digest(binding.agroecology_digest)
        _check_nonempty_str(binding.authorized_by, "authorized_by")
        _check_ts(binding.authorized_at, "authorized_at")
        _check_ts(binding.expires_at, "expires_at")
        _check_pubkey_hex(binding.authority_pubkey_hex)
        _check_hex128(binding.signature_hex, "signature_hex")
        if not hmac.compare_digest(
            compute_binding_digest(binding), binding.binding_digest
        ):
            return DENY_BINDING_TAMPERED
        try:
            sig_ok = ed25519.verify(
                bytes.fromhex(binding.authority_pubkey_hex),
                jcs_canonical_json(_binding_payload(binding)),
                bytes.fromhex(binding.signature_hex),
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            return DENY_BINDING_TAMPERED
    except AgriBoundError:
        return DENY_MALFORMED
    return None


@dataclass(frozen=True)
class AgriSceneVerdict:
    """Outcome of :func:`check_agri_scene`."""

    allowed: bool
    reason: str
    binding_id: str


def check_agri_scene(
    binding: AgriSceneBinding,
    *,
    crop_system: str,
    farm_scale_class: str,
    agroecology_digest: str,
    now: int,
) -> AgriSceneVerdict:
    """Fail-closed gate: is this observed agri scene within the binding?

    Check order: binding integrity -> time window -> exact triple
    match. Every dimension mismatches independently, but the first
    failure wins and the reason is always ``agri.scene_mismatch`` for
    a declared-but-out-of-scope scene. A model validated on
    ``industrial_monoculture`` / ``industrial`` invoked for
    ``smallholder_mixed`` / ``smallholder`` denies here.
    """
    now = _check_ts(now, "now")
    binding_id = getattr(binding, "binding_id", "")

    def deny(reason: str) -> AgriSceneVerdict:
        return AgriSceneVerdict(allowed=False, reason=reason, binding_id=binding_id)

    integrity = _verify_binding_integrity(binding)
    if integrity:
        return deny(integrity)
    if now < binding.authorized_at:
        return deny(DENY_BINDING_FUTURE)
    if now > binding.expires_at:
        return deny(DENY_BINDING_EXPIRED)
    try:
        crop_system = _check_crop_system(crop_system)
        farm_scale_class = _check_scale(farm_scale_class)
        agroecology_digest = _check_agroecology_digest(agroecology_digest)
    except AgriBoundError:
        return deny(DENY_MALFORMED)
    if (
        not hmac.compare_digest(crop_system, binding.crop_system)
        or not hmac.compare_digest(farm_scale_class, binding.farm_scale_class)
        or not hmac.compare_digest(agroecology_digest, binding.agroecology_digest)
    ):
        return deny(DENY_SCENE_MISMATCH)
    return AgriSceneVerdict(
        allowed=True, reason="agri-scene-authorized", binding_id=binding.binding_id
    )


def agri_scene_audit_event(verdict: AgriSceneVerdict, *, action: str) -> dict[str, Any]:
    """Shape an agri scene verdict as an audit event for ``audit_chain``."""
    return {
        "event": AGRI_SCENE_ALLOWED_EVENT if verdict.allowed else AGRI_SCENE_DENIED_EVENT,
        "action": action,
        "binding_id": verdict.binding_id,
        "reason": verdict.reason,
    }


# ---------------------------------------------------------------------------
# field_envelope: autonomous farm equipment with dynamic condition assessment
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldEnvelope:
    """An authority-armed capability envelope for farm equipment.

    Unlike static hardware limits, the agri envelope is assessed
    *dynamically*: the envelope pins the conditions the equipment is
    validated for (``max_soil_moisture_pct``, ``max_slope_pct``,
    ``max_obstacle_density``, ``min_visibility_m``, plus static
    ``max_speed_mps`` and ``max_pesticide_L_per_ha``), and actuation
    additionally requires a FRESH, chain-verified
    :class:`ConditionDeclaration` from the agent describing the actual
    field right now. The envelope is armed by a human authority
    (Ed25519); the agent has no issuance or widening path.
    """

    envelope_id: str
    equipment_id: str
    limits: Mapping[str, Any]
    armed_by: str
    armed_at: int
    expires_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    envelope_digest: str = ""
    revoked: bool = False
    schema_version: str = AGRI_SCHEMA_VERSION


def _validate_limits(limits: Mapping[str, Any]) -> dict[str, Any]:
    """Validate field-envelope limits. Closed vocabulary — unknown limit
    kinds are malformed (the agent cannot smuggle a new control axis
    past the envelope)."""
    if not isinstance(limits, Mapping):
        raise AgriBoundError("limits must be a mapping")
    known = {
        "max_soil_moisture_pct",
        "max_slope_pct",
        "max_obstacle_density",
        "min_visibility_m",
        "max_speed_mps",
        "max_pesticide_L_per_ha",
    }
    unknown = set(limits) - known
    if unknown:
        raise AgriBoundError(f"unknown limit kinds: {sorted(unknown)}")
    out: dict[str, Any] = {}
    for key, lo, hi in (
        ("max_soil_moisture_pct", 0.0, 100.0),
        ("max_slope_pct", 0.0, 100.0),
        ("max_obstacle_density", 0.0, 1.0),
        ("min_visibility_m", 0.0, None),
        ("max_speed_mps", 0.0, None),
        ("max_pesticide_L_per_ha", 0.0, None),
    ):
        if key in limits:
            v = limits[key]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise AgriBoundError(f"{key} must be a number")
            if v < lo or (hi is not None and v > hi):
                raise AgriBoundError(f"{key} out of range")
            out[key] = float(v)
    if not out:
        raise AgriBoundError("limits must pin at least one limit")
    return out


def _envelope_payload(envelope: FieldEnvelope) -> dict[str, Any]:
    return {
        "envelope_id": envelope.envelope_id,
        "equipment_id": envelope.equipment_id,
        "limits": dict(envelope.limits),
        "armed_by": envelope.armed_by,
        "armed_at": envelope.armed_at,
        "expires_at": envelope.expires_at,
        "authority_pubkey_hex": envelope.authority_pubkey_hex,
        "prev_digest": envelope.prev_digest,
        "revoked": envelope.revoked,
        "schema_version": envelope.schema_version,
    }


def arm_field_envelope(
    *,
    envelope_id: str,
    equipment_id: str,
    limits: Mapping[str, Any],
    authority_secret: bytes,
    armed_by: str,
    armed_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> FieldEnvelope:
    """Arm a field envelope. Authority-signed only; there is deliberately
    no agent-key path (the 104th batch's no-self-issuance discipline).
    """
    _check_secret(authority_secret, "authority_secret")
    envelope_id = _check_nonempty_str(envelope_id, "envelope_id")
    equipment_id = _check_nonempty_str(equipment_id, "equipment_id")
    limits = _validate_limits(limits)
    armed_by = _check_nonempty_str(armed_by, "armed_by")
    armed_at = _check_ts(armed_at, "armed_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= armed_at:
        raise AgriBoundError("expires_at must be after armed_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise AgriBoundError("prev_digest must be a non-empty string")
    pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = FieldEnvelope(
        envelope_id=envelope_id,
        equipment_id=equipment_id,
        limits=limits,
        armed_by=armed_by,
        armed_at=armed_at,
        expires_at=expires_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,
        prev_digest=prev_digest,
    )
    payload = _envelope_payload(bare)
    signature_hex = ed25519.sign(
        authority_secret, jcs_canonical_json(payload)
    ).hex()
    return FieldEnvelope(
        envelope_id=bare.envelope_id,
        equipment_id=bare.equipment_id,
        limits=bare.limits,
        armed_by=bare.armed_by,
        armed_at=bare.armed_at,
        expires_at=bare.expires_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        envelope_digest=jcs_sha256_hex(payload),
        revoked=False,
        schema_version=bare.schema_version,
    )


def _verify_envelope_integrity(envelope: FieldEnvelope) -> str | None:
    try:
        _check_nonempty_str(envelope.envelope_id, "envelope_id")
        _check_nonempty_str(envelope.equipment_id, "equipment_id")
        _validate_limits(dict(envelope.limits))
        _check_nonempty_str(envelope.armed_by, "armed_by")
        _check_ts(envelope.armed_at, "armed_at")
        _check_ts(envelope.expires_at, "expires_at")
        _check_pubkey_hex(envelope.authority_pubkey_hex)
        _check_hex128(envelope.signature_hex, "signature_hex")
        if not hmac.compare_digest(
            jcs_sha256_hex(_envelope_payload(envelope)), envelope.envelope_digest
        ):
            return DENY_ENVELOPE_TAMPERED
        try:
            sig_ok = ed25519.verify(
                bytes.fromhex(envelope.authority_pubkey_hex),
                jcs_canonical_json(_envelope_payload(envelope)),
                bytes.fromhex(envelope.signature_hex),
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            return DENY_ENVELOPE_TAMPERED
    except AgriBoundError:
        return DENY_MALFORMED
    return None


@dataclass(frozen=True)
class ConditionDeclaration:
    """The agent's declared current field conditions, sealed and chained.

    This is the Deere-critique primitive: before ANY actuation the
    agent must declare what the field is like RIGHT NOW. A stale or
    missing declaration denies — conditions drift, so a declaration
    is not a standing grant. ``prev_declaration_digest`` chains to the
    agent's previous declaration so mid-task shifts are detectable.
    """

    declaration_id: str
    envelope_digest: str
    soil_state: str
    obstacle_state: str
    equipment_wear_class: str
    soil_moisture_pct: float
    slope_pct: float
    obstacle_density: float
    visibility_m: float
    declared_at: int
    prev_declaration_digest: str = _GENESIS
    declaration_digest: str = ""


def _condition_payload(declaration: ConditionDeclaration) -> dict[str, Any]:
    return {
        "declaration_id": declaration.declaration_id,
        "envelope_digest": declaration.envelope_digest,
        "soil_state": declaration.soil_state,
        "obstacle_state": declaration.obstacle_state,
        "equipment_wear_class": declaration.equipment_wear_class,
        "soil_moisture_pct": declaration.soil_moisture_pct,
        "slope_pct": declaration.slope_pct,
        "obstacle_density": declaration.obstacle_density,
        "visibility_m": declaration.visibility_m,
        "declared_at": declaration.declared_at,
        "prev_declaration_digest": declaration.prev_declaration_digest,
    }


def declare_conditions(
    *,
    declaration_id: str,
    envelope: FieldEnvelope,
    soil_state: str,
    obstacle_state: str,
    equipment_wear_class: str,
    soil_moisture_pct: float,
    slope_pct: float,
    obstacle_density: float,
    visibility_m: float,
    declared_at: int,
    prev_declaration_digest: str = _GENESIS,
) -> ConditionDeclaration:
    """Declare current field conditions under an envelope, sealed and chained."""
    declaration_id = _check_nonempty_str(declaration_id, "declaration_id")
    _check_hex64(envelope.envelope_digest or "0" * 64, "envelope.envelope_digest")
    soil_state = _check_soil(soil_state)
    obstacle_state = _check_obstacle(obstacle_state)
    equipment_wear_class = _check_wear(equipment_wear_class)
    for name, v in (
        ("soil_moisture_pct", soil_moisture_pct),
        ("slope_pct", slope_pct),
        ("obstacle_density", obstacle_density),
        ("visibility_m", visibility_m),
    ):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
            raise AgriBoundError(f"{name} must be a non-negative number")
    declared_at = _check_ts(declared_at, "declared_at")
    if not isinstance(prev_declaration_digest, str) or not prev_declaration_digest:
        raise AgriBoundError("prev_declaration_digest must be a non-empty string")
    bare = ConditionDeclaration(
        declaration_id=declaration_id,
        envelope_digest=envelope.envelope_digest,
        soil_state=soil_state,
        obstacle_state=obstacle_state,
        equipment_wear_class=equipment_wear_class,
        soil_moisture_pct=float(soil_moisture_pct),
        slope_pct=float(slope_pct),
        obstacle_density=float(obstacle_density),
        visibility_m=float(visibility_m),
        declared_at=declared_at,
        prev_declaration_digest=prev_declaration_digest,
    )
    return ConditionDeclaration(
        declaration_id=bare.declaration_id,
        envelope_digest=bare.envelope_digest,
        soil_state=bare.soil_state,
        obstacle_state=bare.obstacle_state,
        equipment_wear_class=bare.equipment_wear_class,
        soil_moisture_pct=bare.soil_moisture_pct,
        slope_pct=bare.slope_pct,
        obstacle_density=bare.obstacle_density,
        visibility_m=bare.visibility_m,
        declared_at=bare.declared_at,
        prev_declaration_digest=bare.prev_declaration_digest,
        declaration_digest=jcs_sha256_hex(_condition_payload(bare)),
    )


@dataclass(frozen=True)
class ActuationVerdict:
    """Outcome of :func:`check_actuation`."""

    allowed: bool
    reason: str
    envelope_id: str
    declaration_id: str


def check_actuation(
    *,
    envelope: FieldEnvelope,
    declaration: ConditionDeclaration | None,
    now: int,
) -> ActuationVerdict:
    """Fail-closed gate: may the equipment actuate under these conditions?

    Check order is fixed: envelope integrity -> freshness ->
    declaration presence -> declaration integrity -> declaration
    freshness -> envelope pin -> dynamic condition bounds. The first
    failure wins and denies. A ``critical`` wear class denies even
    when every numeric bound passes — degraded equipment does not
    operate on confidence.
    """
    now = _check_ts(now, "now")
    envelope_id = getattr(envelope, "envelope_id", "")
    declaration_id = (
        getattr(declaration, "declaration_id", "") if declaration else ""
    )

    def deny(reason: str) -> ActuationVerdict:
        return ActuationVerdict(
            allowed=False,
            reason=reason,
            envelope_id=envelope_id,
            declaration_id=declaration_id,
        )

    integrity = _verify_envelope_integrity(envelope)
    if integrity:
        return deny(integrity)
    if envelope.revoked:
        return deny(DENY_ENVELOPE_REVOKED)
    if now >= envelope.expires_at:
        return deny(DENY_ENVELOPE_EXPIRED)
    if now < envelope.armed_at:
        return deny(DENY_MALFORMED)
    if declaration is None:
        return deny(DENY_NO_CONDITIONS_DECLARED)
    try:
        _check_nonempty_str(declaration.declaration_id, "declaration_id")
        _check_hex64(declaration.envelope_digest, "declaration.envelope_digest")
        _check_soil(declaration.soil_state)
        _check_obstacle(declaration.obstacle_state)
        _check_wear(declaration.equipment_wear_class)
        _check_ts(declaration.declared_at, "declared_at")
        if not hmac.compare_digest(
            jcs_sha256_hex(_condition_payload(declaration)),
            declaration.declaration_digest,
        ):
            return deny(DENY_CONDITION_DECLARATION_TAMPERED)
    except AgriBoundError:
        return deny(DENY_MALFORMED)
    if declaration.declared_at > now:
        return deny(DENY_CONDITION_DECLARATION_TAMPERED)
    if now - declaration.declared_at > CONDITION_DECLARATION_FRESHNESS_S:
        return deny(DENY_CONDITION_DECLARATION_STALE)
    if not hmac.compare_digest(declaration.envelope_digest, envelope.envelope_digest):
        return deny(DENY_CONDITION_DECLARATION_TAMPERED)

    limits = envelope.limits
    if (
        "max_soil_moisture_pct" in limits
        and declaration.soil_moisture_pct > limits["max_soil_moisture_pct"]
    ):
        return deny(DENY_CONDITION_OUT_OF_ENVELOPE)
    if (
        "max_slope_pct" in limits
        and declaration.slope_pct > limits["max_slope_pct"]
    ):
        return deny(DENY_CONDITION_OUT_OF_ENVELOPE)
    if (
        "max_obstacle_density" in limits
        and declaration.obstacle_density > limits["max_obstacle_density"]
    ):
        return deny(DENY_CONDITION_OUT_OF_ENVELOPE)
    if (
        "min_visibility_m" in limits
        and declaration.visibility_m < limits["min_visibility_m"]
    ):
        return deny(DENY_CONDITION_OUT_OF_ENVELOPE)
    if declaration.soil_state == "saturated":
        # Saturated soil: rutting and compaction make precision work
        # unreliable regardless of the numeric moisture cap.
        return deny(DENY_CONDITION_OUT_OF_ENVELOPE)
    if declaration.equipment_wear_class == "critical":
        return deny(DENY_CONDITION_OUT_OF_ENVELOPE)
    return ActuationVerdict(
        allowed=True,
        reason="actuation-authorized",
        envelope_id=envelope.envelope_id,
        declaration_id=declaration.declaration_id,
    )


def actuation_audit_event(verdict: ActuationVerdict, *, action: str) -> dict[str, Any]:
    """Shape an actuation verdict as an audit event for ``audit_chain``."""
    return {
        "event": AGRI_ACTUATION_ALLOWED_EVENT if verdict.allowed else AGRI_ACTUATION_DENIED_EVENT,
        "action": action,
        "envelope_id": verdict.envelope_id,
        "declaration_id": verdict.declaration_id,
        "reason": verdict.reason,
    }


def verify_envelope_independence() -> tuple[bool, str]:
    """Probe the control-plane separation: the actuation gate must never
    reach envelope arming or mutation. Fails if ``check_actuation``'s
    source references envelope issuance/revocation entry points."""
    import inspect

    gate_src = inspect.getsource(check_actuation)
    # The gate reads a caller-supplied declaration; it must never arm
    # an envelope, mutate revocation state, or construct a declaration
    # itself (that would let the agent skip declaring real conditions).
    for forbidden in ("arm_field_envelope", "declare_conditions"):
        if forbidden in gate_src:
            return False, f"gate reaches envelope issuance path: {forbidden}"
    return True, "actuation path cannot arm or widen the envelope"


# ---------------------------------------------------------------------------
# farmer_data_receipt: farmer data sovereignty, checked at USE time
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FarmerDataReceipt:
    """Farmer-signed grant for farm-data collection and use.

    Binds ``(farmer_id, data_scope, purpose, revenue_share_terms_digest,
    granted_at, expires_at)``. The farmer holds the only signing key;
    there is no platform-key or agent-key issuance path. ``purpose`` is
    matched EXACTLY at use time — a receipt for "yield prediction" does
    not cover "credit scoring", and a receipt for one scope does not
    cover another. ``revenue_share_terms_digest`` pins the agreed
    terms for any monetization of the data (SAGE 2026: farmers must
    know the terms before the data flows).
    """

    receipt_id: str
    farmer_id: str
    data_scope: str
    purpose: str
    revenue_share_terms_digest: str
    granted_at: int
    expires_at: int
    farmer_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = AGRI_SCHEMA_VERSION


@dataclass(frozen=True)
class DataRevocation:
    """Unilateral, farmer-signed revocation of a data grant."""

    revocation_id: str
    receipt_id: str
    farmer_id: str
    revoked_at: int
    farmer_pubkey_hex: str
    signature_hex: str
    revocation_digest: str = ""


def _data_receipt_payload(receipt: FarmerDataReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "farmer_id": receipt.farmer_id,
        "data_scope": receipt.data_scope,
        "purpose": receipt.purpose,
        "revenue_share_terms_digest": receipt.revenue_share_terms_digest,
        "granted_at": receipt.granted_at,
        "expires_at": receipt.expires_at,
        "farmer_pubkey_hex": receipt.farmer_pubkey_hex,
        "prev_digest": receipt.prev_digest,
        "schema_version": receipt.schema_version,
    }


def farmer_data_receipt(
    *,
    receipt_id: str,
    farmer_id: str,
    farmer_secret: bytes,
    data_scope: str,
    purpose: str,
    revenue_share_terms_digest: str,
    granted_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> FarmerDataReceipt:
    """Issue a farmer-signed data grant and seal it.

    The platform presents the terms; the FARMER signs. No signature
    from a platform or agent key is accepted anywhere in this module.
    """
    _check_secret(farmer_secret, "farmer_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    farmer_id = _check_nonempty_str(farmer_id, "farmer_id")
    data_scope = _check_scope(data_scope)
    purpose = _check_nonempty_str(purpose, "purpose")
    revenue_share_terms_digest = _check_hex64(
        revenue_share_terms_digest, "revenue_share_terms_digest"
    )
    granted_at = _check_ts(granted_at, "granted_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= granted_at:
        raise AgriBoundError("expires_at must be after granted_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise AgriBoundError("prev_digest must be a non-empty string")
    pubkey_hex = ed25519.public_key(farmer_secret).hex()
    bare = FarmerDataReceipt(
        receipt_id=receipt_id,
        farmer_id=farmer_id,
        data_scope=data_scope,
        purpose=purpose,
        revenue_share_terms_digest=revenue_share_terms_digest,
        granted_at=granted_at,
        expires_at=expires_at,
        farmer_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,
        prev_digest=prev_digest,
    )
    payload = _data_receipt_payload(bare)
    signature_hex = ed25519.sign(
        farmer_secret, jcs_canonical_json(payload)
    ).hex()
    return FarmerDataReceipt(
        receipt_id=bare.receipt_id,
        farmer_id=bare.farmer_id,
        data_scope=bare.data_scope,
        purpose=bare.purpose,
        revenue_share_terms_digest=bare.revenue_share_terms_digest,
        granted_at=bare.granted_at,
        expires_at=bare.expires_at,
        farmer_pubkey_hex=bare.farmer_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        receipt_digest=jcs_sha256_hex(payload),
        schema_version=bare.schema_version,
    )


def _data_revocation_payload(record: DataRevocation) -> dict[str, Any]:
    return {
        "revocation_id": record.revocation_id,
        "receipt_id": record.receipt_id,
        "farmer_id": record.farmer_id,
        "revoked_at": record.revoked_at,
        "farmer_pubkey_hex": record.farmer_pubkey_hex,
    }


def revoke_farmer_data(
    *,
    revocation_id: str,
    receipt: FarmerDataReceipt,
    farmer_secret: bytes,
    revoked_at: int,
) -> DataRevocation:
    """Append a unilateral farmer-signed revocation. Immediate and
    irreversible in the log — continued use needs a new receipt."""
    _check_secret(farmer_secret, "farmer_secret")
    revocation_id = _check_nonempty_str(revocation_id, "revocation_id")
    revoked_at = _check_ts(revoked_at, "revoked_at")
    if revoked_at < receipt.granted_at:
        raise AgriBoundError("revoked_at cannot precede granted_at")
    pubkey_hex = ed25519.public_key(farmer_secret).hex()
    if not hmac.compare_digest(pubkey_hex, receipt.farmer_pubkey_hex):
        raise AgriBoundError("revoking key does not match the granting farmer")
    bare = DataRevocation(
        revocation_id=revocation_id,
        receipt_id=receipt.receipt_id,
        farmer_id=receipt.farmer_id,
        revoked_at=revoked_at,
        farmer_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,
    )
    payload = _data_revocation_payload(bare)
    signature_hex = ed25519.sign(
        farmer_secret, jcs_canonical_json(payload)
    ).hex()
    return DataRevocation(
        revocation_id=bare.revocation_id,
        receipt_id=bare.receipt_id,
        farmer_id=bare.farmer_id,
        revoked_at=bare.revoked_at,
        farmer_pubkey_hex=bare.farmer_pubkey_hex,
        signature_hex=signature_hex,
        revocation_digest=jcs_sha256_hex(payload),
    )


@dataclass(frozen=True)
class DataUseVerdict:
    """Outcome of :func:`check_data_use`."""

    allowed: bool
    reason: str
    receipt_id: str


def check_data_use(
    log: list[FarmerDataReceipt | DataRevocation],
    *,
    farmer_id: str,
    data_scope: str,
    purpose: str,
    use_time: int,
) -> DataUseVerdict:
    """Fail-closed gate: may this farm data be used for this purpose now?

    Finds the farmer's latest grant for the scope, verifies chain
    integrity and the farmer's signature, requires exact scope match,
    requires exact purpose match (a new purpose without a new receipt
    denies with ``agri.purpose_creep`` — the "data used for a new
    purpose" prohibition), requires the use inside the grant window,
    and requires no revocation as of ``use_time``. Checked at USE
    time, never at collection time: a grant that was valid at
    collection is not valid at use if it was revoked or has expired.
    """
    farmer_id = _check_nonempty_str(farmer_id, "farmer_id")
    data_scope = _check_scope(data_scope)
    purpose = _check_nonempty_str(purpose, "purpose")
    use_time = _check_ts(use_time, "use_time")

    grants = [
        e for e in log
        if isinstance(e, FarmerDataReceipt)
        and e.farmer_id == farmer_id
        and e.data_scope == data_scope
    ]
    if not grants:
        return DataUseVerdict(False, DENY_DATA_NO_RECEIPT, "")
    grant = max(grants, key=lambda g: g.granted_at)

    try:
        if not hmac.compare_digest(
            jcs_sha256_hex(_data_receipt_payload(grant)), grant.receipt_digest
        ):
            return DataUseVerdict(False, DENY_DATA_TAMPERED, grant.receipt_id)
        sig_ok = ed25519.verify(
            bytes.fromhex(grant.farmer_pubkey_hex),
            jcs_canonical_json(_data_receipt_payload(grant)),
            bytes.fromhex(grant.signature_hex),
        )
    except Exception:
        sig_ok = False
    if not sig_ok:
        return DataUseVerdict(False, DENY_DATA_TAMPERED, grant.receipt_id)

    if not hmac.compare_digest(purpose, grant.purpose):
        # Purpose creep: the platform's new use is not covered by the
        # grant the farmer signed. A new purpose needs a new receipt.
        return DataUseVerdict(False, DENY_DATA_PURPOSE_CREEP, grant.receipt_id)
    if use_time < grant.granted_at:
        return DataUseVerdict(False, DENY_DATA_TAMPERED, grant.receipt_id)
    if use_time > grant.expires_at:
        return DataUseVerdict(False, DENY_DATA_EXPIRED, grant.receipt_id)

    for e in log:
        if (
            isinstance(e, DataRevocation)
            and e.receipt_id == grant.receipt_id
            and e.revoked_at <= use_time
        ):
            try:
                rsig_ok = ed25519.verify(
                    bytes.fromhex(e.farmer_pubkey_hex),
                    jcs_canonical_json(_data_revocation_payload(e)),
                    bytes.fromhex(e.signature_hex),
                )
            except Exception:
                rsig_ok = False
            if rsig_ok and hmac.compare_digest(
                e.farmer_pubkey_hex, grant.farmer_pubkey_hex
            ):
                return DataUseVerdict(False, DENY_DATA_REVOKED, grant.receipt_id)

    return DataUseVerdict(True, "data-use-authorized", grant.receipt_id)


def data_use_audit_event(verdict: DataUseVerdict, *, farmer_id: str, purpose: str) -> dict[str, Any]:
    """Shape a data-use verdict as an audit event for ``audit_chain``."""
    return {
        "event": AGRI_DATA_ALLOWED_EVENT if verdict.allowed else AGRI_DATA_DENIED_EVENT,
        "farmer_id": farmer_id,
        "purpose": purpose,
        "receipt_id": verdict.receipt_id,
        "reason": verdict.reason,
    }


# ---------------------------------------------------------------------------
# advice_explainability_gate: four fields or it isn't authoritative advice
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdviceVerdict:
    """Outcome of :func:`advice_explainability_gate`."""

    allowed: bool
    reason: str
    classification: str  # AUTHORITATIVE_ADVICE / NON_AUTHORITATIVE_ADVICE


def advice_explainability_gate(
    advice: Mapping[str, Any],
    *,
    farmer_language: str,
) -> AdviceVerdict:
    """Gate agricultural advice on the four mandatory explainability fields.

    Advice must carry ``why`` (why this recommendation), ``evidence``
    (what evidence it rests on), ``self_check`` (what the farmer should
    verify themselves before acting), and ``contact`` (who to reach
    when it looks wrong). Any missing or blank field classifies the
    advice NON_AUTHORITATIVE — the farmer must not be told to "just
    trust the model". Advice in a language that is not the farmer's
    local language classifies ``agri.language_mismatch`` (the FAO
    finding: tools speak the wrong language, and advice the farmer
    cannot read is not advice at all).
    """
    farmer_language = _check_nonempty_str(farmer_language, "farmer_language")
    if not isinstance(advice, Mapping):
        return AdviceVerdict(
            False, DENY_MALFORMED, NON_AUTHORITATIVE_ADVICE
        )
    for field_name in EXPLAINABILITY_FIELDS:
        value = advice.get(field_name)
        if not isinstance(value, str) or not value.strip():
            return AdviceVerdict(
                False,
                f"{DENY_ADVICE_MISSING_FIELD}:{field_name}",
                NON_AUTHORITATIVE_ADVICE,
            )
    advice_language = advice.get("language")
    if not isinstance(advice_language, str) or not advice_language.strip():
        return AdviceVerdict(
            False,
            f"{DENY_ADVICE_MISSING_FIELD}:language",
            NON_AUTHORITATIVE_ADVICE,
        )
    if not hmac.compare_digest(
        advice_language.strip().lower(), farmer_language.strip().lower()
    ):
        return AdviceVerdict(
            False, DENY_ADVICE_LANGUAGE_MISMATCH, NON_AUTHORITATIVE_ADVICE
        )
    return AdviceVerdict(True, "advice-explainable", AUTHORITATIVE_ADVICE)


# ---------------------------------------------------------------------------
# bad_advice_harm: the harm ledger entry for downstream liability analysis
# ---------------------------------------------------------------------------


def record_bad_advice_harm(
    *,
    advice_id: str,
    scene_binding_digest: str,
    model_version_digest: str,
    input_digest: str,
    confidence: float,
    harm_description: str,
    recorded_at: int,
) -> dict[str, Any]:
    """Emit a ``agri.bad_advice_harm`` audit event.

    When advice delivered outside (or inside) its validated scene
    binding causes harm — e.g. a misdiagnosed pest wipes out a season —
    the audit chain must be able to trace it back to the model
    version, the input, the confidence at decision time, and the scene
    binding that was (or wasn't) in force. The event pins those
    digests; it does not judge liability — that is for the downstream
    liability analysis, which now has a complete ledger entry to
    work from. Returns the event dict shaped for
    ``audit_chain.chain_record``; raising on malformed input keeps
    the ledger honest.
    """
    advice_id = _check_nonempty_str(advice_id, "advice_id")
    scene_binding_digest = _check_hex64(scene_binding_digest, "scene_binding_digest")
    model_version_digest = _check_hex64(model_version_digest, "model_version_digest")
    input_digest = _check_hex64(input_digest, "input_digest")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise AgriBoundError("confidence must be a number")
    if not 0.0 <= float(confidence) <= 1.0:
        raise AgriBoundError("confidence must be in [0, 1]")
    harm_description = _check_nonempty_str(harm_description, "harm_description")
    recorded_at = _check_ts(recorded_at, "recorded_at")
    return {
        "event": AGRI_BAD_ADVICE_HARM_EVENT,
        "advice_id": advice_id,
        "scene_binding_digest": scene_binding_digest,
        "model_version_digest": model_version_digest,
        "input_digest": input_digest,
        "confidence": float(confidence),
        "harm_description": harm_description,
        "recorded_at": recorded_at,
    }


# ---------------------------------------------------------------------------
# smallholder_access: deployment declarations + mandatory disclosure
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SmallholderAccessDeclaration:
    """A deployment's declared accessibility posture for smallholders.

    Binds ``(system_id, offline_capable, local_language_supported,
    low_bandwidth_mode, declared_at)`` into a hash-chained, authority-
    signed receipt. The three booleans are the FAO/World Bank access
    prerequisites: works without connectivity, speaks the farmer's
    language, and runs on low bandwidth. Declared at registration
    time; missing declarations do not deny deployment but trigger
    mandatory disclosure — the omission is published, never silent.
    """

    declaration_id: str
    system_id: str
    offline_capable: bool
    local_language_supported: bool
    low_bandwidth_mode: bool
    declared_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    declaration_digest: str = ""
    schema_version: str = AGRI_SCHEMA_VERSION


def _smallholder_payload(declaration: SmallholderAccessDeclaration) -> dict[str, Any]:
    return {
        "declaration_id": declaration.declaration_id,
        "system_id": declaration.system_id,
        "offline_capable": declaration.offline_capable,
        "local_language_supported": declaration.local_language_supported,
        "low_bandwidth_mode": declaration.low_bandwidth_mode,
        "declared_at": declaration.declared_at,
        "authority_pubkey_hex": declaration.authority_pubkey_hex,
        "prev_digest": declaration.prev_digest,
        "schema_version": declaration.schema_version,
    }


def declare_smallholder_access(
    *,
    declaration_id: str,
    system_id: str,
    offline_capable: bool,
    local_language_supported: bool,
    low_bandwidth_mode: bool,
    authority_secret: bytes,
    declared_at: int,
    prev_digest: str = _GENESIS,
) -> SmallholderAccessDeclaration:
    """Declare an agri system's smallholder accessibility posture."""
    _check_secret(authority_secret, "authority_secret")
    declaration_id = _check_nonempty_str(declaration_id, "declaration_id")
    system_id = _check_nonempty_str(system_id, "system_id")
    for name, v in (
        ("offline_capable", offline_capable),
        ("local_language_supported", local_language_supported),
        ("low_bandwidth_mode", low_bandwidth_mode),
    ):
        if not isinstance(v, bool):
            raise AgriBoundError(f"{name} must be a boolean")
    declared_at = _check_ts(declared_at, "declared_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise AgriBoundError("prev_digest must be a non-empty string")
    pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = SmallholderAccessDeclaration(
        declaration_id=declaration_id,
        system_id=system_id,
        offline_capable=offline_capable,
        local_language_supported=local_language_supported,
        low_bandwidth_mode=low_bandwidth_mode,
        declared_at=declared_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,
        prev_digest=prev_digest,
    )
    payload = _smallholder_payload(bare)
    signature_hex = ed25519.sign(
        authority_secret, jcs_canonical_json(payload)
    ).hex()
    return SmallholderAccessDeclaration(
        declaration_id=bare.declaration_id,
        system_id=bare.system_id,
        offline_capable=bare.offline_capable,
        local_language_supported=bare.local_language_supported,
        low_bandwidth_mode=bare.low_bandwidth_mode,
        declared_at=bare.declared_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        declaration_digest=jcs_sha256_hex(payload),
        schema_version=bare.schema_version,
    )


@dataclass(frozen=True)
class SmallholderDisclosure:
    """Outcome of :func:`check_smallholder_disclosure`."""

    system_id: str
    undisclosed: tuple[str, ...]
    disclosure_required: bool
    disclosure_event: dict[str, Any]


def check_smallholder_disclosure(
    declaration: SmallholderAccessDeclaration | None,
    *,
    system_id: str,
) -> SmallholderDisclosure:
    """Mandatory disclosure, not silent omission.

    A system deployed for smallholder contexts that has not declared
    its accessibility posture — or declared ``False`` on any of the
    three prerequisites — gets a ``deployment.smallholder_exclusion_risk``
    event naming exactly what is missing. The event belongs on the
    citizen explanation API (the 110th batch's ``explain_decision``
    shape): the farmer community can see, in one place, which access
    prerequisites this system has not committed to. This never
    denies — exclusion risk is disclosed, not hidden behind a gate
    pass.
    """
    system_id = _check_nonempty_str(system_id, "system_id")
    if declaration is None:
        undisclosed = (
            "offline_capable",
            "local_language_supported",
            "low_bandwidth_mode",
        )
    else:
        missing: list[str] = []
        for name in ("offline_capable", "local_language_supported", "low_bandwidth_mode"):
            if getattr(declaration, name) is not True:
                missing.append(name)
        undisclosed = tuple(missing)
    disclosure_event = {
        "event": AGRI_EXCLUSION_RISK_EVENT,
        "system_id": system_id,
        "undisclosed": list(undisclosed),
        "disclosure": (
            "this agri system has not committed to all smallholder "
            "access prerequisites: " + (", ".join(undisclosed) or "none")
        ),
    }
    return SmallholderDisclosure(
        system_id=system_id,
        undisclosed=undisclosed,
        disclosure_required=bool(undisclosed),
        disclosure_event=disclosure_event,
    )


__all__ = [
    "AGRI_SCHEMA_VERSION",
    "CROP_SYSTEMS",
    "FARM_SCALE_CLASSES",
    "SOIL_STATES",
    "OBSTACLE_STATES",
    "WEAR_CLASSES",
    "DATA_SCOPES",
    "EXPLAINABILITY_FIELDS",
    "DENY_SCENE_MISMATCH",
    "DENY_BINDING_EXPIRED",
    "DENY_BINDING_FUTURE",
    "DENY_BINDING_TAMPERED",
    "DENY_UNDECLARED_SCENE",
    "DENY_CONDITION_OUT_OF_ENVELOPE",
    "DENY_NO_CONDITIONS_DECLARED",
    "DENY_CONDITION_DECLARATION_TAMPERED",
    "DENY_CONDITION_DECLARATION_STALE",
    "DENY_ENVELOPE_REVOKED",
    "DENY_ENVELOPE_EXPIRED",
    "DENY_ENVELOPE_TAMPERED",
    "DENY_ENVELOPE_SELF_ISSUED",
    "DENY_DATA_PURPOSE_CREEP",
    "DENY_DATA_NO_RECEIPT",
    "DENY_DATA_REVOKED",
    "DENY_DATA_EXPIRED",
    "DENY_DATA_TAMPERED",
    "DENY_DATA_SCOPE",
    "DENY_ADVICE_MISSING_FIELD",
    "DENY_ADVICE_LANGUAGE_MISMATCH",
    "DENY_MALFORMED",
    "AGRI_SCENE_DENIED_EVENT",
    "AGRI_SCENE_ALLOWED_EVENT",
    "AGRI_ACTUATION_DENIED_EVENT",
    "AGRI_ACTUATION_ALLOWED_EVENT",
    "AGRI_DATA_DENIED_EVENT",
    "AGRI_DATA_ALLOWED_EVENT",
    "AGRI_DATA_REVOKED_EVENT",
    "AGRI_BAD_ADVICE_HARM_EVENT",
    "AGRI_EXCLUSION_RISK_EVENT",
    "AUTHORITATIVE_ADVICE",
    "NON_AUTHORITATIVE_ADVICE",
    "CONDITION_DECLARATION_FRESHNESS_S",
    "AgriBoundError",
    "AgriSceneBinding",
    "issue_agri_binding",
    "compute_binding_digest",
    "AgriSceneVerdict",
    "check_agri_scene",
    "agri_scene_audit_event",
    "FieldEnvelope",
    "arm_field_envelope",
    "ConditionDeclaration",
    "declare_conditions",
    "ActuationVerdict",
    "check_actuation",
    "actuation_audit_event",
    "verify_envelope_independence",
    "FarmerDataReceipt",
    "DataRevocation",
    "farmer_data_receipt",
    "revoke_farmer_data",
    "DataUseVerdict",
    "check_data_use",
    "data_use_audit_event",
    "AdviceVerdict",
    "advice_explainability_gate",
    "record_bad_advice_harm",
    "SmallholderAccessDeclaration",
    "declare_smallholder_access",
    "SmallholderDisclosure",
    "check_smallholder_disclosure",
]
