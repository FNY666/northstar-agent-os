"""Scene-bound authorization receipts (one-hundred-seventh batch).

Absorbs the 2026 AI-healthcare research thread (mechanism ideas only,
honestly scoped):

* **Authorization is scene-dependent.** A JACR prospective study (3,856
  cases) found brain-aneurysm AI reaching 0.846 sensitivity vs 0.718 for
  physicians — but the effect was extremely scene-dependent: strong
  inpatient, heavy false-positive load outpatient. An authorization
  granted for one scene does not transfer to another. Here every
  capability is bound to an explicit set of ``(care_setting,
  demographic_stratum)`` pairs; use outside the bound set denies.
* **The FDA demographic gap, made fail-closed.** FDA's 2025-01 guidance
  only *suggests* reporting performance by demographic subgroup — as of
  2026-09 a device could still be cleared without ever validating on
  women. Here the performance manifest is mandatory: any stratum
  missing from the manifest is NOT authorized, full stop. There is no
  "probably fine" rung.
* **Recording consent before capture.** Sutter Health was hit with a
  class action in 2026-04 over ambient clinical recording without
  patient informed consent. Ambient capture (audio/video/screen) here
  requires a fresh, subject-signed, purpose-bound recording-consent
  receipt BEFORE capture starts; capture without one denies, and
  revocation is checked at use time, never at collection time (the
  105th batch's consent discipline, applied to capture modalities).

Northstar mapping:

* ``SceneBinding`` — a hash-chained, authority-signed receipt binding
  ``(capability_id, model_version_digest, authorized_pairs,
  manifest_digest)``. ``authorized_pairs`` is a closed-vocabulary set
  of ``(care_setting, demographic_stratum)``. The binding is issued by
  a registered human authority (Ed25519); there is no agent-key path
  (94th/104th-batch no-self-issuance discipline).
* ``declare_scene()`` — the agent must declare its observed scene, and
  the declaration is itself a chained receipt: silent mid-task scene
  shifts are detectable as chain breaks. An undeclared scene denies.
* ``check_scene_authorized()`` — fail-closed gate: undeclared scene,
  out-of-scope pair, manifest mismatch, unvalidated stratum, expired
  or tampered binding all deny. Denials audit as
  ``scene.out_of_scope_denied``.
* ``authorize_capture()`` — ambient-capture gate over a
  subject-signed, revocable recording-consent log (modalities
  ``audio``/``video``/``screen``). Denials audit as
  ``scene.capture_denied``.
* ``bind_model_to_scene()`` / ``check_model_invocation()`` — a model
  version is only invocable for scenes in its binding; invocation for
  an unbound scene classifies ``unverifiable-process`` (87th-batch
  binary semantics: there is no partial tier to launder an
  out-of-scope invocation through).

Honest boundary: this module verifies *declared*-scene consistency
against the binding — digests recompute, signatures verify, the
manifest pins. It cannot verify that the physically true scene
matches the declared one; that needs sensor attestation (twin_receipts
discipline) and is noted as future work. Likewise it cannot prove the
consenting subject understood the grant.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

SCENE_BOUND_SCHEMA_VERSION = "northstar.scene-bound.v1"

#: Closed care-setting vocabulary. Scene is matched exactly — a binding
#: for ``inpatient`` does not cover ``emergency``.
CARE_SETTINGS: tuple[str, ...] = (
    "inpatient",
    "outpatient",
    "emergency",
    "telehealth",
    "home_care",
)

#: Closed demographic-stratum vocabulary. Strata are matched exactly
#: against the performance manifest — a missing stratum is NOT
#: authorized (the FDA 2025-01 gap, made fail-closed).
DEMOGRAPHIC_STRATA: tuple[str, ...] = (
    "pediatric",
    "adult_18_64",
    "adult_65_plus",
)

#: Closed ambient-capture modality vocabulary.
CAPTURE_MODALITIES: tuple[str, ...] = (
    "audio",
    "video",
    "screen",
)

#: Denial reason codes. All start with the ``scene:`` prefix.
DENY_UNDECLARED_SCENE = "scene:undeclared_scene"
DENY_OUT_OF_SCOPE = "scene:out_of_scope"
DENY_MANIFEST_MISMATCH = "scene:manifest_mismatch"
DENY_UNVALIDATED_STRATUM = "scene:unvalidated_stratum"
DENY_BINDING_EXPIRED = "scene:binding_expired"
DENY_BINDING_FUTURE = "scene:binding_from_future"
DENY_BINDING_TAMPERED = "scene:binding_tampered"
DENY_DECLARATION_TAMPERED = "scene:declaration_tampered"
DENY_DECLARATION_FUTURE = "scene:declaration_from_future"
DENY_DECLARATION_UNBOUND = "scene:declaration_unbound"
DENY_UNKNOWN_MODEL = "scene:unknown_model"
DENY_CAPTURE_NO_CONSENT = "scene:capture_no_consent"
DENY_CAPTURE_REVOKED = "scene:capture_revoked"
DENY_CAPTURE_EXPIRED = "scene:capture_expired"
DENY_CAPTURE_SCOPE = "scene:capture_scope_mismatch"
DENY_CAPTURE_TAMPERED = "scene:capture_log_tampered"
DENY_MALFORMED = "scene:malformed"

#: Audit event names (shaped for ``audit_chain.chain_record``).
SCENE_DECLARED_EVENT = "scene.scene_declared"
SCENE_ALLOWED_EVENT = "scene.scene_allowed"
SCENE_DENIED_EVENT = "scene.out_of_scope_denied"
CAPTURE_ALLOWED_EVENT = "scene.capture_allowed"
CAPTURE_DENIED_EVENT = "scene.capture_denied"

#: Binary evidence tiers (87th-batch semantics).
AUTHORITATIVE_SCENE = "authoritative-scene"
NON_AUTHORITATIVE_SCENE = "non-authoritative-scene"
UNVERIFIABLE_PROCESS = "unverifiable-process"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class SceneBoundError(ValueError):
    """Malformed binding/declaration/manifest or a programming error.

    Raised for structural problems (unknown vocabulary, bad digests,
    non-hex fields). Verification *failures* (out-of-scope, expired,
    revoked, bad signature at check time) return verdicts with
    ``allowed=False`` — a failed scene check is a verdict, a malformed
    log is a bug.
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
        raise SceneBoundError(f"{field_name} must be 64 lowercase hex chars")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise SceneBoundError(f"{field_name} must be 128 lowercase hex chars")
    return value


def _check_setting(value: Any) -> str:
    if value not in CARE_SETTINGS:
        raise SceneBoundError(
            f"unknown care setting {value!r}; closed vocabulary {CARE_SETTINGS}"
        )
    return value


def _check_stratum(value: Any) -> str:
    if value not in DEMOGRAPHIC_STRATA:
        raise SceneBoundError(
            f"unknown demographic stratum {value!r}; closed vocabulary {DEMOGRAPHIC_STRATA}"
        )
    return value


def _check_modality(value: Any) -> str:
    if value not in CAPTURE_MODALITIES:
        raise SceneBoundError(
            f"unknown capture modality {value!r}; closed vocabulary {CAPTURE_MODALITIES}"
        )
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SceneBoundError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed (no keypair()).
    if not isinstance(value, bytes) or len(value) != 32:
        raise SceneBoundError(f"{field_name} must be a 32-byte seed")
    return value


def _check_pubkey_hex(value: Any) -> str:
    return _check_hex64(value, "pubkey_hex")


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SceneBoundError(f"{field_name} must be a non-empty string")
    return value


# ---------------------------------------------------------------------------
# Performance manifest
# ---------------------------------------------------------------------------


def build_performance_manifest(
    entries: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, float]]:
    """Build a validated performance manifest.

    ``entries`` maps demographic stratum -> ``{"sensitivity": float,
    "specificity": float, "n": int}``. Strata must come from the closed
    :data:`DEMOGRAPHIC_STRATA` vocabulary; sensitivities/specificities
    must be in ``[0, 1]``; ``n`` must be a positive int. Anything else
    raises :class:`SceneBoundError` — the manifest is the validation
    boundary, never a guess.
    """
    if not isinstance(entries, Mapping) or not entries:
        raise SceneBoundError("performance manifest must be a non-empty mapping")
    manifest: dict[str, dict[str, float]] = {}
    for stratum, metrics in entries.items():
        _check_stratum(stratum)
        if not isinstance(metrics, Mapping):
            raise SceneBoundError(f"metrics for {stratum!r} must be a mapping")
        for key in ("sensitivity", "specificity"):
            val = metrics.get(key)
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                raise SceneBoundError(f"{stratum}.{key} must be a number")
            if not 0.0 <= float(val) <= 1.0:
                raise SceneBoundError(f"{stratum}.{key} must be in [0, 1]")
        n = metrics.get("n")
        # Idempotent: a manifest that already passed validation stores n
        # as float; accept integral floats so re-validation succeeds.
        if isinstance(n, float) and n.is_integer() and n > 0:
            n = int(n)
        if not isinstance(n, int) or isinstance(n, bool) or n <= 0:
            raise SceneBoundError(f"{stratum}.n must be a positive int")
        manifest[stratum] = {
            "sensitivity": float(metrics["sensitivity"]),
            "specificity": float(metrics["specificity"]),
            "n": float(n),
        }
    return manifest


def manifest_digest(manifest: Mapping[str, Mapping[str, float]]) -> str:
    """JCS digest pinning a performance manifest."""
    return jcs_sha256_hex(dict(manifest))


# ---------------------------------------------------------------------------
# SceneBinding: authority-signed, hash-chained authorization receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SceneBinding:
    """Authorization of a capability for explicit (setting, stratum) pairs.

    ``authorized_pairs`` is a sorted tuple of ``(care_setting,
    demographic_stratum)`` drawn from the closed vocabularies.
    ``manifest_digest`` pins the performance manifest; every stratum
    appearing in ``authorized_pairs`` must have a manifest entry at
    issuance (fail-closed FDA gap). ``authority_pubkey_hex`` names the
    human authority that signed; ``prev_digest`` chains to the previous
    binding for the same capability (``"genesis"`` for the first).
    """

    binding_id: str
    capability_id: str
    model_version_digest: str
    authorized_pairs: tuple[tuple[str, str], ...]
    manifest_digest: str
    authorized_by: str
    authorized_at: int
    expires_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    binding_digest: str = ""
    schema_version: str = SCENE_BOUND_SCHEMA_VERSION


def _binding_payload(binding: SceneBinding) -> dict[str, Any]:
    return {
        "binding_id": binding.binding_id,
        "capability_id": binding.capability_id,
        "model_version_digest": binding.model_version_digest,
        "authorized_pairs": [list(p) for p in binding.authorized_pairs],
        "manifest_digest": binding.manifest_digest,
        "authorized_by": binding.authorized_by,
        "authorized_at": binding.authorized_at,
        "expires_at": binding.expires_at,
        "authority_pubkey_hex": binding.authority_pubkey_hex,
        "prev_digest": binding.prev_digest,
        "schema_version": binding.schema_version,
    }


def compute_binding_digest(binding: SceneBinding) -> str:
    """Recompute the JCS digest a binding claims."""
    return jcs_sha256_hex(_binding_payload(binding))


def issue_binding(
    *,
    binding_id: str,
    capability_id: str,
    model_version_digest: str,
    authorized_pairs: list[tuple[str, str]],
    manifest: Mapping[str, Mapping[str, float]],
    authority_secret: bytes,
    authorized_by: str,
    authorized_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> SceneBinding:
    """Issue an authority-signed scene binding and seal it.

    Fail-closed at issuance: unknown settings/strata raise, duplicate
    pairs raise, any stratum in ``authorized_pairs`` missing from the
    manifest raises (the FDA gap — an unvalidated stratum can never be
    authorized), and ``expires_at <= authorized_at`` raises. The
    signature is over the canonical payload (signature excluded from
    the digest input, 97th-batch envelope-pinning pattern).
    """
    _check_secret(authority_secret, "authority_secret")
    binding_id = _check_nonempty_str(binding_id, "binding_id")
    capability_id = _check_nonempty_str(capability_id, "capability_id")
    model_version_digest = _check_hex64(model_version_digest, "model_version_digest")
    authorized_by = _check_nonempty_str(authorized_by, "authorized_by")
    authorized_at = _check_ts(authorized_at, "authorized_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= authorized_at:
        raise SceneBoundError("expires_at must be after authorized_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise SceneBoundError("prev_digest must be a non-empty string")

    pairs: list[tuple[str, str]] = []
    for setting, stratum in authorized_pairs:
        pairs.append((_check_setting(setting), _check_stratum(stratum)))
    if not pairs:
        raise SceneBoundError("authorized_pairs must be non-empty")
    if len(set(pairs)) != len(pairs):
        raise SceneBoundError("duplicate (setting, stratum) pair")
    pairs = sorted(set(pairs))

    manifest = build_performance_manifest(manifest)
    for _, stratum in pairs:
        if stratum not in manifest:
            raise SceneBoundError(
                f"stratum {stratum!r} authorized but missing from the "
                "performance manifest — unvalidated strata are never authorized"
            )

    pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = SceneBinding(
        binding_id=binding_id,
        capability_id=capability_id,
        model_version_digest=model_version_digest,
        authorized_pairs=tuple(pairs),
        manifest_digest=manifest_digest(manifest),
        authorized_by=authorized_by,
        authorized_at=authorized_at,
        expires_at=expires_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,  # placeholder; replaced below
        prev_digest=prev_digest,
    )
    payload = _binding_payload(bare)
    signature_hex = ed25519.sign(
        authority_secret, jcs_canonical_json(payload)
    ).hex()
    return SceneBinding(
        binding_id=bare.binding_id,
        capability_id=bare.capability_id,
        model_version_digest=bare.model_version_digest,
        authorized_pairs=bare.authorized_pairs,
        manifest_digest=bare.manifest_digest,
        authorized_by=bare.authorized_by,
        authorized_at=bare.authorized_at,
        expires_at=bare.expires_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        binding_digest=jcs_sha256_hex(payload),
        schema_version=bare.schema_version,
    )


def _verify_binding_integrity(binding: SceneBinding) -> str | None:
    """Return a denial reason if the binding is malformed/tampered, else None."""
    try:
        _check_nonempty_str(binding.binding_id, "binding_id")
        _check_nonempty_str(binding.capability_id, "capability_id")
        _check_hex64(binding.model_version_digest, "model_version_digest")
        _check_hex64(binding.manifest_digest, "manifest_digest")
        _check_nonempty_str(binding.authorized_by, "authorized_by")
        _check_ts(binding.authorized_at, "authorized_at")
        _check_ts(binding.expires_at, "expires_at")
        _check_pubkey_hex(binding.authority_pubkey_hex)
        _check_hex128(binding.signature_hex, "signature_hex")
        pairs = [(_check_setting(s), _check_stratum(t)) for s, t in binding.authorized_pairs]
        if not pairs or len(set(pairs)) != len(pairs):
            return DENY_MALFORMED
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
    except SceneBoundError:
        return DENY_MALFORMED
    return None


# ---------------------------------------------------------------------------
# SceneDeclaration: the agent's declared observed scene, chained
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SceneDeclaration:
    """The agent's declared observed scene for one task step.

    ``binding_digest`` pins the binding this declaration is made under;
    ``prev_declaration_digest`` chains to the agent's previous
    declaration (``"genesis"`` for the first), so a silent mid-task
    scene shift is detectable as a chain break. There is no way to
    "just act" without declaring — the gate requires a declaration.
    """

    declaration_id: str
    binding_digest: str
    care_setting: str
    demographic_stratum: str
    declared_at: int
    prev_declaration_digest: str = _GENESIS
    declaration_digest: str = ""


def _declaration_payload(declaration: SceneDeclaration) -> dict[str, Any]:
    return {
        "declaration_id": declaration.declaration_id,
        "binding_digest": declaration.binding_digest,
        "care_setting": declaration.care_setting,
        "demographic_stratum": declaration.demographic_stratum,
        "declared_at": declaration.declared_at,
        "prev_declaration_digest": declaration.prev_declaration_digest,
    }


def declare_scene(
    *,
    declaration_id: str,
    binding: SceneBinding,
    care_setting: str,
    demographic_stratum: str,
    declared_at: int,
    prev_declaration_digest: str = _GENESIS,
) -> SceneDeclaration:
    """Declare the observed scene under a binding, sealed and chained."""
    declaration_id = _check_nonempty_str(declaration_id, "declaration_id")
    _check_hex64(binding.binding_digest or "0" * 64, "binding.binding_digest")
    care_setting = _check_setting(care_setting)
    demographic_stratum = _check_stratum(demographic_stratum)
    declared_at = _check_ts(declared_at, "declared_at")
    if not isinstance(prev_declaration_digest, str) or not prev_declaration_digest:
        raise SceneBoundError("prev_declaration_digest must be a non-empty string")
    bare = SceneDeclaration(
        declaration_id=declaration_id,
        binding_digest=binding.binding_digest,
        care_setting=care_setting,
        demographic_stratum=demographic_stratum,
        declared_at=declared_at,
        prev_declaration_digest=prev_declaration_digest,
    )
    return SceneDeclaration(
        declaration_id=bare.declaration_id,
        binding_digest=bare.binding_digest,
        care_setting=bare.care_setting,
        demographic_stratum=bare.demographic_stratum,
        declared_at=bare.declared_at,
        prev_declaration_digest=bare.prev_declaration_digest,
        declaration_digest=jcs_sha256_hex(_declaration_payload(bare)),
    )


# ---------------------------------------------------------------------------
# The scene gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SceneVerdict:
    """Outcome of :func:`check_scene_authorized`."""

    allowed: bool
    reason: str
    classification: str  # AUTHORITATIVE_SCENE / NON_AUTHORITATIVE_SCENE
    binding_id: str
    declaration_id: str


def check_scene_authorized(
    binding: SceneBinding,
    declaration: SceneDeclaration | None,
    manifest: Mapping[str, Mapping[str, float]],
    *,
    now: int,
) -> SceneVerdict:
    """Fail-closed gate: is this declared scene authorized for use?

    Check order is fixed: binding integrity -> binding time window ->
    declaration presence/integrity/binding-pin -> pair membership ->
    manifest pin -> stratum coverage. The first failure wins and
    denies; denials are verdicts, never exceptions.
    """
    now = _check_ts(now, "now")
    binding_id = getattr(binding, "binding_id", "")
    declaration_id = getattr(declaration, "declaration_id", "") if declaration else ""

    def deny(reason: str) -> SceneVerdict:
        return SceneVerdict(
            allowed=False,
            reason=reason,
            classification=NON_AUTHORITATIVE_SCENE,
            binding_id=binding_id,
            declaration_id=declaration_id,
        )

    integrity = _verify_binding_integrity(binding)
    if integrity:
        return deny(integrity)
    if now < binding.authorized_at:
        return deny(DENY_BINDING_FUTURE)
    if now > binding.expires_at:
        return deny(DENY_BINDING_EXPIRED)
    if declaration is None:
        return deny(DENY_UNDECLARED_SCENE)
    try:
        _check_nonempty_str(declaration.declaration_id, "declaration_id")
        _check_hex64(declaration.binding_digest, "declaration.binding_digest")
        _check_setting(declaration.care_setting)
        _check_stratum(declaration.demographic_stratum)
        _check_ts(declaration.declared_at, "declared_at")
        if not hmac.compare_digest(
            jcs_sha256_hex(_declaration_payload(declaration)),
            declaration.declaration_digest,
        ):
            return deny(DENY_DECLARATION_TAMPERED)
    except SceneBoundError:
        return deny(DENY_MALFORMED)
    if declaration.declared_at > now:
        return deny(DENY_DECLARATION_FUTURE)
    if not hmac.compare_digest(declaration.binding_digest, binding.binding_digest):
        return deny(DENY_DECLARATION_UNBOUND)
    if (declaration.care_setting, declaration.demographic_stratum) not in set(
        binding.authorized_pairs
    ):
        return deny(DENY_OUT_OF_SCOPE)
    try:
        manifest = build_performance_manifest(manifest)
    except SceneBoundError:
        return deny(DENY_MALFORMED)
    if not hmac.compare_digest(manifest_digest(manifest), binding.manifest_digest):
        return deny(DENY_MANIFEST_MISMATCH)
    if declaration.demographic_stratum not in manifest:
        # Defense in depth: issuance already refuses this, but a
        # hand-crafted binding must not slip through either.
        return deny(DENY_UNVALIDATED_STRATUM)
    return SceneVerdict(
        allowed=True,
        reason="scene-authorized",
        classification=AUTHORITATIVE_SCENE,
        binding_id=binding.binding_id,
        declaration_id=declaration.declaration_id,
    )


def scene_audit_event(verdict: SceneVerdict, *, action: str) -> dict[str, Any]:
    """Shape a scene verdict as an audit event for ``audit_chain``."""
    return {
        "event": SCENE_ALLOWED_EVENT if verdict.allowed else SCENE_DENIED_EVENT,
        "action": action,
        "binding_id": verdict.binding_id,
        "declaration_id": verdict.declaration_id,
        "reason": verdict.reason,
        "classification": verdict.classification,
    }


# ---------------------------------------------------------------------------
# Recording consent: ambient capture needs a subject-signed grant first
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecordingConsent:
    """Subject-signed grant for ambient capture modalities.

    A minimal, capture-scoped application of the 105th batch's consent
    discipline: the grant is unilateral, revocable, purpose-bound, and
    validity is checked at USE time. ``modalities`` is a non-empty
    subset of :data:`CAPTURE_MODALITIES`.
    """

    consent_id: str
    subject_id: str
    modalities: tuple[str, ...]
    purpose: str
    granted_at: int
    expires_at: int
    subject_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    consent_digest: str = ""


@dataclass(frozen=True)
class RecordingRevocation:
    """Unilateral revocation of a recording-consent grant."""

    revocation_id: str
    consent_id: str
    subject_id: str
    revoked_at: int
    subject_pubkey_hex: str
    signature_hex: str
    revocation_digest: str = ""


def _recording_payload(consent: RecordingConsent) -> dict[str, Any]:
    return {
        "consent_id": consent.consent_id,
        "subject_id": consent.subject_id,
        "modalities": list(consent.modalities),
        "purpose": consent.purpose,
        "granted_at": consent.granted_at,
        "expires_at": consent.expires_at,
        "subject_pubkey_hex": consent.subject_pubkey_hex,
        "prev_digest": consent.prev_digest,
    }


def grant_recording_consent(
    *,
    consent_id: str,
    subject_id: str,
    subject_secret: bytes,
    modalities: list[str],
    purpose: str,
    granted_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> RecordingConsent:
    """Issue a subject-signed ambient-capture grant and seal it."""
    _check_secret(subject_secret, "subject_secret")
    consent_id = _check_nonempty_str(consent_id, "consent_id")
    subject_id = _check_nonempty_str(subject_id, "subject_id")
    purpose = _check_nonempty_str(purpose, "purpose")
    granted_at = _check_ts(granted_at, "granted_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= granted_at:
        raise SceneBoundError("expires_at must be after granted_at")
    mods = tuple(sorted({_check_modality(m) for m in modalities}))
    if not mods:
        raise SceneBoundError("modalities must be non-empty")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise SceneBoundError("prev_digest must be a non-empty string")
    pubkey_hex = ed25519.public_key(subject_secret).hex()
    bare = RecordingConsent(
        consent_id=consent_id,
        subject_id=subject_id,
        modalities=mods,
        purpose=purpose,
        granted_at=granted_at,
        expires_at=expires_at,
        subject_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,
        prev_digest=prev_digest,
    )
    payload = _recording_payload(bare)
    signature_hex = ed25519.sign(
        subject_secret, jcs_canonical_json(payload)
    ).hex()
    return RecordingConsent(
        consent_id=bare.consent_id,
        subject_id=bare.subject_id,
        modalities=bare.modalities,
        purpose=bare.purpose,
        granted_at=bare.granted_at,
        expires_at=bare.expires_at,
        subject_pubkey_hex=bare.subject_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        consent_digest=jcs_sha256_hex(payload),
    )


def _revocation_payload(record: RecordingRevocation) -> dict[str, Any]:
    return {
        "revocation_id": record.revocation_id,
        "consent_id": record.consent_id,
        "subject_id": record.subject_id,
        "revoked_at": record.revoked_at,
        "subject_pubkey_hex": record.subject_pubkey_hex,
    }


def revoke_recording_consent(
    *,
    revocation_id: str,
    consent: RecordingConsent,
    subject_secret: bytes,
    revoked_at: int,
) -> RecordingRevocation:
    """Append a unilateral, subject-signed revocation. Immediate and
    irreversible in the log — a new grant needs a new receipt."""
    _check_secret(subject_secret, "subject_secret")
    revocation_id = _check_nonempty_str(revocation_id, "revocation_id")
    revoked_at = _check_ts(revoked_at, "revoked_at")
    if revoked_at < consent.granted_at:
        raise SceneBoundError("revoked_at cannot precede granted_at")
    pubkey_hex = ed25519.public_key(subject_secret).hex()
    if not hmac.compare_digest(pubkey_hex, consent.subject_pubkey_hex):
        raise SceneBoundError("revoking key does not match the granting subject")
    bare = RecordingRevocation(
        revocation_id=revocation_id,
        consent_id=consent.consent_id,
        subject_id=consent.subject_id,
        revoked_at=revoked_at,
        subject_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,
    )
    payload = _revocation_payload(bare)
    signature_hex = ed25519.sign(
        subject_secret, jcs_canonical_json(payload)
    ).hex()
    return RecordingRevocation(
        revocation_id=bare.revocation_id,
        consent_id=bare.consent_id,
        subject_id=bare.subject_id,
        revoked_at=bare.revoked_at,
        subject_pubkey_hex=bare.subject_pubkey_hex,
        signature_hex=signature_hex,
        revocation_digest=jcs_sha256_hex(payload),
    )


@dataclass(frozen=True)
class CaptureVerdict:
    """Outcome of :func:`authorize_capture`."""

    allowed: bool
    reason: str
    consent_id: str


def authorize_capture(
    log: list[RecordingConsent | RecordingRevocation],
    *,
    subject_id: str,
    modalities: list[str],
    purpose: str,
    use_time: int,
) -> CaptureVerdict:
    """Fail-closed gate: may ambient capture start for this use?

    Every capture must call this FIRST. It finds the subject's latest
    grant, verifies chain integrity and the subject's signature,
    requires the requested modalities to be a subset of the grant,
    requires exact purpose match, requires the use to fall inside the
    grant window, and requires no revocation as of ``use_time``.
    There is no "was once consented" shortcut.
    """
    subject_id = _check_nonempty_str(subject_id, "subject_id")
    purpose = _check_nonempty_str(purpose, "purpose")
    use_time = _check_ts(use_time, "use_time")
    mods = tuple(sorted({_check_modality(m) for m in modalities}))
    if not mods:
        return CaptureVerdict(False, DENY_MALFORMED, "")

    grants = [
        e for e in log
        if isinstance(e, RecordingConsent) and e.subject_id == subject_id
    ]
    if not grants:
        return CaptureVerdict(False, DENY_CAPTURE_NO_CONSENT, "")
    grant = max(grants, key=lambda g: g.granted_at)

    # Chain integrity + signature of the grant.
    try:
        if not hmac.compare_digest(
            jcs_sha256_hex(_recording_payload(grant)), grant.consent_digest
        ):
            return CaptureVerdict(False, DENY_CAPTURE_TAMPERED, grant.consent_id)
        sig_ok = ed25519.verify(
            bytes.fromhex(grant.subject_pubkey_hex),
            jcs_canonical_json(_recording_payload(grant)),
            bytes.fromhex(grant.signature_hex),
        )
    except Exception:
        sig_ok = False
    if not sig_ok:
        return CaptureVerdict(False, DENY_CAPTURE_TAMPERED, grant.consent_id)

    if not set(mods) <= set(grant.modalities):
        return CaptureVerdict(False, DENY_CAPTURE_SCOPE, grant.consent_id)
    if not hmac.compare_digest(purpose, grant.purpose):
        return CaptureVerdict(False, DENY_CAPTURE_SCOPE, grant.consent_id)
    if use_time < grant.granted_at:
        return CaptureVerdict(False, DENY_CAPTURE_TAMPERED, grant.consent_id)
    if use_time > grant.expires_at:
        return CaptureVerdict(False, DENY_CAPTURE_EXPIRED, grant.consent_id)

    for e in log:
        if (
            isinstance(e, RecordingRevocation)
            and e.consent_id == grant.consent_id
            and e.revoked_at <= use_time
        ):
            try:
                rsig_ok = ed25519.verify(
                    bytes.fromhex(e.subject_pubkey_hex),
                    jcs_canonical_json(_revocation_payload(e)),
                    bytes.fromhex(e.signature_hex),
                )
            except Exception:
                rsig_ok = False
            if rsig_ok and hmac.compare_digest(
                e.subject_pubkey_hex, grant.subject_pubkey_hex
            ):
                return CaptureVerdict(False, DENY_CAPTURE_REVOKED, grant.consent_id)

    return CaptureVerdict(True, "capture-authorized", grant.consent_id)


def capture_audit_event(
    verdict: CaptureVerdict, *, subject_id: str, modalities: list[str]
) -> dict[str, Any]:
    """Shape a capture verdict as an audit event for ``audit_chain``."""
    return {
        "event": CAPTURE_ALLOWED_EVENT if verdict.allowed else CAPTURE_DENIED_EVENT,
        "subject_id": subject_id,
        "modalities": sorted(modalities),
        "consent_id": verdict.consent_id,
        "reason": verdict.reason,
    }


# ---------------------------------------------------------------------------
# Model registry: a model version is invocable only for bound scenes
# ---------------------------------------------------------------------------


def bind_model_to_scene(
    registry: Mapping[str, SceneBinding],
    model_version: str,
    binding: SceneBinding,
) -> dict[str, SceneBinding]:
    """Register ``model_version`` under a scene binding.

    Returns a NEW registry (the input is never mutated). Rebinding a
    model version replaces the old binding — the replacement is itself
    a registry write the host must receipt.
    """
    model_version = _check_nonempty_str(model_version, "model_version")
    if _verify_binding_integrity(binding) is not None:
        raise SceneBoundError("cannot register a malformed/tampered binding")
    new_registry = dict(registry)
    new_registry[model_version] = binding
    return new_registry


@dataclass(frozen=True)
class ModelInvocationVerdict:
    """Outcome of :func:`check_model_invocation`."""

    allowed: bool
    reason: str
    classification: str  # AUTHORITATIVE_SCENE / NON_AUTHORITATIVE_SCENE / UNVERIFIABLE_PROCESS


def check_model_invocation(
    registry: Mapping[str, SceneBinding],
    model_version: str,
    declaration: SceneDeclaration | None,
    manifest: Mapping[str, Mapping[str, float]],
    *,
    now: int,
) -> ModelInvocationVerdict:
    """Gate a model invocation on its scene binding.

    Unknown model versions deny outright. A bound model invoked for an
    unbound scene does not merely deny — it classifies
    ``unverifiable-process`` (87th-batch binary semantics): an
    out-of-scope invocation must never be laundered into a partial
    authorization.
    """
    now = _check_ts(now, "now")
    binding = registry.get(model_version) if isinstance(model_version, str) else None
    if binding is None:
        return ModelInvocationVerdict(False, DENY_UNKNOWN_MODEL, UNVERIFIABLE_PROCESS)
    verdict = check_scene_authorized(binding, declaration, manifest, now=now)
    if verdict.allowed:
        return ModelInvocationVerdict(
            True, verdict.reason, AUTHORITATIVE_SCENE
        )
    if verdict.reason in (DENY_OUT_OF_SCOPE, DENY_UNVALIDATED_STRATUM):
        return ModelInvocationVerdict(
            False, verdict.reason, UNVERIFIABLE_PROCESS
        )
    return ModelInvocationVerdict(False, verdict.reason, NON_AUTHORITATIVE_SCENE)
