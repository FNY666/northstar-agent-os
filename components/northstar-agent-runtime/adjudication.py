"""Human final adjudication for AI sports systems (one-hundred-eighteenth batch).

Absorbs the 2026 AI-sports research thread (mechanism ideas only,
honestly scoped):

* **The human keeps the final word.** FIFA's "Football AI" for the
  2026 World Cup (1248 players 3D-scanned, 500Hz IMU smart ball,
  semi-automated offside threshold tightened 50cm to 10cm) still
  reserves human final adjudication for crowded/subjective scenes.
  Here AI officiating/medical/fitness decisions in gated scene
  classes are NON_AUTHORITATIVE by default; release requires a
  registered human adjudicator's countersign bound to the exact
  ``(decision_digest, adjudicator_id, scene_class)`` triple.
* **Full automation has single points of failure.** Wimbledon 2026
  qualifiers: a heat failure paused fully-automated line-calling.
  Here critical automation must declare a fail-closed degradation
  plan (failure mode -> human-takeover procedure); no declared plan
  means the deployment cannot be registered.
* **Concussion AI is assist-only.** JSAMS (2026-05): AI is clinical
  assist; false reassurance is the risk; models trained on male-pro
  data fail on women/children. Here a model serving a population
  outside its declared measured populations is flagged
  ``population_mismatch`` and classified NON_AUTHORITATIVE for that
  population.
* **Biometric data is labor.** Biometric-data ownership is the core
  labor-negotiation issue (no-third-party-resale clauses slowing
  product rollout). Here biometric collection requires a
  subject-signed, purpose-bound receipt; using the data to train a
  model is a NEW purpose (grant for "coaching" does not cover
  "model_training"); resale to third parties without an explicit
  resale grant is a hard deny.
* **Coaching must name its limits.** Spain's 188-paper review:
  "autonomous coaching is far away". Here AI coaching outputs must
  carry an honesty label naming what the coach is NOT qualified for;
  medical-diagnosis framing is denied and redirected to a clinical
  path (the Somni "explicitly non-medical" discipline).
* **Betting stays isolated.** AI deepfake endorsements for betting
  apps are a major abuse vector. Here betting-tagged inputs may not
  flow into officiating/coaching/adjudication/medical pipelines;
  mixing is denied and audited as ``sports.betting_contamination``.

Northstar mapping:

* ``AdjudicationReceipt`` — authority-issued, hash-chained receipt
  binding ``(decision_digest, adjudicator_id, qualified_scenes,
  adjudicated_at, expires_at)``, Ed25519-signed by the issuing
  authority (the competition organizer / governing body).
  ``final_adjudication_gate()``: non-gated scenes allow; gated
  scenes (``crowded_scene``, ``subjective_call``,
  ``medical_advice``, ``youth_athletes``, ``fitness_advice``)
  require a valid, unexpired, chain-intact receipt for the exact
  decision digest. No receipt -> NON_AUTHORITATIVE,
  ``mandatory_human_review=True``.
* ``PopulationFitReceipt`` — authority-signed receipt declaring the
  populations a model capability was measured on (closed
  vocabulary). ``check_population_fit()``: serving a population
  outside the declared set -> ``population_mismatch`` flag and
  NON_AUTHORITATIVE classification (concussion-AI lesson).
* ``BiometricPurposeReceipt`` — subject-signed, purpose-bound,
  revocable receipt for biometric data use (105th-batch use-time
  semantics). ``check_biometric_use()``: purpose not granted ->
  ``sports:biometric_purpose_creep``; resale without an explicit
  resale grant -> hard deny ``sports:biometric_resale_denied``.
* ``check_coach_output()`` — the AI coach's honesty label must name
  its non-qualifications; medical-diagnosis framing denies and
  redirects to the clinical path.
* ``DegradationPlan`` — authority-signed fail-closed degradation
  plan per critical system; ``check_degradation_plan()`` is the hook
  the 110th-batch deployment registry calls: no valid plan ->
  ``sports:no_degradation_plan``.
* ``check_pipeline_mixing()`` — betting-tagged inputs may not enter
  officiating/coaching/adjudication/medical pipelines.

Honest boundary: the gate enforces the *structure* of
human-in-the-loop adjudication — receipt present, signature valid,
human named, plan declared. It does not verify the *quality* of the
human's judgment; a rubber-stamping adjudicator passes this module
and must be caught by organizational oversight (out of scope).

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

ADJUDICATION_SCHEMA_VERSION = "northstar.adjudication.v1"

#: Closed scene-class vocabulary. GATED_SCENES require a human final
#: adjudicator's countersign before an AI decision may be released.
#: Non-gated scenes (routine_coaching, broadcast, stats) do not.
GATED_SCENES: tuple[str, ...] = (
    "crowded_scene",
    "subjective_call",
    "medical_advice",
    "youth_athletes",
    "fitness_advice",
)

#: All known scene classes (gated + free).
SCENE_CLASSES: tuple[str, ...] = GATED_SCENES + (
    "routine_coaching",
    "broadcast",
    "stats",
)

#: Closed measured-population vocabulary. ``mixed_population`` covers
#: every other value (a model measured on a mixed cohort serves any
#: population); any other value covers only itself.
MEASURED_POPULATIONS: tuple[str, ...] = (
    "adult_male_pro",
    "adult_female_pro",
    "youth_athlete",
    "general_adult",
    "mixed_population",
)

#: Closed biometric data-scope vocabulary.
BIOMETRIC_SCOPES: tuple[str, ...] = (
    "performance",
    "health",
    "tracking",
    "biometric_raw",
)

#: Closed biometric-use purpose vocabulary. ``model_training`` is a
#: distinct purpose from every operational purpose: a grant for
#: ``coaching`` never covers ``model_training``.
BIOMETRIC_PURPOSES: tuple[str, ...] = (
    "coaching",
    "medical_care",
    "broadcast",
    "research",
    "model_training",
    "third_party_resale",
)

#: Closed coach-capability vocabulary. A coach may only claim these;
#: medical claims are structurally impossible (see _check).
COACH_CAPABILITIES: tuple[str, ...] = (
    "technique",
    "fitness_programming",
    "nutrition_general",
    "recovery",
    "mental_skills",
)

#: Framings that are medical-diagnosis territory: denied and
#: redirected to the clinical path, never released by the coach.
MEDICAL_FRAMINGS: tuple[str, ...] = (
    "medical_diagnosis",
    "injury_assessment",
    "medical_treatment",
)

#: Closed failure-mode vocabulary for degradation plans.
FAILURE_MODES: tuple[str, ...] = (
    "sensor_failure",
    "compute_failure",
    "comms_failure",
    "heat_failure",
    "power_failure",
)

#: Closed pipeline-source vocabulary. ``betting`` sources are
#: isolated: they may not enter the protected pipelines.
PIPELINE_SOURCES: tuple[str, ...] = (
    "officiating",
    "coaching",
    "adjudication",
    "medical",
    "betting",
    "broadcast",
)

#: Pipelines that betting-tagged inputs may never enter.
PROTECTED_PIPELINES: frozenset[str] = frozenset(
    {"officiating", "coaching", "adjudication", "medical"}
)

#: Classifications (87th-batch binary semantics, no partial tier).
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"
CLASS_UNVERIFIABLE = "unverifiable-process"

#: Denial reason codes. All start with the ``sports:`` prefix.
DENY_NO_ADJUDICATION = "sports:no_adjudication"
DENY_ADJUDICATION_EXPIRED = "sports:adjudication_expired"
DENY_ADJUDICATION_FUTURE = "sports:adjudication_from_future"
DENY_ADJUDICATION_PREDATES_DECISION = "sports:adjudication_predates_decision"
DENY_SCENE_NOT_QUALIFIED = "sports:adjudicator_scene_not_qualified"
DENY_CHAIN_BROKEN = "sports:chain_broken"
DENY_SIGNATURE_INVALID = "sports:signature_invalid"
DENY_POPULATION_MISMATCH = "sports:population_mismatch"
DENY_POPULATION_NO_RECEIPT = "sports:no_population_receipt"
DENY_BIOMETRIC_NO_RECEIPT = "sports:no_purpose_receipt"
DENY_PURPOSE_CREEP = "sports:biometric_purpose_creep"
DENY_RESALE = "sports:biometric_resale_denied"
DENY_BIOMETRIC_REVOKED = "sports:biometric_revoked"
DENY_BIOMETRIC_EXPIRED = "sports:biometric_expired"
DENY_COACH_LABEL_MISSING = "sports:coach_label_missing"
DENY_COACH_DIAGNOSIS = "sports:coach_diagnosis_denied"
DENY_COACH_UNQUALIFIED_TOPIC = "sports:coach_topic_unqualified"
DENY_NO_DEGRADATION_PLAN = "sports:no_degradation_plan"
DENY_BETTING_CONTAMINATION = "sports:betting_contamination"
DENY_MALFORMED = "sports:malformed"

#: Audit event names (shaped for ``audit_chain.chain_record``).
ADJUDICATION_ALLOWED_EVENT = "sports.adjudicated"
ADJUDICATION_DENIED_EVENT = "sports.adjudication_denied"
POPULATION_MISMATCH_EVENT = "sports.population_mismatch"
PURPOSE_CREEP_EVENT = "sports.biometric_purpose_creep"
RESALE_DENIED_EVENT = "sports.biometric_resale_denied"
COACH_DIAGNOSIS_EVENT = "sports.coach_diagnosis_denied"
BETTING_CONTAMINATION_EVENT = "sports.betting_contamination"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class AdjudicationError(ValueError):
    """Malformed receipt/plan/output or a programming error.

    Raised for structural problems (unknown vocabulary, bad digests,
    non-hex fields). Verification *failures* (no receipt, expired,
    revoked, bad signature at check time) return verdicts with
    ``allowed=False`` — a failed sports gate is a verdict, a malformed
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
        raise AdjudicationError(f"{field_name} must be 64 lowercase hex chars")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise AdjudicationError(f"{field_name} must be 128 lowercase hex chars")
    return value


def _check_scene(value: Any) -> str:
    if value not in SCENE_CLASSES:
        raise AdjudicationError(
            f"unknown scene class {value!r}; closed vocabulary {SCENE_CLASSES}"
        )
    return value


def _check_population(value: Any) -> str:
    if value not in MEASURED_POPULATIONS:
        raise AdjudicationError(
            f"unknown population {value!r}; closed vocabulary {MEASURED_POPULATIONS}"
        )
    return value


def _check_scope(value: Any) -> str:
    if value not in BIOMETRIC_SCOPES:
        raise AdjudicationError(
            f"unknown biometric scope {value!r}; closed vocabulary {BIOMETRIC_SCOPES}"
        )
    return value


def _check_purpose(value: Any) -> str:
    if value not in BIOMETRIC_PURPOSES:
        raise AdjudicationError(
            f"unknown purpose {value!r}; closed vocabulary {BIOMETRIC_PURPOSES}"
        )
    return value


def _check_capability(value: Any) -> str:
    if value not in COACH_CAPABILITIES:
        raise AdjudicationError(
            f"unknown coach capability {value!r}; closed vocabulary {COACH_CAPABILITIES}"
        )
    return value


def _check_failure_mode(value: Any) -> str:
    if value not in FAILURE_MODES:
        raise AdjudicationError(
            f"unknown failure mode {value!r}; closed vocabulary {FAILURE_MODES}"
        )
    return value


def _check_pipeline_source(value: Any) -> str:
    if value not in PIPELINE_SOURCES:
        raise AdjudicationError(
            f"unknown pipeline source {value!r}; closed vocabulary {PIPELINE_SOURCES}"
        )
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AdjudicationError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed (no keypair()).
    if not isinstance(value, bytes) or len(value) != 32:
        raise AdjudicationError(f"{field_name} must be a 32-byte seed")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdjudicationError(f"{field_name} must be a non-empty string")
    return value


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    try:
        return bool(
            ed25519.verify(
                bytes.fromhex(pubkey_hex),
                jcs_canonical_json(payload),
                bytes.fromhex(signature_hex),
            )
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# AdjudicationReceipt: human final countersign, hash-chained
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdjudicationReceipt:
    """A human adjudicator's countersign on one AI decision.

    Issued (and Ed25519-signed) by the governing authority, which
    attests the adjudicator's identity and the scenes they are
    qualified to adjudicate. ``qualified_scenes`` is a subset of
    :data:`SCENE_CLASSES`; a countersign for a scene the adjudicator
    is not qualified for denies at check time.
    """

    receipt_id: str
    decision_digest: str
    adjudicator_id: str
    adjudicator_pubkey_hex: str
    qualified_scenes: tuple[str, ...]
    scene_class: str
    adjudicated_at: int
    expires_at: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ADJUDICATION_SCHEMA_VERSION


def _adjudication_payload(receipt: AdjudicationReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "decision_digest": receipt.decision_digest,
        "adjudicator_id": receipt.adjudicator_id,
        "adjudicator_pubkey_hex": receipt.adjudicator_pubkey_hex,
        "qualified_scenes": list(receipt.qualified_scenes),
        "scene_class": receipt.scene_class,
        "adjudicated_at": receipt.adjudicated_at,
        "expires_at": receipt.expires_at,
        "issued_by": receipt.issued_by,
        "authority_pubkey_hex": receipt.authority_pubkey_hex,
        "prev_digest": receipt.prev_digest,
        "schema_version": receipt.schema_version,
    }


def compute_adjudication_digest(receipt: AdjudicationReceipt) -> str:
    """Recompute the JCS digest an adjudication receipt claims."""
    return jcs_sha256_hex(_adjudication_payload(receipt))


def issue_adjudication_receipt(
    *,
    receipt_id: str,
    decision_digest: str,
    adjudicator_id: str,
    adjudicator_pubkey_hex: str,
    qualified_scenes: tuple[str, ...],
    scene_class: str,
    authority_secret: bytes,
    issued_by: str,
    adjudicated_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> AdjudicationReceipt:
    """Issue an authority-signed adjudication countersign receipt.

    Fail-closed at issuance: unknown scenes raise; the adjudicator's
    own pubkey is recorded so a later audit can name the human;
    ``expires_at <= adjudicated_at`` raises. There is no agent-key
    path: countersign registration is a governing-authority act
    (94th/104th-batch no-self-issuance).
    """
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    decision_digest = _check_hex64(decision_digest, "decision_digest")
    adjudicator_id = _check_nonempty_str(adjudicator_id, "adjudicator_id")
    _check_hex64(adjudicator_pubkey_hex, "adjudicator_pubkey_hex")
    qualified_scenes = tuple(_check_scene(s) for s in qualified_scenes)
    if not qualified_scenes:
        raise AdjudicationError("qualified_scenes must be non-empty")
    scene_class = _check_scene(scene_class)
    if scene_class not in qualified_scenes:
        raise AdjudicationError(
            f"scene {scene_class!r} not in adjudicator's qualified scenes"
        )
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    adjudicated_at = _check_ts(adjudicated_at, "adjudicated_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= adjudicated_at:
        raise AdjudicationError("expires_at must be after adjudicated_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise AdjudicationError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = AdjudicationReceipt(
        receipt_id=receipt_id,
        decision_digest=decision_digest,
        adjudicator_id=adjudicator_id,
        adjudicator_pubkey_hex=adjudicator_pubkey_hex,
        qualified_scenes=qualified_scenes,
        scene_class=scene_class,
        adjudicated_at=adjudicated_at,
        expires_at=expires_at,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced below
        prev_digest=prev_digest,
    )
    signature_hex = ed25519.sign(
        authority_secret, jcs_canonical_json(_adjudication_payload(bare))
    ).hex()
    sealed = AdjudicationReceipt(
        **{**bare.__dict__, "signature_hex": signature_hex}
    )
    return AdjudicationReceipt(
        **{**sealed.__dict__, "receipt_digest": compute_adjudication_digest(sealed)}
    )


def _verify_adjudication_chain(log: list[AdjudicationReceipt]) -> None:
    """Raise :class:`AdjudicationError` if the adjudication log is broken."""
    expected_prev = _GENESIS
    for receipt in log:
        if not isinstance(receipt, AdjudicationReceipt):
            raise AdjudicationError("log entry is not an AdjudicationReceipt")
        if not hmac.compare_digest(
            compute_adjudication_digest(receipt), receipt.receipt_digest
        ):
            raise AdjudicationError(
                f"receipt {receipt.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise AdjudicationError(
                f"receipt {receipt.receipt_id!r} chain break: expected "
                f"prev {expected_prev!r}"
            )
        if not _verify_signature(
            receipt.authority_pubkey_hex,
            _adjudication_payload(receipt),
            receipt.signature_hex,
        ):
            raise AdjudicationError(
                f"receipt {receipt.receipt_id!r} authority signature invalid"
            )
        expected_prev = receipt.receipt_digest


@dataclass(frozen=True)
class AdjudicationVerdict:
    """Verdict of the final-adjudication gate."""

    allowed: bool
    reason: str
    classification: str
    receipt_digest: str = ""
    mandatory_human_review: bool = False


def final_adjudication_gate(
    log: list[AdjudicationReceipt],
    *,
    decision_digest: str,
    scene_class: str,
    decision_time: int,
    check_time: int,
) -> AdjudicationVerdict:
    """Fail-closed gate: may this AI decision be released?

    Non-gated scene classes allow without a countersign. Gated
    classes (``crowded_scene``, ``subjective_call``,
    ``medical_advice``, ``youth_athletes``, ``fitness_advice``)
    require a valid, unexpired, chain-intact adjudication receipt for
    the *exact* decision digest, countersigned no earlier than the
    decision itself (a countersign cannot predate the decision it
    blesses). No receipt -> NON_AUTHORITATIVE with
    ``mandatory_human_review=True``: the AI is assist-only here.
    """
    decision_digest = _check_hex64(decision_digest, "decision_digest")
    scene_class = _check_scene(scene_class)
    decision_time = _check_ts(decision_time, "decision_time")
    check_time = _check_ts(check_time, "check_time")

    def _deny(code: str, detail: str) -> AdjudicationVerdict:
        return AdjudicationVerdict(
            allowed=False,
            reason=f"{code}: {detail}",
            classification=CLASS_NON_AUTHORITATIVE,
            mandatory_human_review=True,
        )

    if scene_class not in GATED_SCENES:
        return AdjudicationVerdict(
            allowed=True,
            reason=f"scene {scene_class!r} is not adjudication-gated",
            classification=CLASS_AUTHORITATIVE,
        )

    try:
        _verify_adjudication_chain(log)
    except AdjudicationError as error:
        return _deny(DENY_CHAIN_BROKEN, f"adjudication log integrity failure: {error}")

    matches = [
        r
        for r in log
        if hmac.compare_digest(r.decision_digest, decision_digest)
        and r.scene_class == scene_class
    ]
    if not matches:
        return _deny(
            DENY_NO_ADJUDICATION,
            f"gated scene {scene_class!r}: no human countersign for this decision "
            "— AI output is assist-only until adjudicated",
        )
    receipt = matches[-1]  # latest countersign for the decision wins

    if check_time < receipt.adjudicated_at:
        return _deny(
            DENY_ADJUDICATION_FUTURE, "check_time predates the countersign"
        )
    if receipt.adjudicated_at < decision_time:
        return _deny(
            DENY_ADJUDICATION_PREDATES_DECISION,
            "countersign predates the decision it claims to bless",
        )
    if check_time > receipt.expires_at:
        return _deny(
            DENY_ADJUDICATION_EXPIRED, f"countersign expired at {receipt.expires_at}"
        )
    if scene_class not in receipt.qualified_scenes:
        return _deny(
            DENY_SCENE_NOT_QUALIFIED,
            f"adjudicator {receipt.adjudicator_id!r} not qualified for {scene_class!r}",
        )
    return AdjudicationVerdict(
        allowed=True,
        reason=(
            f"released: human adjudicator {receipt.adjudicator_id!r} countersigned "
            f"decision for {scene_class!r}, chain intact"
        ),
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# PopulationFitReceipt: measured-population declarations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PopulationFitReceipt:
    """Authority-signed declaration of the populations a model capability
    was measured on.

    ``measured_populations`` is the closed set the authority attests;
    ``mixed_population`` covers every population (a mixed-cohort
    measurement serves anyone); any other value covers only itself.
    """

    receipt_id: str
    model_digest: str
    capability_id: str
    measured_populations: tuple[str, ...]
    measured_at: int
    expires_at: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ADJUDICATION_SCHEMA_VERSION


def _population_payload(receipt: PopulationFitReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "model_digest": receipt.model_digest,
        "capability_id": receipt.capability_id,
        "measured_populations": list(receipt.measured_populations),
        "measured_at": receipt.measured_at,
        "expires_at": receipt.expires_at,
        "issued_by": receipt.issued_by,
        "authority_pubkey_hex": receipt.authority_pubkey_hex,
        "prev_digest": receipt.prev_digest,
        "schema_version": receipt.schema_version,
    }


def compute_population_digest(receipt: PopulationFitReceipt) -> str:
    """Recompute the JCS digest a population receipt claims."""
    return jcs_sha256_hex(_population_payload(receipt))


def issue_population_receipt(
    *,
    receipt_id: str,
    model_digest: str,
    capability_id: str,
    measured_populations: tuple[str, ...],
    authority_secret: bytes,
    issued_by: str,
    measured_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> PopulationFitReceipt:
    """Issue an authority-signed measured-population receipt."""
    _check_secret(authority_secret, "authority_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    capability_id = _check_nonempty_str(capability_id, "capability_id")
    measured_populations = tuple(_check_population(p) for p in measured_populations)
    if not measured_populations:
        raise AdjudicationError("measured_populations must be non-empty")
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    measured_at = _check_ts(measured_at, "measured_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= measured_at:
        raise AdjudicationError("expires_at must be after measured_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise AdjudicationError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = PopulationFitReceipt(
        receipt_id=receipt_id,
        model_digest=model_digest,
        capability_id=capability_id,
        measured_populations=measured_populations,
        measured_at=measured_at,
        expires_at=expires_at,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced below
        prev_digest=prev_digest,
    )
    signature_hex = ed25519.sign(
        authority_secret, jcs_canonical_json(_population_payload(bare))
    ).hex()
    sealed = PopulationFitReceipt(
        **{**bare.__dict__, "signature_hex": signature_hex}
    )
    return PopulationFitReceipt(
        **{**sealed.__dict__, "receipt_digest": compute_population_digest(sealed)}
    )


def _verify_population_chain(log: list[PopulationFitReceipt]) -> None:
    """Raise :class:`AdjudicationError` if the population log is broken."""
    expected_prev = _GENESIS
    for receipt in log:
        if not isinstance(receipt, PopulationFitReceipt):
            raise AdjudicationError("log entry is not a PopulationFitReceipt")
        if not hmac.compare_digest(
            compute_population_digest(receipt), receipt.receipt_digest
        ):
            raise AdjudicationError(
                f"receipt {receipt.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise AdjudicationError(
                f"receipt {receipt.receipt_id!r} chain break: expected "
                f"prev {expected_prev!r}"
            )
        if not _verify_signature(
            receipt.authority_pubkey_hex,
            _population_payload(receipt),
            receipt.signature_hex,
        ):
            raise AdjudicationError(
                f"receipt {receipt.receipt_id!r} authority signature invalid"
            )
        expected_prev = receipt.receipt_digest


@dataclass(frozen=True)
class PopulationVerdict:
    """Verdict of the population-fit gate."""

    allowed: bool
    reason: str
    classification: str
    population_mismatch: bool = False
    receipt_digest: str = ""


def check_population_fit(
    log: list[PopulationFitReceipt],
    *,
    model_digest: str,
    capability_id: str,
    target_population: str,
    check_time: int,
) -> PopulationVerdict:
    """Is this model fit to serve this population for this capability?

    The concussion-AI lesson: a model measured on male-pro data does
    not serve youth athletes. Serving a population outside the
    declared measured set -> ``population_mismatch`` flag and
    NON_AUTHORITATIVE classification — the model is assist-only for
    that population until it is measured there.
    """
    model_digest = _check_hex64(model_digest, "model_digest")
    capability_id = _check_nonempty_str(capability_id, "capability_id")
    target_population = _check_population(target_population)
    check_time = _check_ts(check_time, "check_time")

    def _deny(code: str, detail: str, mismatch: bool = False) -> PopulationVerdict:
        return PopulationVerdict(
            allowed=False,
            reason=f"{code}: {detail}",
            classification=CLASS_NON_AUTHORITATIVE,
            population_mismatch=mismatch,
        )

    try:
        _verify_population_chain(log)
    except AdjudicationError as error:
        return _deny(DENY_CHAIN_BROKEN, f"population log integrity failure: {error}")

    matches = [
        r
        for r in log
        if hmac.compare_digest(r.model_digest, model_digest)
        and r.capability_id == capability_id
    ]
    if not matches:
        return _deny(
            DENY_POPULATION_NO_RECEIPT,
            f"no measured-population receipt for capability {capability_id!r}",
        )
    receipt = matches[-1]
    if check_time < receipt.measured_at or check_time > receipt.expires_at:
        return _deny(DENY_POPULATION_NO_RECEIPT, "population receipt not valid now")
    if (
        target_population not in receipt.measured_populations
        and "mixed_population" not in receipt.measured_populations
    ):
        return _deny(
            DENY_POPULATION_MISMATCH,
            f"measured on {receipt.measured_populations}, serving "
            f"{target_population!r} — out-of-population, assist-only",
            mismatch=True,
        )
    return PopulationVerdict(
        allowed=True,
        reason=(
            f"population {target_population!r} within declared measured set "
            f"{receipt.measured_populations}"
        ),
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# BiometricPurposeReceipt: subject-signed, purpose-bound, revocable
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BiometricPurposeReceipt:
    """A data subject's grant for biometric-data use.

    Subject-signed (the athlete holds the key), purpose-bound,
    revocable at use time (105th-batch semantics: no "was once
    consented" shortcut). ``resale_allowed`` defaults to False — the
    labor-negotiation clause: resale to third parties is a hard deny
    without an explicit resale grant.

    Relationship to :class:`consent_receipts.ConsentReceipt`: this is a
    domain-specific profile, not a duplicate. ConsentReceipt is the
    general consent primitive (single exact-match purpose, log-based
    revocation via RevocationRecord, hash-chained). BiometricPurposeReceipt
    keeps multi-purpose tuples, field-level revocation, and the
    biometric-specific ``resale_allowed`` labor clause. Do not merge them;
    collapsing either direction loses semantics.
    """

    receipt_id: str
    subject_id: str
    subject_pubkey_hex: str
    data_scope: str
    purposes: tuple[str, ...]
    resale_allowed: bool
    granted_at: int
    expires_at: int
    revoked: bool = False
    signature_hex: str = ""
    receipt_digest: str = ""
    schema_version: str = ADJUDICATION_SCHEMA_VERSION


def _biometric_payload(receipt: BiometricPurposeReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "subject_id": receipt.subject_id,
        "subject_pubkey_hex": receipt.subject_pubkey_hex,
        "data_scope": receipt.data_scope,
        "purposes": list(receipt.purposes),
        "resale_allowed": receipt.resale_allowed,
        "granted_at": receipt.granted_at,
        "expires_at": receipt.expires_at,
        "revoked": receipt.revoked,
        "schema_version": receipt.schema_version,
    }


def compute_biometric_digest(receipt: BiometricPurposeReceipt) -> str:
    """Recompute the JCS digest a biometric receipt claims."""
    return jcs_sha256_hex(_biometric_payload(receipt))


def grant_biometric_use(
    *,
    receipt_id: str,
    subject_id: str,
    subject_secret: bytes,
    data_scope: str,
    purposes: tuple[str, ...],
    resale_allowed: bool = False,
    granted_at: int,
    expires_at: int,
) -> BiometricPurposeReceipt:
    """The subject grants biometric-data use for named purposes."""
    _check_secret(subject_secret, "subject_secret")
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    subject_id = _check_nonempty_str(subject_id, "subject_id")
    data_scope = _check_scope(data_scope)
    purposes = tuple(_check_purpose(p) for p in purposes)
    if not purposes:
        raise AdjudicationError("purposes must be non-empty")
    if not isinstance(resale_allowed, bool):
        raise AdjudicationError("resale_allowed must be a bool")
    granted_at = _check_ts(granted_at, "granted_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= granted_at:
        raise AdjudicationError("expires_at must be after granted_at")

    subject_pubkey_hex = ed25519.public_key(subject_secret).hex()
    bare = BiometricPurposeReceipt(
        receipt_id=receipt_id,
        subject_id=subject_id,
        subject_pubkey_hex=subject_pubkey_hex,
        data_scope=data_scope,
        purposes=purposes,
        resale_allowed=resale_allowed,
        granted_at=granted_at,
        expires_at=expires_at,
    )
    signature_hex = ed25519.sign(
        subject_secret, jcs_canonical_json(_biometric_payload(bare))
    ).hex()
    sealed = BiometricPurposeReceipt(
        **{**bare.__dict__, "signature_hex": signature_hex}
    )
    return BiometricPurposeReceipt(
        **{**sealed.__dict__, "receipt_digest": compute_biometric_digest(sealed)}
    )


def revoke_biometric_use(
    receipt: BiometricPurposeReceipt, *, subject_secret: bytes
) -> BiometricPurposeReceipt:
    """Revoke a biometric grant. Revocation is terminal: a new grant
    needs a new receipt (105th-batch irreversible-revocation)."""
    _check_secret(subject_secret, "subject_secret")
    if ed25519.public_key(subject_secret).hex() != receipt.subject_pubkey_hex:
        raise AdjudicationError("only the subject's key may revoke this grant")
    bare = BiometricPurposeReceipt(
        **{**receipt.__dict__, "revoked": True, "signature_hex": ""}
    )
    signature_hex = ed25519.sign(
        subject_secret, jcs_canonical_json(_biometric_payload(bare))
    ).hex()
    sealed = BiometricPurposeReceipt(
        **{**bare.__dict__, "signature_hex": signature_hex}
    )
    return BiometricPurposeReceipt(
        **{**sealed.__dict__, "receipt_digest": compute_biometric_digest(sealed)}
    )


def _verify_biometric(receipt: BiometricPurposeReceipt) -> None:
    if not hmac.compare_digest(
        compute_biometric_digest(receipt), receipt.receipt_digest
    ):
        raise AdjudicationError("biometric receipt digest does not recompute")
    if not _verify_signature(
        receipt.subject_pubkey_hex,
        _biometric_payload(receipt),
        receipt.signature_hex,
    ):
        raise AdjudicationError("subject signature invalid")


@dataclass(frozen=True)
class BiometricVerdict:
    """Verdict of the biometric purpose-binding gate."""

    allowed: bool
    reason: str
    classification: str
    receipt_digest: str = ""


def biometric_purpose_binding(
    log: list[BiometricPurposeReceipt],
    *,
    subject_id: str,
    data_scope: str,
    purpose: str,
    check_time: int,
) -> BiometricVerdict:
    """Use-time check: may this biometric use proceed?

    A grant for ``coaching`` never covers ``model_training`` — the
    purpose is matched exactly, and training is a *new* purpose
    requiring a *new* grant. ``third_party_resale`` without an
    explicit ``resale_allowed`` grant is a hard deny (the
    labor-negotiation clause as mechanism). Revoked or expired grants
    deny; there is no "was once consented" shortcut.
    """
    subject_id = _check_nonempty_str(subject_id, "subject_id")
    data_scope = _check_scope(data_scope)
    purpose = _check_purpose(purpose)
    check_time = _check_ts(check_time, "check_time")

    def _deny(code: str, detail: str) -> BiometricVerdict:
        return BiometricVerdict(
            allowed=False,
            reason=f"{code}: {detail}",
            classification=CLASS_UNVERIFIABLE,
        )

    grants = [
        r for r in log if r.subject_id == subject_id and r.data_scope == data_scope
    ]
    if not grants:
        return _deny(
            DENY_BIOMETRIC_NO_RECEIPT,
            f"no biometric grant for subject {subject_id!r} scope {data_scope!r}",
        )
    receipt = grants[-1]  # latest grant for the (subject, scope) wins
    try:
        _verify_biometric(receipt)
    except AdjudicationError as error:
        return _deny(DENY_SIGNATURE_INVALID, f"biometric grant invalid: {error}")
    if receipt.revoked:
        return _deny(DENY_BIOMETRIC_REVOKED, "biometric grant revoked by subject")
    if check_time < receipt.granted_at:
        return _deny(DENY_BIOMETRIC_NO_RECEIPT, "check_time predates the grant")
    if check_time > receipt.expires_at:
        return _deny(
            DENY_BIOMETRIC_EXPIRED, f"biometric grant expired at {receipt.expires_at}"
        )
    if purpose == "third_party_resale" and not receipt.resale_allowed:
        return _deny(
            DENY_RESALE,
            "third-party resale without an explicit resale grant — hard deny",
        )
    if purpose not in receipt.purposes:
        return _deny(
            DENY_PURPOSE_CREEP,
            f"purpose {purpose!r} not granted (granted: {list(receipt.purposes)}) "
            "— training on this data is a new purpose needing a new grant",
        )
    return BiometricVerdict(
        allowed=True,
        reason=(
            f"biometric use {purpose!r} covered by grant {receipt.receipt_id!r} "
            "at use time"
        ),
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Coach honesty labels
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CoachOutput:
    """An AI coach's output with its honesty label.

    ``not_qualified_for`` names the topics this coach disclaims —
    the label is mandatory, and it must be a subset of the honest
    boundary vocabulary. Medical framings are denied outright and
    redirected to the clinical path.
    """

    output_digest: str
    coach_id: str
    claimed_capabilities: tuple[str, ...]
    not_qualified_for: tuple[str, ...]
    framing: str
    topic: str


def check_coach_output(output: CoachOutput) -> BiometricVerdict:
    """Gate an AI coaching output on its honesty label.

    * Medical-diagnosis framing -> deny + clinical redirect (the
      Somni "explicitly non-medical" discipline).
    * Missing/empty ``not_qualified_for`` -> NON_AUTHORITATIVE: a
      coach that names no limits is assist-only.
    * Topic inside ``not_qualified_for`` -> deny.
    """
    if not isinstance(output, CoachOutput):
        raise AdjudicationError("expected a CoachOutput")
    _check_hex64(output.output_digest, "output_digest")
    _check_nonempty_str(output.coach_id, "coach_id")
    for cap in output.claimed_capabilities:
        _check_capability(cap)
    for topic in output.not_qualified_for:
        _check_capability(topic)
    _check_nonempty_str(output.framing, "framing")
    _check_nonempty_str(output.topic, "topic")

    if output.framing in MEDICAL_FRAMINGS:
        return BiometricVerdict(
            allowed=False,
            reason=(
                f"{DENY_COACH_DIAGNOSIS}: framing {output.framing!r} is medical "
                "territory — redirect to the clinical path"
            ),
            classification=CLASS_NON_AUTHORITATIVE,
        )
    if not output.not_qualified_for:
        return BiometricVerdict(
            allowed=False,
            reason=(
                f"{DENY_COACH_LABEL_MISSING}: no honesty label — a coach that "
                "names no limits is assist-only"
            ),
            classification=CLASS_NON_AUTHORITATIVE,
        )
    if output.topic in output.not_qualified_for:
        return BiometricVerdict(
            allowed=False,
            reason=(
                f"{DENY_COACH_UNQUALIFIED_TOPIC}: topic {output.topic!r} is "
                "inside the coach's own disclaimed set"
            ),
            classification=CLASS_NON_AUTHORITATIVE,
        )
    return BiometricVerdict(
        allowed=True,
        reason=(
            f"coach output within claimed capabilities {list(output.claimed_capabilities)}, "
            f"honesty label present (disclaims {list(output.not_qualified_for)})"
        ),
        classification=CLASS_AUTHORITATIVE,
    )


# ---------------------------------------------------------------------------
# DegradationPlan: fail-closed SPOF plan (110th-batch hook)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DegradationPlan:
    """A critical system's fail-closed degradation plan.

    Authority-signed, hash-chained: for each declared failure mode,
    the human-takeover procedure digest is pinned. This is the check
    the 110th-batch deployment registry calls — no valid plan means
    the system cannot be registered (the Wimbledon heat-failure
    lesson: full automation without a failure plan is not
    deployable).
    """

    plan_id: str
    system_id: str
    failure_modes: tuple[str, ...]
    takeover_procedure_digest: str
    tested_at: int
    expires_at: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ADJUDICATION_SCHEMA_VERSION


def _degradation_payload(plan: DegradationPlan) -> dict[str, Any]:
    return {
        "plan_id": plan.plan_id,
        "system_id": plan.system_id,
        "failure_modes": list(plan.failure_modes),
        "takeover_procedure_digest": plan.takeover_procedure_digest,
        "tested_at": plan.tested_at,
        "expires_at": plan.expires_at,
        "issued_by": plan.issued_by,
        "authority_pubkey_hex": plan.authority_pubkey_hex,
        "prev_digest": plan.prev_digest,
        "schema_version": plan.schema_version,
    }


def compute_degradation_digest(plan: DegradationPlan) -> str:
    """Recompute the JCS digest a degradation plan claims."""
    return jcs_sha256_hex(_degradation_payload(plan))


def issue_degradation_plan(
    *,
    plan_id: str,
    system_id: str,
    failure_modes: tuple[str, ...],
    takeover_procedure_digest: str,
    authority_secret: bytes,
    issued_by: str,
    tested_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> DegradationPlan:
    """Issue an authority-signed fail-closed degradation plan."""
    _check_secret(authority_secret, "authority_secret")
    plan_id = _check_nonempty_str(plan_id, "plan_id")
    system_id = _check_nonempty_str(system_id, "system_id")
    failure_modes = tuple(_check_failure_mode(m) for m in failure_modes)
    if not failure_modes:
        raise AdjudicationError("failure_modes must be non-empty")
    takeover_procedure_digest = _check_hex64(
        takeover_procedure_digest, "takeover_procedure_digest"
    )
    issued_by = _check_nonempty_str(issued_by, "issued_by")
    tested_at = _check_ts(tested_at, "tested_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= tested_at:
        raise AdjudicationError("expires_at must be after tested_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise AdjudicationError("prev_digest must be a non-empty string")

    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    bare = DegradationPlan(
        plan_id=plan_id,
        system_id=system_id,
        failure_modes=failure_modes,
        takeover_procedure_digest=takeover_procedure_digest,
        tested_at=tested_at,
        expires_at=expires_at,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="00" * _HEX128_LENGTH,  # placeholder; replaced below
        prev_digest=prev_digest,
    )
    signature_hex = ed25519.sign(
        authority_secret, jcs_canonical_json(_degradation_payload(bare))
    ).hex()
    sealed = DegradationPlan(**{**bare.__dict__, "signature_hex": signature_hex})
    return DegradationPlan(
        **{**sealed.__dict__, "receipt_digest": compute_degradation_digest(sealed)}
    )


def _verify_degradation_chain(log: list[DegradationPlan]) -> None:
    """Raise :class:`AdjudicationError` if the degradation log is broken."""
    expected_prev = _GENESIS
    for plan in log:
        if not isinstance(plan, DegradationPlan):
            raise AdjudicationError("log entry is not a DegradationPlan")
        if not hmac.compare_digest(
            compute_degradation_digest(plan), plan.receipt_digest
        ):
            raise AdjudicationError(
                f"plan {plan.plan_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(plan.prev_digest, expected_prev):
            raise AdjudicationError(
                f"plan {plan.plan_id!r} chain break: expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            plan.authority_pubkey_hex,
            _degradation_payload(plan),
            plan.signature_hex,
        ):
            raise AdjudicationError(
                f"plan {plan.plan_id!r} authority signature invalid"
            )
        expected_prev = plan.receipt_digest


def check_degradation_plan(
    log: list[DegradationPlan],
    *,
    system_id: str,
    check_time: int,
) -> BiometricVerdict:
    """Does this critical system have a valid fail-closed plan?

    The 110th-batch deployment-registration hook: no valid,
    unexpired, chain-intact plan covering at least one failure mode
    -> ``sports:no_degradation_plan`` and the system is not
    registrable. Full automation without a failure plan is not
    deployable.
    """
    system_id = _check_nonempty_str(system_id, "system_id")
    check_time = _check_ts(check_time, "check_time")

    def _deny(code: str, detail: str) -> BiometricVerdict:
        return BiometricVerdict(
            allowed=False,
            reason=f"{code}: {detail}",
            classification=CLASS_UNVERIFIABLE,
        )

    try:
        _verify_degradation_chain(log)
    except AdjudicationError as error:
        return _deny(DENY_CHAIN_BROKEN, f"degradation log integrity failure: {error}")

    plans = [p for p in log if p.system_id == system_id]
    if not plans:
        return _deny(
            DENY_NO_DEGRADATION_PLAN,
            f"no fail-closed degradation plan declared for {system_id!r} — "
            "undeclared failure behavior is not deployable",
        )
    plan = plans[-1]
    if check_time < plan.tested_at or check_time > plan.expires_at:
        return _deny(DENY_NO_DEGRADATION_PLAN, "degradation plan not valid now")
    return BiometricVerdict(
        allowed=True,
        reason=(
            f"degradation plan {plan.plan_id!r} covers "
            f"{list(plan.failure_modes)}, human-takeover procedure pinned"
        ),
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=plan.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Betting isolation
# ---------------------------------------------------------------------------


def check_pipeline_mixing(
    *,
    pipeline: str,
    inputs: tuple[Mapping[str, str], ...],
) -> BiometricVerdict:
    """Betting-tagged inputs may not enter protected pipelines.

    Each input carries a ``source`` in :data:`PIPELINE_SOURCES`. If
    ``pipeline`` is one of ``officiating`` / ``coaching`` /
    ``adjudication`` / ``medical`` and any input is ``betting``-sourced
    -> deny ``sports:betting_contamination`` (audited as
    ``sports.betting_contamination``). Betting pipelines themselves
    are unaffected by this gate.
    """
    pipeline = _check_nonempty_str(pipeline, "pipeline")
    if pipeline not in PIPELINE_SOURCES:
        raise AdjudicationError(f"unknown pipeline {pipeline!r}")
    for entry in inputs:
        if not isinstance(entry, Mapping):
            raise AdjudicationError("pipeline input must be a mapping")
        source = entry.get("source")
        _check_pipeline_source(source)

    tainted = [e for e in inputs if e.get("source") == "betting"]
    if tainted and pipeline in PROTECTED_PIPELINES:
        return BiometricVerdict(
            allowed=False,
            reason=(
                f"{DENY_BETTING_CONTAMINATION}: {len(tainted)} betting-tagged "
                f"input(s) in protected pipeline {pipeline!r}"
            ),
            classification=CLASS_UNVERIFIABLE,
        )
    return BiometricVerdict(
        allowed=True,
        reason=(
            f"pipeline {pipeline!r}: no betting contamination "
            f"({len(inputs)} input(s) checked)"
        ),
        classification=CLASS_AUTHORITATIVE,
    )
