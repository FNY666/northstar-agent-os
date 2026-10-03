"""Environmental-cost receipts (one-hundred-fifteenth batch).

Absorbs the 2026 AI-climate research thread (mechanism ideas only,
honestly scoped):

* **AI's own footprint is now grid-scale.** ~565 TWh of datacenter
  electricity in 2026 (+26%), AI's share of global generation headed
  1.8% -> 3.7-4%; a May-2026 US DOE emergency order drafted
  datacenter generators into PJM; Google reported 10.9B gallons of
  water in 2025 (+34%). Compute budgets (109th batch) meter *units*;
  this module receipts the *environmental* side of the same spend —
  kWh, water, and modeled carbon — so an agent's energy appetite is
  attributable, capped, and curtailment-aware.
* **Grid emergencies are fail-closed, not advisory.** When an
  authority orders curtailment, a workload that keeps burning at full
  rate is a violation, not a suggestion. Curtailment receipts are
  authority-signed and the rate cap is pinned to the budget's own
  baseline — no self-attestation.
* **Detection is not evidence.** MAPL-EMIT ships methane detections
  with confidence *and* spectral fit, and users filter on
  determinism. A detection below ``DETECTION_CONFIDENCE_MIN`` cannot
  authorize downstream action — low-confidence signal is not a
  license to act.
* **Experimental means non-authoritative.** WeatherNext 3 self-labels
  as an "experimental AI forecast system" and defers official alerts
  to national agencies. The maturity label is pinned in the
  registration receipt; experimental systems' outputs classify
  NON_AUTHORITATIVE by default, with no silent label upgrades.
* **Physics constrains extrapolation.** The coastal-AI review found
  purely data-driven models can supplement but not replace physical
  models. Extrapolation beyond the pinned constraint list is
  NON_AUTHORITATIVE (111th-batch ``ConstraintBinding`` semantics).
* **Detection without action is open-loop.** UN MARS flags 80-85% of
  methane releases; the UNEP line is "the challenge is no longer
  finding emissions, it's acting on them." A detection receipt is
  ``open-loop`` until an action-confirmation receipt references it —
  dashboards must not present unconfirmed detections as resolved.
* **Efficiency claims need a named platform.** The Green AI
  peer-reviewed line: an efficiency claim is only *checkable* when it
  binds a named platform and a directly measured metrics digest.
  Anything else is an ``unverifiable-claim``.

Northstar mapping:

* ``EnvProfile`` — authority-signed receipt binding
  ``(budget_id, kwh_total, baseline_kwh_per_hour, grid_region,
  emission_factor_digest, emission_factor_kg_per_kwh, issued_by)``.
  The emission factor is pinned as *both* a digest and a decimal
  string; carbon is computed from the pinned factor and labeled
  ``_est`` everywhere it appears — measured kWh, modeled carbon, and
  the ledger never confuses the two.
* ``EnvironmentalCostLedger.spend()`` — hash-chained ``EnvSpendReceipt``
  ``(budget_id, kwh, water_liters, carbon_kg_est, grid_region,
  emission_factor_digest, purpose, remaining_kwh, prev_hash)``.
  Spend without a registered env profile denies (``env:no_env_profile``);
  overspend against the declared kWh ceiling denies
  (``env:budget_exhausted``) — fail-closed, no borrowing; spend
  without a purpose denies (unattributed energy is unauthorizable
  energy). Active curtailment in the profile's region caps the single
  spend at ``baseline_kwh_per_hour * reduction_factor``;
  exceeding denies ``env:curtailment_violation``.
* ``CurtailmentReceipt`` — authority-signed grid-emergency order
  ``(curtailment_id, grid_region, start_unix, end_unix,
  reduction_factor_permille, issued_by)``.
* ``DetectionRegistry`` — ``detection_receipt()`` binds
  ``(detection_id, claim_digest, confidence, fit_evidence_digest,
  detector_id)``; confidence below ``DETECTION_CONFIDENCE_MIN``
  registers the claim as *not usable as evidence*
  (``env:insufficient_confidence``) — it stays visible (MAPL-EMIT
  shows low-confidence detections) but cannot authorize action.
* ``MaturityRegistry`` — ``(system_id, model_digest, maturity,
  deployment_receipt_digest)``; experimental/pilot outputs classify
  NON_AUTHORITATIVE; the maturity record pins the 110th-batch
  deployment registration digest so the label cannot drift from the
  registered system.
* ``PhysicsGate`` — tasks declaring physical extrapolation must hold
  a ``dual_use.ConstraintBinding``; extrapolation whose applied
  constraints digest does not match the pinned list denies with
  ``env:physics_gap`` (NON_AUTHORITATIVE).
* ``confirm_action()`` — ``ActionConfirmation`` receipts chain a
  detection to a confirmed action; ``link_status()`` reports
  ``open-loop`` vs ``confirmed``.
* ``register_efficiency_claim()`` — binds ``(claim_digest,
  named_platform, measured_metrics_digest)``; missing platform or
  unpinned metrics classify ``env:unverifiable_efficiency_claim``.

Honest boundary: this module attributes *declared* kWh, water, and
modeled carbon. It cannot meter a wall socket or a cooling tower —
real hardware metering needs host cooperation (power meters, water
telemetry), which is outside this module's scope. Carbon is *modeled*
from a pinned emission factor and is labeled ``_est`` on every
surface; presenting it as measured would be dishonest and this
module refuses to do it. What it does guarantee: no authorized env
spend without a spend receipt; the kWh ceiling cannot be silently
widened; curtailment caps are enforced, not suggested; low-confidence
detections cannot authorize action; experimental systems cannot
shed their label; and efficiency claims without a named platform
and measured metrics are unverifiable claims, not facts.

Deterministic: no wall-clock reads (callers inject ``created_unix``
as an integer), canonical JCS hashing, decimal (not binary-float)
carbon arithmetic, constant-time digest comparisons.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Mapping

from canonical_json import jcs_sha256_hex
from dual_use import ConstraintBinding
from ed25519 import public_key as ed_public_key
from ed25519 import sign as ed_sign
from ed25519 import verify as ed_verify

ENV_COST_SCHEMA_VERSION = "northstar.env-cost.v1"

#: System maturities, weakest first. Only ``production`` outputs are
#: authoritative by default; pilot and experimental are
#: NON_AUTHORITATIVE (the WeatherNext 3 discipline: label the system,
#: defer authoritative claims).
MATURITIES: tuple[str, ...] = ("experimental", "pilot", "production")

#: Minimum detection confidence for a detection to be *usable as
#: evidence* (MAPL-EMIT: ship confidence + fit, filter on
#: determinism). Below this, the claim is registered but cannot
#: authorize downstream action.
DETECTION_CONFIDENCE_MIN = 0.7

#: Carbon arithmetic is decimal with this many places; carbon is
#: always labeled ``_est`` (modeled, not measured).
_CARBON_PLACES = 3

#: Denial reason codes. All start with the ``env:`` prefix so audit
#: consumers can filter the family.
DENY_UNKNOWN_BUDGET = "env:unknown_budget"
DENY_PROFILE_EXPIRED = "env:profile_expired"
DENY_BUDGET_EXHAUSTED = "env:budget_exhausted"
DENY_MISSING_PURPOSE = "env:missing_purpose"
DENY_CURTAILMENT_VIOLATION = "env:curtailment_violation"
DENY_INSUFFICIENT_CONFIDENCE = "env:insufficient_confidence"
DENY_EXPERIMENTAL = "env:experimental_non_authoritative"
DENY_PHYSICS_GAP = "env:physics_gap"
DENY_UNVERIFIABLE_EFFICIENCY = "env:unverifiable_efficiency_claim"
DENY_DIGEST_MISMATCH = "env:spend_digest_mismatch"
DENY_CHAIN_GAP = "env:chain_gap"
DENY_MALFORMED = "env:malformed"
DENY_UNKNOWN_DETECTION = "env:unknown_detection"
DENY_OPEN_LOOP = "env:open_loop_detection"

#: Classifications (share the 87th-batch binary vocabulary).
CLASS_AUTHORITATIVE = "AUTHORITATIVE"
CLASS_NON_AUTHORITATIVE = "NON_AUTHORITATIVE"
CLASS_UNVERIFIABLE_CLAIM = "unverifiable-claim"

#: Audit event names (shaped to feed ``audit_chain.chain_record``).
ENV_SPEND_EVENT = "env.spend"
ENV_EXHAUSTED_EVENT = "env.budget_exhausted"
ENV_DENIED_EVENT = "env.use_denied"
ENV_CURTAILMENT_EVENT = "env.curtailment_registered"
DETECTION_REGISTERED_EVENT = "env.detection_registered"
DETECTION_REJECTED_EVENT = "env.detection_rejected"
ACTION_CONFIRMED_EVENT = "env.action_confirmed"
EFFICIENCY_CLAIM_EVENT = "env.efficiency_claim"

_HEX64_LENGTH = 64
_ED25519_SIG_LENGTH = 64


class EnvCostError(ValueError):
    """A malformed profile, receipt, registry, or request — a
    programming error, not a verdict. Verification *failures*
    (unknown budget, overspend, curtailment breach, low confidence,
    experimental output, physics gap, unverifiable claim) return a
    verdict with ``allowed=False`` instead; malformed input raises
    here, fail loud, never guess."""


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _HEX64_LENGTH
        and all(c in "0123456789abcdef" for c in value)
    )


def _require_hex64(value: Any, what: str) -> str:
    if not _is_hex64(value):
        raise EnvCostError(f"{what} must be a 64-char lowercase hex digest")
    return value


def _require_nonempty(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise EnvCostError(f"{what} must be a non-empty string")
    return value


def _require_positive_int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise EnvCostError(f"{what} must be a positive int")
    return value


def _require_nonneg_int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EnvCostError(f"{what} must be a non-negative int")
    return value


def _require_unix(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EnvCostError(f"{what} must be a non-negative int (unix time)")
    return value


def _require_confidence(value: Any, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EnvCostError(f"{what} must be a number in [0, 1]")
    f = float(value)
    if not (0.0 <= f <= 1.0):
        raise EnvCostError(f"{what} must be a number in [0, 1]")
    return f


def _require_decimal_factor(value: Any, what: str) -> str:
    """Pin the emission factor as a *decimal string* (deterministic
    carbon arithmetic; binary floats are banned from receipts)."""
    if not isinstance(value, str) or not value:
        raise EnvCostError(f"{what} must be a non-empty decimal string")
    try:
        d = Decimal(value)
    except InvalidOperation:
        raise EnvCostError(f"{what} must be a valid decimal string")
    if d < 0:
        raise EnvCostError(f"{what} must be non-negative")
    return value


def carbon_kg_est(kwh: int, factor_kg_per_kwh: str) -> str:
    """Modeled carbon for a spend: ``kwh * factor``, decimal,
    labeled ``_est`` at every call site. This is a *model*, not a
    measurement — the ledger never presents it as measured."""
    est = (Decimal(kwh) * Decimal(factor_kg_per_kwh)).quantize(
        Decimal(10) ** -_CARBON_PLACES, rounding=ROUND_HALF_UP
    )
    return format(est, "f")


# ---------------------------------------------------------------------------
# AuthorityRegistry: who may mint env profiles and curtailment orders
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorityRegistry:
    """Maps ``authority_id`` to an Ed25519 public key (32 bytes).

    Only registered *human* authorities may mint env profiles or
    issue curtailment orders. There is no agent-key path: the agent
    is always the *subject* of the profile, never the issuer.
    """

    public_keys: Mapping[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for authority_id, pubkey in self.public_keys.items():
            _require_nonempty(authority_id, "authority_id")
            if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
                raise EnvCostError(
                    f"public key for {authority_id!r} must be 32 bytes"
                )

    def public_key_for(self, authority_id: str) -> bytes | None:
        key = self.public_keys.get(authority_id)
        return bytes(key) if key is not None else None


# ---------------------------------------------------------------------------
# EnvProfile: the authority-signed environmental profile for a budget
# ---------------------------------------------------------------------------


def _profile_payload(
    *,
    budget_id: str,
    kwh_total: int,
    baseline_kwh_per_hour: int,
    grid_region: str,
    emission_factor_digest: str,
    emission_factor_kg_per_kwh: str,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": ENV_COST_SCHEMA_VERSION,
        "budget_id": budget_id,
        "kwh_total": kwh_total,
        "baseline_kwh_per_hour": baseline_kwh_per_hour,
        "grid_region": grid_region,
        "emission_factor_digest": emission_factor_digest,
        "emission_factor_kg_per_kwh": emission_factor_kg_per_kwh,
        "issued_by": issued_by,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class EnvProfile:
    """An authority-signed environmental profile for a compute budget.

    ``kwh_total`` is the lifetime energy ceiling; ``baseline_kwh_per_hour``
    is the pinned burn rate that curtailment orders scale down (the
    curtailment cap is ``baseline * reduction_factor``, never a
    self-declared number). ``emission_factor_kg_per_kwh`` is a decimal
    string pinned alongside its digest — carbon derived from it is
    *modeled*, labeled ``_est`` everywhere.
    """

    budget_id: str
    kwh_total: int
    baseline_kwh_per_hour: int
    grid_region: str
    emission_factor_digest: str
    emission_factor_kg_per_kwh: str
    issued_by: str
    issued_at: int
    expires_at: int
    profile_digest: str
    signature: bytes
    prev_hash: str = ""
    schema_version: str = ENV_COST_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "env-profile",
            "schema_version": self.schema_version,
            "budget_id": self.budget_id,
            "kwh_total": self.kwh_total,
            "baseline_kwh_per_hour": self.baseline_kwh_per_hour,
            "grid_region": self.grid_region,
            "emission_factor_digest": self.emission_factor_digest,
            "emission_factor_kg_per_kwh": self.emission_factor_kg_per_kwh,
            "issued_by": self.issued_by,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "profile_digest": self.profile_digest,
            "signature": self.signature.hex(),
            "prev_hash": self.prev_hash,
        }


def issue_env_profile(
    registry: AuthorityRegistry,
    *,
    budget_id: str,
    kwh_total: int,
    baseline_kwh_per_hour: int,
    grid_region: str,
    emission_factor_digest: str,
    emission_factor_kg_per_kwh: str,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    signature: bytes,
    prev_hash: str = "",
) -> EnvProfile:
    """Mint an env profile. The signature must come from a registered
    human authority over the profile digest; anything else fails loud.
    There is deliberately no agent-key issuance path."""
    if not isinstance(registry, AuthorityRegistry):
        raise EnvCostError("registry must be an AuthorityRegistry")
    _require_nonempty(budget_id, "budget_id")
    _require_positive_int(kwh_total, "kwh_total")
    _require_positive_int(baseline_kwh_per_hour, "baseline_kwh_per_hour")
    _require_nonempty(grid_region, "grid_region")
    _require_hex64(emission_factor_digest, "emission_factor_digest")
    _require_decimal_factor(emission_factor_kg_per_kwh,
                            "emission_factor_kg_per_kwh")
    _require_nonempty(issued_by, "issued_by")
    _require_unix(issued_at, "issued_at")
    _require_unix(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise EnvCostError("expires_at must be after issued_at")
    if prev_hash and not _is_hex64(prev_hash):
        raise EnvCostError("prev_hash must be empty or a 64-char hex digest")
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != _ED25519_SIG_LENGTH:
        raise EnvCostError("signature must be 64 bytes")

    pubkey = registry.public_key_for(issued_by)
    if pubkey is None:
        raise EnvCostError(
            f"issued_by {issued_by!r} is not a registered env authority"
        )
    digest = jcs_sha256_hex(
        _profile_payload(
            budget_id=budget_id,
            kwh_total=kwh_total,
            baseline_kwh_per_hour=baseline_kwh_per_hour,
            grid_region=grid_region,
            emission_factor_digest=emission_factor_digest,
            emission_factor_kg_per_kwh=emission_factor_kg_per_kwh,
            issued_by=issued_by,
            issued_at=issued_at,
            expires_at=expires_at,
            prev_hash=prev_hash,
        )
    )
    if not ed_verify(pubkey, digest.encode("utf-8"), bytes(signature)):
        raise EnvCostError("authority signature does not verify")
    return EnvProfile(
        budget_id=budget_id,
        kwh_total=kwh_total,
        baseline_kwh_per_hour=baseline_kwh_per_hour,
        grid_region=grid_region,
        emission_factor_digest=emission_factor_digest,
        emission_factor_kg_per_kwh=emission_factor_kg_per_kwh,
        issued_by=issued_by,
        issued_at=issued_at,
        expires_at=expires_at,
        profile_digest=digest,
        signature=bytes(signature),
        prev_hash=prev_hash,
    )


# ---------------------------------------------------------------------------
# CurtailmentReceipt: authority-signed grid-emergency order
# ---------------------------------------------------------------------------


def _curtailment_payload(
    *,
    curtailment_id: str,
    grid_region: str,
    start_unix: int,
    end_unix: int,
    reduction_factor_permille: int,
    issued_by: str,
    issued_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": ENV_COST_SCHEMA_VERSION,
        "curtailment_id": curtailment_id,
        "grid_region": grid_region,
        "start_unix": start_unix,
        "end_unix": end_unix,
        "reduction_factor_permille": reduction_factor_permille,
        "issued_by": issued_by,
        "issued_at": issued_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class CurtailmentReceipt:
    """An authority-signed grid-emergency curtailment order.

    ``reduction_factor_permille`` is per-mille (0..1000): during the
    window, a budget's spend rate is capped at
    ``baseline_kwh_per_hour * factor / 1000``. The baseline comes from
    the budget's own pinned ``EnvProfile`` — the capped party cannot
    move it.
    """

    curtailment_id: str
    grid_region: str
    start_unix: int
    end_unix: int
    reduction_factor_permille: int
    issued_by: str
    issued_at: int
    curtailment_digest: str
    signature: bytes
    prev_hash: str = ""
    schema_version: str = ENV_COST_SCHEMA_VERSION

    def active_at(self, unix: int) -> bool:
        return self.start_unix <= unix < self.end_unix

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "env-curtailment",
            "schema_version": self.schema_version,
            "curtailment_id": self.curtailment_id,
            "grid_region": self.grid_region,
            "start_unix": self.start_unix,
            "end_unix": self.end_unix,
            "reduction_factor_permille": self.reduction_factor_permille,
            "issued_by": self.issued_by,
            "issued_at": self.issued_at,
            "curtailment_digest": self.curtailment_digest,
            "signature": self.signature.hex(),
            "prev_hash": self.prev_hash,
        }


def issue_curtailment(
    registry: AuthorityRegistry,
    *,
    curtailment_id: str,
    grid_region: str,
    start_unix: int,
    end_unix: int,
    reduction_factor_permille: int,
    issued_by: str,
    issued_at: int,
    signature: bytes,
    prev_hash: str = "",
) -> CurtailmentReceipt:
    """Issue a curtailment order. Only a registered authority can
    order the grid to shed load; the agent is the *subject*, never the
    issuer."""
    if not isinstance(registry, AuthorityRegistry):
        raise EnvCostError("registry must be an AuthorityRegistry")
    _require_nonempty(curtailment_id, "curtailment_id")
    _require_nonempty(grid_region, "grid_region")
    _require_unix(start_unix, "start_unix")
    _require_unix(end_unix, "end_unix")
    if end_unix <= start_unix:
        raise EnvCostError("end_unix must be after start_unix")
    if (not isinstance(reduction_factor_permille, int)
            or isinstance(reduction_factor_permille, bool)
            or not (0 <= reduction_factor_permille <= 1000)):
        raise EnvCostError("reduction_factor_permille must be an int in [0, 1000]")
    _require_nonempty(issued_by, "issued_by")
    _require_unix(issued_at, "issued_at")
    if prev_hash and not _is_hex64(prev_hash):
        raise EnvCostError("prev_hash must be empty or a 64-char hex digest")
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != _ED25519_SIG_LENGTH:
        raise EnvCostError("signature must be 64 bytes")

    pubkey = registry.public_key_for(issued_by)
    if pubkey is None:
        raise EnvCostError(
            f"issued_by {issued_by!r} is not a registered env authority"
        )
    digest = jcs_sha256_hex(
        _curtailment_payload(
            curtailment_id=curtailment_id,
            grid_region=grid_region,
            start_unix=start_unix,
            end_unix=end_unix,
            reduction_factor_permille=reduction_factor_permille,
            issued_by=issued_by,
            issued_at=issued_at,
            prev_hash=prev_hash,
        )
    )
    if not ed_verify(pubkey, digest.encode("utf-8"), bytes(signature)):
        raise EnvCostError("authority signature does not verify")
    return CurtailmentReceipt(
        curtailment_id=curtailment_id,
        grid_region=grid_region,
        start_unix=start_unix,
        end_unix=end_unix,
        reduction_factor_permille=reduction_factor_permille,
        issued_by=issued_by,
        issued_at=issued_at,
        curtailment_digest=digest,
        signature=bytes(signature),
        prev_hash=prev_hash,
    )


# ---------------------------------------------------------------------------
# EnvSpendReceipt: one hash-chained environmental spend
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnvSpendReceipt:
    """One authorized environmental spend, hash-chained.

    ``kwh`` is declared/metered energy (integer kWh);
    ``water_liters`` is declared cooling water; ``carbon_kg_est`` is
    *modeled* carbon from the profile's pinned emission factor and is
    labeled ``_est`` everywhere — the ledger attributes cost, it does
    not meter physics. ``remaining_kwh`` is the energy balance after
    this spend.
    """

    receipt_id: str
    budget_id: str
    kwh: int
    water_liters: int
    carbon_kg_est: str
    grid_region: str
    emission_factor_digest: str
    purpose: str
    remaining_kwh: int
    prev_hash: str = ""
    created_unix: int = 0
    schema_version: str = ENV_COST_SCHEMA_VERSION

    def receipt_hash(self) -> str:
        return jcs_sha256_hex(
            {
                "schema_version": self.schema_version,
                "receipt_id": self.receipt_id,
                "budget_id": self.budget_id,
                "kwh": self.kwh,
                "water_liters": self.water_liters,
                "carbon_kg_est": self.carbon_kg_est,
                "grid_region": self.grid_region,
                "emission_factor_digest": self.emission_factor_digest,
                "purpose": self.purpose,
                "remaining_kwh": self.remaining_kwh,
                "prev_hash": self.prev_hash,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "env-spend-receipt",
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "budget_id": self.budget_id,
            "kwh": self.kwh,
            "water_liters": self.water_liters,
            "carbon_kg_est": self.carbon_kg_est,
            "grid_region": self.grid_region,
            "emission_factor_digest": self.emission_factor_digest,
            "purpose": self.purpose,
            "remaining_kwh": self.remaining_kwh,
            "prev_hash": self.prev_hash,
            "created_unix": self.created_unix,
            "receipt_hash": self.receipt_hash(),
        }


@dataclass(frozen=True)
class EnvVerdict:
    """The verdict of a gate call."""

    allowed: bool
    reason: str
    classification: str
    audit_event: dict[str, Any]


def _env_event(
    *,
    budget_id: str,
    allowed: bool,
    reason: str,
    kwh: int,
    purpose: str,
    remaining_kwh: int,
    receipt_hash: str,
    created_unix: int,
) -> dict[str, Any]:
    event = ENV_SPEND_EVENT if allowed else ENV_DENIED_EVENT
    if reason == DENY_BUDGET_EXHAUSTED:
        event = ENV_EXHAUSTED_EVENT
    return {
        "event": event,
        "budget_id": budget_id,
        "allowed": allowed,
        "reason": reason,
        "kwh": kwh,
        "purpose": purpose,
        "remaining_kwh": remaining_kwh,
        "receipt_hash": receipt_hash,
        "created_unix": created_unix,
    }


# ---------------------------------------------------------------------------
# EnvironmentalCostLedger: profiles, curtailments, spend chains
# ---------------------------------------------------------------------------


class EnvironmentalCostLedger:
    """Owns env profiles, curtailment orders, and spend chains.

    The ledger is the enforcement point: every authorized energy
    spend passes through :meth:`spend`, which appends a hash-chained
    receipt carrying ``(kwh, water_liters, carbon_kg_est,
    grid_region)``. There is no spend path that bypasses the ledger.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, EnvProfile] = {}
        self._curtailments: list[CurtailmentReceipt] = []
        self._chains: dict[str, list[EnvSpendReceipt]] = {}
        self._receipt_seq = 0

    # -- profiles ------------------------------------------------------

    def register_profile(self, profile: EnvProfile) -> EnvProfile:
        """Register an authority-signed env profile. Duplicate
        budget ids refuse (re-issuance is a new receipt chained via
        ``prev_hash``, never a silent replace)."""
        if not isinstance(profile, EnvProfile):
            raise EnvCostError("profile must be an EnvProfile")
        if profile.budget_id in self._profiles:
            raise EnvCostError(
                f"duplicate env profile for budget {profile.budget_id!r}"
            )
        self._profiles[profile.budget_id] = profile
        self._chains[profile.budget_id] = []
        return profile

    def register_curtailment(self, order: CurtailmentReceipt) -> CurtailmentReceipt:
        """Register an authority-signed curtailment order."""
        if not isinstance(order, CurtailmentReceipt):
            raise EnvCostError("order must be a CurtailmentReceipt")
        self._curtailments.append(order)
        return order

    def remaining_kwh(self, budget_id: str) -> int:
        """Current energy balance. Unknown budgets raise (programmer
        error — the *gate* returns a verdict instead)."""
        profile = self._profiles.get(budget_id)
        if profile is None:
            raise EnvCostError(f"unknown budget {budget_id!r}")
        chain = self._chains[budget_id]
        if not chain:
            return profile.kwh_total
        return chain[-1].remaining_kwh

    def active_curtailment(self, grid_region: str, unix: int) -> CurtailmentReceipt | None:
        """The curtailment order active in ``grid_region`` at ``unix``,
        or None. Orders are authority-signed; the ledger only reads
        them."""
        for order in self._curtailments:
            if order.grid_region == grid_region and order.active_at(unix):
                return order
        return None

    def verify_chain(self, budget_id: str) -> tuple[bool, str]:
        """Balance-walk the spend chain: prev_hash links, receipt
        hashes, and the remaining_kwh step-down. Tampering is caught
        here, not trusted."""
        chain = self._chains.get(budget_id)
        if chain is None:
            return (False, DENY_UNKNOWN_BUDGET)
        profile = self._profiles[budget_id]
        expected_prev = ""
        expected_remaining = profile.kwh_total
        for receipt in chain:
            if receipt.prev_hash != expected_prev:
                return (False, DENY_CHAIN_GAP)
            if receipt.budget_id != budget_id:
                return (False, DENY_DIGEST_MISMATCH)
            if receipt.remaining_kwh != expected_remaining - receipt.kwh:
                return (False, DENY_DIGEST_MISMATCH)
            expected_prev = receipt.receipt_hash()
            expected_remaining = receipt.remaining_kwh
        return (True, "ok")

    # -- the spend gate -------------------------------------------------

    def spend(
        self,
        budget_id: str,
        *,
        kwh: int,
        water_liters: int,
        purpose: str,
        created_unix: int,
    ) -> EnvVerdict:
        """Authorize one environmental spend. Fail-closed order:
        profile present -> profile unexpired -> purpose present ->
        kwh positive -> curtailment cap -> kwh ceiling. The receipt
        carries ``(kwh, water_liters, carbon_kg_est, grid_region)``;
        carbon is *modeled* from the pinned factor (``_est``).
        """
        profile = self._profiles.get(budget_id)
        if profile is None:
            return EnvVerdict(
                allowed=False,
                reason=DENY_UNKNOWN_BUDGET,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event=_env_event(
                    budget_id=budget_id, allowed=False,
                    reason=DENY_UNKNOWN_BUDGET, kwh=0, purpose="",
                    remaining_kwh=0, receipt_hash="", created_unix=created_unix,
                ),
            )
        if created_unix >= profile.expires_at:
            return EnvVerdict(
                allowed=False,
                reason=DENY_PROFILE_EXPIRED,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event=_env_event(
                    budget_id=budget_id, allowed=False,
                    reason=DENY_PROFILE_EXPIRED, kwh=0, purpose="",
                    remaining_kwh=self.remaining_kwh(budget_id),
                    receipt_hash="", created_unix=created_unix,
                ),
            )
        if not isinstance(purpose, str) or not purpose:
            return EnvVerdict(
                allowed=False,
                reason=DENY_MISSING_PURPOSE,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event=_env_event(
                    budget_id=budget_id, allowed=False,
                    reason=DENY_MISSING_PURPOSE, kwh=0, purpose="",
                    remaining_kwh=self.remaining_kwh(budget_id),
                    receipt_hash="", created_unix=created_unix,
                ),
            )
        if not isinstance(kwh, int) or isinstance(kwh, bool) or kwh <= 0:
            return EnvVerdict(
                allowed=False,
                reason=DENY_MALFORMED,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event=_env_event(
                    budget_id=budget_id, allowed=False,
                    reason=DENY_MALFORMED, kwh=0, purpose=purpose,
                    remaining_kwh=self.remaining_kwh(budget_id),
                    receipt_hash="", created_unix=created_unix,
                ),
            )
        _require_nonneg_int(water_liters, "water_liters")
        _require_unix(created_unix, "created_unix")

        # Curtailment: the cap is baseline * factor, both pinned by an
        # authority. Burning at full rate during curtailment denies.
        order = self.active_curtailment(profile.grid_region, created_unix)
        if order is not None:
            cap = (profile.baseline_kwh_per_hour
                   * order.reduction_factor_permille // 1000)
            if kwh > cap:
                return EnvVerdict(
                    allowed=False,
                    reason=DENY_CURTAILMENT_VIOLATION,
                    classification=CLASS_NON_AUTHORITATIVE,
                    audit_event={
                        "event": ENV_DENIED_EVENT,
                        "budget_id": budget_id,
                        "allowed": False,
                        "reason": DENY_CURTAILMENT_VIOLATION,
                        "kwh": kwh,
                        "curtailment_cap_kwh": cap,
                        "curtailment_id": order.curtailment_id,
                        "created_unix": created_unix,
                    },
                )

        remaining = self.remaining_kwh(budget_id)
        if kwh > remaining:
            return EnvVerdict(
                allowed=False,
                reason=DENY_BUDGET_EXHAUSTED,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event=_env_event(
                    budget_id=budget_id, allowed=False,
                    reason=DENY_BUDGET_EXHAUSTED, kwh=kwh, purpose=purpose,
                    remaining_kwh=remaining, receipt_hash="",
                    created_unix=created_unix,
                ),
            )

        self._receipt_seq += 1
        chain = self._chains[budget_id]
        prev_hash = chain[-1].receipt_hash() if chain else ""
        receipt = EnvSpendReceipt(
            receipt_id=f"env-{budget_id}-{self._receipt_seq:06d}",
            budget_id=budget_id,
            kwh=kwh,
            water_liters=water_liters,
            carbon_kg_est=carbon_kg_est(kwh, profile.emission_factor_kg_per_kwh),
            grid_region=profile.grid_region,
            emission_factor_digest=profile.emission_factor_digest,
            purpose=purpose,
            remaining_kwh=remaining - kwh,
            prev_hash=prev_hash,
            created_unix=created_unix,
        )
        chain.append(receipt)
        return EnvVerdict(
            allowed=True,
            reason="ok",
            classification=CLASS_AUTHORITATIVE,
            audit_event=_env_event(
                budget_id=budget_id, allowed=True, reason="ok",
                kwh=kwh, purpose=purpose,
                remaining_kwh=receipt.remaining_kwh,
                receipt_hash=receipt.receipt_hash(),
                created_unix=created_unix,
            ),
        )

    # -- deterministic aggregation --------------------------------------

    def cost_ledger(self, budget_id: str) -> dict[str, Any]:
        """Deterministic aggregation of the spend chain: kWh, water,
        and *estimated* carbon per purpose and totals. No new metrics
        invented — \"cost per outcome\" is computed *from* the
        receipts."""
        chain = self._chains.get(budget_id)
        if chain is None:
            raise EnvCostError(f"unknown budget {budget_id!r}")
        by_purpose: dict[str, dict[str, Any]] = {}
        total_kwh = 0
        total_water = 0
        for receipt in chain:
            total_kwh += receipt.kwh
            total_water += receipt.water_liters
            slot = by_purpose.setdefault(
                receipt.purpose,
                {"kwh": 0, "water_liters": 0, "carbon_kg_est": "0.000"},
            )
            slot["kwh"] += receipt.kwh
            slot["water_liters"] += receipt.water_liters
            slot["carbon_kg_est"] = format(
                (Decimal(slot["carbon_kg_est"])
                 + Decimal(receipt.carbon_kg_est)).quantize(
                    Decimal(10) ** -_CARBON_PLACES, rounding=ROUND_HALF_UP),
                "f",
            )
        profile = self._profiles[budget_id]
        total_carbon = carbon_kg_est(total_kwh, profile.emission_factor_kg_per_kwh)
        return {
            "budget_id": budget_id,
            "total_kwh": total_kwh,
            "total_water_liters": total_water,
            "total_carbon_kg_est": total_carbon,
            "by_purpose": {k: by_purpose[k] for k in sorted(by_purpose)},
            "receipt_count": len(chain),
        }


# ---------------------------------------------------------------------------
# DetectionRegistry: confidence-gated detection receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionClaim:
    """A detection claim binding ``(detection_id, claim_digest,
    confidence, fit_evidence_digest, detector_id)``.

    ``usable_as_evidence`` is False when ``confidence`` is below
    ``DETECTION_CONFIDENCE_MIN`` — the claim stays registered and
    visible (low-confidence detections are still information), but it
    cannot authorize downstream action. Detection is not evidence
    until it clears the gate.
    """

    detection_id: str
    claim_digest: str
    confidence: float
    fit_evidence_digest: str
    detector_id: str
    detected_unix: int
    usable_as_evidence: bool
    schema_version: str = ENV_COST_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "env-detection",
            "schema_version": self.schema_version,
            "detection_id": self.detection_id,
            "claim_digest": self.claim_digest,
            "confidence": self.confidence,
            "fit_evidence_digest": self.fit_evidence_digest,
            "detector_id": self.detector_id,
            "detected_unix": self.detected_unix,
            "usable_as_evidence": self.usable_as_evidence,
        }


class DetectionRegistry:
    """Owns detection claims and the evidence gate."""

    def __init__(self) -> None:
        self._claims: dict[str, DetectionClaim] = {}

    def detection_receipt(
        self,
        *,
        detection_id: str,
        claim_digest: str,
        confidence: float,
        fit_evidence_digest: str,
        detector_id: str,
        detected_unix: int,
    ) -> tuple[DetectionClaim, EnvVerdict]:
        """Register a detection claim. Below
        ``DETECTION_CONFIDENCE_MIN`` the claim registers with
        ``usable_as_evidence=False`` and the verdict denies — the
        signal is kept, the authority to act on it is withheld."""
        _require_nonempty(detection_id, "detection_id")
        _require_hex64(claim_digest, "claim_digest")
        conf = _require_confidence(confidence, "confidence")
        _require_hex64(fit_evidence_digest, "fit_evidence_digest")
        _require_nonempty(detector_id, "detector_id")
        _require_unix(detected_unix, "detected_unix")
        if detection_id in self._claims:
            raise EnvCostError(f"duplicate detection_id {detection_id!r}")
        usable = conf >= DETECTION_CONFIDENCE_MIN
        claim = DetectionClaim(
            detection_id=detection_id,
            claim_digest=claim_digest,
            confidence=conf,
            fit_evidence_digest=fit_evidence_digest,
            detector_id=detector_id,
            detected_unix=detected_unix,
            usable_as_evidence=usable,
        )
        self._claims[detection_id] = claim
        event = DETECTION_REGISTERED_EVENT if usable else DETECTION_REJECTED_EVENT
        return claim, EnvVerdict(
            allowed=usable,
            reason="ok" if usable else DENY_INSUFFICIENT_CONFIDENCE,
            classification=(CLASS_AUTHORITATIVE if usable
                            else CLASS_NON_AUTHORITATIVE),
            audit_event={
                "event": event,
                "detection_id": detection_id,
                "allowed": usable,
                "reason": "ok" if usable else DENY_INSUFFICIENT_CONFIDENCE,
                "confidence": conf,
                "confidence_min": DETECTION_CONFIDENCE_MIN,
                "usable_as_evidence": usable,
                "detected_unix": detected_unix,
            },
        )

    def claim(self, detection_id: str) -> DetectionClaim | None:
        return self._claims.get(detection_id)

    def authorize_action_on_detection(
        self, detection_id: str, action_digest: str, created_unix: int
    ) -> EnvVerdict:
        """Gate downstream action on a detection: unknown detection
        denies; a registered-but-below-threshold detection denies
        (``env:insufficient_confidence``). Detection without
        sufficient confidence is not a license to act."""
        _require_hex64(action_digest, "action_digest")
        _require_unix(created_unix, "created_unix")
        claim = self._claims.get(detection_id)
        if claim is None:
            return EnvVerdict(
                allowed=False,
                reason=DENY_UNKNOWN_DETECTION,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event={
                    "event": ENV_DENIED_EVENT,
                    "detection_id": detection_id,
                    "allowed": False,
                    "reason": DENY_UNKNOWN_DETECTION,
                    "created_unix": created_unix,
                },
            )
        if not claim.usable_as_evidence:
            return EnvVerdict(
                allowed=False,
                reason=DENY_INSUFFICIENT_CONFIDENCE,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event={
                    "event": ENV_DENIED_EVENT,
                    "detection_id": detection_id,
                    "allowed": False,
                    "reason": DENY_INSUFFICIENT_CONFIDENCE,
                    "confidence": claim.confidence,
                    "confidence_min": DETECTION_CONFIDENCE_MIN,
                    "created_unix": created_unix,
                },
            )
        return EnvVerdict(
            allowed=True,
            reason="ok",
            classification=CLASS_AUTHORITATIVE,
            audit_event={
                "event": DETECTION_REGISTERED_EVENT,
                "detection_id": detection_id,
                "action_digest": action_digest,
                "allowed": True,
                "reason": "ok",
                "created_unix": created_unix,
            },
        )


# ---------------------------------------------------------------------------
# MaturityRegistry: experimental-system labeling discipline
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MaturityRecord:
    """A system's maturity label, pinned to its 110th-batch
    deployment registration digest. The label travels *with* the
    registration — the system cannot shed ``experimental`` while
    the registration says otherwise, and the record cannot be
    widened by the system itself."""

    system_id: str
    model_digest: str
    maturity: str
    deployment_receipt_digest: str
    registered_by: str
    registered_at: int
    schema_version: str = ENV_COST_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "env-maturity",
            "schema_version": self.schema_version,
            "system_id": self.system_id,
            "model_digest": self.model_digest,
            "maturity": self.maturity,
            "deployment_receipt_digest": self.deployment_receipt_digest,
            "registered_by": self.registered_by,
            "registered_at": self.registered_at,
        }


class MaturityRegistry:
    """Owns maturity labels and the output classification gate."""

    def __init__(self) -> None:
        self._records: dict[str, MaturityRecord] = {}

    def register(
        self,
        *,
        system_id: str,
        model_digest: str,
        maturity: str,
        deployment_receipt_digest: str,
        registered_by: str,
        registered_at: int,
    ) -> MaturityRecord:
        """Pin a maturity label. Only ``production`` is
        authoritative; pilot and experimental outputs classify
        NON_AUTHORITATIVE. Labels narrow freely (production ->
        experimental); widening requires a fresh registration (the
        record is append-only per system_id — re-registering the
        same id raises, so a label change is a *new* record under a
        new system registration, never a silent edit)."""
        _require_nonempty(system_id, "system_id")
        _require_hex64(model_digest, "model_digest")
        if maturity not in MATURITIES:
            raise EnvCostError(
                f"maturity must be one of {', '.join(MATURITIES)}"
            )
        _require_hex64(deployment_receipt_digest, "deployment_receipt_digest")
        _require_nonempty(registered_by, "registered_by")
        _require_unix(registered_at, "registered_at")
        if system_id in self._records:
            raise EnvCostError(
                f"maturity for {system_id!r} already pinned; "
                "re-labeling requires a new system registration"
            )
        record = MaturityRecord(
            system_id=system_id,
            model_digest=model_digest,
            maturity=maturity,
            deployment_receipt_digest=deployment_receipt_digest,
            registered_by=registered_by,
            registered_at=registered_at,
        )
        self._records[system_id] = record
        return record

    def classify_output(self, system_id: str) -> EnvVerdict:
        """Classify a system's output. Experimental (and pilot)
        systems default NON_AUTHORITATIVE — the WeatherNext 3
        discipline, enforced by receipt rather than by press release."""
        record = self._records.get(system_id)
        if record is None:
            return EnvVerdict(
                allowed=False,
                reason=DENY_UNKNOWN_BUDGET,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event={
                    "event": ENV_DENIED_EVENT,
                    "system_id": system_id,
                    "allowed": False,
                    "reason": DENY_UNKNOWN_BUDGET,
                },
            )
        if record.maturity == "production":
            return EnvVerdict(
                allowed=True,
                reason="ok",
                classification=CLASS_AUTHORITATIVE,
                audit_event={
                    "event": ENV_SPEND_EVENT,
                    "system_id": system_id,
                    "allowed": True,
                    "reason": "ok",
                    "maturity": record.maturity,
                },
            )
        return EnvVerdict(
            allowed=False,
            reason=DENY_EXPERIMENTAL,
            classification=CLASS_NON_AUTHORITATIVE,
            audit_event={
                "event": ENV_DENIED_EVENT,
                "system_id": system_id,
                "allowed": False,
                "reason": DENY_EXPERIMENTAL,
                "maturity": record.maturity,
            },
        )


# ---------------------------------------------------------------------------
# PhysicsGate: extrapolation needs a pinned constraint list
# ---------------------------------------------------------------------------


class PhysicsGate:
    """Physical-extrapolation gate, reusing 111th-batch
    ``dual_use.ConstraintBinding`` semantics: a task that extrapolates
    beyond data must hold an authority-signed, hash-chained constraint
    pin (physical laws, conservation rules, domain limits). The
    extrapolation declares which constraints it applied; if the
    declared digest does not match the pinned list, the result is
    NON_AUTHORITATIVE — a model that sheds its physics to chase a
    score is not evidence (SAFS26-a)."""

    def __init__(self) -> None:
        self._bindings: dict[str, ConstraintBinding] = {}

    def register(self, binding: ConstraintBinding) -> ConstraintBinding:
        if not isinstance(binding, ConstraintBinding):
            raise EnvCostError("binding must be a dual_use.ConstraintBinding")
        self._bindings[binding.task_id] = binding
        return binding

    def authorize_extrapolation(
        self,
        task_id: str,
        applied_constraints_digest: str,
        created_unix: int,
    ) -> EnvVerdict:
        """Authorize one extrapolation. No binding -> deny; applied
        constraints digest != pinned list digest -> NON_AUTHORITATIVE
        (``env:physics_gap``)."""
        _require_nonempty(task_id, "task_id")
        _require_hex64(applied_constraints_digest, "applied_constraints_digest")
        _require_unix(created_unix, "created_unix")
        binding = self._bindings.get(task_id)
        if binding is None:
            return EnvVerdict(
                allowed=False,
                reason=DENY_MALFORMED,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event={
                    "event": ENV_DENIED_EVENT,
                    "task_id": task_id,
                    "allowed": False,
                    "reason": "env:no_constraint_binding",
                    "created_unix": created_unix,
                },
            )
        if not hmac.compare_digest(
            binding.constraint_list_digest, applied_constraints_digest
        ):
            return EnvVerdict(
                allowed=False,
                reason=DENY_PHYSICS_GAP,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event={
                    "event": ENV_DENIED_EVENT,
                    "task_id": task_id,
                    "allowed": False,
                    "reason": DENY_PHYSICS_GAP,
                    "pinned_constraints": binding.constraint_list_digest,
                    "applied_constraints": applied_constraints_digest,
                    "created_unix": created_unix,
                },
            )
        return EnvVerdict(
            allowed=True,
            reason="ok",
            classification=CLASS_AUTHORITATIVE,
            audit_event={
                "event": ENV_SPEND_EVENT,
                "task_id": task_id,
                "allowed": True,
                "reason": "ok",
                "created_unix": created_unix,
            },
        )


# ---------------------------------------------------------------------------
# ActionConfirmation: detect -> action linkage (no open-loop dashboards)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionConfirmation:
    """Links a detection to a confirmed action, hash-chained.

    A detection without a confirmation is ``open-loop``: the system
    found something and nobody acted on it. Dashboards must render
    open-loop detections as *unresolved*, never as handled.
    """

    confirmation_id: str
    detection_id: str
    action_digest: str
    confirmed_by: str
    confirmed_unix: int
    prev_hash: str = ""
    schema_version: str = ENV_COST_SCHEMA_VERSION

    def confirmation_hash(self) -> str:
        return jcs_sha256_hex(
            {
                "schema_version": self.schema_version,
                "confirmation_id": self.confirmation_id,
                "detection_id": self.detection_id,
                "action_digest": self.action_digest,
                "confirmed_by": self.confirmed_by,
                "confirmed_unix": self.confirmed_unix,
                "prev_hash": self.prev_hash,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "env-action-confirmation",
            "schema_version": self.schema_version,
            "confirmation_id": self.confirmation_id,
            "detection_id": self.detection_id,
            "action_digest": self.action_digest,
            "confirmed_by": self.confirmed_by,
            "confirmed_unix": self.confirmed_unix,
            "prev_hash": self.prev_hash,
            "confirmation_hash": self.confirmation_hash(),
        }


class ActionLinker:
    """Owns action confirmations; reports open-loop vs confirmed."""

    def __init__(self, detections: DetectionRegistry) -> None:
        if not isinstance(detections, DetectionRegistry):
            raise EnvCostError("detections must be a DetectionRegistry")
        self._detections = detections
        self._confirmations: dict[str, list[ActionConfirmation]] = {}
        self._seq = 0

    def confirm_action(
        self,
        detection_id: str,
        action_digest: str,
        confirmed_by: str,
        confirmed_unix: int,
    ) -> tuple[ActionConfirmation, EnvVerdict]:
        """Confirm an action on a detection. The detection must be
        registered *and* usable as evidence — confirming action on a
        below-threshold detection denies (``env:insufficient_confidence``):
        acting on a signal you already judged too weak is the failure
        mode this gate exists to catch."""
        _require_nonempty(detection_id, "detection_id")
        _require_hex64(action_digest, "action_digest")
        _require_nonempty(confirmed_by, "confirmed_by")
        _require_unix(confirmed_unix, "confirmed_unix")
        claim = self._detections.claim(detection_id)
        if claim is None:
            return None, EnvVerdict(
                allowed=False,
                reason=DENY_UNKNOWN_DETECTION,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event={
                    "event": ENV_DENIED_EVENT,
                    "detection_id": detection_id,
                    "allowed": False,
                    "reason": DENY_UNKNOWN_DETECTION,
                    "confirmed_unix": confirmed_unix,
                },
            )
        if not claim.usable_as_evidence:
            return None, EnvVerdict(
                allowed=False,
                reason=DENY_INSUFFICIENT_CONFIDENCE,
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event={
                    "event": ENV_DENIED_EVENT,
                    "detection_id": detection_id,
                    "allowed": False,
                    "reason": DENY_INSUFFICIENT_CONFIDENCE,
                    "confidence": claim.confidence,
                    "confirmed_unix": confirmed_unix,
                },
            )
        self._seq += 1
        chain = self._confirmations.setdefault(detection_id, [])
        prev_hash = chain[-1].confirmation_hash() if chain else ""
        confirmation = ActionConfirmation(
            confirmation_id=f"act-{detection_id}-{self._seq:06d}",
            detection_id=detection_id,
            action_digest=action_digest,
            confirmed_by=confirmed_by,
            confirmed_unix=confirmed_unix,
            prev_hash=prev_hash,
        )
        chain.append(confirmation)
        return confirmation, EnvVerdict(
            allowed=True,
            reason="ok",
            classification=CLASS_AUTHORITATIVE,
            audit_event={
                "event": ACTION_CONFIRMED_EVENT,
                "detection_id": detection_id,
                "confirmation_id": confirmation.confirmation_id,
                "allowed": True,
                "reason": "ok",
                "confirmed_unix": confirmed_unix,
            },
        )

    def link_status(self, detection_id: str) -> str:
        """``confirmed`` if at least one action confirmation chains
        to the detection, else ``open-loop``. Unknown detections are
        open-loop too — nobody confirmed anything about them."""
        chain = self._confirmations.get(detection_id)
        return "confirmed" if chain else "open-loop"


# ---------------------------------------------------------------------------
# EfficiencyClaim: the Green AI rule — named platform + measured metrics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EfficiencyClaimRecord:
    """A checkable efficiency claim: ``(claim_digest,
    named_platform, measured_metrics_digest)``. Registration means
    *checkable*, not *true* — the claim can be audited because the
    platform is named and the metrics are pinned. A claim without
    both is an ``unverifiable-claim``, not a fact."""

    claim_id: str
    claim_digest: str
    named_platform: str
    measured_metrics_digest: str
    claimed_by: str
    created_unix: int
    schema_version: str = ENV_COST_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "env-efficiency-claim",
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "claim_digest": self.claim_digest,
            "named_platform": self.named_platform,
            "measured_metrics_digest": self.measured_metrics_digest,
            "claimed_by": self.claimed_by,
            "created_unix": self.created_unix,
        }


class EfficiencyClaimRegistry:
    """Owns efficiency claims; enforces the named-platform rule."""

    def __init__(self) -> None:
        self._claims: dict[str, EfficiencyClaimRecord] = {}

    def register_efficiency_claim(
        self,
        *,
        claim_id: str,
        claim_digest: str,
        named_platform: str,
        measured_metrics_digest: str,
        claimed_by: str,
        created_unix: int,
    ) -> tuple[EfficiencyClaimRecord | None, EnvVerdict]:
        """Register an efficiency claim. Missing named platform or
        unpinned measured metrics -> ``env:unverifiable_efficiency_claim``
        (deny). An efficiency claim without a platform you can point
        at and numbers you can re-run is marketing, not measurement."""
        _require_nonempty(claim_id, "claim_id")
        _require_hex64(claim_digest, "claim_digest")
        _require_nonempty(claimed_by, "claimed_by")
        _require_unix(created_unix, "created_unix")
        if claim_id in self._claims:
            raise EnvCostError(f"duplicate claim_id {claim_id!r}")
        platform_ok = isinstance(named_platform, str) and bool(named_platform)
        metrics_ok = _is_hex64(measured_metrics_digest)
        if not (platform_ok and metrics_ok):
            return None, EnvVerdict(
                allowed=False,
                reason=DENY_UNVERIFIABLE_EFFICIENCY,
                classification=CLASS_UNVERIFIABLE_CLAIM,
                audit_event={
                    "event": EFFICIENCY_CLAIM_EVENT,
                    "claim_id": claim_id,
                    "allowed": False,
                    "reason": DENY_UNVERIFIABLE_EFFICIENCY,
                    "named_platform_present": platform_ok,
                    "measured_metrics_pinned": metrics_ok,
                    "created_unix": created_unix,
                },
            )
        record = EfficiencyClaimRecord(
            claim_id=claim_id,
            claim_digest=claim_digest,
            named_platform=named_platform,
            measured_metrics_digest=measured_metrics_digest,
            claimed_by=claimed_by,
            created_unix=created_unix,
        )
        self._claims[claim_id] = record
        return record, EnvVerdict(
            allowed=True,
            reason="ok",
            classification=CLASS_AUTHORITATIVE,
            audit_event={
                "event": EFFICIENCY_CLAIM_EVENT,
                "claim_id": claim_id,
                "allowed": True,
                "reason": "ok",
                "named_platform": named_platform,
                "created_unix": created_unix,
            },
        )


# ---------------------------------------------------------------------------
# Test/bench scaffolding: authority keypairs
# ---------------------------------------------------------------------------


def authority_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Derive ``(public_key, seed)`` from a 32-byte seed.

    Test and bench scaffolding only: production authorities manage
    keys out-of-band. The seed doubles as the ed25519 secret.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise EnvCostError("seed must be 32 bytes")
    seed = bytes(seed)
    return (ed_public_key(seed), seed)


def _digest_for_signing(payload: dict[str, Any]) -> str:
    return jcs_sha256_hex(payload)


def sign_digest(seed: bytes, digest: str) -> bytes:
    """Sign a JCS digest with the authority seed.

    Test and bench scaffolding only.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise EnvCostError("seed must be 32 bytes")
    _require_hex64(digest, "digest")
    return ed_sign(bytes(seed), digest.encode("utf-8"))


def profile_digest_for_signing(
    *,
    budget_id: str,
    kwh_total: int,
    baseline_kwh_per_hour: int,
    grid_region: str,
    emission_factor_digest: str,
    emission_factor_kg_per_kwh: str,
    issued_by: str,
    issued_at: int,
    expires_at: int,
    prev_hash: str = "",
) -> str:
    """The exact digest ``issue_env_profile`` verifies — exposed so
    tests/bench can sign the same bytes the issuer checks."""
    return _digest_for_signing(
        _profile_payload(
            budget_id=budget_id,
            kwh_total=kwh_total,
            baseline_kwh_per_hour=baseline_kwh_per_hour,
            grid_region=grid_region,
            emission_factor_digest=emission_factor_digest,
            emission_factor_kg_per_kwh=emission_factor_kg_per_kwh,
            issued_by=issued_by,
            issued_at=issued_at,
            expires_at=expires_at,
            prev_hash=prev_hash,
        )
    )


def curtailment_digest_for_signing(
    *,
    curtailment_id: str,
    grid_region: str,
    start_unix: int,
    end_unix: int,
    reduction_factor_permille: int,
    issued_by: str,
    issued_at: int,
    prev_hash: str = "",
) -> str:
    """The exact digest ``issue_curtailment`` verifies."""
    return _digest_for_signing(
        _curtailment_payload(
            curtailment_id=curtailment_id,
            grid_region=grid_region,
            start_unix=start_unix,
            end_unix=end_unix,
            reduction_factor_permille=reduction_factor_permille,
            issued_by=issued_by,
            issued_at=issued_at,
            prev_hash=prev_hash,
        )
    )
