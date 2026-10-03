"""Orbital safety receipts (one-hundred-thirty-fourth batch).

Absorbs the 2026 AI-space research thread (mechanism ideas only,
honestly scoped):

* **Scale of automated avoidance:** Starlink's automated collision
  avoidance reached 140,000+ maneuvers in H1 2025 (Astroscale CEO
  citation). When avoidance becomes fully automatic, the failure mode
  is not "no maneuver" — it is maneuvering on stale or fatigued
  warnings, i.e. auto-maneuver-on-everything.
* **China's "Xingyan" space-awareness constellation** (156 planned,
  launching from H1 2026, with compute units + intelligent processing
  for collision prediction / debris monitoring / space traffic
  management) and **"space intelligent driving"** (layered
  small-onboard-model + large-ground-model, currently "human-machine
  collaboration, supervised autonomy", on-orbit test planned
  end-2026/early-2027): autonomy boundaries are declared in press
  releases, not pinned in anything a machine can verify.
* **India's TakeMe2Space MOI-1A** (Nvidia Orin NX, launched
  2026-10-01): customers upload containerized AI models, only
  results are downlinked. Onboard models decide alone unless their
  autonomy boundary is pinned.
* **US TraCSS:** 70+ operators / 10+ countries / 11,345 satellites in
  the pilot, stuck in FY2026 budget fights, 450 companies lobbying
  against termination. STM data is a shared, fragile, freshness-bound
  good.
* **Zero Debris Week (Seville, 2026-09):** first policy working
  groups on "who pays for non-deorbiting, who bears cleanup
  liability". Liability is currently declared nowhere machine-readable.
* **Counterspace (2026):** 2026-09-14 the US Air Force Secretary
  first publicly admitted operational on-orbit space-control weapons
  (claimed defensive); Germany's first space security strategy
  commits offensive space capabilities; SWF 2026: every recorded
  real-conflict counterspace capability is non-kinetic (jamming /
  navigation disruption / cyber); RPO/refueling/spaceplanes blur the
  peace/weapon boundary — inherently dual-use.

Northstar mapping:

* ``conjunction_receipt()`` — a conjunction warning binds
  ``(warning_digest, uncertainty, freshness)``; an automated
  maneuver on a stale warning is ``orbital:stale_conjunction``, and
  repeated auto-maneuvers on the same pair without ground
  revalidation trip ``orbital:warning_fatigue`` (anti
  auto-maneuver-on-everything).
* ``maneuver_authorization_envelope()`` — autonomous
  collision-avoidance maneuvers bind a Δv authority envelope;
  maneuvers outside the envelope (or its window) are
  ``orbital:envelope_breach`` and need fresh authorization.
* ``stm_data_receipt()`` — STM data binds freshness + uncertainty;
  maneuvers on unbound data classify ``NON_AUTHORITATIVE``
  (``orbital:unbound_stm``).
* ``dual_use_rpo_gate()`` — rendezvous/proximity operations against
  non-cooperative targets route through the 111th-batch dual-use
  screen; a watchlist hit is ``orbital:rpo_escalation``, a near-hit
  is ``NON_AUTHORITATIVE``, and even a clean screen on a
  non-cooperative target is ``NON_AUTHORITATIVE``
  (``orbital:rpo_human_review``) — never auto-executed.
* ``megaconstellation_debris_budget()`` — deployments bind a debris
  budget; over-budget constellations are refused registration
  (``orbital:debris_over_budget``).
* ``onboard_model_receipt()`` — onboard AI autonomy boundaries are
  pinned; beyond-boundary decisions are ``orbital:autonomy_breach``
  and need ground authorization.
* ``counterspace_transparency()`` — on-orbit weapons declarations
  feed an audit event chain shaped for the 113th-batch incident
  receipts; discovered undeclared capabilities are
  ``orbital:undeclared_capability``.
* ``liability_pin()`` — failed deorbits pin a liability receipt
  (who pays, who cleans); a dead object past its deadline with no
  pin is ``orbital:no_liability_pin``.

Honest boundary: receipts bind *declared* orbital discipline. They
do not clear debris, stop militarization, or make STM data true —
they make the declared discipline machine-checkable and make
violations undeniable.

Deterministic: no wall-clock reads (callers inject ``*_at`` as
integer unix epochs), canonical JCS hashing, constant-time digest
comparisons.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

try:
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(payload: Mapping[str, Any]) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def jcs_sha256_hex(payload: Mapping[str, Any]) -> str:  # type: ignore[no-redef]
        import hashlib

        return hashlib.sha256(jcs_canonical_json(payload)).hexdigest()

from ed25519 import sign as ed_sign
from ed25519 import verify as ed_verify

ORBITAL_SCHEMA_VERSION = "northstar.orbital-agents.v1"

#: Denial reason codes. All start with the ``orbital:`` prefix so
#: audit consumers can filter the family.
DENY_UNKNOWN_CONJUNCTION = "orbital:unknown_conjunction"
DENY_STALE_CONJUNCTION = "orbital:stale_conjunction"
DENY_WARNING_FATIGUE = "orbital:warning_fatigue"
DENY_ENVELOPE_BREACH = "orbital:envelope_breach"
DENY_UNBOUND_STM = "orbital:unbound_stm"
DENY_STALE_STM = "orbital:stale_stm"
DENY_RPO_ESCALATION = "orbital:rpo_escalation"
DENY_RPO_NEAR_HIT = "orbital:rpo_near_hit"
DENY_RPO_HUMAN_REVIEW = "orbital:rpo_human_review"
DENY_DEBRIS_OVER_BUDGET = "orbital:debris_over_budget"
DENY_AUTONOMY_BREACH = "orbital:autonomy_breach"
DENY_UNDECLARED_CAPABILITY = "orbital:undeclared_capability"
DENY_NO_LIABILITY_PIN = "orbital:no_liability_pin"
DENY_CHAIN_BREAK = "orbital:chain_break"
DENY_DIGEST_MISMATCH = "orbital:digest_mismatch"
DENY_SIGNATURE_INVALID = "orbital:signature_invalid"

#: Classifications.
CLASS_ALLOW = "allow"
CLASS_DENY = "deny"
CLASS_NON_AUTHORITATIVE = "NON_AUTHORITATIVE"

#: Audit event names (shaped to feed ``audit_chain.chain_record`` /
#: the 113th-batch incident-receipts event chain).
CONJUNCTION_EVENT = "orbital.conjunction_bound"
MANEUVER_EVENT = "orbital.maneuver_checked"
ENVELOPE_EVENT = "orbital.envelope_issued"
STM_EVENT = "orbital.stm_bound"
RPO_EVENT = "orbital.rpo_screened"
DEBRIS_EVENT = "orbital.debris_budget_checked"
ONBOARD_EVENT = "orbital.onboard_decision_checked"
COUNTERSPACE_EVENT = "orbital.counterspace_declared"
LIABILITY_EVENT = "orbital.liability_pinned"

#: Genesis prev digest for hash-chained receipt logs.
_GENESIS = "genesis"

#: Warning-fatigue threshold: more than this many automated
#: maneuvers against the same conjunction pair without an
#: intervening ground revalidation trips ``orbital:warning_fatigue``.
#: The number is declared in code, not learned — the Starlink-scale
#: lesson is that "the model decided again" is not a safety case.
WARNING_FATIGUE_THRESHOLD = 5

#: Closed vocabulary of counterspace capability classes that may be
#: declared. Anything outside this list is unclassifiable and must
#: be declared as ``experimental`` (still declared, still on the
#: record) — never silently operated.
CAPABILITY_CLASSES: tuple[str, ...] = (
    "defensive_rpo",
    "inspection",
    "servicing",
    "refueling",
    "debris_removal",
    "electronic_warfare",
    "kinetic_interceptor",
    "experimental",
)

#: Closed vocabulary of onboard decision classes an authority may
#: pin into an autonomy boundary.
DECISION_CLASSES: tuple[str, ...] = (
    "station_keeping",
    "collision_avoidance",
    "attitude_control",
    "payload_scheduling",
    "power_management",
    "debris_tracking",
    "rpo_approach",
    "weapon_release",
)


class OrbitalError(ValueError):
    """A malformed receipt, registry, or check request — a programming
    error, not a verdict. Verification *failures* (stale warning,
    envelope breach, undeclared capability, digest mismatch) return
    an :class:`OrbitalVerdict` with ``allowed=False`` instead;
    malformed input raises here, fail loud, never guess."""


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex64(value):
        raise OrbitalError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OrbitalError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OrbitalError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    # The vendored ed25519 module takes a raw 32-byte seed.
    if not isinstance(value, bytes) or len(value) != 32:
        raise OrbitalError(f"{field_name} must be a 32-byte seed")
    return value


def _check_nonneg_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OrbitalError(f"{field_name} must be a non-negative int")
    return value


def _check_pos_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise OrbitalError(f"{field_name} must be a positive int")
    return value


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    try:
        return bool(
            ed_verify(
                bytes.fromhex(pubkey_hex),
                jcs_canonical_json(payload),
                bytes.fromhex(signature_hex),
            )
        )
    except Exception:
        return False


def _seal_receipt(
    payload: Mapping[str, Any], authority_secret: bytes
) -> tuple[str, str]:
    """Return ``(receipt_digest, signature_hex)`` for a payload.

    The receipt digest is the JCS-SHA256 of the unsigned payload;
    the signature is over the canonical JSON of the payload.
    """
    digest = jcs_sha256_hex(payload)
    signature = ed_sign(authority_secret, jcs_canonical_json(payload)).hex()
    return digest, signature


def _check_chain(log: list[Any], type_name: str) -> None:
    """Raise :class:`OrbitalError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest``, ``prev_digest``,
    ``authority_pubkey_hex``, ``signature_hex`` and a ``_payload()``
    method; entries must form one chain from ``"genesis"`` with
    recomputing digests and valid authority signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(
            entry.receipt_digest, jcs_sha256_hex(entry._payload())
        ):
            raise OrbitalError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise OrbitalError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        if not _verify_signature(
            entry.authority_pubkey_hex, entry._payload(), entry.signature_hex
        ):
            raise OrbitalError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class OrbitalVerdict:
    """The verdict of an orbital gate."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt: Any = None
    audit_event: dict[str, Any] = field(default_factory=dict)


def orbital_audit_event(
    *,
    action: str,
    allowed: bool,
    reason: str,
    created_unix: int,
    **details: Any,
) -> dict[str, Any]:
    """Build an audit event shaped to feed the incident-receipts
    event chain (113th batch)."""
    _check_nonempty_str(action, "action")
    _check_ts(created_unix, "created_unix")
    return {
        "event": action,
        "allowed": allowed,
        "reason": reason,
        "created_unix": created_unix,
        **details,
    }

# ---------------------------------------------------------------------------
# Conjunction receipts (anti auto-maneuver-on-everything)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConjunctionReceipt:
    """An authority-signed, hash-chained conjunction warning pin.

    Binds ``(warning_digest, uncertainty_km, warned_at, ttl_s)`` so a
    maneuver can prove the warning it acted on was fresh and
    well-bounded. The warning data itself lives out-of-band (STM
    feed); the receipt pins its digest so a stale warning cannot be
    silently re-used.
    """

    receipt_id: str
    warning_id: str
    conjunction_digest: str
    uncertainty_km: float
    warned_at: int
    ttl_s: int
    object_pair: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ORBITAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "warning_id": self.warning_id,
            "conjunction_digest": self.conjunction_digest,
            "uncertainty_km": self.uncertainty_km,
            "warned_at": self.warned_at,
            "ttl_s": self.ttl_s,
            "object_pair": self.object_pair,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def conjunction_receipt(
    *,
    receipt_id: str,
    warning_id: str,
    conjunction_digest: str,
    uncertainty_km: float,
    warned_at: int,
    ttl_s: int,
    object_pair: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> ConjunctionReceipt:
    """Issue a conjunction-warning pin. The signature must come from
    the authority whose public key is pinned; the digest binds the
    warning content."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(warning_id, "warning_id")
    _check_hex64(conjunction_digest, "conjunction_digest")
    if not isinstance(uncertainty_km, (int, float)) or uncertainty_km < 0:
        raise OrbitalError("uncertainty_km must be a non-negative number")
    _check_ts(warned_at, "warned_at")
    _check_pos_int(ttl_s, "ttl_s")
    _check_nonempty_str(object_pair, "object_pair")
    _check_nonempty_str(issued_by, "issued_by")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    if prev_digest != _GENESIS:
        _check_hex64(prev_digest, "prev_digest")
    receipt = ConjunctionReceipt(
        receipt_id=receipt_id,
        warning_id=warning_id,
        conjunction_digest=conjunction_digest,
        uncertainty_km=float(uncertainty_km),
        warned_at=warned_at,
        ttl_s=ttl_s,
        object_pair=object_pair,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        prev_digest=prev_digest,
    )
    digest, signature = _seal_receipt(receipt._payload(), authority_secret)
    return ConjunctionReceipt(
        **{**receipt.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


class ConjunctionRegistry:
    """Owns conjunction-warning pins and the warning-fatigue tripwire.

    Automated maneuvers are checked against a *fresh* pin for the
    warning; a maneuver on a stale warning is
    ``orbital:stale_conjunction``. The fatigue tripwire counts
    automated maneuvers already authorized against the same object
    pair: beyond ``WARNING_FATIGUE_THRESHOLD`` without an
    intervening ground revalidation, the next auto-maneuver is
    ``orbital:warning_fatigue`` — the fleet must get fresh human
    eyes on the pair instead of maneuvering again on autopilot.
    """

    def __init__(self) -> None:
        self._by_warning: dict[str, ConjunctionReceipt] = {}
        self._log: list[ConjunctionReceipt] = []
        self._maneuvers_per_pair: dict[str, int] = {}
        self._revalidated_pairs: set[str] = set()

    def register(self, receipt: ConjunctionReceipt) -> ConjunctionReceipt:
        """Register a warning pin. The log must stay hash-chained;
        duplicate warning ids refuse."""
        if not isinstance(receipt, ConjunctionReceipt):
            raise OrbitalError("receipt must be a ConjunctionReceipt")
        if receipt.warning_id in self._by_warning:
            raise OrbitalError(
                f"duplicate conjunction warning {receipt.warning_id!r}"
            )
        self._log.append(receipt)
        _check_chain(self._log, "conjunction")
        self._by_warning[receipt.warning_id] = receipt
        return receipt

    def ground_revalidation(self, object_pair: str) -> None:
        """Record a ground-station human revalidation of the pair,
        resetting the fatigue counter."""
        _check_nonempty_str(object_pair, "object_pair")
        self._maneuvers_per_pair[object_pair] = 0
        self._revalidated_pairs.add(object_pair)

    def check_maneuver(
        self,
        *,
        warning_id: str,
        dv_ms: float,
        maneuver_at: int,
        now: int,
    ) -> OrbitalVerdict:
        """Check an automated maneuver against a warning pin."""
        _check_nonempty_str(warning_id, "warning_id")
        if not isinstance(dv_ms, (int, float)) or dv_ms < 0:
            raise OrbitalError("dv_ms must be a non-negative number")
        _check_ts(maneuver_at, "maneuver_at")
        _check_ts(now, "now")
        receipt = self._by_warning.get(warning_id)
        if receipt is None:
            return OrbitalVerdict(
                allowed=False,
                reason=f"{DENY_UNKNOWN_CONJUNCTION}: no pin for warning {warning_id!r}",
                classification=CLASS_DENY,
                audit_event=orbital_audit_event(
                    action=CONJUNCTION_EVENT,
                    allowed=False,
                    reason=DENY_UNKNOWN_CONJUNCTION,
                    created_unix=now,
                    warning_id=warning_id,
                ),
            )
        if maneuver_at > receipt.warned_at + receipt.ttl_s:
            return OrbitalVerdict(
                allowed=False,
                reason=f"{DENY_STALE_CONJUNCTION}: warning {warning_id!r} "
                f"expired at {receipt.warned_at + receipt.ttl_s}",
                classification=CLASS_DENY,
                receipt=receipt,
                audit_event=orbital_audit_event(
                    action=CONJUNCTION_EVENT,
                    allowed=False,
                    reason=DENY_STALE_CONJUNCTION,
                    created_unix=now,
                    warning_id=warning_id,
                    receipt_digest=receipt.receipt_digest,
                ),
            )
        count = self._maneuvers_per_pair.get(receipt.object_pair, 0)
        if count >= WARNING_FATIGUE_THRESHOLD:
            return OrbitalVerdict(
                allowed=False,
                reason=f"{DENY_WARNING_FATIGUE}: {count} automated maneuvers "
                f"on pair {receipt.object_pair!r} without ground revalidation",
                classification=CLASS_DENY,
                receipt=receipt,
                audit_event=orbital_audit_event(
                    action=CONJUNCTION_EVENT,
                    allowed=False,
                    reason=DENY_WARNING_FATIGUE,
                    created_unix=now,
                    warning_id=warning_id,
                    object_pair=receipt.object_pair,
                    prior_maneuvers=count,
                ),
            )
        self._maneuvers_per_pair[receipt.object_pair] = count + 1
        self._revalidated_pairs.discard(receipt.object_pair)
        return OrbitalVerdict(
            allowed=True,
            reason="conjunction_fresh",
            classification=CLASS_ALLOW,
            receipt=receipt,
            audit_event=orbital_audit_event(
                action=MANEUVER_EVENT,
                allowed=True,
                reason="conjunction_fresh",
                created_unix=now,
                warning_id=warning_id,
                dv_ms=dv_ms,
                maneuver_number=count + 1,
            ),
        )


# ---------------------------------------------------------------------------
# Maneuver authorization envelopes (Δv authority)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ManeuverEnvelope:
    """An authority-signed Δv authorization envelope.

    Autonomous collision-avoidance may spend at most ``max_dv_ms``
    of delta-v inside ``[valid_from, valid_to]``. Anything beyond
    needs a fresh envelope — the envelope cannot be widened by the
    maneuvering agent itself.
    """

    envelope_id: str
    max_dv_ms: float
    valid_from: int
    valid_to: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = ORBITAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "max_dv_ms": self.max_dv_ms,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "schema_version": self.schema_version,
        }


def maneuver_authorization_envelope(
    *,
    envelope_id: str,
    max_dv_ms: float,
    valid_from: int,
    valid_to: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> ManeuverEnvelope:
    """Issue a Δv authorization envelope."""
    _check_nonempty_str(envelope_id, "envelope_id")
    if not isinstance(max_dv_ms, (int, float)) or max_dv_ms <= 0:
        raise OrbitalError("max_dv_ms must be a positive number")
    _check_ts(valid_from, "valid_from")
    _check_ts(valid_to, "valid_to")
    if valid_to <= valid_from:
        raise OrbitalError("valid_to must be after valid_from")
    _check_nonempty_str(issued_by, "issued_by")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    envelope = ManeuverEnvelope(
        envelope_id=envelope_id,
        max_dv_ms=float(max_dv_ms),
        valid_from=valid_from,
        valid_to=valid_to,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
    )
    digest, signature = _seal_receipt(envelope._payload(), authority_secret)
    return ManeuverEnvelope(
        **{**envelope.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


def check_maneuver(
    envelope: ManeuverEnvelope,
    *,
    dv_ms: float,
    at: int,
    now: int,
) -> OrbitalVerdict:
    """Check a maneuver against its authorization envelope."""
    if not isinstance(envelope, ManeuverEnvelope):
        raise OrbitalError("envelope must be a ManeuverEnvelope")
    if not isinstance(dv_ms, (int, float)) or dv_ms < 0:
        raise OrbitalError("dv_ms must be a non-negative number")
    _check_ts(at, "at")
    _check_ts(now, "now")
    if not _verify_signature(
        envelope.authority_pubkey_hex, envelope._payload(), envelope.signature_hex
    ):
        return OrbitalVerdict(
            allowed=False,
            reason=f"{DENY_SIGNATURE_INVALID}: envelope {envelope.envelope_id!r} "
            "authority signature invalid",
            classification=CLASS_DENY,
            audit_event=orbital_audit_event(
                action=ENVELOPE_EVENT,
                allowed=False,
                reason=DENY_SIGNATURE_INVALID,
                created_unix=now,
                envelope_id=envelope.envelope_id,
            ),
        )
    if dv_ms > envelope.max_dv_ms or not (envelope.valid_from <= at <= envelope.valid_to):
        return OrbitalVerdict(
            allowed=False,
            reason=f"{DENY_ENVELOPE_BREACH}: dv {dv_ms} m/s outside envelope "
            f"{envelope.envelope_id!r} (max {envelope.max_dv_ms} m/s, "
            f"window [{envelope.valid_from}, {envelope.valid_to}])",
            classification=CLASS_DENY,
            receipt=envelope,
            audit_event=orbital_audit_event(
                action=ENVELOPE_EVENT,
                allowed=False,
                reason=DENY_ENVELOPE_BREACH,
                created_unix=now,
                envelope_id=envelope.envelope_id,
                dv_ms=dv_ms,
            ),
        )
    return OrbitalVerdict(
        allowed=True,
        reason="within_envelope",
        classification=CLASS_ALLOW,
        receipt=envelope,
        audit_event=orbital_audit_event(
            action=ENVELOPE_EVENT,
            allowed=True,
            reason="within_envelope",
            created_unix=now,
            envelope_id=envelope.envelope_id,
            dv_ms=dv_ms,
        ),
    )


# ---------------------------------------------------------------------------
# STM data receipts (freshness + uncertainty binding)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class STMDataReceipt:
    """A space-traffic-management data pin.

    Binds ``(data_digest, uncertainty_km, observed_at, ttl_s)`` so a
    maneuver can prove the STM feed snapshot it acted on was fresh
    and bounded. STM data is a shared, fragile good (the TraCSS
    lesson); a maneuver on unbound STM data is not "wrong", it is
    unverifiable — ``NON_AUTHORITATIVE``.
    """

    receipt_id: str
    data_id: str
    data_digest: str
    uncertainty_km: float
    observed_at: int
    ttl_s: int
    source: str
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ORBITAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "data_id": self.data_id,
            "data_digest": self.data_digest,
            "uncertainty_km": self.uncertainty_km,
            "observed_at": self.observed_at,
            "ttl_s": self.ttl_s,
            "source": self.source,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def stm_data_receipt(
    *,
    receipt_id: str,
    data_id: str,
    data_digest: str,
    uncertainty_km: float,
    observed_at: int,
    ttl_s: int,
    source: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> STMDataReceipt:
    """Issue an STM data pin."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(data_id, "data_id")
    _check_hex64(data_digest, "data_digest")
    if not isinstance(uncertainty_km, (int, float)) or uncertainty_km < 0:
        raise OrbitalError("uncertainty_km must be a non-negative number")
    _check_ts(observed_at, "observed_at")
    _check_pos_int(ttl_s, "ttl_s")
    _check_nonempty_str(source, "source")
    _check_nonempty_str(issued_by, "issued_by")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    if prev_digest != _GENESIS:
        _check_hex64(prev_digest, "prev_digest")
    receipt = STMDataReceipt(
        receipt_id=receipt_id,
        data_id=data_id,
        data_digest=data_digest,
        uncertainty_km=float(uncertainty_km),
        observed_at=observed_at,
        ttl_s=ttl_s,
        source=source,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        prev_digest=prev_digest,
    )
    digest, signature = _seal_receipt(receipt._payload(), authority_secret)
    return STMDataReceipt(
        **{**receipt.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


class STMRegistry:
    """Owns STM data pins; maneuvers must act on a bound snapshot."""

    def __init__(self) -> None:
        self._by_data: dict[str, STMDataReceipt] = {}
        self._log: list[STMDataReceipt] = []

    def register(self, receipt: STMDataReceipt) -> STMDataReceipt:
        if not isinstance(receipt, STMDataReceipt):
            raise OrbitalError("receipt must be an STMDataReceipt")
        if receipt.data_id in self._by_data:
            raise OrbitalError(f"duplicate STM data {receipt.data_id!r}")
        self._log.append(receipt)
        _check_chain(self._log, "stm")
        self._by_data[receipt.data_id] = receipt
        return receipt

    def check_bound(self, *, data_id: str, at: int, now: int) -> OrbitalVerdict:
        """Check that a maneuver acts on bound, fresh STM data."""
        _check_nonempty_str(data_id, "data_id")
        _check_ts(at, "at")
        _check_ts(now, "now")
        receipt = self._by_data.get(data_id)
        if receipt is None:
            return OrbitalVerdict(
                allowed=False,
                reason=f"{DENY_UNBOUND_STM}: no STM pin for {data_id!r}",
                classification=CLASS_NON_AUTHORITATIVE,
                audit_event=orbital_audit_event(
                    action=STM_EVENT,
                    allowed=False,
                    reason=DENY_UNBOUND_STM,
                    created_unix=now,
                    data_id=data_id,
                ),
            )
        if at > receipt.observed_at + receipt.ttl_s:
            return OrbitalVerdict(
                allowed=False,
                reason=f"{DENY_STALE_STM}: STM data {data_id!r} expired at "
                f"{receipt.observed_at + receipt.ttl_s}",
                classification=CLASS_DENY,
                receipt=receipt,
                audit_event=orbital_audit_event(
                    action=STM_EVENT,
                    allowed=False,
                    reason=DENY_STALE_STM,
                    created_unix=now,
                    data_id=data_id,
                    receipt_digest=receipt.receipt_digest,
                ),
            )
        return OrbitalVerdict(
            allowed=True,
            reason="stm_bound",
            classification=CLASS_ALLOW,
            receipt=receipt,
            audit_event=orbital_audit_event(
                action=STM_EVENT,
                allowed=True,
                reason="stm_bound",
                created_unix=now,
                data_id=data_id,
                uncertainty_km=receipt.uncertainty_km,
            ),
        )

# ---------------------------------------------------------------------------
# Dual-use RPO gate (111th-batch screen for non-cooperative targets)
# ---------------------------------------------------------------------------


def dual_use_rpo_gate(
    *,
    operation_id: str,
    target_id: str,
    cooperative: bool,
    consent_digest: str | None,
    approach_profile: Mapping[str, Any],
    created_unix: int,
) -> OrbitalVerdict:
    """Gate a rendezvous/proximity operation.

    Cooperative targets (a bound consent digest from the target's
    operator) pass. Non-cooperative targets route through the
    111th-batch dual-use screen: a watchlist hit is
    ``orbital:rpo_escalation`` (deny, human must decide), a near-hit
    is ``NON_AUTHORITATIVE`` — and even a *clean* screen on a
    non-cooperative target is ``NON_AUTHORITATIVE``
    (``orbital:rpo_human_review``): the SWF lesson is that
    RPO/refueling/spaceplane capability is inherently dual-use, so a
    non-cooperative approach is never auto-executed.
    """
    _check_nonempty_str(operation_id, "operation_id")
    _check_nonempty_str(target_id, "target_id")
    if not isinstance(cooperative, bool):
        raise OrbitalError("cooperative must be a bool")
    if not isinstance(approach_profile, Mapping):
        raise OrbitalError("approach_profile must be a mapping")
    _check_ts(created_unix, "created_unix")

    def _event(allowed: bool, reason: str, classification: str, **kw: Any) -> OrbitalVerdict:
        return OrbitalVerdict(
            allowed=allowed,
            reason=reason,
            classification=classification,
            audit_event=orbital_audit_event(
                action=RPO_EVENT,
                allowed=allowed,
                reason=reason,
                created_unix=created_unix,
                operation_id=operation_id,
                target_id=target_id,
                cooperative=cooperative,
                **kw,
            ),
        )

    if cooperative:
        if consent_digest is None or not _is_hex64(consent_digest):
            return _event(
                False, DENY_DIGEST_MISMATCH, CLASS_DENY,
                detail="cooperative target without a bound consent digest",
            )
        return _event(True, "rpo_cooperative_consented", CLASS_ALLOW)

    # Non-cooperative: route through the 111th-batch dual-use screen.
    from dual_use import (
        CALL_ALLOW,
        CALL_ESCALATE,
        CALL_NON_AUTHORITATIVE,
        screen_tool_call,
    )

    screen = screen_tool_call(
        task_id=operation_id,
        tool_name="rpo_approach",
        args={"target_id": target_id, **dict(approach_profile)},
        created_unix=created_unix,
    )
    if screen.classification == CALL_ESCALATE:
        return _event(
            False, DENY_RPO_ESCALATION, CLASS_DENY,
            matched_family=screen.matched_family,
            detail="dual-use watchlist hit on non-cooperative RPO",
        )
    if screen.classification == CALL_NON_AUTHORITATIVE:
        return _event(
            False, DENY_RPO_NEAR_HIT, CLASS_NON_AUTHORITATIVE,
            matched_family=screen.matched_family,
            detail="dual-use near-hit on non-cooperative RPO",
        )
    # Clean screen on a non-cooperative target: still never
    # auto-executed.
    assert screen.classification == CALL_ALLOW
    return _event(
        False, DENY_RPO_HUMAN_REVIEW, CLASS_NON_AUTHORITATIVE,
        detail="non-cooperative RPO requires human review even when the screen is clean",
    )


# ---------------------------------------------------------------------------
# Megaconstellation debris budgets (110th-batch deployment registry)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DebrisBudgetReceipt:
    """An authority-signed debris budget pin for a constellation.

    Binds ``(max_objects, planned_objects, expected_debris_objects)``
    so registration can refuse an over-budget deployment *before* the
    objects are in orbit — the Zero Debris Week lesson is that
    liability argued after launch is liability nobody holds.
    """

    receipt_id: str
    constellation_id: str
    max_objects: int
    planned_objects: int
    expected_debris_objects: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ORBITAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "constellation_id": self.constellation_id,
            "max_objects": self.max_objects,
            "planned_objects": self.planned_objects,
            "expected_debris_objects": self.expected_debris_objects,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def megaconstellation_debris_budget(
    *,
    receipt_id: str,
    constellation_id: str,
    max_objects: int,
    planned_objects: int,
    expected_debris_objects: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> DebrisBudgetReceipt:
    """Issue a debris-budget pin for a constellation deployment."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(constellation_id, "constellation_id")
    _check_pos_int(max_objects, "max_objects")
    _check_nonneg_int(planned_objects, "planned_objects")
    _check_nonneg_int(expected_debris_objects, "expected_debris_objects")
    _check_nonempty_str(issued_by, "issued_by")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    if prev_digest != _GENESIS:
        _check_hex64(prev_digest, "prev_digest")
    receipt = DebrisBudgetReceipt(
        receipt_id=receipt_id,
        constellation_id=constellation_id,
        max_objects=max_objects,
        planned_objects=planned_objects,
        expected_debris_objects=expected_debris_objects,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        prev_digest=prev_digest,
    )
    digest, signature = _seal_receipt(receipt._payload(), authority_secret)
    return DebrisBudgetReceipt(
        **{**receipt.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


def check_debris_budget(
    receipt: DebrisBudgetReceipt,
    *,
    planned_objects: int,
    now: int,
) -> OrbitalVerdict:
    """Check a deployment plan against its debris budget.

    Over-budget plans are refused registration —
    ``orbital:debris_over_budget``. The expected debris count must
    also fit inside the budget: a budget that "fits" only by
    ignoring its own debris line is a tampered budget.
    """
    if not isinstance(receipt, DebrisBudgetReceipt):
        raise OrbitalError("receipt must be a DebrisBudgetReceipt")
    _check_nonneg_int(planned_objects, "planned_objects")
    _check_ts(now, "now")
    if not _verify_signature(
        receipt.authority_pubkey_hex, receipt._payload(), receipt.signature_hex
    ):
        return OrbitalVerdict(
            allowed=False,
            reason=f"{DENY_SIGNATURE_INVALID}: debris budget for "
            f"{receipt.constellation_id!r} has an invalid authority signature",
            classification=CLASS_DENY,
            audit_event=orbital_audit_event(
                action=DEBRIS_EVENT,
                allowed=False,
                reason=DENY_SIGNATURE_INVALID,
                created_unix=now,
                constellation_id=receipt.constellation_id,
            ),
        )
    if planned_objects > receipt.max_objects or (
        receipt.expected_debris_objects > receipt.max_objects
    ):
        return OrbitalVerdict(
            allowed=False,
            reason=f"{DENY_DEBRIS_OVER_BUDGET}: constellation "
            f"{receipt.constellation_id!r} plans {planned_objects} objects "
            f"against a budget of {receipt.max_objects}",
            classification=CLASS_DENY,
            receipt=receipt,
            audit_event=orbital_audit_event(
                action=DEBRIS_EVENT,
                allowed=False,
                reason=DENY_DEBRIS_OVER_BUDGET,
                created_unix=now,
                constellation_id=receipt.constellation_id,
                planned_objects=planned_objects,
                max_objects=receipt.max_objects,
            ),
        )
    return OrbitalVerdict(
        allowed=True,
        reason="within_debris_budget",
        classification=CLASS_ALLOW,
        receipt=receipt,
        audit_event=orbital_audit_event(
            action=DEBRIS_EVENT,
            allowed=True,
            reason="within_debris_budget",
            created_unix=now,
            constellation_id=receipt.constellation_id,
        ),
    )


# ---------------------------------------------------------------------------
# Onboard model autonomy boundaries (pinned, not press-released)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OnboardModelReceipt:
    """A pinned onboard-AI autonomy boundary.

    Declares exactly which decision classes the model may take alone
    (from the closed ``DECISION_CLASSES`` vocabulary). Anything
    outside the boundary needs ground authorization — the
    TakeMe2Space lesson is that "customers upload models, only
    results come down" is fine only when the model's solo-decision
    boundary is pinned in something a machine can verify.
    """

    receipt_id: str
    model_id: str
    autonomy_boundary: tuple[str, ...]
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    receipt_digest: str = ""
    schema_version: str = ORBITAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "model_id": self.model_id,
            "autonomy_boundary": list(self.autonomy_boundary),
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "schema_version": self.schema_version,
        }


def onboard_model_receipt(
    *,
    receipt_id: str,
    model_id: str,
    autonomy_boundary: tuple[str, ...] | list[str],
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
) -> OnboardModelReceipt:
    """Pin an onboard model's autonomy boundary."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(model_id, "model_id")
    if not isinstance(autonomy_boundary, (tuple, list)) or not autonomy_boundary:
        raise OrbitalError("autonomy_boundary must be a non-empty list/tuple")
    boundary = tuple(autonomy_boundary)
    for decision_class in boundary:
        if decision_class not in DECISION_CLASSES:
            raise OrbitalError(
                f"unknown decision class {decision_class!r}; "
                f"must be one of {DECISION_CLASSES}"
            )
    _check_nonempty_str(issued_by, "issued_by")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    receipt = OnboardModelReceipt(
        receipt_id=receipt_id,
        model_id=model_id,
        autonomy_boundary=boundary,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
    )
    digest, signature = _seal_receipt(receipt._payload(), authority_secret)
    return OnboardModelReceipt(
        **{**receipt.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


def check_onboard_decision(
    receipt: OnboardModelReceipt,
    *,
    decision_class: str,
    now: int,
) -> OrbitalVerdict:
    """Check an onboard decision against the pinned boundary."""
    if not isinstance(receipt, OnboardModelReceipt):
        raise OrbitalError("receipt must be an OnboardModelReceipt")
    _check_nonempty_str(decision_class, "decision_class")
    _check_ts(now, "now")
    if not _verify_signature(
        receipt.authority_pubkey_hex, receipt._payload(), receipt.signature_hex
    ):
        return OrbitalVerdict(
            allowed=False,
            reason=f"{DENY_SIGNATURE_INVALID}: autonomy boundary for model "
            f"{receipt.model_id!r} has an invalid authority signature",
            classification=CLASS_DENY,
            audit_event=orbital_audit_event(
                action=ONBOARD_EVENT,
                allowed=False,
                reason=DENY_SIGNATURE_INVALID,
                created_unix=now,
                model_id=receipt.model_id,
            ),
        )
    if decision_class not in receipt.autonomy_boundary:
        return OrbitalVerdict(
            allowed=False,
            reason=f"{DENY_AUTONOMY_BREACH}: model {receipt.model_id!r} may "
            f"decide {sorted(receipt.autonomy_boundary)} alone; "
            f"{decision_class!r} needs ground authorization",
            classification=CLASS_DENY,
            receipt=receipt,
            audit_event=orbital_audit_event(
                action=ONBOARD_EVENT,
                allowed=False,
                reason=DENY_AUTONOMY_BREACH,
                created_unix=now,
                model_id=receipt.model_id,
                decision_class=decision_class,
            ),
        )
    return OrbitalVerdict(
        allowed=True,
        reason="within_autonomy_boundary",
        classification=CLASS_ALLOW,
        receipt=receipt,
        audit_event=orbital_audit_event(
            action=ONBOARD_EVENT,
            allowed=True,
            reason="within_autonomy_boundary",
            created_unix=now,
            model_id=receipt.model_id,
            decision_class=decision_class,
        ),
    )


# ---------------------------------------------------------------------------
# Counterspace transparency (declarations on the incident event chain)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityDeclaration:
    """An authority-signed counterspace capability declaration.

    The declaration binds ``(system_id, capability_class,
    declared_at)`` from the closed ``CAPABILITY_CLASSES``
    vocabulary. Declarations are hash-chained; the audit event is
    shaped to feed the 113th-batch incident-receipts event chain so
    an undeclared capability discovered later is undeniable.
    """

    receipt_id: str
    system_id: str
    capability_class: str
    declared_at: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ORBITAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "system_id": self.system_id,
            "capability_class": self.capability_class,
            "declared_at": self.declared_at,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def counterspace_transparency(
    *,
    receipt_id: str,
    system_id: str,
    capability_class: str,
    declared_at: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> CapabilityDeclaration:
    """Declare an on-orbit capability on the record."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(system_id, "system_id")
    if capability_class not in CAPABILITY_CLASSES:
        raise OrbitalError(
            f"capability_class must be one of {CAPABILITY_CLASSES}"
        )
    _check_ts(declared_at, "declared_at")
    _check_nonempty_str(issued_by, "issued_by")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    if prev_digest != _GENESIS:
        _check_hex64(prev_digest, "prev_digest")
    declaration = CapabilityDeclaration(
        receipt_id=receipt_id,
        system_id=system_id,
        capability_class=capability_class,
        declared_at=declared_at,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        prev_digest=prev_digest,
    )
    digest, signature = _seal_receipt(declaration._payload(), authority_secret)
    return CapabilityDeclaration(
        **{**declaration.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


class CounterspaceRegistry:
    """Owns capability declarations; discovered undeclared
    capabilities are findings, not mysteries."""

    def __init__(self) -> None:
        self._by_system: dict[str, list[CapabilityDeclaration]] = {}
        self._log: list[CapabilityDeclaration] = []

    def declare(self, declaration: CapabilityDeclaration) -> CapabilityDeclaration:
        if not isinstance(declaration, CapabilityDeclaration):
            raise OrbitalError("declaration must be a CapabilityDeclaration")
        self._log.append(declaration)
        _check_chain(self._log, "counterspace")
        self._by_system.setdefault(declaration.system_id, []).append(declaration)
        return declaration

    def check_capability(
        self,
        *,
        system_id: str,
        observed_capability_class: str,
        now: int,
    ) -> OrbitalVerdict:
        """Check an observed capability against declarations.

        An observed capability with no matching declaration is
        ``orbital:undeclared_capability`` — the audit event feeds
        the incident-receipts chain, so the discovery is on the
        record whether or not anyone admits it.
        """
        _check_nonempty_str(system_id, "system_id")
        if observed_capability_class not in CAPABILITY_CLASSES:
            raise OrbitalError(
                f"observed_capability_class must be one of {CAPABILITY_CLASSES}"
            )
        _check_ts(now, "now")
        declared = {
            d.capability_class for d in self._by_system.get(system_id, [])
        }
        if observed_capability_class in declared:
            return OrbitalVerdict(
                allowed=True,
                reason="capability_declared",
                classification=CLASS_ALLOW,
                audit_event=orbital_audit_event(
                    action=COUNTERSPACE_EVENT,
                    allowed=True,
                    reason="capability_declared",
                    created_unix=now,
                    system_id=system_id,
                    capability_class=observed_capability_class,
                ),
            )
        return OrbitalVerdict(
            allowed=False,
            reason=f"{DENY_UNDECLARED_CAPABILITY}: system {system_id!r} "
            f"observed with {observed_capability_class!r} but declared "
            f"{sorted(declared) or 'nothing'}",
            classification=CLASS_DENY,
            audit_event=orbital_audit_event(
                action=COUNTERSPACE_EVENT,
                allowed=False,
                reason=DENY_UNDECLARED_CAPABILITY,
                created_unix=now,
                system_id=system_id,
                capability_class=observed_capability_class,
                declared_classes=sorted(declared),
            ),
        )


# ---------------------------------------------------------------------------
# Liability pins (who pays, who cleans)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LiabilityReceipt:
    """An authority-signed liability pin for an orbital object.

    Binds ``(object_id, payer, cleanup_party, deorbit_deadline)`` —
    the Zero Debris Week question ("who pays for non-deorbiting,
    who bears cleanup liability") answered in advance, in a receipt
    a machine can check.
    """

    receipt_id: str
    object_id: str
    payer: str
    cleanup_party: str
    deorbit_deadline: int
    issued_by: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    receipt_digest: str = ""
    schema_version: str = ORBITAL_SCHEMA_VERSION

    def _payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "object_id": self.object_id,
            "payer": self.payer,
            "cleanup_party": self.cleanup_party,
            "deorbit_deadline": self.deorbit_deadline,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
            "schema_version": self.schema_version,
        }


def liability_pin(
    *,
    receipt_id: str,
    object_id: str,
    payer: str,
    cleanup_party: str,
    deorbit_deadline: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str = _GENESIS,
) -> LiabilityReceipt:
    """Pin liability for an orbital object before it is dead."""
    _check_nonempty_str(receipt_id, "receipt_id")
    _check_nonempty_str(object_id, "object_id")
    _check_nonempty_str(payer, "payer")
    _check_nonempty_str(cleanup_party, "cleanup_party")
    _check_ts(deorbit_deadline, "deorbit_deadline")
    _check_nonempty_str(issued_by, "issued_by")
    _check_hex64(authority_pubkey_hex, "authority_pubkey_hex")
    _check_secret(authority_secret, "authority_secret")
    if prev_digest != _GENESIS:
        _check_hex64(prev_digest, "prev_digest")
    receipt = LiabilityReceipt(
        receipt_id=receipt_id,
        object_id=object_id,
        payer=payer,
        cleanup_party=cleanup_party,
        deorbit_deadline=deorbit_deadline,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        prev_digest=prev_digest,
    )
    digest, signature = _seal_receipt(receipt._payload(), authority_secret)
    return LiabilityReceipt(
        **{**receipt.__dict__, "signature_hex": signature, "receipt_digest": digest}
    )


class LiabilityRegistry:
    """Owns liability pins; a dead object past its deadline with no
    pin is an unowned hazard."""

    def __init__(self) -> None:
        self._by_object: dict[str, LiabilityReceipt] = {}
        self._log: list[LiabilityReceipt] = []

    def register(self, receipt: LiabilityReceipt) -> LiabilityReceipt:
        if not isinstance(receipt, LiabilityReceipt):
            raise OrbitalError("receipt must be a LiabilityReceipt")
        if receipt.object_id in self._by_object:
            raise OrbitalError(f"duplicate liability pin for {receipt.object_id!r}")
        self._log.append(receipt)
        _check_chain(self._log, "liability")
        self._by_object[receipt.object_id] = receipt
        return receipt

    def check_deorbit(
        self,
        *,
        object_id: str,
        at: int,
        still_in_orbit: bool,
        now: int,
    ) -> OrbitalVerdict:
        """Check a deorbit outcome against its liability pin."""
        _check_nonempty_str(object_id, "object_id")
        _check_ts(at, "at")
        if not isinstance(still_in_orbit, bool):
            raise OrbitalError("still_in_orbit must be a bool")
        _check_ts(now, "now")
        receipt = self._by_object.get(object_id)
        if not still_in_orbit:
            return OrbitalVerdict(
                allowed=True,
                reason="deorbited",
                classification=CLASS_ALLOW,
                receipt=receipt,
                audit_event=orbital_audit_event(
                    action=LIABILITY_EVENT,
                    allowed=True,
                    reason="deorbited",
                    created_unix=now,
                    object_id=object_id,
                ),
            )
        if receipt is None:
            return OrbitalVerdict(
                allowed=False,
                reason=f"{DENY_NO_LIABILITY_PIN}: object {object_id!r} still in "
                "orbit with no liability pin — nobody pays, nobody cleans",
                classification=CLASS_DENY,
                audit_event=orbital_audit_event(
                    action=LIABILITY_EVENT,
                    allowed=False,
                    reason=DENY_NO_LIABILITY_PIN,
                    created_unix=now,
                    object_id=object_id,
                ),
            )
        if at > receipt.deorbit_deadline:
            return OrbitalVerdict(
                allowed=True,
                reason=f"liability_pinned: payer={receipt.payer} "
                f"cleanup={receipt.cleanup_party}",
                classification=CLASS_ALLOW,
                receipt=receipt,
                audit_event=orbital_audit_event(
                    action=LIABILITY_EVENT,
                    allowed=True,
                    reason="liability_pinned",
                    created_unix=now,
                    object_id=object_id,
                    payer=receipt.payer,
                    cleanup_party=receipt.cleanup_party,
                    missed_deadline=receipt.deorbit_deadline,
                ),
            )
        return OrbitalVerdict(
            allowed=True,
            reason="deadline_not_reached",
            classification=CLASS_ALLOW,
            receipt=receipt,
            audit_event=orbital_audit_event(
                action=LIABILITY_EVENT,
                allowed=True,
                reason="deadline_not_reached",
                created_unix=now,
                object_id=object_id,
                deorbit_deadline=receipt.deorbit_deadline,
            ),
        )


__all__ = [
    "ORBITAL_SCHEMA_VERSION",
    "OrbitalError",
    "OrbitalVerdict",
    "orbital_audit_event",
    "CAPABILITY_CLASSES",
    "DECISION_CLASSES",
    "WARNING_FATIGUE_THRESHOLD",
    "ConjunctionReceipt",
    "conjunction_receipt",
    "ConjunctionRegistry",
    "ManeuverEnvelope",
    "maneuver_authorization_envelope",
    "check_maneuver",
    "STMDataReceipt",
    "stm_data_receipt",
    "STMRegistry",
    "dual_use_rpo_gate",
    "DebrisBudgetReceipt",
    "megaconstellation_debris_budget",
    "check_debris_budget",
    "OnboardModelReceipt",
    "onboard_model_receipt",
    "check_onboard_decision",
    "CapabilityDeclaration",
    "counterspace_transparency",
    "CounterspaceRegistry",
    "LiabilityReceipt",
    "liability_pin",
    "LiabilityRegistry",
]
