"""Transport & logistics AI discipline (one-hundred-fifty-third batch).

Absorbs the 2026 AI-transport research thread:

* **Baidu Apollo Go, Wuhan (2026-03-31)** — ~100-200 robotaxis froze
  simultaneously on a cloud failure (passengers stuck up to ~2h,
  rear-end collisions); **2026-04-29 China froze all new robotaxi
  permits nationwide** (fleet expansion, new pilots, new cities).
  The governance lesson is *fleet-wide* failure: single-vehicle
  safety != fleet safety, and the regulator demonstrated a
  fast circuit breaker.
* **Waymo, San Francisco** — Dec 2025 blackout (~1,600 stalls);
  July 4 2026 gridlock (dozens blocking lanes, Muni buses, towed);
  Austin: 99 "sleeper" 911 calls in 9 months. Mayor Lurie's 2026-07-16
  letter demanding statewide AV standards.
* **NHTSA (2026-07-08)** — directive on a "clear pattern" of AVs
  interfering with law enforcement / emergency responders (driving
  into incident scenes, blocking ambulances and fire trucks):
  obstruction is now a federal filing trigger.
* **California heavy AV trucking (2026-04)** — first test permits to
  Aurora Innovation and Kodiak AI after the >10,000 lb ban lifted;
  **Teamsters sued 2026-08-15** to vacate the framework (80,000 lb
  driverless trucks = unacceptable public-safety risk + millions of
  blue-collar jobs).
* **CJ Logistics (Korea, 2026-09)** — dual-arm humanoid packing
  robots in live fulfillment, AI auto-dispatch success lifted from
  <50% to 80%+; **Hanjin 2026-07**: Korea's first paid 5-ton
  autonomous trunk run (Gunsan port -> Daejeon mega-hub, 118 km,
  3x/week).
* **Delhi DTC (2026-09)** — AI bus management for 6,269 buses
  (4,519 electric): ETA/delay prediction, route optimization,
  crew/vehicle/depot scheduling, charging optimization, predictive
  maintenance, anomaly detection (speeding, GPS faults, off-route,
  skipped stops, bunching, accidents, panic buttons).
* **China MOT "AI+Transport" (2026)** — six-ministry implementation
  opinion, 860+ inventoried innovation scenarios (41 first-batch
  typical scenarios), and an application-safety guideline covering
  the AI full lifecycle (six governance principles).
* **Germany** — agent-IAM discipline push (verifiable identity,
  least privilege, lifecycle management, MCP endpoint trust,
  behavior monitoring, emergency shutdown); TUV AI-safety
  certification targeted by end-2026; 3-layer liability framing
  (OEM/software strict product liability, fleet operator + remote
  supervisor, infrastructure/V2X).
* **HERE (IAA 2026)** — AI reasoning layer that *explains* route
  decisions to dispatchers with actionable suggestions: the
  architecture shift from "give the answer" to "give the explanation
  + next action".

Northstar mapping, all fail-closed:

* ``route_rationale_gate()`` — every AI routing/dispatch decision
  binds a machine-readable rationale receipt
  (``affected_constraints[]``, ``suggested_actions[]``,
  ``confidence``); a decision executed without a live rationale is
  ``transport:no_rationale`` (HERE lesson: no explanation, no
  execution).
* ``fleet_circuit_breaker()`` — fleets pin a stall-trip threshold
  (count and ratio inside a window); a mass-stall event trips the
  breaker and freezes new dispatch until human review resets it.
  A fleet operating with no registered breaker is
  ``transport:no_kill_switch`` (Apollo Go lesson).
* ``teleoperation_cap()`` — remote supervisors bind a concurrency
  cap and a credential; assignments beyond the cap are
  ``transport:overloaded_supervisor``; expired/missing credentials
  are ``transport:uncredentialed_supervisor`` (3-layer liability
  lesson: parallel-monitoring count is a safety parameter).
* ``agent_iam_discipline()`` — transport agents bind a registered
  identity, least privilege, an MCP tool whitelist, and a kill
  switch; unregistered agents, privilege violations, off-whitelist
  tools, and missing kill switches deny (German agent-IAM lesson).
* ``safety_scenario_checklist()`` — deployments pin a versioned
  safety-scenario checklist (the 860-scenario inventory idea);
  operating a scenario outside the pinned list is
  ``transport:unchecked_scenario`` (MOT lesson).
* ``first_responder_probe()`` — recorded emergency-vehicle
  interference (blocked lane, entered scene, ignored pull-over)
  denies the vehicle in the probe window as
  ``transport:responder_interference`` (NHTSA lesson).
* ``labor_transition_plan()`` — deployments bind a labor
  capability-mapping receipt with a retraining trigger; no plan is
  ``transport:no_labor_plan``; automation past the trigger without
  retraining started is ``transport:retraining_overdue``
  (IRU/Teamsters lesson).
* ``incident_reporting_adapter()`` — city-level incident reports
  bind ``(incident_id, jurisdiction, schema_version)``; an incident
  with no city report past the deadline is
  ``transport:unreported_incident`` (Denver-counterexample lesson).

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (ninety-fifth batch), Ed25519 via
the vendored ``ed25519`` module (ninety-seventh batch pattern), and
all digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* The receipts verify the *claimed* discipline bundle is
  self-consistent and authority-signed; they cannot prove a fleet
  operator actually halted dispatch, a supervisor was truly watching,
  or a city filing reached the regulator — those need external
  attestation.
* The receipt is a governance record, not a substitute for vehicle
  type approval, driver licensing, or labor-law enforcement; it
  makes the reliance decision auditable.
* Trip thresholds, concurrency caps, and reporting deadlines are
  bench parameters drawn from the 2026 research sweep (vendor
  numbers were self-reported and unverified); confirm against the
  deployment's own safety case before operational reliance.
* This module does not make roads safe. It binds declared transport
  discipline so its absence is machine-detectable.
"""

from __future__ import annotations
from _domain_base import DomainError

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()

from ed25519 import public_key as _ed25519_pubkey  # noqa: F401 (re-exported for tests)
from ed25519 import sign as _ed25519_sign
from ed25519 import verify as _ed25519_verify

#: Schema marker, pinned into every digest.
TRANSPORT_SCHEMA_VERSION = "northstar.transport.v1"

#: Classification tiers for a transport check (binary, 87th-batch style).
TRANSPORT_AUTHORITATIVE = "transport-authoritative"
TRANSPORT_NON_AUTHORITATIVE = "transport-non_authoritative"

#: Denial reason codes. ``transport:`` prefix for audit filtering.
DENY_NO_RATIONALE = "transport:no_rationale"
DENY_RATIONALE_TAMPERED = "transport:rationale_tampered"
DENY_LOW_CONFIDENCE = "transport:low_confidence"
DENY_NO_KILL_SWITCH = "transport:no_kill_switch"
DENY_FLEET_TRIPPED = "transport:fleet_tripped"
DENY_UNREGISTERED_SUPERVISOR = "transport:unregistered_supervisor"
DENY_UNCREDENTIALED_SUPERVISOR = "transport:uncredentialed_supervisor"
DENY_OVERLOADED_SUPERVISOR = "transport:overloaded_supervisor"
DENY_UNREGISTERED_AGENT = "transport:unregistered_agent"
DENY_PRIVILEGE_VIOLATION = "transport:privilege_violation"
DENY_TOOL_NOT_WHITELISTED = "transport:tool_not_whitelisted"
DENY_NO_CHECKLIST = "transport:no_checklist"
DENY_UNCHECKED_SCENARIO = "transport:unchecked_scenario"
DENY_RESPONDER_INTERFERENCE = "transport:responder_interference"
DENY_NO_LABOR_PLAN = "transport:no_labor_plan"
DENY_RETRAINING_OVERDUE = "transport:retraining_overdue"
DENY_UNREPORTED_INCIDENT = "transport:unreported_incident"
DENY_LATE_REPORT = "transport:late_report"

#: Minimum rationale confidence for an executable routing decision.
#: Below this the rationale is advisory only and the decision must
#: not execute (HERE lesson: low-confidence routing is a human call).
RATIONALE_CONFIDENCE_MIN = 0.70

#: Default fleet-wide stall-trip thresholds (Apollo Go lesson):
#: trip when EITHER the count OR the ratio inside the window is met.
FLEET_STALL_COUNT_TRIP = 10
FLEET_STALL_RATIO_TRIP_BPS = 500  # 5% of the fleet

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class TransportError(DomainError):
    """A malformed transport receipt/record or a programming error.

    Raised for structural problems (bad digests, unknown kinds,
    broken chains). Verification *failures* (missing rationales,
    tripped breakers, overloaded supervisors) return a
    :class:`TransportVerdict` with ``allowed=False`` — a failed gate
    is a verdict, a malformed record is a bug.
    """


# ---------------------------------------------------------------------------
# Field checks
# ---------------------------------------------------------------------------


def _is_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise TransportError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _require_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TransportError(f"{field_name} must be a non-empty string")
    if value.strip() != value:
        raise TransportError(f"{field_name} must not be padded")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TransportError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_secret(value: Any, field_name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise TransportError(f"{field_name} must be a 32-byte seed")
    return value


def _check_pubkey_hex(value: Any, field_name: str = "authority_pubkey_hex") -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise TransportError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_sig_hex(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise TransportError(f"{field_name} must be a 128-char lowercase hex signature")
    return value


def _check_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise TransportError(f"{field_name} must be a bool")
    return value


def _check_ratio(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TransportError(f"{field_name} must be a number")
    if not 0.0 <= value <= 1.0:
        raise TransportError(f"{field_name} must be in [0, 1]")
    return float(value)


def _check_bps(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TransportError(f"{field_name} must be an int basis-points value")
    if not 0 <= value <= 10_000:
        raise TransportError(f"{field_name} must be in [0, 10000] bps")
    return value


def _check_str_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not value:
        raise TransportError(f"{field_name} must be a non-empty tuple/list of strings")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise TransportError(f"{field_name} entries must be non-empty strings")
        out.append(item)
    return tuple(out)


# ---------------------------------------------------------------------------
# Signing and record verification
# ---------------------------------------------------------------------------


def _sign(secret: bytes, digest_hex: str) -> str:
    return _ed25519_sign(secret, digest_hex.encode("utf-8")).hex()


def _verify(pubkey_hex: str, digest_hex: str, signature_hex: str) -> bool:
    try:
        return bool(
            _ed25519_verify(
                bytes.fromhex(pubkey_hex),
                digest_hex.encode("utf-8"),
                bytes.fromhex(signature_hex),
            )
        )
    except Exception:
        return False


def _check_record(record: Any) -> bool:
    """Recompute a record's digest and verify its authority signature."""
    digest = jcs_sha256_hex(record.payload())
    if not hmac.compare_digest(digest, record.record_digest):
        return False
    return _verify(record.authority_pubkey_hex, digest, record.signature_hex)


@dataclass(frozen=True)
class TransportVerdict:
    """Outcome of one transport & logistics AI discipline check."""

    allowed: bool
    deny_code: str | None
    classification: str
    receipt_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "transport-verdict",
            "allowed": self.allowed,
            "deny_code": self.deny_code,
            "classification": self.classification,
            "receipt_digest": self.receipt_digest,
        }


def _allow(receipt_digest: str = "") -> TransportVerdict:
    return TransportVerdict(
        allowed=True,
        deny_code=None,
        classification=TRANSPORT_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def _deny(deny_code: str) -> TransportVerdict:
    return TransportVerdict(
        allowed=False,
        deny_code=deny_code,
        classification=TRANSPORT_NON_AUTHORITATIVE,
    )


# ---------------------------------------------------------------------------
# 1. Route rationale receipts (HERE lesson: no explanation, no execution)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RouteRationale:
    """Machine-readable rationale bound to one AI routing decision.

    Binds ``(decision_id | route_digest | affected_constraints[] |
    suggested_actions[] | confidence | issued_at | expires_at)`` to the
    dispatch authority's key. The decision may only execute while this
    receipt is live, correctly bound, and above the confidence floor.
    """

    decision_id: str
    route_digest: str
    affected_constraints: tuple[str, ...]
    suggested_actions: tuple[str, ...]
    confidence: float
    issued_at: int
    expires_at: int
    authority_pubkey_hex: str
    signature_hex: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": TRANSPORT_SCHEMA_VERSION,
            "kind": "route-rationale",
            "decision_id": self.decision_id,
            "route_digest": self.route_digest,
            "affected_constraints": list(self.affected_constraints),
            "suggested_actions": list(self.suggested_actions),
            "confidence": self.confidence,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def issue_route_rationale(
    *,
    decision_id: str,
    route_digest: str,
    affected_constraints: tuple[str, ...] | list[str],
    suggested_actions: tuple[str, ...] | list[str],
    confidence: float,
    issued_at: int,
    expires_at: int,
    authority_secret: bytes
) -> RouteRationale:
    """Issue a signed rationale receipt for one AI routing decision."""
    decision_id = _require_str(decision_id, "decision_id")
    route_digest = _check_hex64(route_digest, "route_digest")
    constraints = _check_str_tuple(affected_constraints, "affected_constraints")
    actions = _check_str_tuple(suggested_actions, "suggested_actions")
    confidence = _check_ratio(confidence, "confidence")
    issued_at = _check_ts(issued_at, "issued_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise TransportError("expires_at must be after issued_at")
    _check_secret(authority_secret, "authority_secret")
    pubkey_hex = _ed25519_pubkey(authority_secret).hex()
    bare = RouteRationale(
        decision_id=decision_id,
        route_digest=route_digest,
        affected_constraints=constraints,
        suggested_actions=actions,
        confidence=confidence,
        issued_at=issued_at,
        expires_at=expires_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,
        record_digest="",
    )
    digest = jcs_sha256_hex(bare.payload())
    return RouteRationale(
        decision_id=bare.decision_id,
        route_digest=bare.route_digest,
        affected_constraints=bare.affected_constraints,
        suggested_actions=bare.suggested_actions,
        confidence=bare.confidence,
        issued_at=bare.issued_at,
        expires_at=bare.expires_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=_sign(authority_secret, digest),
        record_digest=digest,
    )


class RouteRegistry:
    """Rationale receipts keyed by decision_id."""

    def __init__(self) -> None:
        self._by_decision: dict[str, RouteRationale] = {}

    def record(self, rationale: RouteRationale) -> None:
        if not _check_record(rationale):
            raise TransportError(
                f"route rationale for {rationale.decision_id!r} fails verification"
            )
        self._by_decision[rationale.decision_id] = rationale

    def get(self, decision_id: str) -> RouteRationale | None:
        return self._by_decision.get(decision_id)


def route_rationale_gate(
    rationales: RouteRegistry,
    *,
    decision_id: str,
    route_digest: str,
    now: int,
) -> TransportVerdict:
    """Gate an AI routing decision on its rationale receipt.

    Fail-closed: no live rationale -> ``transport:no_rationale``;
    tampered or mis-bound rationale -> ``transport:rationale_tampered``;
    confidence below the floor -> ``transport:low_confidence``.
    """
    decision_id = _require_str(decision_id, "decision_id")
    route_digest = _check_hex64(route_digest, "route_digest")
    now = _check_ts(now, "now")
    rationale = rationales.get(decision_id)
    if rationale is None:
        return _deny(DENY_NO_RATIONALE)
    if not _check_record(rationale):
        return _deny(DENY_RATIONALE_TAMPERED)
    if not hmac.compare_digest(rationale.route_digest, route_digest):
        return _deny(DENY_RATIONALE_TAMPERED)
    if now < rationale.issued_at or now > rationale.expires_at:
        return _deny(DENY_NO_RATIONALE)
    if rationale.confidence < RATIONALE_CONFIDENCE_MIN:
        return _deny(DENY_LOW_CONFIDENCE)
    return _allow(rationale.record_digest)


# ---------------------------------------------------------------------------
# 2. Fleet circuit breaker (Apollo Go lesson: fleet-wide failure mode)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FleetConfig:
    """One fleet's pinned stall-trip breaker configuration."""

    fleet_id: str
    fleet_size: int
    stall_count_trip: int
    stall_ratio_trip_bps: int
    window_s: int
    breaker_bound: bool
    registered_at: int
    authority_pubkey_hex: str
    signature_hex: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": TRANSPORT_SCHEMA_VERSION,
            "kind": "fleet-config",
            "fleet_id": self.fleet_id,
            "fleet_size": self.fleet_size,
            "stall_count_trip": self.stall_count_trip,
            "stall_ratio_trip_bps": self.stall_ratio_trip_bps,
            "window_s": self.window_s,
            "breaker_bound": self.breaker_bound,
            "registered_at": self.registered_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


@dataclass(frozen=True)
class StallEvent:
    """One vehicle stall/freeze event, authority-signed."""

    fleet_id: str
    vehicle_id: str
    stalled_at: int
    authority_pubkey_hex: str
    signature_hex: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": TRANSPORT_SCHEMA_VERSION,
            "kind": "stall-event",
            "fleet_id": self.fleet_id,
            "vehicle_id": self.vehicle_id,
            "stalled_at": self.stalled_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def register_fleet(
    *,
    fleet_id: str,
    fleet_size: int,
    stall_count_trip: int = FLEET_STALL_COUNT_TRIP,
    stall_ratio_trip_bps: int = FLEET_STALL_RATIO_TRIP_BPS,
    window_s: int = 600,
    breaker_bound: bool = True,
    registered_at: int,
    authority_secret: bytes
) -> FleetConfig:
    """Register one fleet's stall-trip breaker configuration.

    ``breaker_bound=False`` registers the fleet *without* a breaker —
    the gate then denies it whole-class (``transport:no_kill_switch``):
    the breaker is declared absent rather than silently missing.
    """
    fleet_id = _require_str(fleet_id, "fleet_id")
    if isinstance(fleet_size, bool) or not isinstance(fleet_size, int) or fleet_size <= 0:
        raise TransportError("fleet_size must be a positive int")
    if isinstance(stall_count_trip, bool) or not isinstance(stall_count_trip, int) or stall_count_trip <= 0:
        raise TransportError("stall_count_trip must be a positive int")
    stall_ratio_trip_bps = _check_bps(stall_ratio_trip_bps, "stall_ratio_trip_bps")
    if isinstance(window_s, bool) or not isinstance(window_s, int) or window_s <= 0:
        raise TransportError("window_s must be a positive int")
    breaker_bound = _check_bool(breaker_bound, "breaker_bound")
    registered_at = _check_ts(registered_at, "registered_at")
    _check_secret(authority_secret, "authority_secret")
    pubkey_hex = _ed25519_pubkey(authority_secret).hex()
    bare = FleetConfig(
        fleet_id=fleet_id,
        fleet_size=fleet_size,
        stall_count_trip=stall_count_trip,
        stall_ratio_trip_bps=stall_ratio_trip_bps,
        window_s=window_s,
        breaker_bound=breaker_bound,
        registered_at=registered_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,
        record_digest="",
    )
    digest = jcs_sha256_hex(bare.payload())
    return FleetConfig(
        fleet_id=bare.fleet_id,
        fleet_size=bare.fleet_size,
        stall_count_trip=bare.stall_count_trip,
        stall_ratio_trip_bps=bare.stall_ratio_trip_bps,
        window_s=bare.window_s,
        breaker_bound=bare.breaker_bound,
        registered_at=bare.registered_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=_sign(authority_secret, digest),
        record_digest=digest,
    )


def record_stall_event(
    *,
    fleet_id: str,
    vehicle_id: str,
    stalled_at: int,
    authority_secret: bytes
) -> StallEvent:
    """Record one vehicle stall/freeze event, authority-signed."""
    fleet_id = _require_str(fleet_id, "fleet_id")
    vehicle_id = _require_str(vehicle_id, "vehicle_id")
    stalled_at = _check_ts(stalled_at, "stalled_at")
    _check_secret(authority_secret, "authority_secret")
    pubkey_hex = _ed25519_pubkey(authority_secret).hex()
    bare = StallEvent(
        fleet_id=fleet_id,
        vehicle_id=vehicle_id,
        stalled_at=stalled_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,
        record_digest="",
    )
    digest = jcs_sha256_hex(bare.payload())
    return StallEvent(
        fleet_id=bare.fleet_id,
        vehicle_id=bare.vehicle_id,
        stalled_at=bare.stalled_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=_sign(authority_secret, digest),
        record_digest=digest,
    )


class FleetRegistry:
    """Fleet breaker configs plus their signed stall events."""

    def __init__(self) -> None:
        self._configs: dict[str, FleetConfig] = {}
        self._stalls: dict[str, list[StallEvent]] = {}

    def register(self, config: FleetConfig) -> None:
        if not _check_record(config):
            raise TransportError(
                f"fleet config for {config.fleet_id!r} fails verification"
            )
        self._configs[config.fleet_id] = config
        self._stalls.setdefault(config.fleet_id, [])

    def record_stall(self, event: StallEvent) -> None:
        if event.fleet_id not in self._configs:
            raise TransportError(
                f"stall event for unregistered fleet {event.fleet_id!r}"
            )
        if not _check_record(event):
            raise TransportError("stall event fails verification")
        self._stalls[event.fleet_id].append(event)

    def stalls_in_window(self, fleet_id: str, *, now: int) -> int:
        config = self._configs.get(fleet_id)
        if config is None:
            raise TransportError(f"unknown fleet {fleet_id!r}")
        window_start = now - config.window_s
        return sum(
            1 for e in self._stalls.get(fleet_id, [])
            if window_start <= e.stalled_at <= now
        )

    def is_tripped(self, fleet_id: str, *, now: int) -> bool:
        config = self._configs.get(fleet_id)
        if config is None:
            raise TransportError(f"unknown fleet {fleet_id!r}")
        count = self.stalls_in_window(fleet_id, now=now)
        ratio_bps = (count * 10_000) // config.fleet_size
        return (
            count >= config.stall_count_trip
            or ratio_bps >= config.stall_ratio_trip_bps
        )


def fleet_circuit_breaker(
    fleets: FleetRegistry,
    *,
    fleet_id: str,
    now: int,
) -> TransportVerdict:
    """Gate fleet dispatch on the fleet-level circuit breaker.

    A fleet with no registered breaker config denies whole-class
    (``transport:no_kill_switch``) — the Apollo Go lesson: a fleet
    that cannot halt itself as a fleet may not dispatch as one.
    A tripped breaker denies new dispatch (``transport:fleet_tripped``)
    until a human reviews and resets the stall log.
    """
    fleet_id = _require_str(fleet_id, "fleet_id")
    now = _check_ts(now, "now")
    config = fleets._configs.get(fleet_id)
    if config is None or not config.breaker_bound:
        return _deny(DENY_NO_KILL_SWITCH)
    if not _check_record(config):
        return _deny(DENY_NO_KILL_SWITCH)
    if fleets.is_tripped(fleet_id, now=now):
        return _deny(DENY_FLEET_TRIPPED)
    return _allow(config.record_digest)


# ---------------------------------------------------------------------------
# 3. Teleoperation supervisor cap + credential gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Supervisor:
    """One remote supervisor: concurrency cap + credential binding."""

    supervisor_id: str
    max_concurrent: int
    credential_digest: str
    credential_valid_until: int
    registered_at: int
    authority_pubkey_hex: str
    signature_hex: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": TRANSPORT_SCHEMA_VERSION,
            "kind": "supervisor",
            "supervisor_id": self.supervisor_id,
            "max_concurrent": self.max_concurrent,
            "credential_digest": self.credential_digest,
            "credential_valid_until": self.credential_valid_until,
            "registered_at": self.registered_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def register_supervisor(
    *,
    supervisor_id: str,
    max_concurrent: int,
    credential_digest: str,
    credential_valid_until: int,
    registered_at: int,
    authority_secret: bytes
) -> Supervisor:
    """Register one teleoperation supervisor with cap + credential."""
    supervisor_id = _require_str(supervisor_id, "supervisor_id")
    if isinstance(max_concurrent, bool) or not isinstance(max_concurrent, int) or max_concurrent <= 0:
        raise TransportError("max_concurrent must be a positive int")
    credential_digest = _check_hex64(credential_digest, "credential_digest")
    credential_valid_until = _check_ts(credential_valid_until, "credential_valid_until")
    registered_at = _check_ts(registered_at, "registered_at")
    _check_secret(authority_secret, "authority_secret")
    pubkey_hex = _ed25519_pubkey(authority_secret).hex()
    bare = Supervisor(
        supervisor_id=supervisor_id,
        max_concurrent=max_concurrent,
        credential_digest=credential_digest,
        credential_valid_until=credential_valid_until,
        registered_at=registered_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,
        record_digest="",
    )
    digest = jcs_sha256_hex(bare.payload())
    return Supervisor(
        supervisor_id=bare.supervisor_id,
        max_concurrent=bare.max_concurrent,
        credential_digest=bare.credential_digest,
        credential_valid_until=bare.credential_valid_until,
        registered_at=bare.registered_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=_sign(authority_secret, digest),
        record_digest=digest,
    )


class SupervisorRegistry:
    """Supervisors plus their live vehicle assignments."""

    def __init__(self) -> None:
        self._supervisors: dict[str, Supervisor] = {}
        self._assignments: dict[str, set[str]] = {}

    def register(self, supervisor: Supervisor) -> None:
        if not _check_record(supervisor):
            raise TransportError(
                f"supervisor {supervisor.supervisor_id!r} fails verification"
            )
        self._supervisors[supervisor.supervisor_id] = supervisor
        self._assignments.setdefault(supervisor.supervisor_id, set())

    def assign(self, supervisor_id: str, vehicle_id: str) -> None:
        if supervisor_id not in self._supervisors:
            raise TransportError(f"unknown supervisor {supervisor_id!r}")
        vehicle_id = _require_str(vehicle_id, "vehicle_id")
        self._assignments[supervisor_id].add(vehicle_id)

    def release(self, supervisor_id: str, vehicle_id: str) -> None:
        self._assignments.get(supervisor_id, set()).discard(vehicle_id)

    def active_count(self, supervisor_id: str) -> int:
        return len(self._assignments.get(supervisor_id, set()))

    def get(self, supervisor_id: str) -> Supervisor | None:
        return self._supervisors.get(supervisor_id)


def teleoperation_cap(
    supervisors: SupervisorRegistry,
    *,
    supervisor_id: str,
    now: int,
) -> TransportVerdict:
    """Gate a supervisor's fitness: registered, credentialed, in-cap.

    Unknown supervisor -> ``transport:unregistered_supervisor``;
    expired credential -> ``transport:uncredentialed_supervisor``;
    assignments beyond the cap ->
    ``transport:overloaded_supervisor``. The cap is a safety
    parameter, not an HR guideline (3-layer liability lesson).
    """
    supervisor_id = _require_str(supervisor_id, "supervisor_id")
    now = _check_ts(now, "now")
    supervisor = supervisors.get(supervisor_id)
    if supervisor is None:
        return _deny(DENY_UNREGISTERED_SUPERVISOR)
    if not _check_record(supervisor):
        return _deny(DENY_UNREGISTERED_SUPERVISOR)
    if now > supervisor.credential_valid_until:
        return _deny(DENY_UNCREDENTIALED_SUPERVISOR)
    if supervisors.active_count(supervisor_id) > supervisor.max_concurrent:
        return _deny(DENY_OVERLOADED_SUPERVISOR)
    return _allow(supervisor.record_digest)


# ---------------------------------------------------------------------------
# 4. Transport agent IAM discipline (German lesson: digital-employee rules)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransportAgent:
    """One transport AI agent's pinned IAM posture.

    ``privileges`` is the least-privilege set; ``mcp_tool_whitelist``
    is the approved tool inventory; ``kill_switch_bound`` must be true
    — an agent without an emergency shutdown is not deployable.
    """

    agent_id: str
    identity_pubkey_hex: str
    privileges: tuple[str, ...]
    mcp_tool_whitelist: tuple[str, ...]
    kill_switch_bound: bool
    registered_at: int
    authority_pubkey_hex: str
    signature_hex: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": TRANSPORT_SCHEMA_VERSION,
            "kind": "transport-agent",
            "agent_id": self.agent_id,
            "identity_pubkey_hex": self.identity_pubkey_hex,
            "privileges": list(self.privileges),
            "mcp_tool_whitelist": list(self.mcp_tool_whitelist),
            "kill_switch_bound": self.kill_switch_bound,
            "registered_at": self.registered_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def register_transport_agent(
    *,
    agent_id: str,
    identity_pubkey_hex: str,
    privileges: tuple[str, ...] | list[str],
    mcp_tool_whitelist: tuple[str, ...] | list[str],
    kill_switch_bound: bool,
    registered_at: int,
    authority_secret: bytes
) -> TransportAgent:
    """Register one transport AI agent's IAM posture, authority-signed."""
    agent_id = _require_str(agent_id, "agent_id")
    identity_pubkey_hex = _check_pubkey_hex(identity_pubkey_hex, "identity_pubkey_hex")
    privs = _check_str_tuple(privileges, "privileges")
    tools = _check_str_tuple(mcp_tool_whitelist, "mcp_tool_whitelist")
    kill_switch_bound = _check_bool(kill_switch_bound, "kill_switch_bound")
    registered_at = _check_ts(registered_at, "registered_at")
    _check_secret(authority_secret, "authority_secret")
    pubkey_hex = _ed25519_pubkey(authority_secret).hex()
    bare = TransportAgent(
        agent_id=agent_id,
        identity_pubkey_hex=identity_pubkey_hex,
        privileges=tuple(sorted(set(privs))),
        mcp_tool_whitelist=tuple(sorted(set(tools))),
        kill_switch_bound=kill_switch_bound,
        registered_at=registered_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,
        record_digest="",
    )
    digest = jcs_sha256_hex(bare.payload())
    return TransportAgent(
        agent_id=bare.agent_id,
        identity_pubkey_hex=bare.identity_pubkey_hex,
        privileges=bare.privileges,
        mcp_tool_whitelist=bare.mcp_tool_whitelist,
        kill_switch_bound=bare.kill_switch_bound,
        registered_at=bare.registered_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=_sign(authority_secret, digest),
        record_digest=digest,
    )


class AgentIAMRegistry:
    """Transport AI agents keyed by agent_id."""

    def __init__(self) -> None:
        self._agents: dict[str, TransportAgent] = {}

    def register(self, agent: TransportAgent) -> None:
        if not _check_record(agent):
            raise TransportError(
                f"transport agent {agent.agent_id!r} fails verification"
            )
        self._agents[agent.agent_id] = agent

    def get(self, agent_id: str) -> TransportAgent | None:
        return self._agents.get(agent_id)


def agent_iam_discipline(
    agents: AgentIAMRegistry,
    *,
    agent_id: str,
    requested_privilege: str | None = None,
    tool_name: str | None = None,
) -> TransportVerdict:
    """Gate a transport AI agent's action on its pinned IAM posture.

    Unknown agent -> ``transport:unregistered_agent`` (shadow AI is
    denied, not discovered later); no kill switch ->
    ``transport:no_kill_switch``; privilege outside the least-privilege
    set -> ``transport:privilege_violation``; tool outside the
    whitelist -> ``transport:tool_not_whitelisted``.
    """
    agent_id = _require_str(agent_id, "agent_id")
    agent = agents.get(agent_id)
    if agent is None:
        return _deny(DENY_UNREGISTERED_AGENT)
    if not _check_record(agent):
        return _deny(DENY_UNREGISTERED_AGENT)
    if not agent.kill_switch_bound:
        return _deny(DENY_NO_KILL_SWITCH)
    if requested_privilege is not None:
        requested_privilege = _require_str(requested_privilege, "requested_privilege")
        if requested_privilege not in agent.privileges:
            return _deny(DENY_PRIVILEGE_VIOLATION)
    if tool_name is not None:
        tool_name = _require_str(tool_name, "tool_name")
        if tool_name not in agent.mcp_tool_whitelist:
            return _deny(DENY_TOOL_NOT_WHITELISTED)
    return _allow(agent.record_digest)


# ---------------------------------------------------------------------------
# 5. Safety-scenario checklist (MOT 860-scenario-inventory lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScenarioChecklist:
    """One deployment's pinned safety-scenario checklist.

    ``scenario_ids`` is the pinned, sorted inventory the deployment is
    cleared for; operating a scenario outside it is
    ``transport:unchecked_scenario``.
    """

    deployment_id: str
    scenario_ids: tuple[str, ...]
    pinned_at: int
    authority_pubkey_hex: str
    signature_hex: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": TRANSPORT_SCHEMA_VERSION,
            "kind": "scenario-checklist",
            "deployment_id": self.deployment_id,
            "scenario_ids": list(self.scenario_ids),
            "pinned_at": self.pinned_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def pin_scenario_checklist(
    *,
    deployment_id: str,
    scenario_ids: tuple[str, ...] | list[str],
    pinned_at: int,
    authority_secret: bytes
) -> ScenarioChecklist:
    """Pin one deployment's safety-scenario checklist, authority-signed."""
    deployment_id = _require_str(deployment_id, "deployment_id")
    scenarios = _check_str_tuple(scenario_ids, "scenario_ids")
    pinned_at = _check_ts(pinned_at, "pinned_at")
    _check_secret(authority_secret, "authority_secret")
    pubkey_hex = _ed25519_pubkey(authority_secret).hex()
    bare = ScenarioChecklist(
        deployment_id=deployment_id,
        scenario_ids=tuple(sorted(set(scenarios))),
        pinned_at=pinned_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,
        record_digest="",
    )
    digest = jcs_sha256_hex(bare.payload())
    return ScenarioChecklist(
        deployment_id=bare.deployment_id,
        scenario_ids=bare.scenario_ids,
        pinned_at=bare.pinned_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=_sign(authority_secret, digest),
        record_digest=digest,
    )


class ChecklistRegistry:
    """Pinned scenario checklists keyed by deployment_id."""

    def __init__(self) -> None:
        self._lists: dict[str, ScenarioChecklist] = {}

    def pin(self, checklist: ScenarioChecklist) -> None:
        if not _check_record(checklist):
            raise TransportError(
                f"checklist for {checklist.deployment_id!r} fails verification"
            )
        self._lists[checklist.deployment_id] = checklist

    def get(self, deployment_id: str) -> ScenarioChecklist | None:
        return self._lists.get(deployment_id)


def safety_scenario_checklist(
    checklists: ChecklistRegistry,
    *,
    deployment_id: str,
    scenario_id: str,
) -> TransportVerdict:
    """Gate operating a scenario on the pinned checklist.

    No pinned checklist -> ``transport:no_checklist``; scenario
    outside the pinned inventory -> ``transport:unchecked_scenario``.
    """
    deployment_id = _require_str(deployment_id, "deployment_id")
    scenario_id = _require_str(scenario_id, "scenario_id")
    checklist = checklists.get(deployment_id)
    if checklist is None:
        return _deny(DENY_NO_CHECKLIST)
    if not _check_record(checklist):
        return _deny(DENY_NO_CHECKLIST)
    if scenario_id not in checklist.scenario_ids:
        return _deny(DENY_UNCHECKED_SCENARIO)
    return _allow(checklist.record_digest)


# ---------------------------------------------------------------------------
# 6. First-responder interference probe (NHTSA lesson)
# ---------------------------------------------------------------------------

#: Closed obstruction-kind vocabulary.
OBSTRUCTION_KINDS: tuple[str, ...] = (
    "blocked_lane",
    "entered_scene",
    "ignored_pull_over",
    "delayed_yield",
)


@dataclass(frozen=True)
class ResponderInterference:
    """One recorded emergency-vehicle interference event."""

    incident_id: str
    vehicle_id: str
    responder_type: str
    obstruction_kind: str
    detected_at: int
    authority_pubkey_hex: str
    signature_hex: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": TRANSPORT_SCHEMA_VERSION,
            "kind": "responder-interference",
            "incident_id": self.incident_id,
            "vehicle_id": self.vehicle_id,
            "responder_type": self.responder_type,
            "obstruction_kind": self.obstruction_kind,
            "detected_at": self.detected_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def record_responder_interference(
    *,
    incident_id: str,
    vehicle_id: str,
    responder_type: str,
    obstruction_kind: str,
    detected_at: int,
    authority_secret: bytes
) -> ResponderInterference:
    """Record one emergency-vehicle interference event, signed."""
    incident_id = _require_str(incident_id, "incident_id")
    vehicle_id = _require_str(vehicle_id, "vehicle_id")
    responder_type = _require_str(responder_type, "responder_type")
    if obstruction_kind not in OBSTRUCTION_KINDS:
        raise TransportError(
            f"obstruction_kind must be one of {OBSTRUCTION_KINDS}, saw {obstruction_kind!r}"
        )
    detected_at = _check_ts(detected_at, "detected_at")
    _check_secret(authority_secret, "authority_secret")
    pubkey_hex = _ed25519_pubkey(authority_secret).hex()
    bare = ResponderInterference(
        incident_id=incident_id,
        vehicle_id=vehicle_id,
        responder_type=responder_type,
        obstruction_kind=obstruction_kind,
        detected_at=detected_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,
        record_digest="",
    )
    digest = jcs_sha256_hex(bare.payload())
    return ResponderInterference(
        incident_id=bare.incident_id,
        vehicle_id=bare.vehicle_id,
        responder_type=bare.responder_type,
        obstruction_kind=bare.obstruction_kind,
        detected_at=bare.detected_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=_sign(authority_secret, digest),
        record_digest=digest,
    )


class ResponderRegistry:
    """Interference events keyed by incident_id."""

    def __init__(self) -> None:
        self._incidents: dict[str, ResponderInterference] = {}

    def record(self, incident: ResponderInterference) -> None:
        if not _check_record(incident):
            raise TransportError(
                f"interference {incident.incident_id!r} fails verification"
            )
        self._incidents[incident.incident_id] = incident

    def interferences_for_vehicle(
        self, vehicle_id: str, *, window_start: int, window_end: int
    ) -> list[ResponderInterference]:
        return [
            i for i in self._incidents.values()
            if i.vehicle_id == vehicle_id
            and window_start <= i.detected_at <= window_end
        ]


def first_responder_probe(
    responders: ResponderRegistry,
    *,
    vehicle_id: str,
    window_start: int,
    window_end: int,
) -> TransportVerdict:
    """Probe a vehicle for emergency-vehicle interference in a window.

    Any recorded obstruction (blocked lane, entered scene, ignored
    pull-over, delayed yield) denies the vehicle as
    ``transport:responder_interference`` — the NHTSA lesson: the
    pattern, not the single event, is the filing trigger.
    """
    vehicle_id = _require_str(vehicle_id, "vehicle_id")
    window_start = _check_ts(window_start, "window_start")
    window_end = _check_ts(window_end, "window_end")
    if window_end < window_start:
        raise TransportError("window_end must not precede window_start")
    hits = responders.interferences_for_vehicle(
        vehicle_id, window_start=window_start, window_end=window_end
    )
    if hits:
        return _deny(DENY_RESPONDER_INTERFERENCE)
    return _allow()


# ---------------------------------------------------------------------------
# 7. Labor transition plan (IRU/Teamsters lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LaborPlan:
    """One deployment's bound labor capability-mapping + retraining plan.

    ``retraining_trigger_bps``: when the deployment's automation rate
    reaches this share of the affected workforce, retraining must have
    started; otherwise the deployment is
    ``transport:retraining_overdue``.
    """

    deployment_id: str
    capability_map_digest: str
    retraining_trigger_bps: int
    retraining_started: bool
    bound_at: int
    authority_pubkey_hex: str
    signature_hex: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": TRANSPORT_SCHEMA_VERSION,
            "kind": "labor-plan",
            "deployment_id": self.deployment_id,
            "capability_map_digest": self.capability_map_digest,
            "retraining_trigger_bps": self.retraining_trigger_bps,
            "retraining_started": self.retraining_started,
            "bound_at": self.bound_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def bind_labor_plan(
    *,
    deployment_id: str,
    capability_map_digest: str,
    retraining_trigger_bps: int,
    retraining_started: bool = False,
    bound_at: int,
    authority_secret: bytes
) -> LaborPlan:
    """Bind one deployment's labor transition plan, authority-signed."""
    deployment_id = _require_str(deployment_id, "deployment_id")
    capability_map_digest = _check_hex64(capability_map_digest, "capability_map_digest")
    retraining_trigger_bps = _check_bps(retraining_trigger_bps, "retraining_trigger_bps")
    retraining_started = _check_bool(retraining_started, "retraining_started")
    bound_at = _check_ts(bound_at, "bound_at")
    _check_secret(authority_secret, "authority_secret")
    pubkey_hex = _ed25519_pubkey(authority_secret).hex()
    bare = LaborPlan(
        deployment_id=deployment_id,
        capability_map_digest=capability_map_digest,
        retraining_trigger_bps=retraining_trigger_bps,
        retraining_started=retraining_started,
        bound_at=bound_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,
        record_digest="",
    )
    digest = jcs_sha256_hex(bare.payload())
    return LaborPlan(
        deployment_id=bare.deployment_id,
        capability_map_digest=bare.capability_map_digest,
        retraining_trigger_bps=bare.retraining_trigger_bps,
        retraining_started=bare.retraining_started,
        bound_at=bare.bound_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=_sign(authority_secret, digest),
        record_digest=digest,
    )


class LaborPlanRegistry:
    """Labor plans keyed by deployment_id."""

    def __init__(self) -> None:
        self._plans: dict[str, LaborPlan] = {}

    def bind(self, plan: LaborPlan) -> None:
        if not _check_record(plan):
            raise TransportError(
                f"labor plan for {plan.deployment_id!r} fails verification"
            )
        self._plans[plan.deployment_id] = plan

    def get(self, deployment_id: str) -> LaborPlan | None:
        return self._plans.get(deployment_id)


def labor_transition_plan(
    plans: LaborPlanRegistry,
    *,
    deployment_id: str,
    automation_rate_bps: int,
    now: int,
) -> TransportVerdict:
    """Gate a deployment on its bound labor transition plan.

    No bound plan -> ``transport:no_labor_plan``; automation at or
    past the trigger without retraining started ->
    ``transport:retraining_overdue``. The plan binds the
    capability-mapping digest; it does not grade the training.
    """
    deployment_id = _require_str(deployment_id, "deployment_id")
    automation_rate_bps = _check_bps(automation_rate_bps, "automation_rate_bps")
    now = _check_ts(now, "now")
    plan = plans.get(deployment_id)
    if plan is None:
        return _deny(DENY_NO_LABOR_PLAN)
    if not _check_record(plan):
        return _deny(DENY_NO_LABOR_PLAN)
    if now < plan.bound_at:
        return _deny(DENY_NO_LABOR_PLAN)
    if automation_rate_bps >= plan.retraining_trigger_bps and not plan.retraining_started:
        return _deny(DENY_RETRAINING_OVERDUE)
    return _allow(plan.record_digest)


# ---------------------------------------------------------------------------
# 8. City-level incident reporting adapter (Denver-counterexample lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CityReport:
    """One city-jurisdiction incident report filing receipt."""

    report_id: str
    incident_id: str
    jurisdiction: str
    schema_version: str
    detected_at: int
    filed_at: int
    authority_pubkey_hex: str
    signature_hex: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": TRANSPORT_SCHEMA_VERSION,
            "kind": "city-report",
            "report_id": self.report_id,
            "incident_id": self.incident_id,
            "jurisdiction": self.jurisdiction,
            "schema_version": self.schema_version,
            "detected_at": self.detected_at,
            "filed_at": self.filed_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
        }


def file_city_report(
    *,
    report_id: str,
    incident_id: str,
    jurisdiction: str,
    schema_version: str,
    detected_at: int,
    filed_at: int,
    authority_secret: bytes
) -> CityReport:
    """File one city-jurisdiction incident report, authority-signed."""
    report_id = _require_str(report_id, "report_id")
    incident_id = _require_str(incident_id, "incident_id")
    jurisdiction = _require_str(jurisdiction, "jurisdiction")
    schema_version = _require_str(schema_version, "schema_version")
    detected_at = _check_ts(detected_at, "detected_at")
    filed_at = _check_ts(filed_at, "filed_at")
    if filed_at < detected_at:
        raise TransportError("filed_at must not precede detected_at")
    _check_secret(authority_secret, "authority_secret")
    pubkey_hex = _ed25519_pubkey(authority_secret).hex()
    bare = CityReport(
        report_id=report_id,
        incident_id=incident_id,
        jurisdiction=jurisdiction,
        schema_version=schema_version,
        detected_at=detected_at,
        filed_at=filed_at,
        authority_pubkey_hex=pubkey_hex,
        signature_hex="00" * 64,
        record_digest="",
    )
    digest = jcs_sha256_hex(bare.payload())
    return CityReport(
        report_id=bare.report_id,
        incident_id=bare.incident_id,
        jurisdiction=bare.jurisdiction,
        schema_version=bare.schema_version,
        detected_at=bare.detected_at,
        filed_at=bare.filed_at,
        authority_pubkey_hex=bare.authority_pubkey_hex,
        signature_hex=_sign(authority_secret, digest),
        record_digest=digest,
    )


class CityReportRegistry:
    """City reports keyed by (incident_id, jurisdiction)."""

    def __init__(self) -> None:
        self._reports: dict[tuple[str, str], CityReport] = {}

    def file(self, report: CityReport) -> None:
        if not _check_record(report):
            raise TransportError(
                f"city report {report.report_id!r} fails verification"
            )
        self._reports[(report.incident_id, report.jurisdiction)] = report

    def find(self, incident_id: str, jurisdiction: str) -> CityReport | None:
        return self._reports.get((incident_id, jurisdiction))


def incident_reporting_adapter(
    reports: CityReportRegistry,
    *,
    incident_id: str,
    jurisdiction: str,
    deadline_s: int,
    now: int,
) -> TransportVerdict:
    """Gate an incident on its city-jurisdiction report filing.

    No report for ``(incident_id, jurisdiction)`` ->
    ``transport:unreported_incident``; filed past the deadline ->
    ``transport:late_report``. Jurisdictions with no reporting
    obligation are the caller's decision — this adapter only checks
    the filing that was promised.
    """
    incident_id = _require_str(incident_id, "incident_id")
    jurisdiction = _require_str(jurisdiction, "jurisdiction")
    if isinstance(deadline_s, bool) or not isinstance(deadline_s, int) or deadline_s <= 0:
        raise TransportError("deadline_s must be a positive int")
    now = _check_ts(now, "now")
    report = reports.find(incident_id, jurisdiction)
    if report is None:
        return _deny(DENY_UNREPORTED_INCIDENT)
    if not _check_record(report):
        return _deny(DENY_UNREPORTED_INCIDENT)
    if report.filed_at > report.detected_at + deadline_s:
        return _deny(DENY_LATE_REPORT)
    return _allow(report.record_digest)


__all__ = [
    "TRANSPORT_SCHEMA_VERSION",
    "TRANSPORT_AUTHORITATIVE",
    "TRANSPORT_NON_AUTHORITATIVE",
    "RATIONALE_CONFIDENCE_MIN",
    "FLEET_STALL_COUNT_TRIP",
    "FLEET_STALL_RATIO_TRIP_BPS",
    "OBSTRUCTION_KINDS",
    "DENY_NO_RATIONALE",
    "DENY_RATIONALE_TAMPERED",
    "DENY_LOW_CONFIDENCE",
    "DENY_NO_KILL_SWITCH",
    "DENY_FLEET_TRIPPED",
    "DENY_UNREGISTERED_SUPERVISOR",
    "DENY_UNCREDENTIALED_SUPERVISOR",
    "DENY_OVERLOADED_SUPERVISOR",
    "DENY_UNREGISTERED_AGENT",
    "DENY_PRIVILEGE_VIOLATION",
    "DENY_TOOL_NOT_WHITELISTED",
    "DENY_NO_CHECKLIST",
    "DENY_UNCHECKED_SCENARIO",
    "DENY_RESPONDER_INTERFERENCE",
    "DENY_NO_LABOR_PLAN",
    "DENY_RETRAINING_OVERDUE",
    "DENY_UNREPORTED_INCIDENT",
    "DENY_LATE_REPORT",
    "TransportError",
    "TransportVerdict",
    "RouteRationale",
    "RouteRegistry",
    "FleetConfig",
    "StallEvent",
    "FleetRegistry",
    "Supervisor",
    "SupervisorRegistry",
    "TransportAgent",
    "AgentIAMRegistry",
    "ScenarioChecklist",
    "ChecklistRegistry",
    "ResponderInterference",
    "ResponderRegistry",
    "LaborPlan",
    "LaborPlanRegistry",
    "CityReport",
    "CityReportRegistry",
    "issue_route_rationale",
    "route_rationale_gate",
    "register_fleet",
    "record_stall_event",
    "fleet_circuit_breaker",
    "register_supervisor",
    "teleoperation_cap",
    "register_transport_agent",
    "agent_iam_discipline",
    "pin_scenario_checklist",
    "safety_scenario_checklist",
    "record_responder_interference",
    "first_responder_probe",
    "bind_labor_plan",
    "labor_transition_plan",
    "file_city_report",
    "incident_reporting_adapter",
]
