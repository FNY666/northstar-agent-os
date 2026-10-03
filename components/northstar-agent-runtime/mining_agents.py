"""Mining governance gates (one-hundred-thirty-second batch).

Absorbs the 2026 AI-mining research thread:

* **AI-guided exploration is live but unaudited** — KoBold Metals
  (2026-09) runs AI-guided field teams in DRC Manono on GPS+tablet
  links to a California model, claiming 3x hit rates (commercial-blog
 口径, unaudited); China's 2026 mining report calls AI prospecting
  "industrialized". Governance takeaway: black-box AI exploration
  targets are NON_AUTHORITATIVE unless the targeting evidence is
  disclosed — a target is a hypothesis, not a finding.
* **Autonomous fleets at scale** — China's "10,000-unit year" for
  autonomous mining trucks (8500 shipped, Zijin Julong 60+ unmanned
  trucks at 5000m+ altitude); Volvo autonomous transport past 3M
  tonnes; Fortescue's "The Hive" coordinating 200+ autonomous
  trucks with a 90% employee AI-adoption KPI tied to bonuses.
  Governance takeaway: fleets bind an authority-signed operating
  envelope (action vocabulary + scope); the fleet can never widen it,
  and mixed human/autonomous traffic needs a declared safety
  protocol receipt.
* **Tailings-dam defense** — Brumadinho's lesson: monitoring data
  existed but was ignored; GISTM requires lifecycle monitoring.
  Governance takeaway: tailings dams require *live* multi-sensor
  monitoring receipts, and "data exists but nobody watches" is an
  auditable incident that feeds the 113th-batch incident clock.
* **FPIC pressure** — the Philippines' 2026 revised FPIC guidelines:
  indigenous communities train paralegal teams and fear streamlined
  approvals bypass FPIC; UNPFII demands financial institutions
  implement FPIC without exception. Governance takeaway: without an
  FPIC receipt from every affected community, the whole operation
  class is refused — no partial credit.
* **Labor displacement** — automation removes people from danger
  zones but displaces drivers (Fortescue: +1800 electrical jobs vs
  displaced driver jobs). Governance takeaway: displacement at or
  above the bench threshold requires a published transition /
  retraining plan disclosure (the 126th batch's labor-impact
  receipt, applied to mining).
* **Data sovereignty** — exploration data is a national asset;
  outbound transfers bind a sovereignty receipt (the 114th batch's
  sovereignty semantics).
* **"Green mining" claims** — bind to the 115th-batch env_cost
  ledger; unbound claims are NON_AUTHORITATIVE (the 130th batch's
  evidence-chain rule).

Northstar mapping:

* ``fpic_gate()`` — every affected community needs a live,
  authority-signed FPIC receipt; one missing -> whole-class
  ``mining.no_fpic``.
* ``tailings_monitor_gate()`` — dams need live multi-sensor
  monitoring receipts; stale or missing -> deny, and the watchdog
  emits an auditable incident record for the 113th-batch clock
  (the Brumadinho lesson: silence is the incident).
* ``exploration_transparency()`` — AI exploration targets without a
  disclosed evidence digest are NON_AUTHORITATIVE
  (``mining.undisclosed_targeting``).
* ``autonomous_fleet_envelope()`` — fleets bind an authority-signed
  envelope (closed action vocabulary + geographic scope); actions
  outside deny (``mining.fleet_out_of_envelope``), and the fleet can
  never widen its own envelope.
* ``mixed_fleet_rule()`` — mixed human/autonomous traffic requires a
  live mixed-traffic safety protocol receipt.
* ``labor_transition_receipt()`` — displacement at/above threshold
  requires a published transition-plan disclosure.
* ``exploration_data_sovereignty()`` — cross-border exploration-data
  transfers need a sovereignty receipt.
* ``green_mining_gate()`` — "green mining" claims bind an env_cost
  ledger receipt; unbound -> NON_AUTHORITATIVE.

Honest scoping: this module enforces *declared-mining discipline* —
the software cannot authorize what is not declared, pinned, and
fresh. It does not replace mining law, real FPIC enforcement, or
physical dam engineering. Everything is offline and deterministic;
the only clock is the ``now`` the caller injects (integer epoch
seconds). All digest comparisons use :func:`hmac.compare_digest`.
"""
from __future__ import annotations

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

from ed25519 import sign as _ed25519_sign
from ed25519 import verify as _ed25519_verify

#: Schema marker, pinned into every digest.
SCHEMA_VERSION = "northstar.mining_agents.v1"

#: Displacement threshold at/above which a transition-plan disclosure
#: becomes mandatory (bench parameter, not a legal threshold).
LABOR_DISPLACEMENT_THRESHOLD = 10

#: Freshness windows (seconds).
TAILINGS_FRESHNESS_S = 3600

#: Denial reason codes. All start with ``mining:`` for audit filtering.
DENY_NO_FPIC = "mining:no_fpic"
DENY_FPIC_EXPIRED = "mining:fpic_expired"
DENY_FPIC_REVOKED = "mining:fpic_revoked"
DENY_FPIC_DIGEST_MISMATCH = "mining:fpic_digest_mismatch"
DENY_FPIC_SIGNATURE_INVALID = "mining:fpic_signature_invalid"
DENY_NO_TAILINGS_MONITOR = "mining:no_tailings_monitor"
DENY_STALE_TAILINGS_MONITOR = "mining:stale_tailings_monitor"
DENY_TAILINGS_DIGEST_MISMATCH = "mining:tailings_digest_mismatch"
DENY_UNDISCLOSED_TARGETING = "mining:undisclosed_targeting"
DENY_TARGETING_DIGEST_MISMATCH = "mining:targeting_digest_mismatch"
DENY_NO_FLEET_ENVELOPE = "mining:no_fleet_envelope"
DENY_FLEET_OUT_OF_ENVELOPE = "mining:fleet_out_of_envelope"
DENY_ENVELOPE_WIDENED = "mining:envelope_widened"
DENY_ENVELOPE_DIGEST_MISMATCH = "mining:envelope_digest_mismatch"
DENY_NO_MIXED_TRAFFIC_PROTOCOL = "mining:no_mixed_traffic_protocol"
DENY_MIXED_PROTOCOL_EXPIRED = "mining:mixed_protocol_expired"
DENY_TRANSITION_PLAN_UNDISCLOSED = "mining:transition_plan_undisclosed"
DENY_TRANSITION_DIGEST_MISMATCH = "mining:transition_digest_mismatch"
DENY_UNAUTHORIZED_DATA_EXPORT = "mining:unauthorized_data_export"
DENY_SOVEREIGNTY_EXPIRED = "mining:sovereignty_expired"
DENY_UNSUBSTANTIATED_GREEN_CLAIM = "mining:unsubstantiated_green_claim"
DENY_GREEN_DIGEST_MISMATCH = "mining:green_digest_mismatch"
DENY_MALFORMED = "mining:malformed"
DENY_UNKNOWN_AUTHORITY = "mining:unknown_authority"

#: Classification tiers.
MINING_AUTHORITATIVE = "mining-authoritative"
MINING_NON_AUTHORITATIVE = "mining-non-authoritative"

#: Audit events.
FPIC_RECORDED_EVENT = "mining.fpic_recorded"
FPIC_DENIED_EVENT = "mining.fpic_denied"
TAILINGS_WATCHDOG_EVENT = "mining.tailings_watchdog"
FLEET_ACTION_DENIED_EVENT = "mining.fleet_action_denied"

_GENESIS = "genesis"


class MiningError(ValueError):
    """Malformed mining-governance input. Fail loud, never guess."""


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise MiningError(f"{name} must be a non-empty string")
    return value


def _require_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise MiningError(f"{name} must be an integer")
    return value


def _check_ts(value: Any, name: str) -> int:
    v = _require_int(value, name)
    if v < 0:
        raise MiningError(f"{name} must be a non-negative epoch")
    return v


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, name: str) -> str:
    if not _is_hex(value, 64):
        raise MiningError(f"{name} must be 64 lowercase hex chars")
    return value


def _check_sig(value: Any, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 64:
        raise MiningError(f"{name} must be 64 bytes")
    return value


def _check_pubkey_hex(value: Any, name: str) -> str:
    if not _is_hex(value, 64):
        raise MiningError(f"{name} must be a 64-hex-char Ed25519 public key")
    return value


class AuthorityRegistry:
    """Registered human authorities (authority_id -> Ed25519 public key)."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register(self, authority_id: str, public_key: bytes) -> None:
        _require_str(authority_id, "authority_id")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise MiningError("public_key must be 32 bytes")
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


def _sign_digest(authority_secret: bytes, digest_hex: str) -> bytes:
    if not isinstance(authority_secret, bytes) or len(authority_secret) != 32:
        raise MiningError("authority_secret must be 32 bytes")
    return _ed25519_sign(authority_secret, digest_hex.encode("utf-8"))


@dataclass(frozen=True)
class MiningVerdict:
    """A gate verdict: fail-closed, with an audit-ready reason."""

    allowed: bool
    deny_code: str | None
    classification: str
    detail: str
    evidence_digest: str | None = None


def _allow(detail: str, evidence_digest: str | None = None) -> MiningVerdict:
    return MiningVerdict(
        allowed=True,
        deny_code=None,
        classification=MINING_AUTHORITATIVE,
        detail=detail,
        evidence_digest=evidence_digest,
    )


def _deny(deny_code: str, detail: str) -> MiningVerdict:
    return MiningVerdict(
        allowed=False,
        deny_code=deny_code,
        classification=MINING_NON_AUTHORITATIVE,
        detail=detail,
        evidence_digest=None,
    )


def _check_chain(receipts: list[Any], label: str) -> None:
    for receipt in receipts:
        expected = jcs_sha256_hex(
            {
                "schema": SCHEMA_VERSION,
                "label": label,
                "body": receipt.body_digest_input(),
            }
        )
        if not hmac.compare_digest(expected, receipt.receipt_digest):
            raise MiningError(
                f"{label} receipt {receipt.receipt_id!r} digest mismatch"
            )


# ---------------------------------------------------------------------------
# FPIC receipts: free, prior and informed consent from affected communities
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FPICReceipt:
    """An FPIC consent receipt bound to a site and a community.

    No receipt for an affected community -> the whole operation class
    is refused (``mining.no_fpic``). There is no partial credit: one
    missing community denies the site.
    """

    receipt_id: str
    site_id: str
    community_id: str
    process_digest: str
    issued_by: str
    authority_pubkey_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str
    receipt_digest: str
    signature: bytes

    def body_digest_input(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "site_id": self.site_id,
            "community_id": self.community_id,
            "process_digest": self.process_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "prev_digest": self.prev_digest,
        }


def compute_fpic_digest(
    *,
    receipt_id: str,
    site_id: str,
    community_id: str,
    process_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    issued_at: int,
    expires_at: int,
    prev_digest: str,
) -> str:
    return jcs_sha256_hex(
        {
            "schema": SCHEMA_VERSION,
            "label": "fpic",
            "body": {
                "receipt_id": receipt_id,
                "site_id": site_id,
                "community_id": community_id,
                "process_digest": process_digest,
                "issued_by": issued_by,
                "authority_pubkey_hex": authority_pubkey_hex,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "prev_digest": prev_digest,
            },
        }
    )


def fpic_receipt(
    *,
    receipt_id: str,
    site_id: str,
    community_id: str,
    process_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str,
) -> FPICReceipt:
    """Issue an FPIC consent receipt for one community at one site."""
    _require_str(receipt_id, "receipt_id")
    _require_str(site_id, "site_id")
    _require_str(community_id, "community_id")
    _check_hex64(process_digest, "process_digest")
    _require_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise MiningError("expires_at must be after issued_at")
    _require_str(prev_digest, "prev_digest")
    digest = compute_fpic_digest(
        receipt_id=receipt_id,
        site_id=site_id,
        community_id=community_id,
        process_digest=process_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    signature = _sign_digest(authority_secret, digest)
    return FPICReceipt(
        receipt_id=receipt_id,
        site_id=site_id,
        community_id=community_id,
        process_digest=process_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
        receipt_digest=digest,
        signature=signature,
    )


class FPICLog:
    """Hash-chained log of FPIC receipts, with revocation."""

    def __init__(self) -> None:
        self._log: list[FPICReceipt] = []
        self._revoked: set[str] = set()

    def append(self, receipt: FPICReceipt) -> FPICReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise MiningError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "fpic")
        self._log.append(receipt)
        return receipt

    def revoke(self, receipt_id: str) -> None:
        _require_str(receipt_id, "receipt_id")
        self._revoked.add(receipt_id)

    def latest_for(self, site_id: str, community_id: str) -> FPICReceipt | None:
        for receipt in reversed(self._log):
            if receipt.site_id == site_id and receipt.community_id == community_id:
                return receipt
        return None

    def is_revoked(self, receipt_id: str) -> bool:
        return receipt_id in self._revoked


def fpic_gate(
    *,
    authorities: AuthorityRegistry,
    log: FPICLog,
    site_id: str,
    affected_communities: tuple[str, ...],
    now: int,
) -> MiningVerdict:
    """The FPIC gate: every affected community needs a live receipt.

    Fail-closed: one missing, expired, revoked, or tampered receipt
    denies the whole site class with ``mining.no_fpic`` (or the
    specific sub-code). Streamlined approvals cannot bypass this —
    that is the 2026 Philippines lesson.
    """
    _require_str(site_id, "site_id")
    if not affected_communities or not all(
        isinstance(c, str) and c for c in affected_communities
    ):
        raise MiningError("affected_communities must be a non-empty tuple of str")
    now = _check_ts(now, "now")
    for community_id in affected_communities:
        receipt = log.latest_for(site_id, community_id)
        if receipt is None:
            return _deny(
                DENY_NO_FPIC,
                f"site {site_id!r}: no FPIC receipt for community "
                f"{community_id!r} — whole operation class refused",
            )
        if log.is_revoked(receipt.receipt_id):
            return _deny(
                DENY_FPIC_REVOKED,
                f"site {site_id!r}: FPIC receipt {receipt.receipt_id!r} "
                f"for community {community_id!r} was revoked",
            )
        if not (receipt.issued_at <= now <= receipt.expires_at):
            return _deny(
                DENY_FPIC_EXPIRED,
                f"site {site_id!r}: FPIC receipt {receipt.receipt_id!r} "
                f"for community {community_id!r} not live at {now}",
            )
        expected = compute_fpic_digest(
            receipt_id=receipt.receipt_id,
            site_id=receipt.site_id,
            community_id=receipt.community_id,
            process_digest=receipt.process_digest,
            issued_by=receipt.issued_by,
            authority_pubkey_hex=receipt.authority_pubkey_hex,
            issued_at=receipt.issued_at,
            expires_at=receipt.expires_at,
            prev_digest=receipt.prev_digest,
        )
        if not hmac.compare_digest(expected, receipt.receipt_digest):
            return _deny(
                DENY_FPIC_DIGEST_MISMATCH,
                f"site {site_id!r}: FPIC receipt {receipt.receipt_id!r} "
                "digest mismatch — treated as no consent",
            )
        deny = _verify_signature(
            authorities,
            authority_id=receipt.issued_by,
            digest_hex=receipt.receipt_digest,
            signature=receipt.signature,
            deny_code=DENY_FPIC_SIGNATURE_INVALID,
        )
        if deny is not None:
            return _deny(
                deny,
                f"site {site_id!r}: FPIC receipt {receipt.receipt_id!r} "
                f"signature invalid — treated as no consent",
            )
    return _allow(
        f"site {site_id!r}: FPIC receipts live for "
        f"{len(affected_communities)} affected communities",
    )


# ---------------------------------------------------------------------------
# Tailings-dam monitoring: live multi-sensor receipts + watchdog incidents
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TailingsMonitorReceipt:
    """A live multi-sensor monitoring receipt for a tailings dam.

    The Brumadinho lesson: data that exists but nobody watches is an
    incident. A missing or stale receipt denies *and* emits an
    auditable watchdog incident for the 113th-batch incident clock.
    """

    receipt_id: str
    dam_id: str
    sensor_set_digest: str
    last_reading_at: int
    reading_digest: str
    issued_by: str
    authority_pubkey_hex: str
    issued_at: int
    prev_digest: str
    receipt_digest: str
    signature: bytes

    def body_digest_input(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "dam_id": self.dam_id,
            "sensor_set_digest": self.sensor_set_digest,
            "last_reading_at": self.last_reading_at,
            "reading_digest": self.reading_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "issued_at": self.issued_at,
            "prev_digest": self.prev_digest,
        }


def compute_tailings_digest(
    *,
    receipt_id: str,
    dam_id: str,
    sensor_set_digest: str,
    last_reading_at: int,
    reading_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    issued_at: int,
    prev_digest: str,
) -> str:
    return jcs_sha256_hex(
        {
            "schema": SCHEMA_VERSION,
            "label": "tailings-monitor",
            "body": {
                "receipt_id": receipt_id,
                "dam_id": dam_id,
                "sensor_set_digest": sensor_set_digest,
                "last_reading_at": last_reading_at,
                "reading_digest": reading_digest,
                "issued_by": issued_by,
                "authority_pubkey_hex": authority_pubkey_hex,
                "issued_at": issued_at,
                "prev_digest": prev_digest,
            },
        }
    )


def tailings_monitoring_receipt(
    *,
    receipt_id: str,
    dam_id: str,
    sensor_set_digest: str,
    last_reading_at: int,
    reading_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    prev_digest: str,
) -> TailingsMonitorReceipt:
    """Issue a tailings-dam monitoring receipt for one reading cycle."""
    _require_str(receipt_id, "receipt_id")
    _require_str(dam_id, "dam_id")
    _check_hex64(sensor_set_digest, "sensor_set_digest")
    _check_ts(last_reading_at, "last_reading_at")
    _check_hex64(reading_digest, "reading_digest")
    _require_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_ts(issued_at, "issued_at")
    _require_str(prev_digest, "prev_digest")
    digest = compute_tailings_digest(
        receipt_id=receipt_id,
        dam_id=dam_id,
        sensor_set_digest=sensor_set_digest,
        last_reading_at=last_reading_at,
        reading_digest=reading_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    signature = _sign_digest(authority_secret, digest)
    return TailingsMonitorReceipt(
        receipt_id=receipt_id,
        dam_id=dam_id,
        sensor_set_digest=sensor_set_digest,
        last_reading_at=last_reading_at,
        reading_digest=reading_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        prev_digest=prev_digest,
        receipt_digest=digest,
        signature=signature,
    )


class TailingsMonitorLog:
    """Hash-chained log of tailings monitoring receipts."""

    def __init__(self) -> None:
        self._log: list[TailingsMonitorReceipt] = []

    def append(self, receipt: TailingsMonitorReceipt) -> TailingsMonitorReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise MiningError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "tailings-monitor")
        self._log.append(receipt)
        return receipt

    def latest_for(self, dam_id: str) -> TailingsMonitorReceipt | None:
        for receipt in reversed(self._log):
            if receipt.dam_id == dam_id:
                return receipt
        return None


@dataclass(frozen=True)
class WatchdogIncident:
    """An auditable watchdog incident for the 113th-batch incident clock.

    The module does not file the incident itself (honest boundary:
    filing is a governance decision the operator makes); it produces
    the evidence record the caller files.
    """

    incident_id: str
    dam_id: str
    kind: str
    detected_at: int
    evidence_digest: str


def tailings_monitor_gate(
    *,
    authorities: AuthorityRegistry,
    log: TailingsMonitorLog,
    dam_id: str,
    now: int,
) -> tuple[MiningVerdict, WatchdogIncident | None]:
    """The tailings gate: live multi-sensor monitoring required.

    Fail-closed: no receipt -> ``mining.no_tailings_monitor``; a
    reading older than ``TAILINGS_FRESHNESS_S`` ->
    ``mining.stale_tailings_monitor``. Both cases emit a watchdog
    incident (the Brumadinho lesson: unwatched monitoring is itself
    the incident) for the caller to file on the 113th-batch clock.
    """
    _require_str(dam_id, "dam_id")
    now = _check_ts(now, "now")
    receipt = log.latest_for(dam_id)
    if receipt is None:
        incident = WatchdogIncident(
            incident_id=f"tailings-watchdog-{dam_id}-{now}",
            dam_id=dam_id,
            kind="no_monitoring",
            detected_at=now,
            evidence_digest=jcs_sha256_hex(
                {"schema": SCHEMA_VERSION, "dam_id": dam_id, "now": now}
            ),
        )
        return (
            _deny(
                DENY_NO_TAILINGS_MONITOR,
                f"dam {dam_id!r}: no tailings monitoring receipt — "
                "watchdog incident emitted",
            ),
            incident,
        )
    expected = compute_tailings_digest(
        receipt_id=receipt.receipt_id,
        dam_id=receipt.dam_id,
        sensor_set_digest=receipt.sensor_set_digest,
        last_reading_at=receipt.last_reading_at,
        reading_digest=receipt.reading_digest,
        issued_by=receipt.issued_by,
        authority_pubkey_hex=receipt.authority_pubkey_hex,
        issued_at=receipt.issued_at,
        prev_digest=receipt.prev_digest,
    )
    if not hmac.compare_digest(expected, receipt.receipt_digest):
        return (
            _deny(
                DENY_TAILINGS_DIGEST_MISMATCH,
                f"dam {dam_id!r}: monitoring receipt digest mismatch",
            ),
            None,
        )
    deny = _verify_signature(
        authorities,
        authority_id=receipt.issued_by,
        digest_hex=receipt.receipt_digest,
        signature=receipt.signature,
        deny_code=DENY_TAILINGS_DIGEST_MISMATCH,
    )
    if deny is not None:
        return (
            _deny(
                deny,
                f"dam {dam_id!r}: monitoring receipt signature invalid",
            ),
            None,
        )
    if now - receipt.last_reading_at > TAILINGS_FRESHNESS_S:
        incident = WatchdogIncident(
            incident_id=f"tailings-watchdog-{dam_id}-{now}",
            dam_id=dam_id,
            kind="stale_monitoring",
            detected_at=now,
            evidence_digest=receipt.receipt_digest,
        )
        return (
            _deny(
                DENY_STALE_TAILINGS_MONITOR,
                f"dam {dam_id!r}: last reading "
                f"{now - receipt.last_reading_at}s old — data exists but "
                "nobody watches; watchdog incident emitted",
            ),
            incident,
        )
    return (
        _allow(
            f"dam {dam_id!r}: monitoring live, last reading "
            f"{now - receipt.last_reading_at}s ago",
            receipt.receipt_digest,
        ),
        None,
    )


# ---------------------------------------------------------------------------
# Exploration transparency: AI targets are hypotheses, not findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExplorationTargetReceipt:
    """An AI exploration target with its disclosed evidence digest.

    A target without a disclosed evidence digest is NON_AUTHORITATIVE
    (``mining.undisclosed_targeting``): the model may be wrong, and an
    undisclosed model cannot even be checked.
    """

    receipt_id: str
    target_id: str
    evidence_digest: str
    model_digest: str
    issued_by: str
    authority_pubkey_hex: str
    issued_at: int
    prev_digest: str
    receipt_digest: str
    signature: bytes

    def body_digest_input(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "target_id": self.target_id,
            "evidence_digest": self.evidence_digest,
            "model_digest": self.model_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "issued_at": self.issued_at,
            "prev_digest": self.prev_digest,
        }


def compute_target_digest(
    *,
    receipt_id: str,
    target_id: str,
    evidence_digest: str,
    model_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    issued_at: int,
    prev_digest: str,
) -> str:
    return jcs_sha256_hex(
        {
            "schema": SCHEMA_VERSION,
            "label": "exploration-target",
            "body": {
                "receipt_id": receipt_id,
                "target_id": target_id,
                "evidence_digest": evidence_digest,
                "model_digest": model_digest,
                "issued_by": issued_by,
                "authority_pubkey_hex": authority_pubkey_hex,
                "issued_at": issued_at,
                "prev_digest": prev_digest,
            },
        }
    )


def exploration_target_receipt(
    *,
    receipt_id: str,
    target_id: str,
    evidence_digest: str,
    model_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    prev_digest: str,
) -> ExplorationTargetReceipt:
    """Issue an exploration-target receipt with disclosed evidence."""
    _require_str(receipt_id, "receipt_id")
    _require_str(target_id, "target_id")
    _check_hex64(evidence_digest, "evidence_digest")
    _check_hex64(model_digest, "model_digest")
    _require_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_ts(issued_at, "issued_at")
    _require_str(prev_digest, "prev_digest")
    digest = compute_target_digest(
        receipt_id=receipt_id,
        target_id=target_id,
        evidence_digest=evidence_digest,
        model_digest=model_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    signature = _sign_digest(authority_secret, digest)
    return ExplorationTargetReceipt(
        receipt_id=receipt_id,
        target_id=target_id,
        evidence_digest=evidence_digest,
        model_digest=model_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        prev_digest=prev_digest,
        receipt_digest=digest,
        signature=signature,
    )


class ExplorationLog:
    """Hash-chained log of exploration-target receipts."""

    def __init__(self) -> None:
        self._log: list[ExplorationTargetReceipt] = []

    def append(self, receipt: ExplorationTargetReceipt) -> ExplorationTargetReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise MiningError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "exploration-target")
        self._log.append(receipt)
        return receipt

    def latest_for(self, target_id: str) -> ExplorationTargetReceipt | None:
        for receipt in reversed(self._log):
            if receipt.target_id == target_id:
                return receipt
        return None


def exploration_transparency(
    *,
    authorities: AuthorityRegistry,
    log: ExplorationLog,
    target_id: str,
) -> MiningVerdict:
    """Exploration-target transparency check.

    Fail-open is never an option for a *finding*, but a target is a
    hypothesis: an undisclosed black-box target is NON_AUTHORITATIVE,
    not a hard deny — downstream decisions must not treat it as
    evidence. A tampered receipt, however, is a hard deny.
    """
    _require_str(target_id, "target_id")
    receipt = log.latest_for(target_id)
    if receipt is None:
        return _deny(
            DENY_UNDISCLOSED_TARGETING,
            f"target {target_id!r}: AI exploration target has no "
            "disclosed evidence digest — NON_AUTHORITATIVE hypothesis",
        )
    expected = compute_target_digest(
        receipt_id=receipt.receipt_id,
        target_id=receipt.target_id,
        evidence_digest=receipt.evidence_digest,
        model_digest=receipt.model_digest,
        issued_by=receipt.issued_by,
        authority_pubkey_hex=receipt.authority_pubkey_hex,
        issued_at=receipt.issued_at,
        prev_digest=receipt.prev_digest,
    )
    if not hmac.compare_digest(expected, receipt.receipt_digest):
        return _deny(
            DENY_TARGETING_DIGEST_MISMATCH,
            f"target {target_id!r}: targeting receipt digest mismatch",
        )
    deny = _verify_signature(
        authorities,
        authority_id=receipt.issued_by,
        digest_hex=receipt.receipt_digest,
        signature=receipt.signature,
        deny_code=DENY_TARGETING_DIGEST_MISMATCH,
    )
    if deny is not None:
        return _deny(
            deny,
            f"target {target_id!r}: targeting receipt signature invalid",
        )
    return _allow(
        f"target {target_id!r}: evidence digest disclosed under model "
        f"{receipt.model_digest[:16]}…",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Autonomous fleet envelopes: the fleet can never widen its own envelope
# ---------------------------------------------------------------------------

#: Closed fleet-action vocabulary marker: envelopes declare exactly
#: which action classes the fleet may perform.
FLEET_ACTIONS: tuple[str, ...] = (
    "haul",
    "dump",
    "charge",
    "park",
    "inspect",
    "emergency_stop",
)


@dataclass(frozen=True)
class FleetEnvelopeReceipt:
    """An authority-signed operating envelope for an autonomous fleet.

    Binds ``(fleet_id | action_vocabulary | geographic_scope_digest |
    issued_at | expires_at)``. Actions outside the vocabulary deny;
    any attempt by the fleet to widen the envelope denies and audits.
    """

    receipt_id: str
    fleet_id: str
    action_vocabulary: tuple[str, ...]
    geographic_scope_digest: str
    issued_by: str
    authority_pubkey_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str
    receipt_digest: str
    signature: bytes

    def body_digest_input(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "fleet_id": self.fleet_id,
            "action_vocabulary": list(self.action_vocabulary),
            "geographic_scope_digest": self.geographic_scope_digest,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "prev_digest": self.prev_digest,
        }


def compute_fleet_envelope_digest(
    *,
    receipt_id: str,
    fleet_id: str,
    action_vocabulary: tuple[str, ...],
    geographic_scope_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    issued_at: int,
    expires_at: int,
    prev_digest: str,
) -> str:
    return jcs_sha256_hex(
        {
            "schema": SCHEMA_VERSION,
            "label": "fleet-envelope",
            "body": {
                "receipt_id": receipt_id,
                "fleet_id": fleet_id,
                "action_vocabulary": list(action_vocabulary),
                "geographic_scope_digest": geographic_scope_digest,
                "issued_by": issued_by,
                "authority_pubkey_hex": authority_pubkey_hex,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "prev_digest": prev_digest,
            },
        }
    )


def fleet_envelope_receipt(
    *,
    receipt_id: str,
    fleet_id: str,
    action_vocabulary: tuple[str, ...],
    geographic_scope_digest: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str,
) -> FleetEnvelopeReceipt:
    """Issue an authority-signed operating envelope for a fleet."""
    _require_str(receipt_id, "receipt_id")
    _require_str(fleet_id, "fleet_id")
    if not action_vocabulary or not all(
        isinstance(a, str) and a in FLEET_ACTIONS for a in action_vocabulary
    ):
        raise MiningError(
            f"action_vocabulary must be a non-empty tuple from {FLEET_ACTIONS}"
        )
    _check_hex64(geographic_scope_digest, "geographic_scope_digest")
    _require_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise MiningError("expires_at must be after issued_at")
    _require_str(prev_digest, "prev_digest")
    digest = compute_fleet_envelope_digest(
        receipt_id=receipt_id,
        fleet_id=fleet_id,
        action_vocabulary=action_vocabulary,
        geographic_scope_digest=geographic_scope_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    signature = _sign_digest(authority_secret, digest)
    return FleetEnvelopeReceipt(
        receipt_id=receipt_id,
        fleet_id=fleet_id,
        action_vocabulary=action_vocabulary,
        geographic_scope_digest=geographic_scope_digest,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
        receipt_digest=digest,
        signature=signature,
    )


class FleetEnvelopeLog:
    """Hash-chained log of fleet-envelope receipts."""

    def __init__(self) -> None:
        self._log: list[FleetEnvelopeReceipt] = []

    def append(self, receipt: FleetEnvelopeReceipt) -> FleetEnvelopeReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise MiningError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "fleet-envelope")
        self._log.append(receipt)
        return receipt

    def latest_for(self, fleet_id: str) -> FleetEnvelopeReceipt | None:
        for receipt in reversed(self._log):
            if receipt.fleet_id == fleet_id:
                return receipt
        return None


def _check_envelope_live(
    authorities: AuthorityRegistry,
    receipt: FleetEnvelopeReceipt,
    now: int,
) -> str | None:
    """Return a denial code if the envelope is not live/valid, else None."""
    if not (receipt.issued_at <= now <= receipt.expires_at):
        return DENY_NO_FLEET_ENVELOPE
    expected = compute_fleet_envelope_digest(
        receipt_id=receipt.receipt_id,
        fleet_id=receipt.fleet_id,
        action_vocabulary=receipt.action_vocabulary,
        geographic_scope_digest=receipt.geographic_scope_digest,
        issued_by=receipt.issued_by,
        authority_pubkey_hex=receipt.authority_pubkey_hex,
        issued_at=receipt.issued_at,
        expires_at=receipt.expires_at,
        prev_digest=receipt.prev_digest,
    )
    if not hmac.compare_digest(expected, receipt.receipt_digest):
        return DENY_ENVELOPE_DIGEST_MISMATCH
    return _verify_signature(
        authorities,
        authority_id=receipt.issued_by,
        digest_hex=receipt.receipt_digest,
        signature=receipt.signature,
        deny_code=DENY_ENVELOPE_DIGEST_MISMATCH,
    )


def autonomous_fleet_envelope(
    *,
    authorities: AuthorityRegistry,
    log: FleetEnvelopeLog,
    fleet_id: str,
    action: str,
    requested_by: str,
    now: int,
) -> MiningVerdict:
    """Check one fleet action against the authority-signed envelope.

    Fail-closed: no live envelope -> ``mining.no_fleet_envelope``;
    an action outside the vocabulary -> ``mining.fleet_out_of_envelope``;
    a request that tries to widen the vocabulary (``requested_by`` is
    the fleet itself asking for a new action class) ->
    ``mining.envelope_widened`` — the fleet can never widen its own
    envelope (the 104th/126th batch's no-self-widening, applied to
    mining).
    """
    _require_str(fleet_id, "fleet_id")
    _require_str(action, "action")
    _require_str(requested_by, "requested_by")
    now = _check_ts(now, "now")
    receipt = log.latest_for(fleet_id)
    if receipt is None:
        return _deny(
            DENY_NO_FLEET_ENVELOPE,
            f"fleet {fleet_id!r}: no operating envelope — action refused",
        )
    deny = _check_envelope_live(authorities, receipt, now)
    if deny is not None:
        return _deny(
            deny,
            f"fleet {fleet_id!r}: envelope not live or tampered",
        )
    if action not in receipt.action_vocabulary:
        if requested_by == fleet_id:
            return _deny(
                DENY_ENVELOPE_WIDENED,
                f"fleet {fleet_id!r}: self-widening attempt for action "
                f"{action!r} — the fleet can never widen its own envelope",
            )
        return _deny(
            DENY_FLEET_OUT_OF_ENVELOPE,
            f"fleet {fleet_id!r}: action {action!r} outside envelope "
            f"vocabulary {list(receipt.action_vocabulary)}",
        )
    return _allow(
        f"fleet {fleet_id!r}: action {action!r} inside envelope",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Mixed traffic: human + autonomous fleets share the pit
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MixedTrafficReceipt:
    """A mixed-traffic safety protocol receipt for a site.

    Where human-driven and autonomous equipment share haul roads, a
    declared safety protocol (right-of-way rules, speed limits,
    communication channels, geofenced exclusion zones) must be bound
    to the site and live. Undisclosed mixing is refused.
    """

    receipt_id: str
    site_id: str
    protocol_digest: str
    protocol_version: str
    issued_by: str
    authority_pubkey_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str
    receipt_digest: str
    signature: bytes

    def body_digest_input(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "site_id": self.site_id,
            "protocol_digest": self.protocol_digest,
            "protocol_version": self.protocol_version,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "prev_digest": self.prev_digest,
        }


def compute_mixed_traffic_digest(
    *,
    receipt_id: str,
    site_id: str,
    protocol_digest: str,
    protocol_version: str,
    issued_by: str,
    authority_pubkey_hex: str,
    issued_at: int,
    expires_at: int,
    prev_digest: str,
) -> str:
    return jcs_sha256_hex(
        {
            "schema": SCHEMA_VERSION,
            "label": "mixed-traffic",
            "body": {
                "receipt_id": receipt_id,
                "site_id": site_id,
                "protocol_digest": protocol_digest,
                "protocol_version": protocol_version,
                "issued_by": issued_by,
                "authority_pubkey_hex": authority_pubkey_hex,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "prev_digest": prev_digest,
            },
        }
    )


def mixed_traffic_receipt(
    *,
    receipt_id: str,
    site_id: str,
    protocol_digest: str,
    protocol_version: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str,
) -> MixedTrafficReceipt:
    """Issue a mixed-traffic safety protocol receipt for a site."""
    _require_str(receipt_id, "receipt_id")
    _require_str(site_id, "site_id")
    _check_hex64(protocol_digest, "protocol_digest")
    _require_str(protocol_version, "protocol_version")
    _require_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise MiningError("expires_at must be after issued_at")
    _require_str(prev_digest, "prev_digest")
    digest = compute_mixed_traffic_digest(
        receipt_id=receipt_id,
        site_id=site_id,
        protocol_digest=protocol_digest,
        protocol_version=protocol_version,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    signature = _sign_digest(authority_secret, digest)
    return MixedTrafficReceipt(
        receipt_id=receipt_id,
        site_id=site_id,
        protocol_digest=protocol_digest,
        protocol_version=protocol_version,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
        receipt_digest=digest,
        signature=signature,
    )


class MixedTrafficLog:
    """Hash-chained log of mixed-traffic protocol receipts."""

    def __init__(self) -> None:
        self._log: list[MixedTrafficReceipt] = []

    def append(self, receipt: MixedTrafficReceipt) -> MixedTrafficReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise MiningError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "mixed-traffic")
        self._log.append(receipt)
        return receipt

    def latest_for(self, site_id: str) -> MixedTrafficReceipt | None:
        for receipt in reversed(self._log):
            if receipt.site_id == site_id:
                return receipt
        return None


def mixed_fleet_rule(
    *,
    authorities: AuthorityRegistry,
    log: MixedTrafficLog,
    site_id: str,
    mixed_traffic: bool,
    now: int,
) -> MiningVerdict:
    """The mixed-traffic rule: mixing requires a live protocol receipt.

    Fail-closed: a site running mixed human/autonomous traffic without
    a live protocol receipt is refused
    (``mining.no_mixed_traffic_protocol``). Pure-autonomous or
    pure-human sites are out of scope and pass with a note.
    """
    _require_str(site_id, "site_id")
    if not isinstance(mixed_traffic, bool):
        raise MiningError("mixed_traffic must be a bool")
    now = _check_ts(now, "now")
    if not mixed_traffic:
        return _allow(
            f"site {site_id!r}: no mixed traffic — rule out of scope",
        )
    receipt = log.latest_for(site_id)
    if receipt is None:
        return _deny(
            DENY_NO_MIXED_TRAFFIC_PROTOCOL,
            f"site {site_id!r}: mixed human/autonomous traffic with no "
            "declared safety protocol",
        )
    if not (receipt.issued_at <= now <= receipt.expires_at):
        return _deny(
            DENY_MIXED_PROTOCOL_EXPIRED,
            f"site {site_id!r}: mixed-traffic protocol receipt "
            f"{receipt.receipt_id!r} not live at {now}",
        )
    expected = compute_mixed_traffic_digest(
        receipt_id=receipt.receipt_id,
        site_id=receipt.site_id,
        protocol_digest=receipt.protocol_digest,
        protocol_version=receipt.protocol_version,
        issued_by=receipt.issued_by,
        authority_pubkey_hex=receipt.authority_pubkey_hex,
        issued_at=receipt.issued_at,
        expires_at=receipt.expires_at,
        prev_digest=receipt.prev_digest,
    )
    if not hmac.compare_digest(expected, receipt.receipt_digest):
        return _deny(
            DENY_NO_MIXED_TRAFFIC_PROTOCOL,
            f"site {site_id!r}: mixed-traffic receipt digest mismatch",
        )
    deny = _verify_signature(
        authorities,
        authority_id=receipt.issued_by,
        digest_hex=receipt.receipt_digest,
        signature=receipt.signature,
        deny_code=DENY_NO_MIXED_TRAFFIC_PROTOCOL,
    )
    if deny is not None:
        return _deny(
            deny,
            f"site {site_id!r}: mixed-traffic receipt signature invalid",
        )
    return _allow(
        f"site {site_id!r}: mixed traffic under protocol "
        f"{receipt.protocol_version!r}",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Labor transition: automation displaces drivers — say so, with a plan
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LaborTransitionReceipt:
    """A published transition/retraining plan for displaced workers.

    Automation that displaces drivers at or above
    ``LABOR_DISPLACEMENT_THRESHOLD`` must carry a published plan
    (retraining digest and/or labor-agreement digest). The Fortescue
    lesson: new electrical jobs do not cancel the disclosure duty
    for displaced driver jobs.
    """

    receipt_id: str
    site_id: str
    displaced_roles: tuple[str, ...]
    displaced_count: int
    plan_digest: str
    published_at: int
    issued_by: str
    authority_pubkey_hex: str
    prev_digest: str
    receipt_digest: str
    signature: bytes

    def body_digest_input(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "site_id": self.site_id,
            "displaced_roles": list(self.displaced_roles),
            "displaced_count": self.displaced_count,
            "plan_digest": self.plan_digest,
            "published_at": self.published_at,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


def compute_transition_digest(
    *,
    receipt_id: str,
    site_id: str,
    displaced_roles: tuple[str, ...],
    displaced_count: int,
    plan_digest: str,
    published_at: int,
    issued_by: str,
    authority_pubkey_hex: str,
    prev_digest: str,
) -> str:
    return jcs_sha256_hex(
        {
            "schema": SCHEMA_VERSION,
            "label": "labor-transition",
            "body": {
                "receipt_id": receipt_id,
                "site_id": site_id,
                "displaced_roles": list(displaced_roles),
                "displaced_count": displaced_count,
                "plan_digest": plan_digest,
                "published_at": published_at,
                "issued_by": issued_by,
                "authority_pubkey_hex": authority_pubkey_hex,
                "prev_digest": prev_digest,
            },
        }
    )


def labor_transition_receipt(
    *,
    receipt_id: str,
    site_id: str,
    displaced_roles: tuple[str, ...],
    displaced_count: int,
    plan_digest: str,
    published_at: int,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    prev_digest: str,
) -> LaborTransitionReceipt:
    """Publish a labor-transition plan for displaced workers."""
    _require_str(receipt_id, "receipt_id")
    _require_str(site_id, "site_id")
    if not displaced_roles or not all(
        isinstance(r, str) and r for r in displaced_roles
    ):
        raise MiningError("displaced_roles must be a non-empty tuple of str")
    displaced_count = _require_int(displaced_count, "displaced_count")
    if displaced_count < 0:
        raise MiningError("displaced_count must be non-negative")
    _check_hex64(plan_digest, "plan_digest")
    _check_ts(published_at, "published_at")
    _require_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _require_str(prev_digest, "prev_digest")
    digest = compute_transition_digest(
        receipt_id=receipt_id,
        site_id=site_id,
        displaced_roles=displaced_roles,
        displaced_count=displaced_count,
        plan_digest=plan_digest,
        published_at=published_at,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        prev_digest=prev_digest,
    )
    signature = _sign_digest(authority_secret, digest)
    return LaborTransitionReceipt(
        receipt_id=receipt_id,
        site_id=site_id,
        displaced_roles=displaced_roles,
        displaced_count=displaced_count,
        plan_digest=plan_digest,
        published_at=published_at,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        prev_digest=prev_digest,
        receipt_digest=digest,
        signature=signature,
    )


class LaborTransitionLog:
    """Hash-chained log of labor-transition receipts."""

    def __init__(self) -> None:
        self._log: list[LaborTransitionReceipt] = []

    def append(self, receipt: LaborTransitionReceipt) -> LaborTransitionReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise MiningError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "labor-transition")
        self._log.append(receipt)
        return receipt

    def latest_for(self, site_id: str) -> LaborTransitionReceipt | None:
        for receipt in reversed(self._log):
            if receipt.site_id == site_id:
                return receipt
        return None


def check_labor_transition(
    *,
    authorities: AuthorityRegistry,
    log: LaborTransitionLog,
    site_id: str,
    displaced_count: int,
    now: int,
) -> MiningVerdict:
    """The labor-transition check: displace at scale -> publish a plan.

    Fail-closed: displacement at or above ``LABOR_DISPLACEMENT_THRESHOLD``
    with no published transition plan ->
    ``mining.transition_plan_undisclosed``. Below the threshold the
    check is out of scope and passes with a note.
    """
    _require_str(site_id, "site_id")
    displaced_count = _require_int(displaced_count, "displaced_count")
    if displaced_count < 0:
        raise MiningError("displaced_count must be non-negative")
    now = _check_ts(now, "now")
    if displaced_count < LABOR_DISPLACEMENT_THRESHOLD:
        return _allow(
            f"site {site_id!r}: {displaced_count} displaced workers below "
            "disclosure threshold — check out of scope",
        )
    receipt = log.latest_for(site_id)
    if receipt is None:
        return _deny(
            DENY_TRANSITION_PLAN_UNDISCLOSED,
            f"site {site_id!r}: {displaced_count} workers displaced with no "
            "published transition plan",
        )
    expected = compute_transition_digest(
        receipt_id=receipt.receipt_id,
        site_id=receipt.site_id,
        displaced_roles=receipt.displaced_roles,
        displaced_count=receipt.displaced_count,
        plan_digest=receipt.plan_digest,
        published_at=receipt.published_at,
        issued_by=receipt.issued_by,
        authority_pubkey_hex=receipt.authority_pubkey_hex,
        prev_digest=receipt.prev_digest,
    )
    if not hmac.compare_digest(expected, receipt.receipt_digest):
        return _deny(
            DENY_TRANSITION_DIGEST_MISMATCH,
            f"site {site_id!r}: transition receipt digest mismatch",
        )
    deny = _verify_signature(
        authorities,
        authority_id=receipt.issued_by,
        digest_hex=receipt.receipt_digest,
        signature=receipt.signature,
        deny_code=DENY_TRANSITION_DIGEST_MISMATCH,
    )
    if deny is not None:
        return _deny(
            deny,
            f"site {site_id!r}: transition receipt signature invalid",
        )
    return _allow(
        f"site {site_id!r}: transition plan published for "
        f"{receipt.displaced_count} displaced workers",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Exploration data sovereignty: exploration data is a national asset
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataSovereigntyReceipt:
    """A sovereignty receipt for cross-border exploration-data transfer.

    Exploration data leaving the host country must bind
    ``(dataset_id | host_country | export_purpose | authorized_by)``.
    Unbound export is refused — the KoBold lesson: AI prospecting data
    is the asset, and the asset's movement is governed.
    """

    receipt_id: str
    dataset_id: str
    host_country: str
    export_purpose: str
    authorized_by: str
    authority_pubkey_hex: str
    issued_at: int
    expires_at: int
    prev_digest: str
    receipt_digest: str
    signature: bytes

    def body_digest_input(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "dataset_id": self.dataset_id,
            "host_country": self.host_country,
            "export_purpose": self.export_purpose,
            "authorized_by": self.authorized_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "prev_digest": self.prev_digest,
        }


def compute_sovereignty_digest(
    *,
    receipt_id: str,
    dataset_id: str,
    host_country: str,
    export_purpose: str,
    authorized_by: str,
    authority_pubkey_hex: str,
    issued_at: int,
    expires_at: int,
    prev_digest: str,
) -> str:
    return jcs_sha256_hex(
        {
            "schema": SCHEMA_VERSION,
            "label": "data-sovereignty",
            "body": {
                "receipt_id": receipt_id,
                "dataset_id": dataset_id,
                "host_country": host_country,
                "export_purpose": export_purpose,
                "authorized_by": authorized_by,
                "authority_pubkey_hex": authority_pubkey_hex,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "prev_digest": prev_digest,
            },
        }
    )


def sovereignty_receipt(
    *,
    receipt_id: str,
    dataset_id: str,
    host_country: str,
    export_purpose: str,
    authorized_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    expires_at: int,
    prev_digest: str,
) -> DataSovereigntyReceipt:
    """Issue a data-sovereignty receipt for a cross-border transfer."""
    _require_str(receipt_id, "receipt_id")
    _require_str(dataset_id, "dataset_id")
    _require_str(host_country, "host_country")
    _require_str(export_purpose, "export_purpose")
    _require_str(authorized_by, "authorized_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise MiningError("expires_at must be after issued_at")
    _require_str(prev_digest, "prev_digest")
    digest = compute_sovereignty_digest(
        receipt_id=receipt_id,
        dataset_id=dataset_id,
        host_country=host_country,
        export_purpose=export_purpose,
        authorized_by=authorized_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    signature = _sign_digest(authority_secret, digest)
    return DataSovereigntyReceipt(
        receipt_id=receipt_id,
        dataset_id=dataset_id,
        host_country=host_country,
        export_purpose=export_purpose,
        authorized_by=authorized_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
        receipt_digest=digest,
        signature=signature,
    )


class DataSovereigntyLog:
    """Hash-chained log of data-sovereignty receipts."""

    def __init__(self) -> None:
        self._log: list[DataSovereigntyReceipt] = []

    def append(self, receipt: DataSovereigntyReceipt) -> DataSovereigntyReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise MiningError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "data-sovereignty")
        self._log.append(receipt)
        return receipt

    def latest_for(self, dataset_id: str) -> DataSovereigntyReceipt | None:
        for receipt in reversed(self._log):
            if receipt.dataset_id == dataset_id:
                return receipt
        return None


def check_data_export(
    *,
    authorities: AuthorityRegistry,
    log: DataSovereigntyLog,
    dataset_id: str,
    destination_country: str,
    host_country: str,
    now: int,
) -> MiningVerdict:
    """The data-sovereignty check for exploration-data transfers.

    Fail-closed: cross-border export without a live sovereignty
    receipt -> ``mining.unauthorized_data_export``. Domestic use
    (destination == host) is out of scope and passes with a note.
    """
    _require_str(dataset_id, "dataset_id")
    _require_str(destination_country, "destination_country")
    _require_str(host_country, "host_country")
    now = _check_ts(now, "now")
    if destination_country == host_country:
        return _allow(
            f"dataset {dataset_id!r}: domestic use in {host_country!r} — "
            "sovereignty check out of scope",
        )
    receipt = log.latest_for(dataset_id)
    if receipt is None:
        return _deny(
            DENY_UNAUTHORIZED_DATA_EXPORT,
            f"dataset {dataset_id!r}: cross-border export to "
            f"{destination_country!r} with no sovereignty receipt",
        )
    if receipt.host_country != host_country:
        return _deny(
            DENY_UNAUTHORIZED_DATA_EXPORT,
            f"dataset {dataset_id!r}: sovereignty receipt covers "
            f"{receipt.host_country!r}, not {host_country!r}",
        )
    if not (receipt.issued_at <= now <= receipt.expires_at):
        return _deny(
            DENY_SOVEREIGNTY_EXPIRED,
            f"dataset {dataset_id!r}: sovereignty receipt "
            f"{receipt.receipt_id!r} not live at {now}",
        )
    expected = compute_sovereignty_digest(
        receipt_id=receipt.receipt_id,
        dataset_id=receipt.dataset_id,
        host_country=receipt.host_country,
        export_purpose=receipt.export_purpose,
        authorized_by=receipt.authorized_by,
        authority_pubkey_hex=receipt.authority_pubkey_hex,
        issued_at=receipt.issued_at,
        expires_at=receipt.expires_at,
        prev_digest=receipt.prev_digest,
    )
    if not hmac.compare_digest(expected, receipt.receipt_digest):
        return _deny(
            DENY_UNAUTHORIZED_DATA_EXPORT,
            f"dataset {dataset_id!r}: sovereignty receipt digest mismatch",
        )
    deny = _verify_signature(
        authorities,
        authority_id=receipt.authorized_by,
        digest_hex=receipt.receipt_digest,
        signature=receipt.signature,
        deny_code=DENY_UNAUTHORIZED_DATA_EXPORT,
    )
    if deny is not None:
        return _deny(
            deny,
            f"dataset {dataset_id!r}: sovereignty receipt signature invalid",
        )
    return _allow(
        f"dataset {dataset_id!r}: export to {destination_country!r} "
        f"authorized for purpose {receipt.export_purpose!r}",
        receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# Green-mining claims: bind the env_cost ledger or stay quiet
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GreenClaimReceipt:
    """A "green mining" claim bound to the 115th-batch env_cost ledger.

    A marketing claim carrying environmental keywords with no bound
    ledger receipt is NON_AUTHORITATIVE
    (``mining.unsubstantiated_green_claim``) — the 130th batch's
    evidence-chain rule, applied to mining.
    """

    receipt_id: str
    claim_id: str
    ledger_digest: str
    measured_scope: str
    issued_by: str
    authority_pubkey_hex: str
    issued_at: int
    prev_digest: str
    receipt_digest: str
    signature: bytes

    def body_digest_input(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "ledger_digest": self.ledger_digest,
            "measured_scope": self.measured_scope,
            "issued_by": self.issued_by,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "issued_at": self.issued_at,
            "prev_digest": self.prev_digest,
        }


def compute_green_claim_digest(
    *,
    receipt_id: str,
    claim_id: str,
    ledger_digest: str,
    measured_scope: str,
    issued_by: str,
    authority_pubkey_hex: str,
    issued_at: int,
    prev_digest: str,
) -> str:
    return jcs_sha256_hex(
        {
            "schema": SCHEMA_VERSION,
            "label": "green-claim",
            "body": {
                "receipt_id": receipt_id,
                "claim_id": claim_id,
                "ledger_digest": ledger_digest,
                "measured_scope": measured_scope,
                "issued_by": issued_by,
                "authority_pubkey_hex": authority_pubkey_hex,
                "issued_at": issued_at,
                "prev_digest": prev_digest,
            },
        }
    )


def green_claim_receipt(
    *,
    receipt_id: str,
    claim_id: str,
    ledger_digest: str,
    measured_scope: str,
    issued_by: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    issued_at: int,
    prev_digest: str,
) -> GreenClaimReceipt:
    """Issue a green-mining claim receipt bound to the env_cost ledger."""
    _require_str(receipt_id, "receipt_id")
    _require_str(claim_id, "claim_id")
    _check_hex64(ledger_digest, "ledger_digest")
    _require_str(measured_scope, "measured_scope")
    _require_str(issued_by, "issued_by")
    _check_pubkey_hex(authority_pubkey_hex, "authority_pubkey_hex")
    _check_ts(issued_at, "issued_at")
    _require_str(prev_digest, "prev_digest")
    digest = compute_green_claim_digest(
        receipt_id=receipt_id,
        claim_id=claim_id,
        ledger_digest=ledger_digest,
        measured_scope=measured_scope,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        prev_digest=prev_digest,
    )
    signature = _sign_digest(authority_secret, digest)
    return GreenClaimReceipt(
        receipt_id=receipt_id,
        claim_id=claim_id,
        ledger_digest=ledger_digest,
        measured_scope=measured_scope,
        issued_by=issued_by,
        authority_pubkey_hex=authority_pubkey_hex,
        issued_at=issued_at,
        prev_digest=prev_digest,
        receipt_digest=digest,
        signature=signature,
    )


class GreenClaimLog:
    """Hash-chained log of green-mining claim receipts."""

    def __init__(self) -> None:
        self._log: list[GreenClaimReceipt] = []

    def append(self, receipt: GreenClaimReceipt) -> GreenClaimReceipt:
        expected_prev = self._log[-1].receipt_digest if self._log else _GENESIS
        if not hmac.compare_digest(receipt.prev_digest, expected_prev):
            raise MiningError(
                f"receipt {receipt.receipt_id!r} does not chain to the log tip"
            )
        _check_chain([receipt], "green-claim")
        self._log.append(receipt)
        return receipt

    def latest_for(self, claim_id: str) -> GreenClaimReceipt | None:
        for receipt in reversed(self._log):
            if receipt.claim_id == claim_id:
                return receipt
        return None


def green_mining_gate(
    *,
    authorities: AuthorityRegistry,
    log: GreenClaimLog,
    claim_id: str,
    ledger_digest: str | None,
) -> MiningVerdict:
    """The green-mining gate: environmental claims need bound ledgers.

    A "green mining" claim with no bound env_cost ledger receipt is
    NON_AUTHORITATIVE (``mining.unsubstantiated_green_claim``). A
    receipt whose ledger digest does not match the claimed ledger is
    a hard deny (``mining.green_digest_mismatch``).
    """
    _require_str(claim_id, "claim_id")
    receipt = log.latest_for(claim_id)
    if receipt is None:
        return _deny(
            DENY_UNSUBSTANTIATED_GREEN_CLAIM,
            f"claim {claim_id!r}: 'green mining' claim with no bound "
            "env_cost ledger receipt — NON_AUTHORITATIVE",
        )
    if ledger_digest is not None:
        _check_hex64(ledger_digest, "ledger_digest")
        if not hmac.compare_digest(ledger_digest, receipt.ledger_digest):
            return _deny(
                DENY_GREEN_DIGEST_MISMATCH,
                f"claim {claim_id!r}: bound ledger digest does not match "
                "the claimed ledger",
            )
    deny = _verify_signature(
        authorities,
        authority_id=receipt.issued_by,
        digest_hex=receipt.receipt_digest,
        signature=receipt.signature,
        deny_code=DENY_GREEN_DIGEST_MISMATCH,
    )
    if deny is not None:
        return _deny(
            deny,
            f"claim {claim_id!r}: green-claim receipt signature invalid",
        )
    return _allow(
        f"claim {claim_id!r}: green-mining claim bound to env_cost ledger "
        f"(scope {receipt.measured_scope!r})",
        receipt.receipt_digest,
    )


__all__ = [
    "SCHEMA_VERSION",
    "LABOR_DISPLACEMENT_THRESHOLD",
    "TAILINGS_FRESHNESS_S",
    "MiningError",
    "AuthorityRegistry",
    "MiningVerdict",
    "MINING_AUTHORITATIVE",
    "MINING_NON_AUTHORITATIVE",
    "FPICReceipt",
    "fpic_receipt",
    "FPICLog",
    "fpic_gate",
    "TailingsMonitorReceipt",
    "tailings_monitoring_receipt",
    "TailingsMonitorLog",
    "WatchdogIncident",
    "tailings_monitor_gate",
    "ExplorationTargetReceipt",
    "exploration_target_receipt",
    "ExplorationLog",
    "exploration_transparency",
    "FLEET_ACTIONS",
    "FleetEnvelopeReceipt",
    "fleet_envelope_receipt",
    "FleetEnvelopeLog",
    "autonomous_fleet_envelope",
    "MixedTrafficReceipt",
    "mixed_traffic_receipt",
    "MixedTrafficLog",
    "mixed_fleet_rule",
    "LaborTransitionReceipt",
    "labor_transition_receipt",
    "LaborTransitionLog",
    "check_labor_transition",
    "DataSovereigntyReceipt",
    "sovereignty_receipt",
    "DataSovereigntyLog",
    "check_data_export",
    "GreenClaimReceipt",
    "green_claim_receipt",
    "GreenClaimLog",
    "green_mining_gate",
]
