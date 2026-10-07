"""Origin shield: shield-PoP layering in front of origins.

CDN-shaped origin-shield bookkeeping (Cloudflare Argo / Fastly Shield /
Akamai-style fan-in collapsing): an ``OriginShield`` ledger books which
origins sit behind a shield point-of-presence layer, so edge caches fetch
through the shield instead of hammering the origin directly.

- ``shield(shield_id, origin, seq, region, tier)`` pins a shield layer in
  front of an origin. Regions are pinned to a shield-PoP vocabulary;
  tiers are pinned to ``single-pop`` / ``regional`` / ``global``.
- ``collapse(shield_id, seq, reason)`` removes the shield layer
  terminally: the origin falls back to direct edge fetching. Collapsing
  an already-collapsed shield is refused fail-closed.
- ``tier(shield_id)`` is a pure read view returning the shield's tier.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock; failed mutations consume their seq — fail-closed
ledger position), RLock-guarded, fail-closed taxonomy, stdlib-only plus
the standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins over version-pinned parts, ``audit.ndjson/1`` events, version pin
``origin-shield.v1``, schema pin ``northstar.origin-shield.v1``,
``main()`` self-check.

Honest scope: this module books *reported* shield topology. It cannot
observe real PoP routing, cannot prove a fetch actually transited the
shield, and cannot measure origin offload — a ``shielded`` record means
"the host declared a shield layer", never "traffic is shielded". Pair
with ``cdn_manager``-style edge wiring and real telemetry for
production. Raw origin hostnames never cross the audit boundary
(ids + digest pins only).
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
ORIGIN_SHIELD_VERSION = "origin-shield.v1"

#: Schema pin carried by records and audit events.
ORIGIN_SHIELD_SCHEMA = "northstar.origin-shield.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned shield-PoP region vocabulary.
REGIONS = (
    "us-east",
    "us-west",
    "eu-west",
    "eu-central",
    "ap-southeast",
    "ap-northeast",
    "sa-east",
    "me-south",
)

#: Pinned shield tier vocabulary.
TIER_SINGLE = "single-pop"
TIER_REGIONAL = "regional"
TIER_GLOBAL = "global"
TIERS = (TIER_SINGLE, TIER_REGIONAL, TIER_GLOBAL)

#: Pinned collapse-reason vocabulary.
COLLAPSE_REASONS = (
    "cost",
    "latency",
    "migration",
    "incident",
    "decommission",
)

#: Shield lifecycle states.
STATE_ACTIVE = "active"
STATE_COLLAPSED = "collapsed"


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class OriginShieldError(ValueError):
    """Base for all origin-shield structural problems and refused transitions."""


class BadShieldError(OriginShieldError):
    """Shield definition is malformed (bad id/origin/region/tier)."""


class UnknownShieldError(OriginShieldError):
    """No shield is pinned under the requested id."""


class DuplicateShieldError(OriginShieldError):
    """A shield id is already registered."""


class TerminalShieldError(OriginShieldError):
    """The shield is already collapsed; the transition is terminal."""


class BadCollapseError(OriginShieldError):
    """Collapse input is malformed (bad reason)."""


class SeqOrderError(OriginShieldError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OriginShieldError(f"{name} must be a non-empty string")
    return value.strip()


def _check_origin(value: Any) -> str:
    origin = _check_nonempty_str(value, "origin")
    if len(origin) > 253:
        raise BadShieldError("origin must be at most 253 chars")
    if any(ch.isspace() for ch in origin):
        raise BadShieldError("origin must not contain whitespace")
    if "://" in origin:
        raise BadShieldError("origin must be a bare host, not a URL")
    return origin.lower()


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([ORIGIN_SHIELD_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShieldRecord:
    """One pinned origin-shield layer (frozen)."""

    shield_id: str
    origin: str
    region: str
    tier: str
    seq: int
    digest: str
    schema: str = ORIGIN_SHIELD_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "shield", self.shield_id, self.origin, self.region,
            self.tier, self.seq,
        )


@dataclass(frozen=True)
class CollapseRecord:
    """One terminal shield-collapse event (frozen)."""

    collapse_id: str
    shield_id: str
    reason: str
    seq: int
    digest: str
    schema: str = ORIGIN_SHIELD_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "collapse", self.collapse_id, self.shield_id,
            self.reason, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_SHIELD_PINNED = "origin-shield.shield-pinned"
KIND_SHIELD_COLLAPSED = "origin-shield.shield-collapsed"
KIND_REJECTED = "origin-shield.rejected"
_KINDS = (
    KIND_SHIELD_PINNED,
    KIND_SHIELD_COLLAPSED,
    KIND_REJECTED,
)

# Origin hostnames never cross the audit boundary; ids + pins only.
_BANNED_AUDIT_KEYS = {"origin"}


def origin_shield_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the origin-shield module."""
    if kind not in _KINDS:
        raise OriginShieldError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise OriginShieldError("detail must be a mapping")
    if any(k in detail for k in _BANNED_AUDIT_KEYS):
        raise OriginShieldError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": ORIGIN_SHIELD_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class OriginShield:
    """Deterministic origin-shield topology ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._shields: Dict[str, ShieldRecord] = {}
        self._state: Dict[str, str] = {}            # shield_id -> state
        self._collapses: Dict[str, CollapseRecord] = {}
        self._collapse_ids: Dict[str, str] = {}     # shield_id -> collapse_id
        self._shield_seq = 0
        self._collapse_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _audit_locked(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit.append(
            origin_shield_audit_event(kind, detail, self._last_seq)
        )

    def _reject_locked(self, seq: int, reason: str) -> None:
        self._claim_seq(seq)
        self._audit_locked(KIND_REJECTED, {"reason": reason})

    # -- mutations ------------------------------------------------------

    def shield(
        self,
        shield_id: str,
        origin: str,
        seq: int,
        region: str = "us-east",
        tier: str = TIER_SINGLE,
    ) -> ShieldRecord:
        """Pin a shield layer in front of ``origin``."""
        with self._lock:
            shield_id = _check_nonempty_str(shield_id, "shield_id")
            try:
                origin = _check_origin(origin)
            except OriginShieldError:
                self._reject_locked(seq, "bad-origin")
                raise
            if region not in REGIONS:
                self._reject_locked(seq, "unknown-region")
                raise BadShieldError(f"unknown region: {region!r}")
            if tier not in TIERS:
                self._reject_locked(seq, "unknown-tier")
                raise BadShieldError(f"unknown tier: {tier!r}")
            if shield_id in self._shields:
                self._reject_locked(seq, "duplicate-shield")
                raise DuplicateShieldError(
                    f"shield already pinned: {shield_id!r}"
                )
            self._claim_seq(seq)
            self._shield_seq += 1
            rec = ShieldRecord(
                shield_id=shield_id,
                origin=origin,
                region=region,
                tier=tier,
                seq=seq,
                digest=_pin("shield", shield_id, origin, region, tier, seq),
            )
            self._shields[shield_id] = rec
            self._state[shield_id] = STATE_ACTIVE
            self._audit_locked(
                KIND_SHIELD_PINNED,
                {"shield_id": shield_id, "digest": rec.digest,
                 "region": region, "tier": tier},
            )
            return rec

    def collapse(self, shield_id: str, seq: int,
                 reason: str = "migration") -> CollapseRecord:
        """Terminally remove the shield layer; the origin goes direct."""
        with self._lock:
            shield_id = _check_nonempty_str(shield_id, "shield_id")
            if reason not in COLLAPSE_REASONS:
                self._reject_locked(seq, "bad-reason")
                raise BadCollapseError(f"unknown collapse reason: {reason!r}")
            if shield_id not in self._shields:
                self._reject_locked(seq, "unknown-shield")
                raise UnknownShieldError(
                    f"no shield pinned: {shield_id!r}"
                )
            if self._state[shield_id] == STATE_COLLAPSED:
                self._reject_locked(seq, "terminal-collapse")
                raise TerminalShieldError(
                    f"shield already collapsed: {shield_id!r}"
                )
            self._claim_seq(seq)
            self._collapse_seq += 1
            collapse_id = f"col-{self._collapse_seq}"
            rec = CollapseRecord(
                collapse_id=collapse_id,
                shield_id=shield_id,
                reason=reason,
                seq=seq,
                digest=_pin("collapse", collapse_id, shield_id, reason, seq),
            )
            self._collapses[collapse_id] = rec
            self._collapse_ids[shield_id] = collapse_id
            self._state[shield_id] = STATE_COLLAPSED
            self._audit_locked(
                KIND_SHIELD_COLLAPSED,
                {"shield_id": shield_id, "collapse_id": collapse_id,
                 "digest": rec.digest, "reason": reason},
            )
            return rec

    # -- views ----------------------------------------------------------

    def tier(self, shield_id: str) -> str:
        """Return the shield's pinned tier (pure view; no seq consumed)."""
        with self._lock:
            rec = self._shields.get(shield_id)
            if rec is None:
                raise UnknownShieldError(
                    f"no shield pinned: {shield_id!r}"
                )
            return rec.tier

    def status(self, shield_id: str) -> str:
        """Return ``active`` or ``collapsed`` (pure view)."""
        with self._lock:
            if shield_id not in self._shields:
                raise UnknownShieldError(
                    f"no shield pinned: {shield_id!r}"
                )
            return self._state[shield_id]

    def shield_record(self, shield_id: str) -> ShieldRecord:
        """Return the pinned shield record (pure view)."""
        with self._lock:
            rec = self._shields.get(shield_id)
            if rec is None:
                raise UnknownShieldError(
                    f"no shield pinned: {shield_id!r}"
                )
            return rec

    def collapse_record(self, collapse_id: str) -> CollapseRecord:
        """Return a collapse record (pure view)."""
        with self._lock:
            rec = self._collapses.get(collapse_id)
            if rec is None:
                raise OriginShieldError(
                    f"unknown collapse: {collapse_id!r}"
                )
            return rec

    def collapse_of(self, shield_id: str) -> CollapseRecord | None:
        """Return the collapse record for a shield, or None (pure view)."""
        with self._lock:
            cid = self._collapse_ids.get(shield_id)
            return self._collapses.get(cid) if cid else None

    def shield_ids(self) -> List[str]:
        """Sorted shield ids (pure view)."""
        with self._lock:
            return sorted(self._shields)

    def active_ids(self) -> List[str]:
        """Ids of shields still in ``active`` state (pure view)."""
        with self._lock:
            return sorted(
                sid for sid, st in self._state.items()
                if st == STATE_ACTIVE
            )

    def audit_log(self) -> List[Dict[str, Any]]:
        """The internal audit trail (pure view)."""
        with self._lock:
            return list(self._audit)


def main() -> None:
    os = OriginShield()
    rec = os.shield("sh1", "origin.example.com", 1,
                    region="eu-west", tier="regional")
    assert rec.verify()
    assert os.tier("sh1") == "regional"
    assert os.status("sh1") == "active"
    try:
        os.shield("sh1", "dup.example.com", 2)
    except DuplicateShieldError:
        pass
    else:
        raise AssertionError("duplicate shield must raise")
    col = os.collapse("sh1", 3, reason="latency")
    assert col.verify()
    assert os.status("sh1") == "collapsed"
    try:
        os.collapse("sh1", 4)
    except TerminalShieldError:
        pass
    else:
        raise AssertionError("double collapse must raise")
    # Failed mutations consumed their seqs: next must be > 4.
    try:
        os.shield("sh2", "x.example", 1)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("rewound seq must raise")
    print("origin-shield OK: shield, tier, collapse, terminal, pins, audit")


if __name__ == "__main__":
    main()
