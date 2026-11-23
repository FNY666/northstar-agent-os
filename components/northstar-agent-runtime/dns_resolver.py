"""DNS record bookkeeping with TTL expiry — a deterministic resolver ledger.

A ``DNSResolver`` mirrors the *bookkeeping half* of a caching DNS resolver:
``add_record(name, rtype, value, ttl_s, seq)`` registers a zone record,
``resolve(name, rtype, now_s, seq)`` answers queries from those records
(including CNAME chain following with loop detection), and ``ttl(name, rtype,
now_s)`` reports the remaining TTL of a cached record.

TTL expiry is driven entirely by caller-supplied logical seconds
(``now_s``) — never the wall clock — so identical call sequences replay
byte-identically in tests and audit.

House style: no wall-clock, stdlib-only, deterministic, frozen records,
fail-closed validation, version/schema pins, ``main()`` self-check.

Honest scope: pure bookkeeping over host-reported records. This module
cannot observe the wire, cannot prove a record is globally true, and does
not implement recursion against the public DNS (no network). A positive
answer means "this ledger pinned that answer", never "the internet agrees".
Host-reported ``now_s`` regression (time moving backwards) is refused
fail-closed so a lying clock cannot resurrect expired records.

Version pin: dns-resolver.v1
Schema pin: northstar.dns-resolver.v1
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

DNS_RESOLVER_VERSION = "dns-resolver.v1"
SCHEMA_PIN = "northstar.dns-resolver.v1"

# Maximum CNAME hops followed before giving up (RFC 1034 does not fix one;
# 10 matches common resolver caps).
MAX_CNAME_HOPS = 10

SUPPORTED_RTYPES = frozenset(
    {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "CAA", "SOA"}
)

_NAME_RE = re.compile(r"^(?=.{1,253}\.?$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*$", re.IGNORECASE)


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class DNSResolverError(Exception):
    """Base error for dns_resolver."""


class UnknownNameError(DNSResolverError):
    """No records exist for this name."""


class RecordTypeError(DNSResolverError):
    """No records of this type exist for the name."""


class UnknownRtypeError(DNSResolverError):
    """Unsupported record type."""


class DuplicateRecordError(DNSResolverError):
    """An identical record is already registered."""


class CNAMELoopError(DNSResolverError):
    """CNAME chain loops or exceeds the hop limit."""


class ClockRegressionError(DNSResolverError):
    """Caller-supplied now_s moved backwards — refused fail-closed."""


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

def _require_str(name: str, value) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    return value


def _require_int(name: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    return value


def _require_nonneg_int(name: str, value) -> int:
    v = _require_int(name, value)
    if v < 0:
        raise ValueError(f"{name} must be non-negative")
    return v


def _require_positive_int(name: str, value) -> int:
    v = _require_int(name, value)
    if v <= 0:
        raise ValueError(f"{name} must be positive")
    return v


def _check_name(name: str) -> str:
    _require_str("name", name)
    normalized = name.rstrip(".").lower()
    if not normalized:
        raise ValueError("name must be non-empty")
    if len(normalized) > 253:
        raise ValueError("name too long (>253 chars)")
    if _NAME_RE.match(normalized + ".") is None:
        raise ValueError(f"malformed DNS name: {name!r}")
    return normalized


def _check_rtype(rtype: str) -> str:
    _require_str("rtype", rtype)
    upper = rtype.upper()
    if upper not in SUPPORTED_RTYPES:
        raise UnknownRtypeError(f"unsupported rtype: {rtype!r}")
    return upper


def _digest(body: str) -> str:
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Frozen records
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class DNSRecord:
    """One pinned zone record (frozen)."""

    name: str       # normalized (lowercase, no trailing dot)
    rtype: str      # uppercased, member of SUPPORTED_RTYPES
    value: str      # rdata as text (e.g. "93.184.216.34", "alias.example.com")
    ttl_s: int      # original TTL in seconds
    inserted_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_name(self.name)
        _check_rtype(self.rtype)
        _require_str("value", self.value)
        if len(self.value) > 4096:
            raise ValueError("value too long (>4096 chars)")
        _require_positive_int("ttl_s", self.ttl_s)
        _require_nonneg_int("inserted_seq", self.inserted_seq)


@dataclass(frozen=True)
class CachedRecord:
    """A DNSRecord plus its ledger state (frozen)."""

    record: DNSRecord
    digest: str           # sha256: pin over (name, rtype, value, ttl_s, inserted_seq)
    expires_at_s: int     # now_s + ttl_s at insertion
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.record, DNSRecord):
            raise TypeError("record must be a DNSRecord")
        _require_str("digest", self.digest)
        _require_nonneg_int("expires_at_s", self.expires_at_s)


@dataclass(frozen=True)
class ResolveResult:
    """One query answer (frozen)."""

    name: str                      # queried name (normalized)
    rtype: str                     # queried rtype
    records: Tuple[DNSRecord, ...]  # live answers, in insertion order
    cname_chain: Tuple[str, ...]    # CNAME hops followed ("" when direct)
    min_ttl_remaining_s: int       # lowest remaining TTL across answers
    query_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_name(self.name)
        _check_rtype(self.rtype)
        if not isinstance(self.records, tuple):
            raise TypeError("records must be a tuple")
        for r in self.records:
            if not isinstance(r, DNSRecord):
                raise TypeError("records must hold DNSRecords")
        if not isinstance(self.cname_chain, tuple):
            raise TypeError("cname_chain must be a tuple")
        _require_nonneg_int("min_ttl_remaining_s", self.min_ttl_remaining_s)
        _require_nonneg_int("query_seq", self.query_seq)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "rtype": self.rtype,
            "records": [
                {
                    "name": r.name,
                    "rtype": r.rtype,
                    "value": r.value,
                    "ttl_s": r.ttl_s,
                }
                for r in self.records
            ],
            "cname_chain": list(self.cname_chain),
            "min_ttl_remaining_s": self.min_ttl_remaining_s,
            "query_seq": self.query_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TTLReport:
    """Remaining-TTL report for (name, rtype) (frozen)."""

    name: str
    rtype: str
    min_remaining_s: int  # lowest remaining TTL among live records
    live_count: int
    now_s: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_name(self.name)
        _check_rtype(self.rtype)
        _require_nonneg_int("min_remaining_s", self.min_remaining_s)
        _require_nonneg_int("live_count", self.live_count)
        _require_nonneg_int("now_s", self.now_s)


@dataclass(frozen=True)
class ExpireReport:
    """Report of one expiry sweep (frozen)."""

    now_s: int
    dropped: int
    remaining: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_nonneg_int("now_s", self.now_s)
        _require_nonneg_int("dropped", self.dropped)
        _require_nonneg_int("remaining", self.remaining)


# --------------------------------------------------------------------------
# Resolver
# --------------------------------------------------------------------------

class DNSResolver:
    """In-memory DNS record + TTL ledger (RLock-guarded, deterministic)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # (name, rtype) -> list[CachedRecord] in insertion order
        self._zone: Dict[Tuple[str, str], List[CachedRecord]] = {}
        # (name, rtype) -> list[CachedRecord]; CNAME targets live in the same zone
        self._highest_now_s = -1  # monotonic caller clock guard

    # -- internal ------------------------------------------------------

    def _check_clock(self, now_s: int) -> None:
        _require_nonneg_int("now_s", now_s)
        if now_s < self._highest_now_s:
            raise ClockRegressionError(
                f"now_s moved backwards ({now_s} < {self._highest_now_s})"
            )
        if now_s > self._highest_now_s:
            self._highest_now_s = now_s

    def _live(self, key: Tuple[str, str], now_s: int) -> List[CachedRecord]:
        return [c for c in self._zone.get(key, []) if c.expires_at_s > now_s]

    def _name_known(self, name: str, now_s: int) -> bool:
        """True if any live record exists under this name (any rtype)."""
        for (n, _), cached in self._zone.items():
            if n == name and any(c.expires_at_s > now_s for c in cached):
                return True
        return False

    @staticmethod
    def _pin(name: str, rtype: str, value: str, ttl_s: int, seq: int) -> str:
        body = "|".join((name, rtype, value, str(ttl_s), str(seq)))
        return _digest(body)

    # -- mutation ------------------------------------------------------

    def add_record(self, name: str, rtype: str, value: str,
                   ttl_s: int, now_s: int, seq: int) -> CachedRecord:
        """Register one record; returns the frozen CachedRecord."""
        norm = _check_name(name)
        rt = _check_rtype(rtype)
        _require_str("value", value)
        if len(value) > 4096:
            raise ValueError("value too long (>4096 chars)")
        _require_positive_int("ttl_s", ttl_s)
        _require_nonneg_int("seq", seq)
        with self._lock:
            self._check_clock(now_s)
            key = (norm, rt)
            for existing in self._zone.get(key, []):
                if existing.record.value == value and existing.record.ttl_s == ttl_s:
                    raise DuplicateRecordError(
                        f"identical record already registered: {norm} {rt}"
                    )
            record = DNSRecord(
                name=norm, rtype=rt, value=value, ttl_s=ttl_s, inserted_seq=seq
            )
            cached = CachedRecord(
                record=record,
                digest=self._pin(norm, rt, value, ttl_s, seq),
                expires_at_s=now_s + ttl_s,
            )
            self._zone.setdefault(key, []).append(cached)
            return cached

    def remove(self, name: str, rtype: str, seq: int) -> int:
        """Remove all records for (name, rtype); returns count removed."""
        norm = _check_name(name)
        rt = _check_rtype(rtype)
        _require_nonneg_int("seq", seq)
        with self._lock:
            key = (norm, rt)
            removed = len(self._zone.pop(key, []))
            return removed

    def expire(self, now_s: int, seq: int) -> ExpireReport:
        """Drop every expired record; returns a frozen report."""
        _require_nonneg_int("seq", seq)
        with self._lock:
            self._check_clock(now_s)
            dropped = 0
            remaining = 0
            for key in list(self._zone.keys()):
                live = [c for c in self._zone[key] if c.expires_at_s > now_s]
                dropped += len(self._zone[key]) - len(live)
                if live:
                    self._zone[key] = live
                    remaining += len(live)
                else:
                    del self._zone[key]
            return ExpireReport(now_s=now_s, dropped=dropped, remaining=remaining)

    # -- reads ---------------------------------------------------------

    def resolve(self, name: str, rtype: str, now_s: int, seq: int) -> ResolveResult:
        """Answer a query; follows CNAME chains, expires by now_s.

        Raises UnknownNameError (nothing under this name),
        RecordTypeError (no records of this type, and no CNAME either),
        CNAMELoopError (chain loops or exceeds MAX_CNAME_HOPS).
        """
        norm = _check_name(name)
        rt = _check_rtype(rtype)
        _require_nonneg_int("seq", seq)
        with self._lock:
            self._check_clock(now_s)
            target = norm
            chain: List[str] = []
            seen = {norm}
            for _ in range(MAX_CNAME_HOPS + 1):
                key = (target, rt)
                live = self._live(key, now_s)
                if live:
                    remaining = min(c.expires_at_s - now_s for c in live)
                    return ResolveResult(
                        name=norm,
                        rtype=rt,
                        records=tuple(c.record for c in live),
                        cname_chain=tuple(chain),
                        min_ttl_remaining_s=remaining,
                        query_seq=seq,
                    )
                # no direct records: look for a CNAME
                cname_live = self._live((target, "CNAME"), now_s)
                if not cname_live:
                    if target == norm and not self._name_known(norm, now_s):
                        raise UnknownNameError(f"no records for {norm!r}")
                    if target == norm:
                        raise RecordTypeError(
                            f"no {rt} records for {norm!r}"
                        )
                    raise RecordTypeError(
                        f"no {rt} records for {norm!r} (via {target!r})"
                    )
                next_target = _check_name(cname_live[0].record.value)
                chain.append(next_target)
                if next_target in seen:
                    raise CNAMELoopError(f"CNAME loop at {next_target!r}")
                seen.add(next_target)
                target = next_target
            raise CNAMELoopError(f"CNAME chain exceeded {MAX_CNAME_HOPS} hops")

    def ttl(self, name: str, rtype: str, now_s: int) -> TTLReport:
        """Report remaining TTL for live (name, rtype) records."""
        norm = _check_name(name)
        rt = _check_rtype(rtype)
        with self._lock:
            self._check_clock(now_s)
            live = self._live((norm, rt), now_s)
            if not live:
                raise RecordTypeError(f"no live {rt} records for {norm!r}")
            remaining = min(c.expires_at_s - now_s for c in live)
            return TTLReport(
                name=norm,
                rtype=rt,
                min_remaining_s=remaining,
                live_count=len(live),
                now_s=now_s,
            )

    # -- views ---------------------------------------------------------

    def names(self) -> Tuple[str, ...]:
        """Sorted names present in the zone."""
        with self._lock:
            return tuple(sorted({name for (name, _) in self._zone.keys()}))

    def record_count(self) -> int:
        """Total registered records (including expired-but-not-swept)."""
        with self._lock:
            return sum(len(v) for v in self._zone.values())


# --------------------------------------------------------------------------
# Audit event shaper
# --------------------------------------------------------------------------

_AUDIT_KINDS = frozenset(
    {"record-added", "resolved", "ttl-queried", "expired", "removed", "rejected"}
)


def dns_resolver_audit_event(kind: str, seq: int, detail: str = "") -> dict:
    """Shape an audit.ndjson/1-compatible record."""
    _require_str("kind", kind)
    _require_nonneg_int("seq", seq)
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown audit kind: {kind!r}")
    if not isinstance(detail, str):
        raise TypeError("detail must be a str")
    return {
        "kind": f"dns-resolver.{kind}",
        "seq": seq,
        "detail": detail,
        "module": "dns_resolver",
        "module_version": DNS_RESOLVER_VERSION,
        "schema": SCHEMA_PIN,
        "format": "audit.ndjson/1",
    }


# --------------------------------------------------------------------------
# main() self-check
# --------------------------------------------------------------------------

def main() -> None:
    r = DNSResolver()
    r.add_record("example.com", "A", "93.184.216.34", ttl_s=60, now_s=0, seq=0)
    r.add_record("alias.example.com", "CNAME", "example.com", ttl_s=60, now_s=0, seq=1)
    direct = r.resolve("example.com", "A", now_s=10, seq=2)
    assert direct.records[0].value == "93.184.216.34"
    assert direct.min_ttl_remaining_s == 50
    via_cname = r.resolve("alias.example.com", "A", now_s=10, seq=3)
    assert via_cname.cname_chain == ("example.com",)
    assert via_cname.records[0].value == "93.184.216.34"
    report = r.ttl("example.com", "A", now_s=10)
    assert report.min_remaining_s == 50 and report.live_count == 1
    try:
        r.resolve("example.com", "A", now_s=61, seq=4)
    except UnknownNameError:
        pass
    else:
        raise AssertionError("expired record still resolved")
    swept = r.expire(now_s=61, seq=5)
    assert swept.dropped >= 1
    print("dns-resolver OK: add, resolve, cname, ttl, expiry")


if __name__ == "__main__":
    main()
