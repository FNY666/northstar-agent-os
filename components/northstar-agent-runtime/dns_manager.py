"""DNS manager — simulated authoritative-DNS bookkeeping (Route53/Cloudflare shaped).

Research note (DNS literature): Route53 and Cloudflare model DNS as
*hosted zones* holding *record sets*; each record set names a record
type (A/AAAA/CNAME/MX/TXT/SRV/NS/PTR/CAA), a TTL, and a list of
values. Operators (RFC 1034/1035) include zone creation, record
upsert, record deletion, and health checks that gate routing answers.
This module takes the intersection for a single-host deterministic
ledger:

* **Zones**: ``zone`` books a hosted zone (id + validated domain
  name). Domains are normalized to lowercase, ASCII, label-validated
  (each label 1-63 chars, total <=253), no trailing-dot ambiguity.
* **Records**: ``record`` books one record set under a zone. Record
  types are a pinned vocabulary with per-type value validation (A =
  IPv4 quad, AAAA = IPv6 via ``ipaddress``, CNAME = single hostname,
  MX = (priority, host), TXT = strings, SRV = (priority, weight,
  port, target), NS/PTR = hostname, CAA = (flags, tag, value)).
  CNAME exclusivity is enforced (RFC 1034 §3.6.2): a name holding a
  CNAME cannot hold other records, and vice versa.
* **Health**: ``health`` books a health-check definition against a
  hostname/IP target; ``report`` books host-reported observations as
  data; ``health_status`` is a pure read view of the current verdict
  (``healthy``/``unhealthy``/``unknown`` when nothing reported).

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool/negative
/rewind refused), RLock-guarded, fail-closed taxonomy, stdlib-only
(``canonical_json`` sibling helper behind the standard try/except
fallback), sha256 digest pins over type-tagged canonical payloads,
``audit.ndjson/1`` events.

Honest boundary: this module books *declared* DNS state
deterministically. It performs no DNS resolution, cannot observe wire
truth, cannot prove propagation, and does not answer queries — the
host declares every record and every health observation. A ``healthy``
verdict means "the host reported success", never "the endpoint
answered". Production still needs a real authoritative nameserver,
zone transfers/AXFR, and a health-check prober.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import threading
from dataclasses import dataclass
from typing import Any, Mapping

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
DNS_MANAGER_VERSION = "dns-manager.v1"

#: Schema pin carried by records and audit events.
DNS_MANAGER_SCHEMA = "northstar.dns-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned record-type vocabulary (drift detectable).
RTYPE_A = "A"
RTYPE_AAAA = "AAAA"
RTYPE_CNAME = "CNAME"
RTYPE_MX = "MX"
RTYPE_TXT = "TXT"
RTYPE_SRV = "SRV"
RTYPE_NS = "NS"
RTYPE_PTR = "PTR"
RTYPE_CAA = "CAA"
RECORD_TYPES = (
    RTYPE_A,
    RTYPE_AAAA,
    RTYPE_CNAME,
    RTYPE_MX,
    RTYPE_TXT,
    RTYPE_SRV,
    RTYPE_NS,
    RTYPE_PTR,
    RTYPE_CAA,
)

#: Health verdicts (computed data).
HEALTHY = "healthy"
UNHEALTHY = "unhealthy"
UNKNOWN = "unknown"
HEALTH_VERDICTS = (HEALTHY, UNHEALTHY, UNKNOWN)

#: Audit event kinds.
KIND_ZONE_CREATED = "dns.zone-created"
KIND_RECORD_CREATED = "dns.record-created"
KIND_RECORD_DELETED = "dns.record-deleted"
KIND_HEALTH_DEFINED = "dns.health-defined"
KIND_HEALTH_REPORTED = "dns.health-reported"
KIND_REJECTED = "dns.rejected"
_KINDS = (
    KIND_ZONE_CREATED,
    KIND_RECORD_CREATED,
    KIND_RECORD_DELETED,
    KIND_HEALTH_DEFINED,
    KIND_HEALTH_REPORTED,
    KIND_REJECTED,
)

#: TTL bounds (seconds).
TTL_MIN = 1
TTL_MAX = 2147483647
DEFAULT_TTL = 300

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DNSManagerError(ValueError):
    """Base error for the DNS manager."""


class BadZoneError(DNSManagerError):
    """Malformed zone (bad id or domain)."""


class DuplicateZoneError(DNSManagerError):
    """A zone with this id is already defined."""


class UnknownZoneError(DNSManagerError):
    """No zone with this id is defined."""


class BadRecordError(DNSManagerError):
    """Malformed record (bad type, name, values, TTL)."""


class DuplicateRecordError(DNSManagerError):
    """A record with this id already exists."""


class UnknownRecordError(DNSManagerError):
    """No record with this id exists."""


class CnameConflictError(DNSManagerError):
    """CNAME exclusivity violated (RFC 1034 3.6.2)."""


class BadHealthError(DNSManagerError):
    """Malformed health check definition."""


class DuplicateHealthError(DNSManagerError):
    """A health check with this id is already defined."""


class UnknownHealthError(DNSManagerError):
    """No health check with this id is defined."""


class BadObservationError(DNSManagerError):
    """Malformed host-reported health observation."""


class SeqOrderError(DNSManagerError):
    """Seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DNSManagerError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DNSManagerError(f"{field_name} must be a non-empty string")
    return value


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise DNSManagerError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise DNSManagerError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise DNSManagerError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return _DIGEST_PREFIX + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


def _validate_domain(value: Any, field_name: str) -> str:
    """Validate and normalize a zone domain (no ``@`` allowed)."""
    raw = _check_nonempty_str(value, field_name)
    domain = raw.strip().rstrip(".").lower()
    if not domain or len(domain) > 253 or not domain.isascii():
        raise BadZoneError(f"{field_name} must be 1-253 ASCII chars")
    for label in domain.split("."):
        if not _LABEL_RE.match(label):
            raise BadZoneError(f"{field_name} has a bad label: {label!r}")
    return domain


def _validate_hostname(value: Any, field_name: str) -> str:
    """Validate and normalize a hostname (target of CNAME/NS/MX/PTR)."""
    raw = _check_nonempty_str(value, field_name)
    host = raw.strip().rstrip(".").lower()
    if not host or len(host) > 253 or not host.isascii():
        raise BadRecordError(f"{field_name} must be 1-253 ASCII chars")
    for label in host.split("."):
        if not _LABEL_RE.match(label):
            raise BadRecordError(f"{field_name} has a bad label: {label!r}")
    return host


def _validate_record_name(value: Any, zone_domain: str) -> str:
    """Validate a record name: ``@`` (apex) or a name inside the zone."""
    raw = _check_nonempty_str(value, "name")
    name = raw.strip().rstrip(".").lower()
    if name == "@":
        return "@"
    if not name or len(name) > 253 or not name.isascii():
        raise BadRecordError("name must be '@' or a 1-253 ASCII char name")
    for label in name.split("."):
        if not _LABEL_RE.match(label):
            raise BadRecordError(f"name has a bad label: {label!r}")
    if name == zone_domain or name.endswith("." + zone_domain):
        return name
    # Relative name inside the zone.
    full = name + "." + zone_domain
    if len(full) > 253:
        raise BadRecordError("name exceeds 253 chars inside its zone")
    return name


def _validate_values(rtype: str, values: Any) -> tuple:
    """Validate record values per type; return canonical tuple of tuples."""
    if not isinstance(values, (list, tuple)) or not values:
        raise BadRecordError("values must be a non-empty list")
    cleaned: list[tuple] = []
    for v in values:
        if rtype == RTYPE_A:
            if not isinstance(v, str):
                raise BadRecordError("A value must be a string")
            parts = v.strip().split(".")
            if len(parts) != 4:
                raise BadRecordError(f"bad IPv4: {v!r}")
            try:
                octets = [int(p) for p in parts]
            except ValueError:
                raise BadRecordError(f"bad IPv4: {v!r}")
            if any(o < 0 or o > 255 for o in octets) or any(
                not p.isdigit() for p in parts
            ):
                raise BadRecordError(f"bad IPv4: {v!r}")
            cleaned.append((v.strip(),))
        elif rtype == RTYPE_AAAA:
            if not isinstance(v, str):
                raise BadRecordError("AAAA value must be a string")
            try:
                addr = ipaddress.IPv6Address(v.strip())
            except (ipaddress.AddressValueError, ValueError):
                raise BadRecordError(f"bad IPv6: {v!r}")
            cleaned.append((str(addr),))
        elif rtype in (RTYPE_CNAME, RTYPE_NS, RTYPE_PTR):
            cleaned.append((_validate_hostname(v, "value"),))
            if rtype == RTYPE_CNAME and len(values) != 1:
                raise BadRecordError("CNAME takes exactly one value")
        elif rtype == RTYPE_MX:
            if not isinstance(v, (list, tuple)) or len(v) != 2:
                raise BadRecordError("MX value must be (priority, host)")
            prio, host = v
            if isinstance(prio, bool) or not isinstance(prio, int) or not (
                0 <= prio <= 65535
            ):
                raise BadRecordError("MX priority must be an int 0-65535")
            cleaned.append((prio, _validate_hostname(host, "MX host")))
        elif rtype == RTYPE_TXT:
            if not isinstance(v, str) or len(v) > 255:
                raise BadRecordError("TXT value must be a string <=255 chars")
            cleaned.append((v,))
        elif rtype == RTYPE_SRV:
            if not isinstance(v, (list, tuple)) or len(v) != 4:
                raise BadRecordError("SRV value must be (priority, weight, port, target)")
            prio, weight, port, target = v
            for num, field in ((prio, "priority"), (weight, "weight"), (port, "port")):
                if isinstance(num, bool) or not isinstance(num, int) or not (
                    0 <= num <= 65535
                ):
                    raise BadRecordError(f"SRV {field} must be an int 0-65535")
            cleaned.append((prio, weight, port, _validate_hostname(target, "SRV target")))
        elif rtype == RTYPE_CAA:
            if not isinstance(v, (list, tuple)) or len(v) != 3:
                raise BadRecordError("CAA value must be (flags, tag, value)")
            flags, tag, cval = v
            if isinstance(flags, bool) or not isinstance(flags, int) or not (
                0 <= flags <= 255
            ):
                raise BadRecordError("CAA flags must be an int 0-255")
            if not isinstance(tag, str) or not tag.strip() or len(tag) > 15:
                raise BadRecordError("CAA tag must be a non-empty string <=15 chars")
            if not isinstance(cval, str) or not cval:
                raise BadRecordError("CAA value must be a non-empty string")
            cleaned.append((flags, tag.strip().lower(), cval))
    if rtype == RTYPE_CNAME and len(cleaned) != 1:
        raise BadRecordError("CNAME takes exactly one value")
    return tuple(cleaned)


def _validate_ttl(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (
        TTL_MIN <= value <= TTL_MAX
    ):
        raise BadRecordError(f"ttl must be an int {TTL_MIN}-{TTL_MAX}")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ZoneRecord:
    """A pinned hosted zone."""

    zone_id: str
    domain: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(["zone", self.zone_id, self.domain, self.seq], seed),
        )


@dataclass(frozen=True)
class DNSRecord:
    """One pinned DNS record set."""

    record_id: str
    zone_id: str
    name: str
    rtype: str
    values: tuple
    ttl: int
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "record",
                    self.record_id,
                    self.zone_id,
                    self.name,
                    self.rtype,
                    [list(v) for v in self.values],
                    self.ttl,
                    self.seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class RecordDeletion:
    """A terminal record deletion (frozen)."""

    record_id: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest, _pin(["record-deleted", self.record_id, self.seq], seed)
        )


@dataclass(frozen=True)
class HealthCheckRecord:
    """A pinned health-check definition."""

    check_id: str
    target: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(["health-check", self.check_id, self.target, self.seq], seed),
        )


@dataclass(frozen=True)
class HealthObservation:
    """One sealed, host-reported health observation (verdicts are data)."""

    obs_id: str
    check_id: str
    healthy: bool
    prev_digest: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "health-observation",
                    self.obs_id,
                    self.check_id,
                    self.healthy,
                    self.prev_digest,
                    self.seq,
                ],
                seed,
            ),
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def dns_manager_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the DNS manager."""
    if kind not in _KINDS:
        raise DNSManagerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    # Record values (IPs, hostnames) never cross the audit boundary;
    # ids + digest pins only.
    banned = {"values", "target"}
    if any(k in detail for k in banned):
        raise DNSManagerError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "dns_manager",
        "module_version": DNS_MANAGER_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# DNSManager
# ---------------------------------------------------------------------------


class DNSManager:
    """Deterministic authoritative-DNS bookkeeping.

    All mutations require a caller-supplied strictly increasing ``seq``.
    Failed mutations consume their seq (ledger position stays total).
    Reads (``health_status``, ``records_for``, ``zone_record``,
    ``record_entry``, ``zone_ids``, ``record_ids``) validate the seq
    shape but do not consume it and write no audit rows.
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._zones: dict[str, ZoneRecord] = {}
        self._records: dict[str, DNSRecord] = {}
        self._deleted: dict[str, RecordDeletion] = {}
        self._health: dict[str, HealthCheckRecord] = {}
        self._observations: dict[str, HealthObservation] = {}
        self._obs_ids: list[str] = []
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(dns_manager_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    # -- zones ----------------------------------------------------------

    def zone(self, zone_id: str, domain: str, seq: int) -> ZoneRecord:
        """Book a hosted zone."""
        seq = self._next_seq(seq)
        zone_id = _check_nonempty_str(zone_id, "zone_id").strip()
        try:
            domain = _validate_domain(domain, "domain")
        except DNSManagerError as exc:
            self._reject(seq, str(exc))
            raise
        with self._lock:
            if zone_id in self._zones:
                self._reject(seq, f"duplicate zone_id: {zone_id!r}")
                raise DuplicateZoneError(f"duplicate zone_id: {zone_id!r}")
            if any(z.domain == domain for z in self._zones.values()):
                self._reject(seq, f"duplicate domain: {domain!r}")
                raise DuplicateZoneError(f"duplicate domain: {domain!r}")
            rec = ZoneRecord(
                zone_id=zone_id,
                domain=domain,
                seq=seq,
                digest=_pin(["zone", zone_id, domain, seq], self._seed),
            )
            self._zones[zone_id] = rec
            self._emit(
                KIND_ZONE_CREATED,
                seq,
                zone_id=zone_id,
                digest=rec.digest,
            )
            return rec

    # -- records --------------------------------------------------------

    def record(
        self,
        record_id: str,
        zone_id: str,
        name: str,
        rtype: str,
        values: Any,
        seq: int,
        ttl: int = DEFAULT_TTL,
    ) -> DNSRecord:
        """Book one DNS record set under a zone (CNAME-exclusive)."""
        seq = self._next_seq(seq)
        record_id = _check_nonempty_str(record_id, "record_id").strip()
        with self._lock:
            zone = self._zones.get(zone_id)
            if zone is None:
                self._reject(seq, f"unknown zone_id: {zone_id!r}")
                raise UnknownZoneError(f"unknown zone_id: {zone_id!r}")
            if record_id in self._records or record_id in self._deleted:
                self._reject(seq, f"duplicate record_id: {record_id!r}")
                raise DuplicateRecordError(f"duplicate record_id: {record_id!r}")
            try:
                if rtype not in RECORD_TYPES:
                    raise BadRecordError(f"unknown rtype: {rtype!r}")
                cname = _validate_record_name(name, zone.domain)
                clean_values = _validate_values(rtype, values)
                clean_ttl = _validate_ttl(ttl)
            except DNSManagerError as exc:
                self._reject(seq, str(exc))
                raise
            # CNAME exclusivity (RFC 1034 3.6.2), per zone+name.
            siblings = [
                r
                for r in self._records.values()
                if r.zone_id == zone_id and r.name == cname
            ]
            if rtype == RTYPE_CNAME:
                if siblings:
                    self._reject(seq, f"CNAME conflicts at {cname!r}")
                    raise CnameConflictError(f"CNAME conflicts at {cname!r}")
            else:
                if any(r.rtype == RTYPE_CNAME for r in siblings):
                    self._reject(seq, f"name {cname!r} holds a CNAME")
                    raise CnameConflictError(f"name {cname!r} holds a CNAME")
            rec = DNSRecord(
                record_id=record_id,
                zone_id=zone_id,
                name=cname,
                rtype=rtype,
                values=clean_values,
                ttl=clean_ttl,
                seq=seq,
                digest=_pin(
                    [
                        "record",
                        record_id,
                        zone_id,
                        cname,
                        rtype,
                        [list(v) for v in clean_values],
                        clean_ttl,
                        seq,
                    ],
                    self._seed,
                ),
            )
            self._records[record_id] = rec
            self._emit(
                KIND_RECORD_CREATED,
                seq,
                record_id=record_id,
                zone_id=zone_id,
                rtype=rtype,
                digest=rec.digest,
            )
            return rec

    def delete_record(self, record_id: str, seq: int) -> RecordDeletion:
        """Terminally delete a record set (ids are never recycled)."""
        seq = self._next_seq(seq)
        with self._lock:
            if record_id in self._deleted:
                self._reject(seq, f"record already deleted: {record_id!r}")
                raise UnknownRecordError(f"record already deleted: {record_id!r}")
            rec = self._records.pop(record_id, None)
            if rec is None:
                self._reject(seq, f"unknown record_id: {record_id!r}")
                raise UnknownRecordError(f"unknown record_id: {record_id!r}")
            deletion = RecordDeletion(
                record_id=record_id,
                seq=seq,
                digest=_pin(["record-deleted", record_id, seq], self._seed),
            )
            self._deleted[record_id] = deletion
            self._emit(
                KIND_RECORD_DELETED,
                seq,
                record_id=record_id,
                digest=deletion.digest,
            )
            return deletion

    # -- health ----------------------------------------------------------

    def health(self, check_id: str, target: str, seq: int) -> HealthCheckRecord:
        """Book a health-check definition against a hostname/IP target."""
        seq = self._next_seq(seq)
        check_id = _check_nonempty_str(check_id, "check_id").strip()
        try:
            raw = _check_nonempty_str(target, "target").strip().rstrip(".")
            if ":" in raw or all(c.isdigit() or c == "." for c in raw):
                # IP literal (v4 or v6).
                try:
                    clean_target = str(ipaddress.ip_address(raw))
                except ValueError:
                    raise BadHealthError(f"bad IP target: {target!r}")
            else:
                clean_target = _validate_hostname(raw, "target")
        except DNSManagerError as exc:
            self._reject(seq, str(exc))
            raise
        with self._lock:
            if check_id in self._health:
                self._reject(seq, f"duplicate check_id: {check_id!r}")
                raise DuplicateHealthError(f"duplicate check_id: {check_id!r}")
            rec = HealthCheckRecord(
                check_id=check_id,
                target=clean_target,
                seq=seq,
                digest=_pin(["health-check", check_id, clean_target, seq], self._seed),
            )
            self._health[check_id] = rec
            self._emit(
                KIND_HEALTH_DEFINED,
                seq,
                check_id=check_id,
                digest=rec.digest,
            )
            return rec

    def report(self, check_id: str, healthy: Any, seq: int) -> HealthObservation:
        """Book a host-reported health observation (verdict is data)."""
        seq = self._next_seq(seq)
        with self._lock:
            if check_id not in self._health:
                self._reject(seq, f"unknown check_id: {check_id!r}")
                raise UnknownHealthError(f"unknown check_id: {check_id!r}")
            if not isinstance(healthy, bool):
                self._reject(seq, "healthy must be a bool")
                raise BadObservationError("healthy must be a bool")
            prev_digest = (
                self._observations[self._obs_ids[-1]].digest
                if self._obs_ids
                else _GENESIS
            )
            obs_id = f"obs-{len(self._obs_ids)}"
            obs = HealthObservation(
                obs_id=obs_id,
                check_id=check_id,
                healthy=healthy,
                prev_digest=prev_digest,
                seq=seq,
                digest=_pin(
                    [
                        "health-observation",
                        obs_id,
                        check_id,
                        healthy,
                        prev_digest,
                        seq,
                    ],
                    self._seed,
                ),
            )
            self._observations[obs_id] = obs
            self._obs_ids.append(obs_id)
            self._emit(
                KIND_HEALTH_REPORTED,
                seq,
                check_id=check_id,
                obs_id=obs_id,
                digest=obs.digest,
            )
            return obs

    # -- read views ------------------------------------------------------

    def health_status(self, check_id: str, seq: Any) -> str:
        """Current health verdict as data (pure read; seq validated only)."""
        _check_seq(seq, "seq")
        with self._lock:
            if check_id not in self._health:
                raise UnknownHealthError(f"unknown check_id: {check_id!r}")
            for obs_id in reversed(self._obs_ids):
                obs = self._observations[obs_id]
                if obs.check_id == check_id:
                    return HEALTHY if obs.healthy else UNHEALTHY
            return UNKNOWN

    def zone_record(self, zone_id: str, seq: Any) -> ZoneRecord:
        _check_seq(seq, "seq")
        with self._lock:
            rec = self._zones.get(zone_id)
            if rec is None:
                raise UnknownZoneError(f"unknown zone_id: {zone_id!r}")
            return rec

    def record_entry(self, record_id: str, seq: Any) -> DNSRecord:
        _check_seq(seq, "seq")
        with self._lock:
            rec = self._records.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record_id: {record_id!r}")
            return rec

    def records_for(self, zone_id: str, seq: Any) -> tuple:
        """Record ids in a zone (pure read)."""
        _check_seq(seq, "seq")
        with self._lock:
            if zone_id not in self._zones:
                raise UnknownZoneError(f"unknown zone_id: {zone_id!r}")
            return tuple(
                r.record_id
                for r in self._records.values()
                if r.zone_id == zone_id
            )

    def zone_ids(self, seq: Any) -> tuple:
        _check_seq(seq, "seq")
        with self._lock:
            return tuple(sorted(self._zones))

    def record_ids(self, seq: Any) -> tuple:
        _check_seq(seq, "seq")
        with self._lock:
            return tuple(sorted(self._records))

    def audit_log(self, seq: Any) -> tuple:
        _check_seq(seq, "seq")
        with self._lock:
            return tuple(self._audit_log)


def main() -> None:
    mgr = DNSManager(seed="selfcheck")
    z = mgr.zone("z1", "Example.COM.", 0)
    assert z.domain == "example.com" and z.verify(seed="selfcheck")
    r = mgr.record("r1", "z1", "www", "A", ["93.184.216.34"], 1)
    assert r.values == (("93.184.216.34",),) and r.verify(seed="selfcheck")
    h = mgr.health("h1", "93.184.216.34", 2)
    assert h.verify(seed="selfcheck")
    assert mgr.health_status("h1", 3) == "unknown"
    o = mgr.report("h1", True, 4)
    assert o.verify(seed="selfcheck")
    assert mgr.health_status("h1", 5) == "healthy"
    d = mgr.delete_record("r1", 6)
    assert d.verify(seed="selfcheck")
    print("dns-manager OK: zone, record, health, report, delete, pins, audit")


if __name__ == "__main__":
    main()
