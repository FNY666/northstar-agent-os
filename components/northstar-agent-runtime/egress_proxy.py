"""Egress forward-proxy policy: destination allowlist and request filtering.

An ``EgressProxy`` books host-reported egress-proxy decisions as a
deterministic single-host state machine:

- ``allow(entry_id, target, kind, seq)`` pins an allowlist entry: a
  single ``host`` (``example.com:443``), a ``domain`` suffix
  (``.internal.example.com``), or a ``cidr`` range (``10.0.0.0/8``).
- ``remove(entry_id, seq, reason)`` terminally removes an entry.
- ``filter(request_id, destination, seq, method="GET")`` returns a
  frozen ``FilterDecision``: ``verdict="allow"`` when the destination
  matches a pinned entry, ``"deny"`` otherwise. Denials are *data*,
  never raised.
- Views: ``allow_entry()`` / ``allow_ids()`` / ``active_ids()`` /
  ``decision()`` / ``decisions_for()`` / ``stats()`` / ``audit_log()``.

House style: frozen dataclasses, caller-supplied strictly increasing
int seqs (no wall-clock), RLock-guarded, fail-closed taxonomy,
stdlib-only plus the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, ``audit.ndjson/1`` events, version pin
``egress-proxy.v1``, schema pin ``northstar.egress-proxy.v1``,
``main()`` self-check.

Honest scope: this module books *declared* policy and host-reported
destinations; it cannot observe the wire, cannot prove a connection
actually transited the proxy, and cannot detect destinations the host
never reports. A quiet ledger means "no known egress", never "no
egress". CIDR/host matching is string/numeric only; DNS rebinding and
SNI/IP mismatch are outside the model.
"""

from __future__ import annotations

import hashlib
import ipaddress
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
EGRESS_PROXY_VERSION = "egress-proxy.v1"

#: Schema pin carried by records and audit events.
EGRESS_PROXY_SCHEMA = "northstar.egress-proxy.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned allowlist entry kinds.
KIND_HOST = "host"
KIND_DOMAIN = "domain"
KIND_CIDR = "cidr"
_KINDS = (KIND_HOST, KIND_DOMAIN, KIND_CIDR)

#: Pinned HTTP method vocabulary.
_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")

#: Pinned filter verdicts.
VERDICT_ALLOW = "allow"
VERDICT_DENY = "deny"
_VERDICTS = (VERDICT_ALLOW, VERDICT_DENY)

#: Fail-open is never simulated: unmatched destinations deny.
_DEFAULT_VERDICT = VERDICT_DENY


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class EgressProxyError(ValueError):
    """Base for all egress-proxy structural problems and refused transitions."""


class BadEntryError(EgressProxyError):
    """Allowlist entry definition is malformed (bad id, kind, target)."""


class DuplicateEntryError(EgressProxyError):
    """An entry id is already pinned."""


class UnknownEntryError(EgressProxyError):
    """No allowlist entry with that id."""


class RemovedEntryError(EgressProxyError):
    """The entry was terminally removed."""


class AlreadyRemovedError(EgressProxyError):
    """The entry is already removed."""


class BadRequestError(EgressProxyError):
    """Filter request is malformed (bad id, destination, method)."""


class DuplicateRequestError(EgressProxyError):
    """A request id was already booked."""


class SeqOrderError(EgressProxyError):
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
        raise EgressProxyError(f"{name} must be a non-empty string")
    return value.strip()


def _check_entry_id(value: Any) -> str:
    entry_id = _check_nonempty_str(value, "entry_id")
    if len(entry_id) > 128:
        raise BadEntryError("entry_id must be <= 128 chars")
    return entry_id


def _check_request_id(value: Any) -> str:
    request_id = _check_nonempty_str(value, "request_id")
    if len(request_id) > 128:
        raise BadRequestError("request_id must be <= 128 chars")
    return request_id


def _check_kind(value: Any) -> str:
    if value not in _KINDS:
        raise BadEntryError(f"kind must be one of {_KINDS}")
    return value


def _check_target(kind: str, value: Any) -> str:
    """Validate the allowlist target for the pinned kind."""
    if not isinstance(value, str) or not value.strip():
        raise BadEntryError("target must be a non-empty string")
    target = value.strip()
    if len(target) > 253:
        raise BadEntryError("target must be <= 253 chars")
    if kind == KIND_CIDR:
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise BadEntryError(f"target is not a valid CIDR: {target!r}")
        return target
    if kind == KIND_DOMAIN:
        if not target.startswith("."):
            raise BadEntryError("domain target must start with '.'")
        label = target[1:]
        if not label or any(
            not part or len(part) > 63 for part in label.split(".")
        ):
            raise BadEntryError(f"domain target is malformed: {target!r}")
        return target.lower()
    # KIND_HOST: "hostname" or "hostname:port".
    host, _, port = target.partition(":")
    host = host.strip()
    if not host or any(c.isspace() for c in host):
        raise BadEntryError(f"host target is malformed: {target!r}")
    if port:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise BadEntryError(f"host port out of range: {target!r}")
        return f"{host.lower()}:{int(port)}"
    return host.lower()


def _check_destination(value: Any) -> str:
    """Validate a host-reported destination the proxy filters on."""
    if not isinstance(value, str) or not value.strip():
        raise BadRequestError("destination must be a non-empty string")
    destination = value.strip()
    if len(destination) > 253:
        raise BadRequestError("destination must be <= 253 chars")
    if any(c.isspace() for c in destination):
        raise BadRequestError("destination must not contain whitespace")
    # Refuse URL schemes: destinations are host-shaped, not URLs.
    if "://" in destination:
        raise BadRequestError("destination must not carry a URL scheme")
    return destination


def _check_method(value: Any) -> str:
    if value not in _METHODS:
        raise BadRequestError(f"method must be one of {_METHODS}")
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([EGRESS_PROXY_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _match(entry_kind: str, entry_target: str, destination: str) -> bool:
    """Decide whether a destination matches a pinned allowlist entry."""
    if entry_kind == KIND_DOMAIN:
        host = destination.partition(":")[0].lower()
        return host == entry_target[1:] or host.endswith(entry_target)
    if entry_kind == KIND_CIDR:
        ip_part = destination.partition(":")[0]
        try:
            addr = ipaddress.ip_address(ip_part)
        except ValueError:
            return False
        try:
            network = ipaddress.ip_network(entry_target, strict=False)
        except ValueError:  # pragma: no cover - validated at pin time
            return False
        return addr in network
    # KIND_HOST
    return destination.lower() == entry_target


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AllowEntry:
    """One pinned allowlist entry (frozen)."""

    entry_id: str
    kind: str
    target: str
    seq: int
    removed: bool
    digest: str
    schema: str = EGRESS_PROXY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "allow", self.entry_id, self.kind, self.target, self.seq,
            self.removed,
        )


@dataclass(frozen=True)
class RemoveRecord:
    """One terminal allowlist removal (frozen)."""

    entry_id: str
    reason: str
    seq: int
    digest: str
    schema: str = EGRESS_PROXY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "remove", self.entry_id, self.reason, self.seq
        )


@dataclass(frozen=True)
class FilterDecision:
    """One filter verdict (frozen). ``deny`` is *data*, never raised."""

    request_id: str
    destination: str
    method: str
    verdict: str
    matched_entry_id: Optional[str]
    seq: int
    digest: str
    schema: str = EGRESS_PROXY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "filter", self.request_id, self.destination, self.method,
            self.verdict, self.matched_entry_id or "", self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_ALLOW_ADDED = "egress.allow-added"
KIND_ALLOW_REMOVED = "egress.allow-removed"
KIND_FILTERED = "egress.filtered"
KIND_REJECTED = "egress.rejected"
_AUDIT_KINDS = (
    KIND_ALLOW_ADDED, KIND_ALLOW_REMOVED, KIND_FILTERED, KIND_REJECTED,
)


def egress_proxy_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the egress-proxy module."""
    if kind not in _AUDIT_KINDS:
        raise EgressProxyError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise EgressProxyError("detail must be a mapping")
    # Raw destinations and targets never cross the audit boundary;
    # ids + digest pins only.
    banned = {"destination", "target", "host", "hosts"}
    if any(k in detail for k in banned):
        raise EgressProxyError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": EGRESS_PROXY_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The proxy ledger
# ---------------------------------------------------------------------------


class EgressProxy:
    """Deterministic egress-proxy allowlist/filter ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._entries: Dict[str, AllowEntry] = {}
        self._removals: Dict[str, RemoveRecord] = {}
        self._decisions: Dict[str, FilterDecision] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internal helpers -------------------------------------------------

    def _consume_seq(self, seq: Any) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(egress_proxy_audit_event(kind, detail, seq))

    def _reject(self, seq: int, op: str, error: str) -> None:
        self._emit(KIND_REJECTED, seq, op=op, error=error)

    # -- allowlist ---------------------------------------------------------

    def allow(
        self, entry_id: Any, target: Any, kind: Any, seq: Any
    ) -> AllowEntry:
        """Pin an allowlist entry. Duplicate ids are refused fail-closed."""
        with self._lock:
            seq = self._consume_seq(seq)
            try:
                entry_id = _check_entry_id(entry_id)
                kind = _check_kind(kind)
                target = _check_target(kind, target)
                if entry_id in self._entries:
                    raise DuplicateEntryError(
                        f"entry already pinned: {entry_id!r}"
                    )
            except EgressProxyError as exc:
                self._reject(seq, "allow", type(exc).__name__)
                raise
            record = AllowEntry(
                entry_id=entry_id,
                kind=kind,
                target=target,
                seq=seq,
                removed=False,
                digest=_pin("allow", entry_id, kind, target, seq, False),
            )
            self._entries[entry_id] = record
            self._emit(
                KIND_ALLOW_ADDED, seq, entry_id=entry_id, entry_kind=kind,
            )
            return record

    def remove(self, entry_id: Any, seq: Any, reason: str = "") -> RemoveRecord:
        """Terminally remove an allowlist entry."""
        with self._lock:
            seq = self._consume_seq(seq)
            try:
                entry_id = _check_nonempty_str(entry_id, "entry_id")
                entry = self._entries.get(entry_id)
                if entry is None:
                    raise UnknownEntryError(f"unknown entry: {entry_id!r}")
                if entry.removed:
                    raise AlreadyRemovedError(
                        f"entry already removed: {entry_id!r}"
                    )
                reason = reason if isinstance(reason, str) else ""
                if len(reason) > 256:
                    raise BadEntryError("reason must be <= 256 chars")
            except EgressProxyError as exc:
                self._reject(seq, "remove", type(exc).__name__)
                raise
            record = RemoveRecord(
                entry_id=entry_id,
                reason=reason,
                seq=seq,
                digest=_pin("remove", entry_id, reason, seq),
            )
            self._removals[entry_id] = record
            self._entries[entry_id] = AllowEntry(
                entry_id=entry.entry_id,
                kind=entry.kind,
                target=entry.target,
                seq=entry.seq,
                removed=True,
                digest=_pin(
                    "allow", entry.entry_id, entry.kind, entry.target,
                    entry.seq, True,
                ),
            )
            self._emit(KIND_ALLOW_REMOVED, seq, entry_id=entry_id)
            return record

    # -- filtering ----------------------------------------------------------

    def filter(
        self,
        request_id: Any,
        destination: Any,
        seq: Any,
        method: str = "GET",
    ) -> FilterDecision:
        """Book a filter verdict. Denials are data, never raised."""
        with self._lock:
            seq = self._consume_seq(seq)
            try:
                request_id = _check_request_id(request_id)
                destination = _check_destination(destination)
                method = _check_method(method)
                if request_id in self._decisions:
                    raise DuplicateRequestError(
                        f"request already booked: {request_id!r}"
                    )
            except EgressProxyError as exc:
                self._reject(seq, "filter", type(exc).__name__)
                raise
            matched: Optional[str] = None
            verdict = _DEFAULT_VERDICT
            for entry_id in sorted(self._entries):
                entry = self._entries[entry_id]
                if entry.removed:
                    continue
                if _match(entry.kind, entry.target, destination):
                    matched = entry_id
                    verdict = VERDICT_ALLOW
                    break
            decision = FilterDecision(
                request_id=request_id,
                destination=destination,
                method=method,
                verdict=verdict,
                matched_entry_id=matched,
                seq=seq,
                digest=_pin(
                    "filter", request_id, destination, method, verdict,
                    matched or "", seq,
                ),
            )
            self._decisions[request_id] = decision
            self._emit(
                KIND_FILTERED, seq, request_id=request_id, verdict=verdict,
                matched_entry_id=matched or "",
            )
            return decision

    # -- views --------------------------------------------------------------

    def allow_entry(self, entry_id: Any) -> AllowEntry:
        """Return a pinned entry; unknown ids raise."""
        with self._lock:
            entry_id = _check_nonempty_str(entry_id, "entry_id")
            entry = self._entries.get(entry_id)
            if entry is None:
                raise UnknownEntryError(f"unknown entry: {entry_id!r}")
            return entry

    def allow_ids(self) -> Tuple[str, ...]:
        """All pinned entry ids, sorted."""
        with self._lock:
            return tuple(sorted(self._entries))

    def active_ids(self) -> Tuple[str, ...]:
        """Non-removed entry ids, sorted."""
        with self._lock:
            return tuple(
                eid for eid in sorted(self._entries)
                if not self._entries[eid].removed
            )

    def decision(self, request_id: Any) -> FilterDecision:
        """Return a booked filter decision; unknown ids raise."""
        with self._lock:
            request_id = _check_nonempty_str(request_id, "request_id")
            decision = self._decisions.get(request_id)
            if decision is None:
                raise BadRequestError(f"unknown request: {request_id!r}")
            return decision

    def decisions_for(self, destination: Any) -> Tuple[FilterDecision, ...]:
        """All booked decisions for one destination, in seq order."""
        with self._lock:
            destination = _check_destination(destination)
            return tuple(
                d for d in sorted(
                    self._decisions.values(), key=lambda d: d.seq
                )
                if d.destination == destination
            )

    def stats(self) -> Dict[str, int]:
        """Pure read view: counts of entries, removals, decisions."""
        with self._lock:
            decisions = list(self._decisions.values())
            return {
                "entries": len(self._entries),
                "active": len(self.active_ids()),
                "removed": len(self._removals),
                "decisions": len(decisions),
                "allowed": sum(1 for d in decisions
                               if d.verdict == VERDICT_ALLOW),
                "denied": sum(1 for d in decisions
                              if d.verdict == VERDICT_DENY),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events, in seq order."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Exercise the happy path; exits non-zero on failure."""
    proxy = EgressProxy()
    entry = proxy.allow("e1", ".internal.example.com", KIND_DOMAIN, 1)
    assert entry.verify()
    assert proxy.active_ids() == ("e1",)
    allowed = proxy.filter("r1", "api.internal.example.com", 2)
    assert allowed.verify()
    assert allowed.verdict == VERDICT_ALLOW
    assert allowed.matched_entry_id == "e1"
    denied = proxy.filter("r2", "evil.example.net", 3)
    assert denied.verify()
    assert denied.verdict == VERDICT_DENY
    assert denied.matched_entry_id is None
    proxy.remove("e1", 4, "decommissioned")
    assert proxy.active_ids() == ()
    post = proxy.filter("r3", "api.internal.example.com", 5)
    assert post.verdict == VERDICT_DENY
    print("egress-proxy OK: allow, filter, deny, remove, audit")


if __name__ == "__main__":
    main()
