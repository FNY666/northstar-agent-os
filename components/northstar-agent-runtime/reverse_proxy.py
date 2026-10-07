"""Reverse proxy: nginx-style request routing decision logic.

Research note: a reverse proxy sits in front of upstreams and decides, per
request, *which* backend serves it, *how* the request is rewritten on the
way there, and *which* headers survive the hop (nginx, HAProxy, Envoy all
do this). This module is the *decision half*: given a request and a caller
seq, it returns a frozen, digest-pinned ``ProxyDecision`` naming the
upstream, the rewritten path, and the outgoing header set. It never opens
a socket — transport belongs to the host.

* **Upstreams** — named ``host:port`` backends with weights and
  fail-fast state. ``add_upstream`` validates fail-closed; duplicate names
  are refused.
* **Balancing** — ``round_robin`` (deterministic rotation),
  ``weighted`` (weight-proportional rotation over a precomputed schedule),
  ``least_conn`` (caller-reported in-flight counts), and ``ip_hash``
  (deterministic ``sha256`` pin over the client IP modulo the *sorted*
  active names — stable across instances, replay-exact from the audit log).
* **Rewrites** — ``rewrite(pattern, replacement)`` registers ordered
  regex rules; the first matching rule rewrites the path (nginx rule
  order). Rules are compiled at registration; bad patterns raise
  fail-closed at *registration*, never at request time.
* **Headers** — per-request header surgery: hop-by-hop headers
  (``connection``, ``keep-alive``, ``transfer-encoding``, ``upgrade``,
  ``proxy-*``) are stripped, ``X-Forwarded-For`` gains the client IP,
  ``Host`` becomes the upstream host, plus caller-registered
  set/remove rules applied in order.
* **Failover** — ``note_failure(name)`` bumps a counter; at
  ``max_fails`` the upstream is marked down automatically.
  ``mark_up``/``mark_down`` give the host explicit control.
  When no upstream is usable, ``proxy`` raises ``NoUpstreamAvailable``
  fail-closed — a refused request, never a silently dropped one.

Honest scope: this books *routing decisions*, not traffic — it cannot
prove an upstream is reachable, that a rewritten path resolves, or that
an ``ip_hash`` mapping survives an upstream set change (a changed set
re-hashes by design, like nginx's). ``least_conn`` trusts the host's
in-flight numbers. It records who was chosen and why, verifiable from
the audit record.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence, Tuple

#: Module version.
REVERSE_PROXY_VERSION = "reverse-proxy.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.reverse-proxy.v1"

#: Hop-by-hop headers stripped on every proxied request (RFC 2616 §13.5.1).
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

_HEALTHY = "healthy"
_DOWN = "down"


class ReverseProxyError(Exception):
    """Base error for the reverse proxy module."""


class DuplicateUpstreamError(ReverseProxyError):
    """An upstream with this name is already registered."""


class UnknownUpstreamError(ReverseProxyError):
    """No upstream with this name exists."""


class NoUpstreamAvailable(ReverseProxyError):
    """All upstreams are down; the request cannot be routed."""


class BadRewriteError(ReverseProxyError):
    """A rewrite rule is invalid (bad regex or bad replacement)."""


class BadHeaderRuleError(ReverseProxyError):
    """A header rule is invalid."""


class BadRequestError(ReverseProxyError):
    """The request record is malformed."""


class BalanceStrategy(str, Enum):
    """Load-balancing strategies."""

    ROUND_ROBIN = "round_robin"
    WEIGHTED = "weighted"
    LEAST_CONN = "least_conn"
    IP_HASH = "ip_hash"


def _check_seq(seq: Any) -> None:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ReverseProxyError("seq must be a non-negative int")


def _check_name(name: Any, what: str = "name") -> str:
    if not isinstance(name, str) or not name:
        raise ReverseProxyError(f"{what} must be a non-empty str")
    return name


def _digest(body: str) -> str:
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Upstream:
    """A registered backend."""

    name: str
    host: str
    port: int
    weight: int = 1
    max_fails: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "weight": self.weight,
            "max_fails": self.max_fails,
            "version": REVERSE_PROXY_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class RewriteRule:
    """One ordered regex rewrite rule."""

    pattern: str
    replacement: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "replacement": self.replacement,
            "version": REVERSE_PROXY_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class HeaderRule:
    """One ordered header surgery rule: set or remove."""

    action: str  # "set" | "remove"
    header: str
    value: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "header": self.header,
            "value": self.value,
            "version": REVERSE_PROXY_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class ProxyRequest:
    """An incoming request to route."""

    method: str
    path: str
    headers: Tuple[Tuple[str, str], ...]
    client_ip: str
    seq: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "headers": [list(pair) for pair in self.headers],
            "client_ip": self.client_ip,
            "seq": self.seq,
            "version": REVERSE_PROXY_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class ProxyDecision:
    """The frozen routing outcome for one request."""

    upstream_name: str
    upstream_host: str
    upstream_port: int
    rewritten_path: str
    outgoing_headers: Tuple[Tuple[str, str], ...]
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "upstream_name": self.upstream_name,
            "upstream_host": self.upstream_host,
            "upstream_port": self.upstream_port,
            "rewritten_path": self.rewritten_path,
            "outgoing_headers": [list(pair) for pair in self.outgoing_headers],
            "digest": self.digest,
            "version": REVERSE_PROXY_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class HealthReport:
    """Snapshot of upstream health state."""

    states: Tuple[Tuple[str, str, int], ...]  # (name, state, fail_count)

    def as_dict(self) -> dict[str, Any]:
        return {
            "states": [list(row) for row in self.states],
            "version": REVERSE_PROXY_VERSION,
            "schema": SCHEMA_PIN,
        }


class ReverseProxy:
    """nginx-style routing decision state machine (RLock-guarded)."""

    def __init__(self, strategy: str = BalanceStrategy.ROUND_ROBIN.value) -> None:
        try:
            self._strategy = BalanceStrategy(strategy)
        except ValueError:
            raise ReverseProxyError(
                f"strategy must be one of "
                f"{sorted(s.value for s in BalanceStrategy)}, got {strategy!r}"
            )
        self._lock = threading.RLock()
        self._upstreams: dict[str, Upstream] = {}
        self._state: dict[str, str] = {}  # name -> healthy/down
        self._fails: dict[str, int] = {}
        self._inflight: dict[str, int] = {}
        self._rr_cursor: int = 0
        self._weighted_schedule: list[str] = []
        self._rewrites: list[Tuple[re.Pattern[str], str, RewriteRule]] = []
        self._header_rules: list[HeaderRule] = []

    # ------------------------------------------------------------------ setup

    def add_upstream(
        self,
        name: str,
        host: str,
        port: int,
        weight: int = 1,
        max_fails: int = 1,
    ) -> Upstream:
        """Register a backend. Duplicate names and bad values raise."""
        _check_name(name, "upstream name")
        if not isinstance(host, str) or not host:
            raise ReverseProxyError("host must be a non-empty str")
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            raise ReverseProxyError("port must be an int in 1..65535")
        for label, value in (("weight", weight), ("max_fails", max_fails)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ReverseProxyError(f"{label} must be a positive int")
        with self._lock:
            if name in self._upstreams:
                raise DuplicateUpstreamError(f"upstream {name!r} already registered")
            upstream = Upstream(name=name, host=host, port=port, weight=weight, max_fails=max_fails)
            self._upstreams[name] = upstream
            self._state[name] = _HEALTHY
            self._fails[name] = 0
            self._inflight[name] = 0
            self._rebuild_schedule()
            return upstream

    def remove_upstream(self, name: str) -> None:
        """Drop an upstream; unknown names raise."""
        _check_name(name, "upstream name")
        with self._lock:
            if name not in self._upstreams:
                raise UnknownUpstreamError(f"unknown upstream {name!r}")
            del self._upstreams[name]
            del self._state[name]
            del self._fails[name]
            del self._inflight[name]
            self._rebuild_schedule()

    def rewrite(self, pattern: str, replacement: str) -> RewriteRule:
        """Register an ordered regex rewrite rule; bad regex raises now."""
        if not isinstance(pattern, str) or not isinstance(replacement, str):
            raise BadRewriteError("pattern and replacement must be str")
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise BadRewriteError(f"invalid regex {pattern!r}: {exc}") from exc
        # Replacement is validated by a dry run on the empty string.
        try:
            compiled.sub(replacement, "")
        except re.error as exc:
            raise BadRewriteError(f"invalid replacement {replacement!r}: {exc}") from exc
        rule = RewriteRule(pattern=pattern, replacement=replacement)
        with self._lock:
            self._rewrites.append((compiled, replacement, rule))
            return rule

    def header_rule(self, action: str, header: str, value: str = "") -> HeaderRule:
        """Register an ordered header surgery rule (``set`` or ``remove``)."""
        if action not in ("set", "remove"):
            raise BadHeaderRuleError("action must be 'set' or 'remove'")
        if not isinstance(header, str) or not header:
            raise BadHeaderRuleError("header must be a non-empty str")
        if not isinstance(value, str):
            raise BadHeaderRuleError("value must be str")
        rule = HeaderRule(action=action, header=header, value=value)
        with self._lock:
            self._header_rules.append(rule)
            return rule

    # ----------------------------------------------------------------- health

    def mark_down(self, name: str) -> None:
        self._set_state(name, _DOWN)

    def mark_up(self, name: str) -> None:
        with self._lock:
            self._set_state(name, _HEALTHY)
            self._fails[name] = 0

    def _set_state(self, name: str, state: str) -> None:
        _check_name(name, "upstream name")
        with self._lock:
            if name not in self._upstreams:
                raise UnknownUpstreamError(f"unknown upstream {name!r}")
            self._state[name] = state

    def note_failure(self, name: str) -> None:
        """Record one failed attempt; trips to down at ``max_fails``."""
        _check_name(name, "upstream name")
        with self._lock:
            if name not in self._upstreams:
                raise UnknownUpstreamError(f"unknown upstream {name!r}")
            self._fails[name] += 1
            if self._fails[name] >= self._upstreams[name].max_fails:
                self._state[name] = _DOWN

    def set_inflight(self, name: str, count: int) -> None:
        """Host-reported in-flight connection count (least_conn strategy)."""
        _check_name(name, "upstream name")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ReverseProxyError("inflight count must be a non-negative int")
        with self._lock:
            if name not in self._upstreams:
                raise UnknownUpstreamError(f"unknown upstream {name!r}")
            self._inflight[name] = count

    def health(self) -> HealthReport:
        with self._lock:
            states = tuple(
                (name, self._state[name], self._fails[name])
                for name in sorted(self._upstreams)
            )
            return HealthReport(states=states)

    # --------------------------------------------------------------- routing

    def _active(self) -> list[str]:
        return sorted(n for n, s in self._state.items() if s == _HEALTHY)

    def _rebuild_schedule(self) -> None:
        schedule: list[str] = []
        for name in sorted(self._upstreams):
            schedule.extend([name] * self._upstreams[name].weight)
        self._weighted_schedule = schedule
        self._rr_cursor = 0

    def _choose(self, request: ProxyRequest) -> str:
        active = self._active()
        if not active:
            raise NoUpstreamAvailable("all upstreams are down")
        if self._strategy is BalanceStrategy.ROUND_ROBIN:
            # Rotate over the *active* names in sorted order: deterministic
            # even as upstreams flap.
            name = active[self._rr_cursor % len(active)]
            self._rr_cursor += 1
            return name
        if self._strategy is BalanceStrategy.WEIGHTED:
            sched = [n for n in self._weighted_schedule if n in self._state and self._state[n] == _HEALTHY]
            if not sched:
                raise NoUpstreamAvailable("all upstreams are down")
            name = sched[self._rr_cursor % len(sched)]
            self._rr_cursor += 1
            return name
        if self._strategy is BalanceStrategy.LEAST_CONN:
            # Lowest caller-reported inflight; ties break by name (sorted).
            return min(active, key=lambda n: (self._inflight[n], n))
        # IP_HASH: stable across instances and replays.
        pin = int(hashlib.sha256(request.client_ip.encode("utf-8")).hexdigest(), 16)
        return active[pin % len(active)]

    def _rewrite_path(self, path: str) -> str:
        for compiled, replacement, _rule in self._rewrites:
            new_path, n = compiled.subn(replacement, path, count=1)
            if n:
                return new_path
        return path

    def _outgoing_headers(self, request: ProxyRequest, upstream: Upstream) -> Tuple[Tuple[str, str], ...]:
        headers: dict[str, str] = {}
        for key, value in request.headers:
            if not isinstance(key, str) or not isinstance(value, str):
                raise BadRequestError("header keys and values must be str")
            if key.lower() in _HOP_BY_HOP:
                continue
            headers[key] = value  # last occurrence wins, like nginx
        headers["Host"] = upstream.host
        fwd = headers.get("X-Forwarded-For")
        headers["X-Forwarded-For"] = (
            f"{fwd}, {request.client_ip}" if fwd else request.client_ip
        )
        for rule in self._header_rules:
            if rule.action == "set":
                headers[rule.header] = rule.value
            else:
                headers.pop(rule.header, None)
        return tuple(sorted(headers.items()))

    def proxy(self, request: ProxyRequest) -> ProxyDecision:
        """Route one request: choose upstream, rewrite path, fix headers."""
        if not isinstance(request, ProxyRequest):
            raise BadRequestError("request must be a ProxyRequest")
        _check_seq(request.seq)
        for attr in ("method", "path", "client_ip"):
            value = getattr(request, attr)
            if not isinstance(value, str) or not value:
                raise BadRequestError(f"request.{attr} must be a non-empty str")
        with self._lock:
            upstream_name = self._choose(request)
            upstream = self._upstreams[upstream_name]
            rewritten_path = self._rewrite_path(request.path)
            outgoing = self._outgoing_headers(request, upstream)
            body = (
                f"{upstream_name}|{upstream.host}|{upstream.port}|"
                f"{rewritten_path}|{sorted(outgoing)}|{request.seq}"
            )
            return ProxyDecision(
                upstream_name=upstream_name,
                upstream_host=upstream.host,
                upstream_port=upstream.port,
                rewritten_path=rewritten_path,
                outgoing_headers=outgoing,
                digest=_digest(body),
            )

    def make_request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        client_ip: str,
        seq: int,
    ) -> ProxyRequest:
        """Convenience constructor for a request record."""
        if not isinstance(headers, Mapping):
            raise BadRequestError("headers must be a mapping")
        pairs = tuple((k, v) for k, v in headers.items())
        return ProxyRequest(
            method=method, path=path, headers=pairs, client_ip=client_ip, seq=seq
        )

    def upstreams(self) -> Tuple[Upstream, ...]:
        with self._lock:
            return tuple(self._upstreams[name] for name in sorted(self._upstreams))

    def rules(self) -> Tuple[RewriteRule, ...]:
        with self._lock:
            return tuple(rule for _c, _r, rule in self._rewrites)


def reverse_proxy_audit_event(
    kind: str, seq: Any, detail: Optional[Mapping[str, Any]] = None
) -> dict[str, Any]:
    """Shape a reverse-proxy event as an ``audit.ndjson/1``-style record."""
    kinds = {
        "upstream-added",
        "upstream-removed",
        "proxy-routed",
        "rewrite-applied",
        "upstream-down",
        "upstream-up",
        "routed",
        "rejected",
    }
    if kind not in kinds:
        raise ReverseProxyError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    if detail is not None and not isinstance(detail, Mapping):
        raise ReverseProxyError("detail must be a mapping")
    return {
        "audit_seq": seq,
        "event": "reverse-proxy",
        "kind": kind,
        "detail": dict(detail) if detail else {},
        "version": REVERSE_PROXY_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    """Self-check: route, rewrite, headers, failover, audit."""
    rp = ReverseProxy()
    rp.add_upstream("a", "a.internal", 8080)
    rp.add_upstream("b", "b.internal", 8080, weight=2)
    rp.rewrite(r"^/api/(.*)$", r"/v2/\1")
    rp.header_rule("set", "X-Tenant", "acme")

    d1 = rp.proxy(rp.make_request("GET", "/api/users", {"Connection": "close"}, "1.2.3.4", 0))
    assert d1.rewritten_path == "/v2/users", d1.rewritten_path
    assert dict(d1.outgoing_headers)["X-Tenant"] == "acme"
    assert d1.digest.startswith("sha256:")

    # Round-robin over two upstreams.
    d2 = rp.proxy(rp.make_request("GET", "/x", {}, "1.2.3.4", 1))
    assert {d1.upstream_name, d2.upstream_name} == {"a", "b"}

    # Failover: b down -> everything lands on a.
    rp.mark_down("b")
    for i in range(3):
        assert rp.proxy(rp.make_request("GET", "/", {}, "9.9.9.9", 10 + i)).upstream_name == "a"
    rp.mark_down("a")
    try:
        rp.proxy(rp.make_request("GET", "/", {}, "9.9.9.9", 20))
    except NoUpstreamAvailable:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected NoUpstreamAvailable")

    rec = reverse_proxy_audit_event("proxy-routed", 0, {"upstream": "a"})
    assert rec["event"] == "reverse-proxy" and rec["kind"] == "proxy-routed"

    print("reverse-proxy OK: routing, rewrite, headers, failover, audit")


if __name__ == "__main__":
    main()
