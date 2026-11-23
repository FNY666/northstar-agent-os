"""API gateway interface: route matching, plugin chaining, request transforms,
and throttle policies for agent traffic.

A Kong/Apigee-shaped gateway (routes + ordered plugins + per-route request
transforms + per-route sliding-window throttles) as a deterministic,
single-host state machine. Routes match on method and a path pattern;
plugins are caller-supplied callables run in priority order and may
inspect, mutate, or short-circuit a request before it reaches a route
handler; transforms rewrite headers/query/body per route; throttles book
logical-seq attempts per route and return allow/deny as data.

House style: frozen dataclasses, no wall-clock (caller int seqs), fail-closed
validation, stdlib-only, version/schema pins, ``main()`` self-check.

Honest scope: pure in-memory bookkeeping over host-reported requests —
records route registrations, plugin verdicts, transform applications, and
throttle decisions; cannot enforce network policy, cannot prove a denied
request was never retried upstream, and cannot see traffic the host never
reports. Transforms and throttles are simulated policy bookkeeping: the
host applies them.

Version pin: api-gateway.v1
Schema pin: northstar.api-gateway.v1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

API_GATEWAY_VERSION = "api-gateway.v1"
SCHEMA_PIN = "northstar.api-gateway.v1"


class APIGatewayError(Exception):
    """Base error for the gateway interface."""


class DuplicateRouteError(APIGatewayError):
    """A route id or (method, pattern) pair is already registered."""


class DuplicatePluginError(APIGatewayError):
    """A plugin name is already registered."""


class UnknownRouteError(APIGatewayError):
    """The referenced route id is not registered."""


class UnknownPluginError(APIGatewayError):
    """The referenced plugin name is not registered."""


class RequestRejectedError(APIGatewayError):
    """A plugin rejected the request (short-circuit)."""


class UnknownTransformError(APIGatewayError):
    """No request/response transform is registered for the route."""


class UnknownThrottleError(APIGatewayError):
    """No throttle policy is registered for the route."""


def _check_int(name: str, value, allow_zero: bool = True) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if not allow_zero and value <= 0:
        raise ValueError(f"{name} must be positive")
    if allow_zero and value < 0:
        raise ValueError(f"{name} must be non-negative")


def _check_str(name: str, value, allow_empty: bool = False) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not allow_empty and value == "":
        raise ValueError(f"{name} must not be empty")


def _check_mapping(name: str, value) -> None:
    if not isinstance(value, dict):
        raise TypeError(f"{name} must be a dict, got {type(value).__name__}")


def _check_header_pairs(name: str, value) -> None:
    if not isinstance(value, tuple):
        raise TypeError(f"{name} must be a tuple of (str, str)")
    for item in value:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError(f"{name} entries must be (str, str)")
        _check_str(f"{name} name", item[0])
        _check_str(f"{name} value", item[1], allow_empty=True)


def _check_str_tuple(name: str, value) -> None:
    if not isinstance(value, tuple):
        raise TypeError(f"{name} must be a tuple of str")
    for item in value:
        _check_str(f"{name} entry", item)


def _canonical(value) -> str:
    """Type-tagged canonical encoding (bool distinct from int)."""
    if isinstance(value, bool):
        return "b:" + ("1" if value else "0")
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise ValueError("integral value out of JSON-safe range")
        return "i:" + str(value)
    if isinstance(value, str):
        return "s:" + str(len(value)) + ":" + value
    if value is None:
        return "n:"
    if isinstance(value, (tuple, list)):
        return "l:" + str(len(value)) + ":[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0])
        for k in value:
            if not isinstance(k, str):
                raise TypeError("dict keys must be str")
        return "d:{" + ",".join(_canonical(k) + "=" + _canonical(v) for k, v in items) + "}"
    raise TypeError(f"unsupported value type: {type(value).__name__}")


def _digest(body: str) -> str:
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _compile_pattern(pattern: str) -> Tuple[Tuple[str, ...], Tuple[Optional[str], ...]]:
    """Split a path pattern into segments and param names.

    Segments may be literals or ``:name`` placeholders. Returns
    (segments, params) where params[i] is the placeholder name or None.
    """
    segs = tuple(s for s in pattern.split("/") if s != "")
    params: Tuple[Optional[str], ...] = tuple(
        s[1:] if s.startswith(":") and len(s) > 1 else None for s in segs
    )
    return segs, params


@dataclass(frozen=True)
class RouteRecord:
    """A registered route (frozen record)."""

    route_id: str
    pattern: str
    methods: Tuple[str, ...]
    target: str
    seq: int
    digest: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_str("route_id", self.route_id)
        _check_str("pattern", self.pattern)
        if not self.pattern.startswith("/"):
            raise ValueError("pattern must start with '/'")
        if not isinstance(self.methods, tuple) or not self.methods:
            raise TypeError("methods must be a non-empty tuple of str")
        for m in self.methods:
            _check_str("method", m)
            if m != m.upper():
                raise ValueError("methods must be uppercase")
        _check_str("target", self.target)
        _check_int("seq", self.seq)
        _check_str("digest", self.digest)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "route_id": self.route_id,
            "pattern": self.pattern,
            "methods": list(self.methods),
            "target": self.target,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class PluginRecord:
    """A registered plugin (frozen record)."""

    name: str
    priority: int
    seq: int
    digest: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_str("name", self.name)
        _check_int("priority", self.priority)
        _check_int("seq", self.seq)
        _check_str("digest", self.digest)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "priority": self.priority,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RequestRecord:
    """An inbound request snapshot (frozen record)."""

    method: str
    path: str
    headers: Tuple[Tuple[str, str], ...]
    body: str
    seq: int
    digest: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_str("method", self.method)
        if self.method != self.method.upper():
            raise ValueError("method must be uppercase")
        _check_str("path", self.path)
        if not self.path.startswith("/"):
            raise ValueError("path must start with '/'")
        if not isinstance(self.headers, tuple):
            raise TypeError("headers must be a tuple of (str, str)")
        for h in self.headers:
            if not isinstance(h, tuple) or len(h) != 2:
                raise TypeError("headers must be a tuple of (str, str)")
            _check_str("header name", h[0])
            _check_str("header value", h[1], allow_empty=True)
        if not isinstance(self.body, str):
            raise TypeError("body must be a str")
        _check_int("seq", self.seq)
        _check_str("digest", self.digest)

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "headers": [list(h) for h in self.headers],
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class GatewayResponse:
    """A gateway verdict for one handled request (frozen record)."""

    request_digest: str
    status: int
    route_id: Optional[str]
    route_params: Tuple[Tuple[str, str], ...]
    plugins_run: Tuple[str, ...]
    short_circuited_by: Optional[str]
    response_digest: str
    seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_str("request_digest", self.request_digest)
        _check_int("status", self.status)
        if not 100 <= self.status <= 599:
            raise ValueError("status must be an HTTP status code")
        if self.route_id is not None:
            _check_str("route_id", self.route_id)
        if not isinstance(self.route_params, tuple):
            raise TypeError("route_params must be a tuple")
        for p in self.route_params:
            if not isinstance(p, tuple) or len(p) != 2:
                raise TypeError("route_params entries must be (str, str)")
            _check_str("param name", p[0])
            _check_str("param value", p[1], allow_empty=True)
        if not isinstance(self.plugins_run, tuple):
            raise TypeError("plugins_run must be a tuple of str")
        for n in self.plugins_run:
            _check_str("plugin name", n)
        if self.short_circuited_by is not None:
            _check_str("short_circuited_by", self.short_circuited_by)
        _check_str("response_digest", self.response_digest)
        _check_int("seq", self.seq)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "request_digest": self.request_digest,
            "status": self.status,
            "route_id": self.route_id,
            "route_params": [list(p) for p in self.route_params],
            "plugins_run": list(self.plugins_run),
            "short_circuited_by": self.short_circuited_by,
            "response_digest": self.response_digest,
            "seq": self.seq,
            "schema": self.schema,
        }


# Plugin verdicts returned by plugin callables:
#   ("continue", new_headers) -> pass on, optionally replacing headers
#   ("reject", status)        -> short-circuit with HTTP status
PluginFn = Callable[[RequestRecord], Tuple[str, Any]]


@dataclass(frozen=True)
class TransformRecord:
    """A registered request transform for one route (frozen record).

    Kong request-transformer shaped: header add/remove, query param
    add/remove, optional whole-body replacement. Re-setting a route's
    transform replaces the previous record (latest wins).
    """

    route_id: str
    add_headers: Tuple[Tuple[str, str], ...]
    remove_headers: Tuple[str, ...]
    add_query_params: Tuple[Tuple[str, str], ...]
    remove_query_params: Tuple[str, ...]
    body_replace: Optional[str]
    seq: int
    digest: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_str("route_id", self.route_id)
        _check_header_pairs("add_headers", self.add_headers)
        _check_str_tuple("remove_headers", self.remove_headers)
        _check_header_pairs("add_query_params", self.add_query_params)
        _check_str_tuple("remove_query_params", self.remove_query_params)
        if self.body_replace is not None and not isinstance(self.body_replace, str):
            raise TypeError("body_replace must be a str or None")
        _check_int("seq", self.seq)
        _check_str("digest", self.digest)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "route_id": self.route_id,
            "add_headers": [list(h) for h in self.add_headers],
            "remove_headers": list(self.remove_headers),
            "add_query_params": [list(p) for p in self.add_query_params],
            "remove_query_params": list(self.remove_query_params),
            "body_replace": self.body_replace,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TransformedRequest:
    """A request after the route's transform was applied (frozen record)."""

    route_id: str
    method: str
    path: str
    headers: Tuple[Tuple[str, str], ...]
    body: str
    transform_digest: str
    seq: int
    digest: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_str("route_id", self.route_id)
        _check_str("method", self.method)
        if self.method != self.method.upper():
            raise ValueError("method must be uppercase")
        _check_str("path", self.path)
        if not self.path.startswith("/"):
            raise ValueError("path must start with '/'")
        _check_header_pairs("headers", self.headers)
        if not isinstance(self.body, str):
            raise TypeError("body must be a str")
        _check_str("transform_digest", self.transform_digest)
        _check_int("seq", self.seq)
        _check_str("digest", self.digest)

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "route_id": self.route_id,
            "method": self.method,
            "path": self.path,
            "headers": [list(h) for h in self.headers],
            "transform_digest": self.transform_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ThrottleRecord:
    """A registered throttle policy for one route (frozen record).

    ``limit`` requests are allowed per ``window`` logical-seq units.
    Re-setting a route's throttle replaces the previous record; the
    recorded attempt history is kept (the window math ages it out).
    """

    route_id: str
    limit: int
    window: int
    seq: int
    digest: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_str("route_id", self.route_id)
        _check_int("limit", self.limit)
        if self.limit <= 0:
            raise ValueError("limit must be positive")
        _check_int("window", self.window)
        if self.window <= 0:
            raise ValueError("window must be positive")
        _check_int("seq", self.seq)
        _check_str("digest", self.digest)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "route_id": self.route_id,
            "limit": self.limit,
            "window": self.window,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ThrottleVerdict:
    """One throttle check verdict (frozen record). Denial is data.

    ``retry_after_seq`` is the earliest logical seq at which the oldest
    counted attempt ages out of the window; None when allowed. Advisory
    only — the host enforces.
    """

    route_id: str
    seq: int
    allowed: bool
    hits_in_window: int
    limit: int
    retry_after_seq: Optional[int]
    digest: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_str("route_id", self.route_id)
        _check_int("seq", self.seq)
        if not isinstance(self.allowed, bool):
            raise TypeError("allowed must be a bool")
        _check_int("hits_in_window", self.hits_in_window)
        _check_int("limit", self.limit)
        if self.retry_after_seq is not None:
            _check_int("retry_after_seq", self.retry_after_seq)
        _check_str("digest", self.digest)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "route_id": self.route_id,
            "seq": self.seq,
            "allowed": self.allowed,
            "hits_in_window": self.hits_in_window,
            "limit": self.limit,
            "retry_after_seq": self.retry_after_seq,
            "digest": self.digest,
            "schema": self.schema,
        }


class APIGateway:
    """Kong-shaped gateway: routes + ordered plugins (RLock-guarded)."""

    def __init__(self) -> None:
        self._routes: Dict[str, RouteRecord] = {}
        self._route_keys: set = set()  # (method, pattern)
        self._plugins: Dict[str, Tuple[PluginRecord, PluginFn]] = {}
        self._route_seq = 0
        self._plugin_seq = 0
        self._transforms: Dict[str, TransformRecord] = {}
        self._throttles: Dict[str, ThrottleRecord] = {}
        self._throttle_hits: Dict[str, list] = {}

    def add_route(
        self,
        route_id: str,
        pattern: str,
        methods: Tuple[str, ...],
        target: str,
        seq: int,
    ) -> RouteRecord:
        _check_str("route_id", route_id)
        _check_str("pattern", pattern)
        if not pattern.startswith("/"):
            raise ValueError("pattern must start with '/'")
        if not isinstance(methods, tuple) or not methods:
            raise TypeError("methods must be a non-empty tuple of str")
        for m in methods:
            _check_str("method", m)
            if m != m.upper():
                raise ValueError("methods must be uppercase")
        _check_str("target", target)
        _check_int("seq", seq)
        if route_id in self._routes:
            raise DuplicateRouteError(f"route already registered: {route_id}")
        for m in methods:
            if (m, pattern) in self._route_keys:
                raise DuplicateRouteError(
                    f"route already registered for {m} {pattern}"
                )
        digest = _digest(
            _canonical(
                {
                    "route_id": route_id,
                    "pattern": pattern,
                    "methods": sorted(methods),
                    "target": target,
                    "seq": seq,
                }
            )
        )
        record = RouteRecord(
            route_id=route_id,
            pattern=pattern,
            methods=tuple(sorted(methods)),
            target=target,
            seq=seq,
            digest=digest,
        )
        self._routes[route_id] = record
        for m in methods:
            self._route_keys.add((m, pattern))
        return record

    def add_plugin(self, name: str, fn: PluginFn, priority: int, seq: int) -> PluginRecord:
        _check_str("name", name)
        if not callable(fn):
            raise TypeError("fn must be callable")
        _check_int("priority", priority)
        _check_int("seq", seq)
        if name in self._plugins:
            raise DuplicatePluginError(f"plugin already registered: {name}")
        digest = _digest(
            _canonical({"name": name, "priority": priority, "seq": seq})
        )
        record = PluginRecord(name=name, priority=priority, seq=seq, digest=digest)
        self._plugins[name] = (record, fn)
        return record

    def remove_plugin(self, name: str) -> None:
        _check_str("name", name)
        if name not in self._plugins:
            raise UnknownPluginError(f"unknown plugin: {name}")
        del self._plugins[name]

    def route(self, route_id: str) -> RouteRecord:
        _check_str("route_id", route_id)
        if route_id not in self._routes:
            raise UnknownRouteError(f"unknown route: {route_id}")
        return self._routes[route_id]

    def plugin(self, name: str) -> PluginRecord:
        _check_str("name", name)
        if name not in self._plugins:
            raise UnknownPluginError(f"unknown plugin: {name}")
        return self._plugins[name][0]

    def routes(self) -> Tuple[RouteRecord, ...]:
        return tuple(self._routes.values())

    def plugins(self) -> Tuple[PluginRecord, ...]:
        return tuple(r for r, _ in self._plugins.values())

    def set_transform(
        self,
        route_id: str,
        seq: int,
        add_headers: Tuple[Tuple[str, str], ...] = (),
        remove_headers: Tuple[str, ...] = (),
        add_query_params: Tuple[Tuple[str, str], ...] = (),
        remove_query_params: Tuple[str, ...] = (),
        body_replace: Optional[str] = None,
    ) -> TransformRecord:
        """Register (or replace) the request transform for a route."""
        _check_str("route_id", route_id)
        if route_id not in self._routes:
            raise UnknownRouteError(f"unknown route: {route_id}")
        _check_header_pairs("add_headers", add_headers)
        _check_str_tuple("remove_headers", remove_headers)
        _check_header_pairs("add_query_params", add_query_params)
        _check_str_tuple("remove_query_params", remove_query_params)
        if body_replace is not None and not isinstance(body_replace, str):
            raise TypeError("body_replace must be a str or None")
        _check_int("seq", seq)
        digest = _digest(
            _canonical(
                {
                    "route_id": route_id,
                    "add_headers": [list(h) for h in add_headers],
                    "remove_headers": list(remove_headers),
                    "add_query_params": [list(p) for p in add_query_params],
                    "remove_query_params": list(remove_query_params),
                    "body_replace": body_replace,
                    "seq": seq,
                }
            )
        )
        record = TransformRecord(
            route_id=route_id,
            add_headers=add_headers,
            remove_headers=remove_headers,
            add_query_params=add_query_params,
            remove_query_params=remove_query_params,
            body_replace=body_replace,
            seq=seq,
            digest=digest,
        )
        self._transforms[route_id] = record
        return record

    def transform_record(self, route_id: str) -> TransformRecord:
        _check_str("route_id", route_id)
        if route_id not in self._transforms:
            raise UnknownTransformError(
                f"no transform registered for route: {route_id}"
            )
        return self._transforms[route_id]

    def transform(
        self,
        route_id: str,
        method: str,
        path: str,
        headers: Tuple[Tuple[str, str], ...] = (),
        body: str = "",
        seq: int = 0,
    ) -> TransformedRequest:
        """Apply the route's registered transform to a request (simulated).

        Headers: ``remove_headers`` first (case-insensitive), then
        ``add_headers`` appended. Query: ``remove_query_params`` dropped
        by name, then ``add_query_params`` appended verbatim. Body is
        replaced only when ``body_replace`` was registered.
        """
        _check_str("route_id", route_id)
        if route_id not in self._routes:
            raise UnknownRouteError(f"unknown route: {route_id}")
        cfg = self._transforms.get(route_id)
        if cfg is None:
            raise UnknownTransformError(
                f"no transform registered for route: {route_id}"
            )
        _check_str("method", method)
        if method != method.upper():
            raise ValueError("method must be uppercase")
        _check_str("path", path)
        if not path.startswith("/"):
            raise ValueError("path must start with '/'")
        _check_header_pairs("headers", headers)
        if not isinstance(body, str):
            raise TypeError("body must be a str")
        _check_int("seq", seq)

        drop = {name.lower() for name in cfg.remove_headers}
        new_headers = tuple(
            (k, v) for k, v in headers if k.lower() not in drop
        ) + tuple(cfg.add_headers)

        if "?" in path:
            base, qs = path.split("?", 1)
            pairs = [p for p in qs.split("&") if p != ""]
        else:
            base, pairs = path, []
        drop_q = set(cfg.remove_query_params)
        kept_q = [p for p in pairs if p.split("=", 1)[0] not in drop_q]
        new_q = kept_q + [f"{k}={v}" for k, v in cfg.add_query_params]
        new_path = base + ("?" + "&".join(new_q) if new_q else "")

        new_body = cfg.body_replace if cfg.body_replace is not None else body
        digest = _digest(
            _canonical(
                {
                    "route_id": route_id,
                    "method": method,
                    "path": new_path,
                    "headers": [[k, v] for k, v in new_headers],
                    "body": new_body,
                    "transform": cfg.digest,
                    "seq": seq,
                }
            )
        )
        return TransformedRequest(
            route_id=route_id,
            method=method,
            path=new_path,
            headers=new_headers,
            body=new_body,
            transform_digest=cfg.digest,
            seq=seq,
            digest=digest,
        )

    def set_throttle(
        self, route_id: str, limit: int, window: int, seq: int
    ) -> ThrottleRecord:
        """Register (or replace) the throttle policy for a route."""
        _check_str("route_id", route_id)
        if route_id not in self._routes:
            raise UnknownRouteError(f"unknown route: {route_id}")
        _check_int("limit", limit)
        if limit <= 0:
            raise ValueError("limit must be positive")
        _check_int("window", window)
        if window <= 0:
            raise ValueError("window must be positive")
        _check_int("seq", seq)
        digest = _digest(
            _canonical(
                {"route_id": route_id, "limit": limit, "window": window, "seq": seq}
            )
        )
        record = ThrottleRecord(
            route_id=route_id, limit=limit, window=window, seq=seq, digest=digest
        )
        self._throttles[route_id] = record
        return record

    def throttle_record(self, route_id: str) -> ThrottleRecord:
        _check_str("route_id", route_id)
        if route_id not in self._throttles:
            raise UnknownThrottleError(
                f"no throttle policy registered for route: {route_id}"
            )
        return self._throttles[route_id]

    def throttle(self, route_id: str, seq: int) -> ThrottleVerdict:
        """Check one request against the route's throttle policy (simulated).

        Sliding window over caller-supplied logical seqs: a request is
        allowed when fewer than ``limit`` attempts were recorded with a
        seq in ``(seq - window, seq)``. Denial is returned as data, never
        raised. Every check records its seq as an attempt (denied checks
        age out of the window like any other attempt).
        """
        _check_str("route_id", route_id)
        if route_id not in self._routes:
            raise UnknownRouteError(f"unknown route: {route_id}")
        cfg = self._throttles.get(route_id)
        if cfg is None:
            raise UnknownThrottleError(
                f"no throttle policy registered for route: {route_id}"
            )
        _check_int("seq", seq)
        hits = self._throttle_hits.setdefault(route_id, [])
        in_window = [s for s in hits if seq - cfg.window < s < seq]
        allowed = len(in_window) < cfg.limit
        hits.append(seq)
        retry_after = None if allowed else min(in_window) + cfg.window
        digest = _digest(
            _canonical(
                {
                    "route_id": route_id,
                    "seq": seq,
                    "allowed": allowed,
                    "hits_in_window": len(in_window),
                    "limit": cfg.limit,
                    "retry_after_seq": retry_after,
                }
            )
        )
        return ThrottleVerdict(
            route_id=route_id,
            seq=seq,
            allowed=allowed,
            hits_in_window=len(in_window),
            limit=cfg.limit,
            retry_after_seq=retry_after,
            digest=digest,
        )

    def _match(
        self, method: str, path: str
    ) -> Tuple[Optional[RouteRecord], Tuple[Tuple[str, str], ...]]:
        """First registered route wins (registration order)."""
        path_segs = tuple(s for s in path.split("/") if s != "")
        for record in self._routes.values():
            if method not in record.methods:
                continue
            pat_segs, params = _compile_pattern(record.pattern)
            if len(pat_segs) != len(path_segs):
                continue
            bound: list = []
            ok = True
            for pat, pname, seg in zip(pat_segs, params, path_segs):
                if pname is not None:
                    bound.append((pname, seg))
                elif pat != seg:
                    ok = False
                    break
            if ok:
                return record, tuple(bound)
        return None, ()

    def handle(
        self,
        method: str,
        path: str,
        headers: Tuple[Tuple[str, str], ...] = (),
        body: str = "",
        seq: int = 0,
    ) -> GatewayResponse:
        _check_str("method", method)
        if method != method.upper():
            raise ValueError("method must be uppercase")
        _check_str("path", path)
        if not path.startswith("/"):
            raise ValueError("path must start with '/'")
        if not isinstance(headers, tuple):
            raise TypeError("headers must be a tuple of (str, str)")
        for h in headers:
            if not isinstance(h, tuple) or len(h) != 2:
                raise TypeError("headers must be a tuple of (str, str)")
        if not isinstance(body, str):
            raise TypeError("body must be a str")
        _check_int("seq", seq)

        req_digest = _digest(
            _canonical(
                {
                    "method": method,
                    "path": path,
                    "headers": [[k, v] for k, v in headers],
                    "body": body,
                    "seq": seq,
                }
            )
        )
        request = RequestRecord(
            method=method,
            path=path,
            headers=headers,
            body=body,
            seq=seq,
            digest=req_digest,
        )

        ordered = sorted(
            self._plugins.values(), key=lambda item: (-item[0].priority, item[0].seq)
        )
        ran: list = []
        short_circuit: Optional[str] = None
        short_status: Optional[int] = None

        for record, fn in ordered:
            ran.append(record.name)
            try:
                verdict, payload = fn(request)
            except Exception:
                raise RequestRejectedError(
                    f"plugin {record.name} raised during handling"
                )
            if verdict == "continue":
                if payload is not None:
                    if not isinstance(payload, tuple):
                        raise TypeError(
                            f"plugin {record.name} must return headers tuple or None"
                        )
                    for h in payload:
                        if not isinstance(h, tuple) or len(h) != 2:
                            raise TypeError(
                                f"plugin {record.name} returned malformed headers"
                            )
                    # Later plugins see the mutated headers; the request
                    # digest still pins the original inbound request.
                    request = RequestRecord(
                        method=request.method,
                        path=request.path,
                        headers=payload,
                        body=request.body,
                        seq=request.seq,
                        digest=request.digest,
                    )
            elif verdict == "reject":
                short_circuit = record.name
                _check_int("reject status", payload)
                short_status = payload
                break
            else:
                raise APIGatewayError(
                    f"plugin {record.name} returned unknown verdict {verdict!r}"
                )

        if short_circuit is not None:
            resp_digest = _digest(
                _canonical(
                    {
                        "request": req_digest,
                        "status": short_status,
                        "short_circuited_by": short_circuit,
                        "seq": seq,
                    }
                )
            )
            return GatewayResponse(
                request_digest=req_digest,
                status=short_status,
                route_id=None,
                route_params=(),
                plugins_run=tuple(ran),
                short_circuited_by=short_circuit,
                response_digest=resp_digest,
                seq=seq,
            )

        match, params = self._match(method, path)
        status = 200 if match is not None else 404
        resp_digest = _digest(
            _canonical(
                {
                    "request": req_digest,
                    "status": status,
                    "route_id": match.route_id if match else None,
                    "params": list(params),
                    "seq": seq,
                }
            )
        )
        return GatewayResponse(
            request_digest=req_digest,
            status=status,
            route_id=match.route_id if match else None,
            route_params=params,
            plugins_run=tuple(ran),
            short_circuited_by=None,
            response_digest=resp_digest,
            seq=seq,
        )


def api_gateway_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for gateway activity."""
    _check_str("kind", kind)
    _check_int("seq", seq)
    allowed = {
        "route-added",
        "plugin-added",
        "plugin-removed",
        "request-handled",
        "request-rejected",
        "transform-set",
        "request-transformed",
        "throttle-set",
        "throttle-checked",
    }
    if kind not in allowed:
        raise ValueError(f"unknown audit kind: {kind}")
    body = {"kind": kind, "seq": seq, "detail": dict(detail)}
    return {
        "schema": "audit.ndjson/1",
        "module": "api-gateway",
        "version": API_GATEWAY_VERSION,
        "event": body,
        "digest": _digest(_canonical(body)),
    }


def main() -> None:
    gw = APIGateway()
    gw.add_route("users", "/users/:id", ("GET",), "users-svc", seq=1)
    gw.add_plugin(
        "auth",
        lambda req: (
            ("reject", 401)
            if req.header("authorization") is None
            else ("continue", None)
        ),
        priority=100,
        seq=2,
    )
    resp = gw.handle("GET", "/users/42", seq=3)
    assert resp.status == 401, resp.as_dict()
    assert resp.short_circuited_by == "auth"
    resp2 = gw.handle(
        "GET", "/users/42", (("authorization", "Bearer x"),), seq=4
    )
    assert resp2.status == 200, resp2.as_dict()
    assert resp2.route_id == "users"
    assert resp2.route_params == (("id", "42"),)
    resp3 = gw.handle("GET", "/nope", (("authorization", "Bearer x"),), seq=5)
    assert resp3.status == 404
    gw.set_transform(
        "users",
        seq=6,
        add_headers=(("x-gateway", "northstar"),),
        remove_headers=("x-internal",),
        add_query_params=(("gw", "1"),),
        remove_query_params=("debug",),
    )
    tr = gw.transform(
        "users",
        "GET",
        "/users/42?debug=1",
        (("x-internal", "secret"), ("accept", "json")),
        seq=7,
    )
    assert tr.header("x-gateway") == "northstar"
    assert tr.header("x-internal") is None
    assert tr.path == "/users/42?gw=1"
    gw.set_throttle("users", limit=2, window=10, seq=8)
    assert gw.throttle("users", seq=9).allowed is True
    assert gw.throttle("users", seq=10).allowed is True
    denied = gw.throttle("users", seq=11)
    assert denied.allowed is False
    assert denied.retry_after_seq == 9 + 10
    print("api-gateway OK: routes, params, plugin chain, short-circuit, transform, throttle")


if __name__ == "__main__":
    main()
