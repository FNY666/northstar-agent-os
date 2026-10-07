"""Ingress controller: NGINX / Traefik-shaped routing bookkeeping (simulated).

Interface:
    IngressController.rule(rule_id, host, path, backend, seq, path_type="prefix")
        -> sealed RuleRecord
    IngressController.tls(host, seq, cert_digest, key_digest="")
        -> sealed TLSRecord (cert booked by digest only)
    IngressController.rewrite(rule_id, pattern, replacement, seq)
        -> sealed RewriteRecord (pattern validated to compile, never executed)
    IngressController.remove(rule_id, seq, reason="")
        -> sealed RemovalRecord (terminal; ids are never recycled)
    IngressController.match(host, path, seq)
        -> sealed MatchReport (pure read view: longest-prefix wins)

Routing is deterministic single-host bookkeeping over host-reported data:
hosts, paths and backends are declared by the host (GIGO boundary).
``match()`` never dials a backend and never terminates TLS; TLS records book
the *declared* cert/key by digest only -- certificate bytes never enter a
record or cross the audit boundary. Rewrite patterns are host-supplied regex
strings validated to *compile* at definition time but never executed here;
matches are host-applied. No sockets, no wire truth.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (failed mutations consume their seq), no wall-clock, RLock-guarded,
fail-closed, stdlib-only + standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List, Optional

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


_MODULE_VERSION = "ingress-controller.v1"
_SCHEMA_PIN = "northstar.ingress-controller.v1"
_AUDIT_TYPE = "audit.ndjson/1"

# Pinned path-match vocabulary (NGINX location shape / Traefik Path+PathPrefix).
PATH_TYPES = ("prefix", "exact")

# Host caps (DNS-shaped, same discipline as origin_shield).
_HOST_MAX_LEN = 253

# Rewrite id space.
_MAX_REWRITES_PER_RULE = 1024


class IngressControllerError(ValueError):
    """Base for all ingress_controller errors."""


class BadRuleError(IngressControllerError):
    """Rule id / host / path / backend failed validation."""


class DuplicateRuleError(IngressControllerError):
    """A rule with this id is already pinned."""


class UnknownRuleError(IngressControllerError):
    """Rule id not found."""


class RemovedRuleError(IngressControllerError):
    """Rule was removed; its id is retired and never recycled."""


class BadTLSError(IngressControllerError):
    """TLS host / cert digest failed validation."""


class DuplicateTLError(IngressControllerError):
    """A TLS binding for this host already exists."""


class BadRewriteError(IngressControllerError):
    """Rewrite pattern / replacement failed validation."""


class SeqOrderError(IngressControllerError):
    """Caller seq did not strictly increase."""


def _reject(reason: str) -> IngressControllerError:
    table = {
        "bad-rule": BadRuleError,
        "duplicate-rule": DuplicateRuleError,
        "unknown-rule": UnknownRuleError,
        "removed-rule": RemovedRuleError,
        "bad-tls": BadTLSError,
        "duplicate-tls": DuplicateTLError,
        "bad-rewrite": BadRewriteError,
        "seq": SeqOrderError,
    }
    return table.get(reason, IngressControllerError)(reason)


def _check_seq_kind(seq: Any) -> None:
    # bool is an int subclass; reject it explicitly (house discipline).
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise _reject("seq")


def _digest(kind: str, payload: Any) -> str:
    h = hashlib.sha256()
    h.update(kind.encode("utf-8"))
    h.update(b"\x00")
    h.update(jcs_canonical_json(payload))
    return "sha256:" + h.hexdigest()


def _check_host(host: Any) -> str:
    if not isinstance(host, str) or not host:
        raise BadRuleError("host must be a non-empty string")
    host = host.strip().lower()
    if not host:
        raise BadRuleError("host must be a non-empty string")
    if len(host) > _HOST_MAX_LEN:
        raise BadRuleError("host exceeds 253 characters")
    if "://" in host or any(c.isspace() for c in host):
        raise BadRuleError("host must be a bare hostname (no scheme/whitespace)")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
        raise BadRuleError(f"host is not DNS-shaped: {host!r}")
    return host


def _check_path(path: Any) -> str:
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 2048:
        raise BadRuleError("path must start with '/' and be <= 2048 chars")
    if any(c.isspace() or ord(c) < 32 for c in path):
        raise BadRuleError("path carries whitespace/control characters")
    return path


def _check_backend(backend: Any) -> str:
    if not isinstance(backend, str) or not backend:
        raise BadRuleError("backend must be a non-empty string")
    backend = backend.strip()
    if not backend or any(c.isspace() for c in backend):
        raise BadRuleError("backend must be a single token (no whitespace)")
    if ":" in backend:
        host_part, _, port_part = backend.rpartition(":")
        if not host_part or not port_part.isdigit():
            raise BadRuleError("backend host:port is malformed")
        port = int(port_part)
        if not 1 <= port <= 65535:
            raise BadRuleError("backend port out of range 1-65535")
    return backend


def _check_digest(value: Any, name: str) -> str:
    # Digests are opaque booking tokens (e.g. "sha256:..." pins); only the
    # shape is validated -- the module never sees key material.
    if not isinstance(value, str) or not value or len(value) > 256:
        raise BadTLSError(f"{name} must be a non-empty string <= 256 chars")
    if any(c.isspace() for c in value):
        raise BadTLSError(f"{name} must be a single token")
    return value


# ---------------------------------------------------------------------------
# Sealed records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleRecord:
    rule_id: str
    host: str
    path: str
    backend: str
    path_type: str
    created_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("rule", payload)


@dataclass(frozen=True)
class TLSRecord:
    tls_id: str
    host: str
    cert_digest: str
    key_digest: str
    bound_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("tls", payload)


@dataclass(frozen=True)
class RewriteRecord:
    rewrite_id: str
    rule_id: str
    pattern: str
    replacement: str
    supersedes: str  # rewrite_id of the record this replaces, "" if first
    set_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("rewrite", payload)


@dataclass(frozen=True)
class RemovalRecord:
    removal_id: str
    rule_id: str
    reason: str
    removed_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("removal", payload)


@dataclass(frozen=True)
class MatchReport:
    report_id: str
    host: str
    path: str
    matched: bool
    rule_id: str  # "" when no rule matched
    backend: str  # "" when no rule matched
    tls_present: bool
    rewrite_present: bool
    reported_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("match", payload)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class IngressController:
    """Deterministic NGINX/Traefik-shaped ingress routing bookkeeping.

    Args:
        audit: caller-supplied ``(event_dict) -> None`` sink for
            ``audit.ndjson/1`` events. Must be callable.
    """

    def __init__(self, audit: Callable[[Dict[str, Any]], None]) -> None:
        if not callable(audit):
            raise IngressControllerError("audit must be callable")
        self._audit = audit
        self._lock = threading.RLock()
        self._seq = 0
        self._rule_counter = 0
        self._tls_counter = 0
        self._rewrite_counter = 0
        self._removal_counter = 0
        self._report_counter = 0
        self._rules: Dict[str, RuleRecord] = {}
        self._removed: Dict[str, RemovalRecord] = {}
        self._tls: Dict[str, TLSRecord] = {}  # host -> TLSRecord
        self._rewrites: Dict[str, RewriteRecord] = {}  # rule_id -> active RewriteRecord

    # -- internal helpers ----------------------------------------------------

    def _require_seq(self, seq: int) -> None:
        _check_seq_kind(seq)
        if seq <= self._seq:
            raise _reject("seq")
        self._seq = seq

    def _emit(self, kind: str, seq: int, detail: Dict[str, Any]) -> None:
        self._audit(
            {
                "schema_version": _AUDIT_TYPE,
                "component": "northstar-agent-runtime",
                "module": _MODULE_VERSION,
                "event": kind,
                "seq": seq,
                "detail": detail,
            }
        )

    def _fail_locked(self, reason: str, seq: int, why: str = "") -> IngressControllerError:
        # Failed mutations consume their seq (batch discipline).
        self._require_seq(seq)
        self._emit("ingress.rejected", seq, {"reason": reason, "why": why})
        return _reject(reason)

    @staticmethod
    def _pin(kind: str, rec: Any) -> Any:
        payload = {k: v for k, v in asdict(rec).items() if k != "digest"}
        return type(rec)(**{**payload, "digest": _digest(kind, payload)})

    # -- public API ----------------------------------------------------------

    def rule(
        self,
        rule_id: Any,
        host: Any,
        path: Any,
        backend: Any,
        seq: int,
        path_type: str = "prefix",
    ) -> RuleRecord:
        """Pin a routing rule: host + path -> backend (NGINX location / Traefik router)."""
        with self._lock:
            try:
                if not isinstance(rule_id, str) or not rule_id:
                    raise BadRuleError("rule_id must be a non-empty string")
                if path_type not in PATH_TYPES:
                    raise BadRuleError(f"path_type must be one of {PATH_TYPES}")
                host_n = _check_host(host)
                path_n = _check_path(path)
                backend_n = _check_backend(backend)
            except IngressControllerError:
                raise self._fail_locked("bad-rule", seq, "rule fields invalid")
            if rule_id in self._removed:
                raise self._fail_locked("removed-rule", seq, "rule id retired")
            if rule_id in self._rules:
                raise self._fail_locked("duplicate-rule", seq, "rule id taken")
            self._require_seq(seq)
            self._rule_counter += 1
            rec = self._pin(
                "rule",
                RuleRecord(
                    rule_id=rule_id,
                    host=host_n,
                    path=path_n,
                    backend=backend_n,
                    path_type=path_type,
                    created_at_seq=seq,
                ),
            )
            self._rules[rule_id] = rec
            self._emit(
                "ingress.rule-defined",
                seq,
                {
                    "rule_id": rule_id,
                    "host": host_n,
                    "path_type": path_type,
                    "digest": rec.digest,
                },
            )
            return rec

    def tls(
        self,
        host: Any,
        seq: int,
        cert_digest: Any,
        key_digest: Any = "",
    ) -> TLSRecord:
        """Book a TLS cert binding for a host, by digest only.

        Certificate/key bytes never enter a record: only the digests are
        pinned. A host may carry at most one active binding.
        """
        with self._lock:
            try:
                host_n = _check_host(host)
                cert_n = _check_digest(cert_digest, "cert_digest")
                key_n = _check_digest(key_digest, "key_digest") if key_digest else ""
            except IngressControllerError:
                raise self._fail_locked("bad-tls", seq, "tls fields invalid")
            if host_n in self._tls:
                raise self._fail_locked("duplicate-tls", seq, "host already bound")
            self._require_seq(seq)
            self._tls_counter += 1
            rec = self._pin(
                "tls",
                TLSRecord(
                    tls_id=f"tls-{self._tls_counter}",
                    host=host_n,
                    cert_digest=cert_n,
                    key_digest=key_n,
                    bound_at_seq=seq,
                ),
            )
            self._tls[host_n] = rec
            self._emit(
                "ingress.tls-bound",
                seq,
                {"tls_id": rec.tls_id, "host": host_n, "digest": rec.digest},
            )
            return rec

    def rewrite(
        self, rule_id: Any, pattern: Any, replacement: Any, seq: int
    ) -> RewriteRecord:
        """Attach a rewrite to a rule (NGINX ``rewrite`` / Traefik ReplacePathRegex).

        The pattern must compile as a regex at definition time but is never
        executed by this module -- rewrites are host-applied (GIGO boundary).
        Re-setting a rewrite supersedes the previous one; the superseded id
        is linked so the chain is auditable.
        """
        with self._lock:
            if rule_id in self._removed:
                raise self._fail_locked("removed-rule", seq, "rule id retired")
            if rule_id not in self._rules:
                raise self._fail_locked("unknown-rule", seq, "rule not found")
            try:
                if not isinstance(pattern, str) or not pattern or len(pattern) > 2048:
                    raise BadRewriteError("pattern must be a non-empty str <= 2048")
                re.compile(pattern)  # validated to compile; never executed here
                if not isinstance(replacement, str) or len(replacement) > 2048:
                    raise BadRewriteError("replacement must be a str <= 2048")
            except IngressControllerError:
                raise self._fail_locked("bad-rewrite", seq, "rewrite fields invalid")
            except re.error as exc:
                raise self._fail_locked("bad-rewrite", seq, f"pattern: {exc}")
            self._require_seq(seq)
            self._rewrite_counter += 1
            prev = self._rewrites.get(rule_id)
            if prev is not None and self._rewrite_counter - int(prev.rewrite_id.split("-")[1]) > _MAX_REWRITES_PER_RULE:
                # Degenerate guard; effectively unreachable in tests.
                raise self._fail_locked("bad-rewrite", seq, "rewrite churn")
            rec = self._pin(
                "rewrite",
                RewriteRecord(
                    rewrite_id=f"rw-{self._rewrite_counter}",
                    rule_id=rule_id,
                    pattern=pattern,
                    replacement=replacement,
                    supersedes=prev.rewrite_id if prev is not None else "",
                    set_at_seq=seq,
                ),
            )
            self._rewrites[rule_id] = rec
            self._emit(
                "ingress.rewrite-set",
                seq,
                {
                    "rewrite_id": rec.rewrite_id,
                    "rule_id": rule_id,
                    "supersedes": rec.supersedes,
                    "digest": rec.digest,
                },
            )
            return rec

    def remove(self, rule_id: Any, seq: int, reason: str = "") -> RemovalRecord:
        """Terminally remove a rule. The id is retired and never recycled."""
        with self._lock:
            if rule_id in self._removed:
                raise self._fail_locked("removed-rule", seq, "already removed")
            if rule_id not in self._rules:
                raise self._fail_locked("unknown-rule", seq, "rule not found")
            if not isinstance(reason, str) or len(reason) > 512:
                raise self._fail_locked("bad-rule", seq, "reason must be str <= 512")
            self._require_seq(seq)
            self._removal_counter += 1
            rec = self._pin(
                "removal",
                RemovalRecord(
                    removal_id=f"rm-{self._removal_counter}",
                    rule_id=rule_id,
                    reason=reason,
                    removed_at_seq=seq,
                ),
            )
            del self._rules[rule_id]
            self._rewrites.pop(rule_id, None)  # rewrite dies with its rule
            self._removed[rule_id] = rec
            self._emit(
                "ingress.rule-removed",
                seq,
                {"removal_id": rec.removal_id, "rule_id": rule_id, "digest": rec.digest},
            )
            return rec

    def match(self, host: Any, path: Any, seq: int) -> MatchReport:
        """Pure read view: which rule would route (host, path)?

        Longest-prefix wins among ``prefix`` rules for the host; an ``exact``
        rule wins over every prefix rule. No match is data, never raised.
        The caller's seq is validated but not consumed.
        """
        with self._lock:
            _check_seq_kind(seq)
            try:
                host_n = _check_host(host)
                path_n = _check_path(path)
            except IngressControllerError as exc:
                raise IngressControllerError(str(exc))
            self._report_counter += 1
            best: Optional[RuleRecord] = None
            for rec in self._rules.values():
                if rec.host != host_n:
                    continue
                if rec.path_type == "exact":
                    if path_n == rec.path:
                        best = rec
                        break
                elif path_n.startswith(rec.path):
                    if best is None or (best.path_type == "prefix"
                                        and len(rec.path) > len(best.path)):
                        best = rec
            if best is None:
                report = self._pin(
                    "match",
                    MatchReport(
                        report_id=f"mr-{self._report_counter}",
                        host=host_n,
                        path=path_n,
                        matched=False,
                        rule_id="",
                        backend="",
                        tls_present=host_n in self._tls,
                        rewrite_present=False,
                        reported_at_seq=seq,
                    ),
                )
            else:
                report = self._pin(
                    "match",
                    MatchReport(
                        report_id=f"mr-{self._report_counter}",
                        host=host_n,
                        path=path_n,
                        matched=True,
                        rule_id=best.rule_id,
                        backend=best.backend,
                        tls_present=host_n in self._tls,
                        rewrite_present=best.rule_id in self._rewrites,
                        reported_at_seq=seq,
                    ),
                )
            # Audited-read event: pure view, ledger untouched.
            self._emit(
                "ingress.matched",
                seq,
                {
                    "report_id": report.report_id,
                    "matched": report.matched,
                    "rule_id": report.rule_id,
                    "digest": report.digest,
                },
            )
            return report

    # -- views ---------------------------------------------------------------

    def rule_record(self, rule_id: str) -> RuleRecord:
        with self._lock:
            if rule_id in self._removed:
                raise RemovedRuleError(f"rule removed: {rule_id!r}")
            try:
                return self._rules[rule_id]
            except KeyError:
                raise UnknownRuleError(f"unknown rule: {rule_id!r}")

    def rule_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._rules)

    def removed_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._removed)

    def tls_for(self, host: str) -> Optional[TLSRecord]:
        with self._lock:
            return self._tls.get(host)

    def rewrite_for(self, rule_id: str) -> Optional[RewriteRecord]:
        with self._lock:
            return self._rewrites.get(rule_id)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "rules": len(self._rules),
                "removed": len(self._removed),
                "tls_bindings": len(self._tls),
                "rewrites": len(self._rewrites),
                "seq": self._seq,
            }


def ingress_controller_audit_event(kind: str, detail: Dict[str, Any], seq: int) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the ingress-controller module."""
    _kinds = (
        "ingress.rule-defined",
        "ingress.tls-bound",
        "ingress.rewrite-set",
        "ingress.rule-removed",
        "ingress.matched",
        "ingress.rejected",
    )
    if kind not in _kinds:
        raise IngressControllerError(f"unknown audit kind: {kind!r}")
    _check_seq_kind(seq)
    if not isinstance(detail, dict):
        raise IngressControllerError("detail must be a dict")
    # Secrets never cross the audit boundary; digests only.
    banned = {"cert", "key", "pattern", "replacement", "cert_digest_raw"}
    if any(k in detail for k in banned):
        raise IngressControllerError("detail carries banned keys")
    return {
        "schema_version": _AUDIT_TYPE,
        "component": "northstar-agent-runtime",
        "module": _MODULE_VERSION,
        "schema": _SCHEMA_PIN,
        "event": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def main() -> int:
    events: List[Dict[str, Any]] = []
    ic = IngressController(audit=events.append)
    r = ic.rule("web", "example.com", "/app", "svc-web:8080", 1)
    assert r.verify_digest()
    t = ic.tls("example.com", 2, cert_digest="sha256:abc", key_digest="sha256:def")
    assert t.verify_digest()
    w = ic.rewrite("web", r"^/app/(.*)$", r"/\1", 3)
    assert w.verify_digest() and w.supersedes == ""
    m = ic.match("example.com", "/app/index", 4)
    assert m.matched and m.rule_id == "web" and m.tls_present and m.rewrite_present
    ic.rule("api", "example.com", "/app", "svc-api:9000", 5, path_type="exact")
    m2 = ic.match("example.com", "/app", 6)
    assert m2.rule_id == "api"  # exact beats prefix
    ic.remove("api", 7, reason="decommissioned")
    print("ingress-controller OK: rule, tls, rewrite, match, remove, pins")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
