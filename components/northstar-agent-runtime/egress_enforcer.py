"""Deterministic egress policy engine: the enforcement half of the gateway.

Layer 1 (the policy gate: action cards, approval, capability allowlists)
decides *whether* an action may proceed. This module is Layer 2: it decides
*where* the resulting bytes may go and *what shape* the request may take, at a
boundary the agent process cannot reconfigure.

The threat model is explicit: tool handlers run *in-process* today, and MCP
server subprocesses inherit the main process's network. An in-process
"gateway" the agent calls voluntarily is a convention, not a chokepoint. The
enforcement therefore lives in a separate sidecar process
(``components/northstar-egress-sidecar/``) that holds every external
credential and owns the only network path; the agent process gets no direct
route. This module is the sidecar's brain.

The engine itself is pure and offline: DNS resolution is injected, the clock
is injected, budgets are passed in, and no socket is ever opened here. That
keeps every decision deterministic and unit-testable.

Check order (fail-closed, cheapest first):

1. destination rule lookup by the *agent-named* hostname (exact match)
2. sidecar-side DNS resolution (never the agent's word for the address)
3. CONNECT-time authorization on the *resolved* IP:port, with an SSRF guard
   against private/loopback/link-local targets
4. credential-broker bypass check: for destinations with a brokered
   credential, the agent must not smuggle its own Authorization header
5. request-shape validation (method, path prefix) per destination
6. approval binding: ``verify_card_binding`` on the presented action card
   plus a signature check on the approver's receipt
7. DLP tripwire on the request body
8. per-agent, per-destination byte budget

Every decision -- allow or deny -- emits a signed egress receipt into the
hash-chained audit feed. Deny codes are stable and dot-namespaced under
``egress.`` so the governance bench can assert on them machine-readably.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from action_card import ActionCard, verify_card_binding
from audit_chain import chain_records, sign_record
from canonical_json import jcs_canonical_json, jcs_sha256_hex
from ed25519 import sign as ed_sign
from ed25519 import verify as ed_verify
from permissions import digest_arguments

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 has tomllib; keep the import honest.
    tomllib = None  # type: ignore[assignment]

#: Schema markers.
EGRESS_POLICY_SCHEMA = "northstar.egress.v1"
EGRESS_RECEIPT_KIND = "egress-receipt/1"
APPROVAL_RECEIPT_KIND = "egress-approval-receipt/1"
POLICY_FILE_NAME = "northstar-egress.toml"

#: Stable, dot-namespaced deny codes. The governance bench asserts on these.
DENY_DESTINATION_DENIED = "egress.destination_denied"
DENY_UNRESOLVED = "egress.unresolved_destination"
DENY_SHAPE = "egress.shape_violation"
DENY_APPROVAL_BINDING = "egress.approval_binding_invalid"
DENY_DLP = "egress.dlp_hit"
DENY_BUDGET = "egress.budget_exceeded"
DENY_BYPASS = "egress.credentialless_bypass_attempt"

#: Headers the agent must never supply for a destination whose credential the
#: sidecar brokers. The sidecar injects the credential itself; an agent that
#: brings its own is trying to bypass the broker (possibly with a stolen key).
BROKERED_AUTH_HEADERS = frozenset({"authorization", "proxy-authorization"})

#: DLP tripwire patterns (regex, searched against the request body). This is
#: a tripwire, not a guarantee: it catches the common exfiltration shapes, it
#: does not prove a payload is clean.
DEFAULT_DLP_PATTERNS: tuple[str, ...] = (
    r"sk-[A-Za-z0-9]{20,}",  # OpenAI-style secret keys
    r"AKIA[0-9A-Z]{16}",  # AWS access key IDs
    r"xox[baprs]-[A-Za-z0-9-]{10,}",  # Slack tokens
    r"ghp_[A-Za-z0-9]{20,}",  # GitHub personal access tokens
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",  # PEM private keys
)

MAX_BODY_BYTES = 1_048_576  # 1 MiB cap on a single egress request body.
MAX_HEADER_CHARS = 8_192
RECEIPT_ID_BYTES = 16


class EgressPolicyError(ValueError):
    """A policy file or request that refuses to be loaded or honored."""


@dataclass(frozen=True)
class DestinationRule:
    """One allowlisted egress destination.

    ``hosts`` are the exact hostnames the agent may name (lowercased at load;
    no wildcards -- an allowlist entry must name what it means). ``ports``,
    ``methods`` and ``path_prefixes`` bound the request shape *at that
    destination*: allowlisting a host never exposes its admin endpoints.
    ``credential`` is a *reference* (``deploy-hook-token``), never a value;
    the sidecar resolves it from its own environment. ``allow_private_ips``
    opts a destination into intranet targets (default deny: SSRF guard).
    """

    name: str
    hosts: tuple[str, ...]
    ports: tuple[int, ...]
    methods: tuple[str, ...]
    path_prefixes: tuple[str, ...]
    require_approval: bool = False
    credential: str = ""
    max_bytes_per_day: int | None = None
    allow_private_ips: bool = False
    #: TLS for the upstream connection (default on). The sidecar dials the
    #: authorized IP and validates the certificate against the hostname.
    tls: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "hosts": list(self.hosts),
            "ports": list(self.ports),
            "methods": list(self.methods),
            "path_prefixes": list(self.path_prefixes),
            "require_approval": self.require_approval,
            "credential": self.credential,
            "max_bytes_per_day": self.max_bytes_per_day,
            "allow_private_ips": self.allow_private_ips,
            "tls": self.tls,
        }


@dataclass(frozen=True)
class EgressPolicy:
    """Versioned, sealed egress policy. Loaded fail-closed from TOML."""

    revision: str
    destinations: Mapping[str, DestinationRule]
    dlp_patterns: tuple[str, ...] = DEFAULT_DLP_PATTERNS

    def destination_for(self, host: str) -> DestinationRule | None:
        """Exact (case-insensitive) hostname lookup. No wildcards, no suffix
        matching: ``evil-example.com`` never matches ``example.com``."""
        wanted = str(host or "").strip().lower()
        if not wanted:
            return None
        for rule in self.destinations.values():
            if wanted in rule.hosts:
                return rule
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": EGRESS_POLICY_SCHEMA,
            "revision": self.revision,
            "destinations": {k: v.as_dict() for k, v in self.destinations.items()},
        }


def _compiled_dlp(patterns: Sequence[str]) -> tuple[re.Pattern[str], ...]:
    try:
        return tuple(re.compile(p) for p in patterns)
    except re.error as exc:
        raise EgressPolicyError(f"invalid DLP pattern: {exc}") from exc


def load_egress_policy(directory: str | Path) -> EgressPolicy:
    """Load and seal an egress policy. Fails closed on any defect.

    The policy file names credential *references* only. A ``credential`` value
    that looks like a secret (too long, wrong charset) is rejected at load:
    secrets live in the sidecar's environment, never in the policy file.
    """
    if tomllib is None:  # pragma: no cover - Python 3.10+ always has tomllib.
        raise EgressPolicyError("tomllib is unavailable")
    path = Path(directory) / POLICY_FILE_NAME
    if not path.is_file():
        raise EgressPolicyError(f"egress policy not found: {path}")
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EgressPolicyError(f"cannot parse egress policy {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise EgressPolicyError("egress policy root must be a table")
    schema = str(raw.get("schema_version", EGRESS_POLICY_SCHEMA))
    if schema != EGRESS_POLICY_SCHEMA:
        raise EgressPolicyError(f"unsupported egress policy schema: {schema!r}")
    revision = str(raw.get("revision", "")).strip()
    if not revision or len(revision) > 128:
        raise EgressPolicyError("egress policy requires a revision (<= 128 chars)")
    dest_raw = raw.get("destinations", {})
    if not isinstance(dest_raw, dict) or not dest_raw:
        raise EgressPolicyError("egress policy needs at least one [destinations.<name>] table")
    destinations: dict[str, DestinationRule] = {}
    seen_hosts: dict[str, str] = {}
    for name, table in dest_raw.items():
        rule = _load_destination_rule(str(name), table, seen_hosts)
        destinations[rule.name] = rule
    dlp_raw = raw.get("dlp_patterns", None)
    if dlp_raw is None:
        dlp_patterns = DEFAULT_DLP_PATTERNS
    else:
        if not isinstance(dlp_raw, list) or not all(isinstance(p, str) for p in dlp_raw):
            raise EgressPolicyError("dlp_patterns must be a list of strings")
        dlp_patterns = tuple(dlp_raw)
    _compiled_dlp(dlp_patterns)  # fail closed on a bad regex now, not at request time.
    return EgressPolicy(
        revision=revision,
        destinations=MappingProxyType(destinations),
        dlp_patterns=dlp_patterns,
    )


def _load_destination_rule(name: str, table: Any, seen_hosts: dict[str, str]) -> DestinationRule:
    if not name or len(name) > 64:
        raise EgressPolicyError("destination name must be 1-64 chars")
    if not isinstance(table, dict):
        raise EgressPolicyError(f"destination {name!r}: must be a table")
    hosts = _str_tuple(table.get("hosts"), f"destination {name!r}: hosts")
    if not hosts:
        raise EgressPolicyError(f"destination {name!r}: hosts must be non-empty")
    hosts = tuple(h.lower() for h in hosts)
    for marker in ("*",):
        if any(marker in h for h in hosts):
            raise EgressPolicyError(f"destination {name!r}: wildcard hosts are not allowed")
    for h in hosts:
        if h in seen_hosts:
            raise EgressPolicyError(
                f"destination {name!r}: host {h!r} already allowlisted under {seen_hosts[h]!r}"
            )
        seen_hosts[h] = name
    ports_raw = table.get("ports", ())
    if not isinstance(ports_raw, (list, tuple)) or not ports_raw:
        raise EgressPolicyError(f"destination {name!r}: ports must be a non-empty list")
    ports: list[int] = []
    for p in ports_raw:
        if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
            raise EgressPolicyError(f"destination {name!r}: invalid port {p!r}")
        ports.append(p)
    methods = _str_tuple(table.get("methods"), f"destination {name!r}: methods")
    if not methods:
        raise EgressPolicyError(f"destination {name!r}: methods must be non-empty")
    methods = tuple(m.upper() for m in methods)
    prefixes = _str_tuple(table.get("path_prefixes"), f"destination {name!r}: path_prefixes")
    if not prefixes:
        raise EgressPolicyError(f"destination {name!r}: path_prefixes must be non-empty")
    for prefix in prefixes:
        if not prefix.startswith("/"):
            raise EgressPolicyError(f"destination {name!r}: path prefix {prefix!r} must start with '/'")
    credential = str(table.get("credential", "") or "").strip()
    if credential and (len(credential) > 32 or not re.fullmatch(r"[A-Za-z0-9._-]+", credential)):
        raise EgressPolicyError(
            f"destination {name!r}: credential must be a short reference name "
            "(<= 32 chars; the value lives in the sidecar's environment, not the policy file)"
        )
    max_bytes = table.get("max_bytes_per_day", None)
    if max_bytes is not None:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
            raise EgressPolicyError(f"destination {name!r}: max_bytes_per_day must be a positive int")
    allow_private = table.get("allow_private_ips", False)
    if not isinstance(allow_private, bool):
        raise EgressPolicyError(f"destination {name!r}: allow_private_ips must be a bool")
    tls = table.get("tls", True)
    if not isinstance(tls, bool):
        raise EgressPolicyError(f"destination {name!r}: tls must be a bool")
    return DestinationRule(
        name=name,
        hosts=hosts,
        ports=tuple(ports),
        methods=methods,
        path_prefixes=prefixes,
        require_approval=bool(table.get("require_approval", False)),
        credential=credential,
        max_bytes_per_day=max_bytes,
        allow_private_ips=allow_private,
        tls=tls,
    )


def _str_tuple(value: Any, what: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) and v.strip() for v in value):
        raise EgressPolicyError(f"{what} must be a list of non-empty strings")
    return tuple(str(v).strip() for v in value)


@dataclass(frozen=True)
class ApprovalReceipt:
    """A signed binding between an approval decision and one action card.

    The enforcer never decides "was this approved by the right human" -- that
    is the runtime's separation gate (``action_card.resolve_card``). It only
    verifies the *cryptographic binding*: the receipt's signature (from the
    approver's key, which the sidecar holds as a public key in its config)
    covers ``(card_id, call_id, arguments_digest)``, and the receipt's digest
    must equal the card's digest. A replayed or mutated request fails closed.
    """

    card_id: str
    call_id: str
    arguments_digest: str
    approver_id: str
    decided_at: float
    signature: str  # hex Ed25519 over the canonical receipt body.

    def _signing_body(self) -> dict[str, Any]:
        return {
            "kind": APPROVAL_RECEIPT_KIND,
            "card_id": self.card_id,
            "call_id": self.call_id,
            "arguments_digest": self.arguments_digest,
            "approver_id": self.approver_id,
            "decided_at": self.decided_at,
        }

    def as_dict(self) -> dict[str, Any]:
        body = self._signing_body()
        body["signature"] = self.signature
        return body


def build_approval_receipt(
    *,
    card_id: str,
    call_id: str,
    arguments_digest: str,
    approver_id: str,
    approver_seed: bytes,
    decided_at: float | None = None,
) -> ApprovalReceipt:
    """Sign an approval receipt. Called by the approver's side (which holds
    the private key), never by the agent."""
    for label, value in (
        ("card_id", card_id),
        ("call_id", call_id),
        ("arguments_digest", arguments_digest),
        ("approver_id", approver_id),
    ):
        if not str(value or "").strip():
            raise EgressPolicyError(f"approval receipt needs a non-empty {label}")
    if not isinstance(approver_seed, (bytes, bytearray)) or len(approver_seed) != 32:
        raise EgressPolicyError("approver_seed must be a 32-byte Ed25519 seed")
    ts = time.time() if decided_at is None else float(decided_at)
    unsigned = ApprovalReceipt(
        card_id=str(card_id),
        call_id=str(call_id),
        arguments_digest=str(arguments_digest),
        approver_id=str(approver_id),
        decided_at=ts,
        signature="",
    )
    sig = ed_sign(bytes(approver_seed), jcs_canonical_json(unsigned._signing_body()))
    return ApprovalReceipt(
        card_id=unsigned.card_id,
        call_id=unsigned.call_id,
        arguments_digest=unsigned.arguments_digest,
        approver_id=unsigned.approver_id,
        decided_at=unsigned.decided_at,
        signature=sig.hex(),
    )


def verify_approval_receipt(receipt: ApprovalReceipt, approver_public_key: bytes) -> bool:
    """Verify an approval receipt's signature. False on any defect; never raises."""
    try:
        if not isinstance(approver_public_key, (bytes, bytearray)) or len(approver_public_key) != 32:
            return False
        signature = bytes.fromhex(receipt.signature)
        if len(signature) != 64:
            return False
        return bool(ed_verify(bytes(approver_public_key), jcs_canonical_json(receipt._signing_body()), signature))
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class EgressRequest:
    """One outbound request as the agent describes it.

    Every field here is *agent-supplied* except where the sidecar overrides:
    the sidecar resolves the hostname itself and authorizes the resolved
    address, so ``host`` is only a lookup key into the policy, never the
    authority for where bytes go.
    """

    request_id: str
    agent_id: str
    run_id: str
    host: str
    port: int
    method: str
    path: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""
    call_id: str = ""
    arguments: Mapping[str, Any] = field(default_factory=dict)
    card: ActionCard | None = None
    approval_receipt: ApprovalReceipt | None = None

    def shape_hash(self) -> str:
        return jcs_sha256_hex(
            {
                "method": str(self.method or "").upper(),
                "path": str(self.path or ""),
                "body_len": len(self.body or b""),
            }
        )


@dataclass(frozen=True)
class EgressVerdict:
    """The engine's decision on one request."""

    allowed: bool
    deny_code: str  # "" when allowed; "egress.*" when denied.
    reason: str
    dial_ips: tuple[str, ...]  # resolved, policy-permitted IPs; sidecar dials dial_ips[0].
    receipt: dict[str, Any]  # the chained (+optionally signed) egress receipt.
    receipt_id: str


class EgressBudgetLedger:
    """Per-agent, per-destination byte budgets, bucketed by UTC day.

    Mirrors ``budget.Budget``'s observe/exhausted shape, but counts *bytes*:
    ``budget.py`` prices LLM token spend, which is a different resource.
    """

    def __init__(self) -> None:
        self._counters: dict[tuple[str, str, int], int] = {}

    @staticmethod
    def _bucket(now: float) -> int:
        return int(now // 86400)

    def usage(self, agent_id: str, destination: str, *, now: float) -> int:
        return self._counters.get((agent_id, destination, self._bucket(now)), 0)

    def observe(self, agent_id: str, destination: str, nbytes: int, *, now: float, limit: int | None) -> bool:
        """Record ``nbytes`` against the budget. Returns False (and records
        nothing) when the observation would exceed ``limit``."""
        if limit is None:
            return True
        if nbytes < 0:
            return False
        key = (agent_id, destination, self._bucket(now))
        used = self._counters.get(key, 0)
        if used + nbytes > limit:
            return False
        self._counters[key] = used + nbytes
        return True


def _ip_permitted(ip_text: str, rule: DestinationRule) -> bool:
    """SSRF guard: refuse non-public targets unless the rule opts in."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    if rule.allow_private_ips:
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _deny(
    *,
    deny_code: str,
    reason: str,
    request: EgressRequest,
    policy: EgressPolicy,
    rule: DestinationRule | None,
    resolved_ips: Sequence[str],
    now: float,
    enforcer_seed: bytes | None,
    key_id: str | None,
    approval_binding: dict[str, Any] | None,
) -> EgressVerdict:
    receipt_id = secrets.token_hex(RECEIPT_ID_BYTES)
    receipt = _build_receipt(
        receipt_id=receipt_id,
        verdict="deny",
        deny_code=deny_code,
        reason=reason,
        request=request,
        policy=policy,
        rule=rule,
        resolved_ips=tuple(resolved_ips),
        dial_ips=(),
        now=now,
        approval_binding=approval_binding,
    )
    sealed = _seal_receipt(receipt, request=request, enforcer_seed=enforcer_seed, key_id=key_id)
    return EgressVerdict(
        allowed=False,
        deny_code=deny_code,
        reason=reason,
        dial_ips=(),
        receipt=sealed,
        receipt_id=receipt_id,
    )


def _build_receipt(
    *,
    receipt_id: str,
    verdict: str,
    deny_code: str,
    reason: str,
    request: EgressRequest,
    policy: EgressPolicy,
    rule: DestinationRule | None,
    resolved_ips: tuple[str, ...],
    dial_ips: tuple[str, ...],
    now: float,
    approval_binding: dict[str, Any] | None,
) -> dict[str, Any]:
    card = request.card
    return {
        "kind": EGRESS_RECEIPT_KIND,
        "receipt_id": receipt_id,
        "agent_id": request.agent_id,
        "run_id": request.run_id,
        "request_id": request.request_id,
        "action_id": card.card_id if card is not None else "",
        "call_id": request.call_id,
        "arguments_digest": card.arguments_digest if card is not None else digest_arguments(request.arguments),
        "resolved_destination": {
            "host": str(request.host or "").lower(),
            "port": request.port,
            "ips": list(resolved_ips),
            "dial_ips": list(dial_ips),
        },
        "request_shape_hash": request.shape_hash(),
        "destination_rule": rule.name if rule is not None else "",
        "policy_revision": policy.revision,
        "verdict": verdict,
        "deny_code": deny_code,
        "reason": reason,
        "approval_binding": approval_binding,
        "decided_at": now,
    }


def _seal_receipt(
    receipt: dict[str, Any],
    *,
    request: EgressRequest,
    enforcer_seed: bytes | None,
    key_id: str | None,
) -> dict[str, Any]:
    """Chain the receipt into the tamper-evident feed and sign it.

    Chain first, then sign: the signature covers the chain position too.
    An unsigned receipt (no enforcer key configured) is still hash-chained;
    the signature is the stronger claim, the chain is the baseline.
    """
    chained = chain_records(
        [receipt],
        component="egress",
        session_id=request.run_id or None,
        run_id=request.run_id or None,
        key_id=key_id,
    )
    sealed = chained[0]
    if enforcer_seed is not None:
        if not isinstance(enforcer_seed, (bytes, bytearray)) or len(enforcer_seed) != 32:
            raise EgressPolicyError("enforcer_seed must be a 32-byte Ed25519 seed")
        sealed = sign_record(sealed, bytes(enforcer_seed))
    return sealed


def authorize_egress(
    policy: EgressPolicy,
    request: EgressRequest,
    *,
    resolve: Callable[[str], list[str]],
    now: float,
    budgets: EgressBudgetLedger | None = None,
    approver_keys: Mapping[str, bytes] | None = None,
    enforcer_seed: bytes | None = None,
    key_id: str | None = None,
) -> EgressVerdict:
    """Decide one egress request. Pure: no sockets, no clock reads.

    ``resolve`` is the sidecar's own DNS resolver (injected so tests can pin
    answers); ``now`` is the sidecar's clock. Every denial carries a stable
    ``egress.*`` code and emits a chained receipt.
    """
    if not isinstance(policy, EgressPolicy):
        raise EgressPolicyError("policy must be an EgressPolicy")
    ts = float(now)
    approval_binding: dict[str, Any] | None = None

    def deny(code: str, reason: str, rule: DestinationRule | None = None, ips: Sequence[str] = ()) -> EgressVerdict:
        return _deny(
            deny_code=code,
            reason=reason,
            request=request,
            policy=policy,
            rule=rule,
            resolved_ips=ips,
            now=ts,
            enforcer_seed=enforcer_seed,
            key_id=key_id,
            approval_binding=approval_binding,
        )

    # 1. Destination rule lookup on the agent-named hostname (exact match).
    rule = policy.destination_for(request.host)
    if rule is None:
        return deny(DENY_DESTINATION_DENIED, f"host {request.host!r} is not in the egress allowlist")
    if request.port not in rule.ports:
        return deny(DENY_DESTINATION_DENIED, f"port {request.port} not allowlisted for {rule.name!r}", rule)

    # 2. Resolve via the sidecar's own resolver. Never the agent's address.
    try:
        resolved = [ip for ip in (resolve(request.host) or []) if str(ip).strip()]
    except Exception as exc:  # a failing resolver fails closed, never open.
        return deny(DENY_UNRESOLVED, f"resolver failed for {request.host!r}: {exc}", rule)
    if not resolved:
        return deny(DENY_UNRESOLVED, f"no addresses resolved for {request.host!r}", rule)

    # 3. CONNECT-time authorization on the resolved IPs (+ SSRF guard).
    dial_ips = tuple(ip for ip in resolved if _ip_permitted(ip, rule))
    if not dial_ips:
        return deny(
            DENY_DESTINATION_DENIED,
            f"resolved addresses for {request.host!r} are not permitted targets",
            rule,
            resolved,
        )

    # 4. Credential-broker bypass check: the agent must not bring its own
    #    Authorization header for a destination whose credential the sidecar
    #    brokers. The sidecar injects it; anything else is a bypass attempt.
    if rule.credential:
        supplied = {str(k or "").strip().lower() for k in (request.headers or {})}
        smuggled = sorted(supplied & BROKERED_AUTH_HEADERS)
        if smuggled:
            return deny(
                DENY_BYPASS,
                f"agent-supplied auth header(s) {smuggled} on brokered destination {rule.name!r}: "
                "the sidecar injects the credential",
                rule,
                resolved,
            )

    # 5. Request-shape validation at the allowlisted destination.
    method = str(request.method or "").upper()
    if method not in rule.methods:
        return deny(DENY_SHAPE, f"method {method!r} not allowed for {rule.name!r}", rule, resolved)
    path = str(request.path or "")
    if not path.startswith("/") or not any(path.startswith(p) for p in rule.path_prefixes):
        return deny(DENY_SHAPE, f"path {path!r} not allowlisted for {rule.name!r}", rule, resolved)
    body = request.body or b""
    if len(body) > MAX_BODY_BYTES:
        return deny(DENY_SHAPE, f"body {len(body)} bytes exceeds the {MAX_BODY_BYTES} cap", rule, resolved)

    # 6. Approval binding for destinations that require it.
    if rule.require_approval:
        card = request.card
        receipt = request.approval_receipt
        if card is None or receipt is None:
            return deny(
                DENY_APPROVAL_BINDING,
                f"destination {rule.name!r} requires an approved action card",
                rule,
                resolved,
            )
        keys = approver_keys or {}
        binding_ok = (
            secrets.compare_digest(str(receipt.card_id or ""), str(card.card_id or ""))
            and secrets.compare_digest(str(receipt.call_id or ""), str(request.call_id or ""))
            and secrets.compare_digest(str(receipt.arguments_digest or ""), str(card.arguments_digest or ""))
            and verify_card_binding(card, call_id=request.call_id, arguments=request.arguments)
            and str(receipt.approver_id or "") in keys
            and verify_approval_receipt(receipt, keys[str(receipt.approver_id or "")])
        )
        if not binding_ok:
            return deny(
                DENY_APPROVAL_BINDING,
                "approval receipt does not bind this card, call, and arguments",
                rule,
                resolved,
            )
        approval_binding = {"approver_id": receipt.approver_id, "card_id": card.card_id}

    # 7. DLP tripwire on the request body.
    if body:
        text = body.decode("utf-8", errors="replace")
        for pattern in _compiled_dlp(policy.dlp_patterns):
            if pattern.search(text):
                return deny(DENY_DLP, f"request body matches DLP tripwire {pattern.pattern!r}", rule, resolved)

    # 8. Byte budget.
    if budgets is not None and rule.max_bytes_per_day is not None:
        if not budgets.observe(request.agent_id, rule.name, len(body), now=ts, limit=rule.max_bytes_per_day):
            return deny(
                DENY_BUDGET,
                f"byte budget exceeded for {request.agent_id!r} on {rule.name!r}",
                rule,
                resolved,
            )

    # Allow: build, chain, and sign the receipt.
    receipt_id = secrets.token_hex(RECEIPT_ID_BYTES)
    receipt = _build_receipt(
        receipt_id=receipt_id,
        verdict="allow",
        deny_code="",
        reason=f"allowed by {rule.name!r} (policy {policy.revision})",
        request=request,
        policy=policy,
        rule=rule,
        resolved_ips=tuple(resolved),
        dial_ips=dial_ips,
        now=ts,
        approval_binding=approval_binding,
    )
    sealed = _seal_receipt(receipt, request=request, enforcer_seed=enforcer_seed, key_id=key_id)
    return EgressVerdict(
        allowed=True,
        deny_code="",
        reason=f"allowed by {rule.name!r}",
        dial_ips=dial_ips,
        receipt=sealed,
        receipt_id=receipt_id,
    )


def policy_file_path(directory: str | Path) -> Path:
    """Where ``load_egress_policy`` looks."""
    return Path(directory) / POLICY_FILE_NAME


def card_from_dict(value: Any) -> ActionCard:
    """Rebuild an :class:`ActionCard` from its ``as_dict()`` form.

    The sidecar receives the card over the Unix socket and must re-verify the
    binding against the actual request arguments. Reconstruction is strict:
    anything malformed raises :class:`EgressPolicyError` and the request fails
    closed. A forged card alone grants nothing -- for destinations that
    require approval, the approver's signature (which the agent never holds)
    is what the enforcer checks.
    """
    from action_card import ActionProvenance, GateCheck, GateDecision

    if not isinstance(value, dict):
        raise EgressPolicyError("card must be a mapping")
    try:
        provenance_raw = value["provenance"]
        gate_raw = value["gate"]
        provenance = ActionProvenance(
            agent=str(provenance_raw.get("agent", "")),
            session_id=str(provenance_raw.get("session_id", "")),
            turn_index=int(provenance_raw.get("turn_index", 0)),
            depth=int(provenance_raw.get("depth", 0)),
            delegation_chain=tuple(str(x) for x in provenance_raw.get("delegation_chain", ())),
        )
        gate = GateDecision(
            would_auto_approve=bool(gate_raw.get("would_auto_approve", False)),
            auto_approved=bool(gate_raw.get("auto_approved", False)),
            policy_basis=str(gate_raw.get("policy_basis", "")),
            checks=tuple(
                GateCheck(
                    id=str(c.get("id", "")),
                    passed=bool(c.get("passed", False)),
                    detail=str(c.get("detail", "")),
                )
                for c in gate_raw.get("checks", ())
            ),
        )
        return ActionCard(
            card_id=str(value["card_id"]),
            tool=str(value["tool"]),
            call_id=str(value["call_id"]),
            arguments_digest=str(value["arguments_digest"]),
            risk_tier=str(value.get("risk_tier", "unknown")),
            provenance=provenance,
            gate=gate,
            agent_hint=str(value.get("agent_hint_untrusted", "")),
            created_unix=float(value.get("created_unix", 0.0)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise EgressPolicyError(f"malformed action card: {exc}") from exc


def approval_receipt_from_dict(value: Any) -> ApprovalReceipt:
    """Rebuild an :class:`ApprovalReceipt` from its ``as_dict()`` form."""
    if not isinstance(value, dict):
        raise EgressPolicyError("approval receipt must be a mapping")
    try:
        return ApprovalReceipt(
            card_id=str(value["card_id"]),
            call_id=str(value["call_id"]),
            arguments_digest=str(value["arguments_digest"]),
            approver_id=str(value["approver_id"]),
            decided_at=float(value["decided_at"]),
            signature=str(value["signature"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise EgressPolicyError(f"malformed approval receipt: {exc}") from exc
