"""Egress sidecar: the only process that may open outbound network connections.

The agent process has no direct network route (deployment requirement,
verified by ``doctor --check-egress``). Every outbound connection is a
Unix-socket request to this daemon carrying the action-card ID and approval
binding. The sidecar:

1. validates the wire request (bounded, typed, no code or env smuggling);
2. resolves DNS *itself* -- never the agent's word for the address;
3. authorizes via :mod:`egress_enforcer` against the real resolved
   destination at CONNECT time (destination, shape, approval binding,
   DLP tripwire, byte budget);
4. dials the authorized IP directly (TLS with SNI=hostname, certificate
   validated against the hostname -- no TOCTOU re-resolution);
5. injects the brokered credential server-side (the agent never sees it);
6. returns the response with the credential scrubbed, plus the signed
   egress receipt.

Credential store: environment variables ``NORTHSTAR_EGRESS_CRED_<NAME>``
where ``<NAME>`` is the uppercased credential reference from the policy with
non-alphanumerics mapped to ``_``. Read once at startup into memory; never
logged, never returned to the caller.

Import note: the policy engine lives in the ``northstar-agent-runtime``
component (it reuses ``action_card``, ``audit_chain``, ``canonical_json``,
``ed25519``). Set ``NORTHSTAR_RUNTIME_DIR`` to that component's directory;
the systemd unit does this. As a fallback the sidecar looks next to its own
file (``../northstar-agent-runtime``), which covers a source checkout.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _runtime_dir() -> Path:
    override = os.environ.get("NORTHSTAR_RUNTIME_DIR", "").strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / "northstar-agent-runtime"


_RUNTIME = _runtime_dir()
if str(_RUNTIME) not in sys.path:
    sys.path.insert(0, str(_RUNTIME))

from egress_enforcer import (  # noqa: E402
    BROKERED_AUTH_HEADERS,
    EgressBudgetLedger,
    EgressPolicy,
    EgressPolicyError,
    EgressRequest,
    EgressVerdict,
    approval_receipt_from_dict,
    authorize_egress,
    card_from_dict,
    load_egress_policy,
)

# Wire bounds. The engine caps bodies at 1 MiB; the transport caps the line.
MAX_BODY_B64_CHARS = 1_800_000  # ~1.3 MiB of base64, headroom over the 1 MiB body cap.
MAX_HEADERS = 32
MAX_HEADER_NAME_CHARS = 128
MAX_HEADER_VALUE_CHARS = 8_192
MAX_RESPONSE_BYTES = 4_194_304  # 4 MiB; responses may be larger than requests.
MIN_TIMEOUT_MS = 1_000
MAX_TIMEOUT_MS = 120_000
CONNECT_TIMEOUT_S = 10.0

SOCKET_NAME = "egress.sock"
SOCKET_ROOT = Path("/var/run/northstar-egress")

_CRED_ENV_PREFIX = "NORTHSTAR_EGRESS_CRED_"


@dataclass
class RequestValidation:
    ok: bool
    errors: tuple[str, ...] = ()


def _cred_env_name(reference: str) -> str:
    return _CRED_ENV_PREFIX + re.sub(r"[^A-Za-z0-9]", "_", reference).upper()


class CredentialStore:
    """Brokered credentials, held only in the sidecar process."""

    def __init__(self, references: set[str]) -> None:
        self._values: dict[str, str] = {}
        for ref in references:
            value = os.environ.get(_cred_env_name(ref), "")
            if value:
                self._values[ref] = value

    def get(self, reference: str) -> str | None:
        return self._values.get(reference)

    def known_values(self) -> tuple[str, ...]:
        return tuple(self._values.values())


class SidecarContext:
    """Everything the sidecar needs beyond one request."""

    def __init__(
        self,
        *,
        policy: EgressPolicy,
        credentials: CredentialStore,
        approver_keys: dict[str, bytes],
        enforcer_seed: bytes | None,
        key_id: str | None = None,
        resolver: Any | None = None,
    ) -> None:
        self.policy = policy
        self.credentials = credentials
        self.approver_keys = approver_keys
        self.enforcer_seed = enforcer_seed
        self.key_id = key_id
        self.budgets = EgressBudgetLedger()
        self._resolver = resolver or _system_resolver

    def resolve(self, host: str) -> list[str]:
        return self._resolver(host)


def _system_resolver(host: str) -> list[str]:
    """The sidecar's own DNS resolution. One lookup, reused for dialing --
    the authorized address is the connected address (no TOCTOU)."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    seen: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    return seen


def classify_request(value: Any) -> RequestValidation:
    """Validate the wire request. Narrow by construction: only the declared
    fields are read; shell commands, environment data, and tool declarations
    are not accepted from the caller."""
    errors: list[str] = []
    if not isinstance(value, dict):
        return RequestValidation(False, ("request must be a JSON object",))

    def need(name: str, types: tuple[type, ...]) -> Any:
        v = value.get(name)
        if v is None or not isinstance(v, types) or (isinstance(v, str) and not v.strip()):
            errors.append(f"{name} is required")
            return None
        return v

    request_id = need("request_id", (str,))
    if isinstance(request_id, str) and len(request_id) > 128:
        errors.append("request_id too long")
    need("agent_id", (str,))
    need("run_id", (str,))
    host = need("host", (str,))
    if isinstance(host, str) and len(host) > 253:
        errors.append("host too long")
    port = value.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        errors.append("port must be an integer 1-65535")
    method = need("method", (str,))
    if isinstance(method, str) and (not method.strip() or len(method) > 16):
        errors.append("method malformed")
    path = need("path", (str,))
    if isinstance(path, str) and (not path.startswith("/") or len(path) > 4_096):
        errors.append("path must start with '/' and stay bounded")

    headers = value.get("headers", {})
    if not isinstance(headers, dict):
        errors.append("headers must be an object")
    else:
        if len(headers) > MAX_HEADERS:
            errors.append("too many headers")
        for k, v in headers.items():
            if not isinstance(k, str) or not isinstance(v, str):
                errors.append("header names and values must be strings")
                break
            if len(k) > MAX_HEADER_NAME_CHARS or len(v) > MAX_HEADER_VALUE_CHARS:
                errors.append("header too long")
                break

    body_b64 = value.get("body_b64", "")
    if not isinstance(body_b64, str):
        errors.append("body_b64 must be a string")
    elif len(body_b64) > MAX_BODY_B64_CHARS:
        errors.append("body_b64 too long")
    else:
        try:
            base64.b64decode(body_b64, validate=True) if body_b64 else b""
        except (binascii.Error, ValueError):
            errors.append("body_b64 is not valid base64")

    timeout_ms = value.get("timeout_ms", 30_000)
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool):
        errors.append("timeout_ms must be an integer")
    elif not MIN_TIMEOUT_MS <= timeout_ms <= MAX_TIMEOUT_MS:
        errors.append("timeout_ms outside the permitted range")

    for name in ("card", "approval_receipt"):
        v = value.get(name)
        if v is not None and not isinstance(v, dict):
            errors.append(f"{name} must be an object when present")
    arguments = value.get("arguments", {})
    if not isinstance(arguments, dict):
        errors.append("arguments must be an object")

    return RequestValidation(not errors, tuple(errors))


def _to_egress_request(value: dict[str, Any]) -> EgressRequest:
    body = base64.b64decode(value.get("body_b64", "") or "", validate=True)
    card = None
    if value.get("card") is not None:
        card = card_from_dict(value["card"])
    receipt = None
    if value.get("approval_receipt") is not None:
        receipt = approval_receipt_from_dict(value["approval_receipt"])
    headers = {str(k): str(v) for k, v in (value.get("headers") or {}).items()}
    return EgressRequest(
        request_id=str(value["request_id"]),
        agent_id=str(value["agent_id"]),
        run_id=str(value["run_id"]),
        host=str(value["host"]),
        port=int(value["port"]),
        method=str(value["method"]),
        path=str(value["path"]),
        headers=headers,
        body=body,
        call_id=str(value.get("call_id", "")),
        arguments=dict(value.get("arguments") or {}),
        card=card,
        approval_receipt=receipt,
    )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to the authorized IP, with SNI and cert validation against the
    hostname. The TCP connection goes to ``dial_ip`` (the address the
    enforcer authorized); the TLS handshake still names the real host, so
    certificate validation is unchanged and no second DNS lookup happens."""

    def __init__(self, host: str, port: int, dial_ip: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._dial_ip = dial_ip

    def connect(self) -> None:
        raw = socket.create_connection((self._dial_ip, self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain HTTP to the authorized IP (the Host header still names the host)."""

    def __init__(self, host: str, port: int, dial_ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._dial_ip = dial_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._dial_ip, self.port), timeout=self.timeout)


def _perform_http(
    *,
    host: str,
    dial_ip: str,
    port: int,
    tls: bool,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    timeout_s: float,
) -> tuple[int, dict[str, str], bytes, bool]:
    """Execute the authorized request. Returns (status, headers, body, truncated)."""
    if tls:
        context = ssl.create_default_context()
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(host, port, dial_ip, timeout_s, context)
    else:
        conn = _PinnedHTTPConnection(host, port, dial_ip, timeout_s)
    try:
        conn.request(method, path, body=body or None, headers=headers)
        response = conn.getresponse()
        status = response.status
        resp_headers = {k.lower(): v for k, v in response.getheaders()}
        chunks: list[bytes] = []
        remaining = MAX_RESPONSE_BYTES + 1
        truncated = False
        while remaining > 0:
            chunk = response.read(min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        else:
            truncated = True
        return status, resp_headers, b"".join(chunks)[:MAX_RESPONSE_BYTES], truncated
    finally:
        conn.close()


def _scrub(value: str, secrets_: tuple[str, ...]) -> str:
    for secret in secrets_:
        if secret and secret in value:
            value = value.replace(secret, "[REDACTED]")
    return value


def run_one(value: dict[str, Any], ctx: SidecarContext) -> dict[str, Any]:
    """Handle one validated wire request. Never raises: failures are
    encoded as ``status: denied | error`` with a receipt when one exists."""
    request_id = value.get("request_id") if isinstance(value, dict) else None
    validation = classify_request(value)
    if not validation.ok:
        return {
            "request_id": request_id,
            "status": "rejected",
            "errors": list(validation.errors),
        }
    try:
        request = _to_egress_request(value)
    except EgressPolicyError as exc:
        return {"request_id": request_id, "status": "rejected", "errors": [str(exc)]}

    now = time.time()
    try:
        verdict: EgressVerdict = authorize_egress(
            ctx.policy,
            request,
            resolve=ctx.resolve,
            now=now,
            budgets=ctx.budgets,
            approver_keys=ctx.approver_keys,
            enforcer_seed=ctx.enforcer_seed,
            key_id=ctx.key_id,
        )
    except EgressPolicyError as exc:  # fail closed on engine misuse.
        return {"request_id": request_id, "status": "error", "error": str(exc)}

    if not verdict.allowed:
        return {
            "request_id": request_id,
            "status": "denied",
            "deny_code": verdict.deny_code,
            "reason": verdict.reason,
            "receipt": verdict.receipt,
        }

    rule = ctx.policy.destination_for(request.host)
    assert rule is not None  # authorized, so the rule exists.
    headers = dict(request.headers)
    credential_value: str | None = None
    if rule.credential:
        # The engine already rejected agent-supplied Authorization headers for
        # brokered destinations; inject the real credential here, in the
        # sidecar, where the agent cannot see it.
        credential_value = ctx.credentials.get(rule.credential)
        if credential_value is None:
            return {
                "request_id": request_id,
                "status": "error",
                "error": f"credential {rule.credential!r} is not configured in the sidecar",
                "receipt": verdict.receipt,
            }
        headers["authorization"] = f"Bearer {credential_value}"
    # The Host header names the host; the socket goes to the authorized IP.
    # E7: force, never setdefault — an agent-supplied Host could route a
    # brokered credential to an attacker vhost on shared-IP/CDN hosting
    # while TLS still validates request.host.
    headers["host"] = request.host
    headers["user-agent"] = "northstar-egress-sidecar/1"
    headers.setdefault("connection", "close")

    timeout_s = min(max(int(value.get("timeout_ms", 30_000)) / 1000.0, 1.0), 120.0)
    try:
        status, resp_headers, resp_body, truncated = _perform_http(
            host=request.host,
            dial_ip=verdict.dial_ips[0],
            port=request.port,
            tls=rule.tls,
            method=request.method.upper(),
            path=request.path,
            headers=headers,
            body=request.body,
            timeout_s=timeout_s,
        )
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return {
            "request_id": request_id,
            "status": "error",
            "error": f"upstream request failed: {type(exc).__name__}",
            "receipt": verdict.receipt,
        }

    # Credential reflection guard: a malicious endpoint must not be able to
    # bounce the brokered credential back to the agent.
    scrubbed_headers = {k: _scrub(v, ctx.credentials.known_values()) for k, v in resp_headers.items()}
    body_text = resp_body.decode("utf-8", errors="replace")
    scrubbed_text = _scrub(body_text, ctx.credentials.known_values())
    scrubbed_body = scrubbed_text.encode("utf-8", errors="replace")

    return {
        "request_id": request_id,
        "status": "ok",
        "http_status": status,
        "headers": scrubbed_headers,
        "body_b64": base64.b64encode(scrubbed_body).decode("ascii"),
        "truncated": truncated,
        "receipt": verdict.receipt,
    }


def build_context(
    *,
    policy_dir: str | Path,
    approver_keys: dict[str, bytes] | None = None,
    enforcer_seed: bytes | None = None,
    key_id: str | None = None,
) -> SidecarContext:
    """Build the sidecar context from on-disk config + environment."""
    policy = load_egress_policy(policy_dir)
    references = {rule.credential for rule in policy.destinations.values() if rule.credential}
    credentials = CredentialStore(references)
    missing = sorted(ref for ref in references if credentials.get(ref) is None)
    if missing:
        raise EgressPolicyError(
            "sidecar refuses to start: credential(s) not in the environment: "
            + ", ".join(f"NORTHSTAR_EGRESS_CRED_{re.sub(r'[^A-Za-z0-9]', '_', m).upper()}" for m in missing)
        )
    return SidecarContext(
        policy=policy,
        credentials=credentials,
        approver_keys=dict(approver_keys or {}),
        enforcer_seed=enforcer_seed,
        key_id=key_id,
    )
