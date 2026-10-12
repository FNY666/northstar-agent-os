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
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


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
    FORBIDDEN_EGRESS_HEADERS,
    _HTTP_TOKEN_RE,
    _valid_egress_hostname,
    approval_receipt_from_dict,
    authorize_egress,
    build_rejection_receipt,
    card_from_dict,
    load_egress_policy,
)
from audit_chain import (  # noqa: E402
    CHAIN_VERSION_V2,
    chain_record,
    chain_records,
    verify_lines,
)
from canonical_json import jcs_canonical_json  # noqa: E402
from ed25519 import public_key as ed25519_public_key  # noqa: E402

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


class ReceiptFeed:
    """Persistent, append-only JSONL feed of egress receipts.

    Every receipt the sidecar issues -- allowed, denied, rejected, or
    error -- is appended here, so an auditor can reconstruct the full
    egress history even across sidecar restarts. Thread-safe: the socket
    server dispatches requests on a thread pool.

    Each inner receipt retains its own engine seal. An outer sidecar-level
    chain links feed entries in append order, so deleting, reordering, or
    changing entries breaks ``audit_chain.verify_lines``. Startup verifies
    the chain and migrates valid legacy singleton receipts before accepting
    new requests.

    Append failures are reported to the caller and recorded on the instance
    (``last_error``). Allowed egress must persist its authorization receipt
    before opening the upstream connection; feed failure therefore blocks
    that network side effect.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        enforcer_seed: bytes | None = None,
        key_id: str | None = None,
        trusted_public_keys: Mapping[str, bytes] | None = None,
    ) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._receipt_digests: dict[str, None] = {}
        self.last_error: str | None = None
        self.appended = 0
        self.enforcer_seed = bytes(enforcer_seed) if enforcer_seed is not None else None
        self.key_id = key_id
        self.trusted_public_keys = {str(k): bytes(v) for k, v in (trusted_public_keys or {}).items()}
        if self.enforcer_seed is not None:
            current_public_key = ed25519_public_key(self.enforcer_seed)
            current_lookup_id = key_id or "__legacy_default__"
            configured = self.trusted_public_keys.get(current_lookup_id)
            if configured is not None and configured != current_public_key:
                raise EgressPolicyError(f"trusted public key for {current_lookup_id!r} conflicts with signing seed")
            self.trusted_public_keys[current_lookup_id] = current_public_key
        self._session_id = "egress-feed:" + hashlib.sha256(str(self.path.resolve()).encode()).hexdigest()[:24]
        self._tail_hash: str | None = None
        self._load_and_verify()

    def _public_keys(self) -> dict[str, bytes] | None:
        if not self.trusted_public_keys:
            return None
        return self.trusted_public_keys

    def _load_and_verify(self) -> None:
        if not self.path.exists():
            return
        try:
            with self.path.open("rb") as handle:
                first_line = handle.readline()
                if not first_line:
                    return
                first_record = json.loads(first_line.decode("utf-8"))
        except EgressPolicyError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EgressPolicyError(f"cannot read egress receipt feed: {type(exc).__name__}") from exc
        if not isinstance(first_record, dict):
            raise EgressPolicyError("egress receipt feed contains a non-object record")
        if first_record.get("feed_format") == "northstar.egress-feed/2":
            try:
                with self.path.open("rb") as handle:
                    result = verify_lines(
                        (line.decode("utf-8", "strict") for line in handle),
                        public_key=self._public_keys(),
                        expect_session_id=self._session_id,
                        require_signatures=self.enforcer_seed is not None,
                    )
                    if not result.ok:
                        raise EgressPolicyError(f"egress receipt feed chain is invalid: {result.reason}")
                    self.appended = result.chained
                    handle.seek(0)
                    last_record = None
                    for line in handle:
                        if line.strip():
                            last_record = json.loads(line.decode("utf-8", "strict"))
                if not isinstance(last_record, dict):
                    raise EgressPolicyError("egress receipt feed has no final chained record")
                self._tail_hash = str(last_record["chain_hash"])
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError) as exc:
                raise EgressPolicyError(f"cannot verify egress receipt feed: {type(exc).__name__}") from exc
            return

        # Previous versions wrote each receipt as its own singleton chain.
        # Verify every surviving receipt independently, then preserve it as a
        # nested object in one newly linked feed. This cannot recover history
        # already deleted from the legacy file, but it prevents further gaps.
        self._migrate_legacy()

    def _migrate_legacy(self) -> None:
        temporary = self.path.with_name(f".{self.path.name}.migrate-{os.getpid()}")
        self._tail_hash = None
        self.appended = 0
        try:
            with self.path.open("rb") as source, open(temporary, "xb") as target:
                for index, line in enumerate(source, 1):
                    if not line.endswith(b"\n"):
                        raise EgressPolicyError(f"legacy egress receipt {index} is not newline terminated")
                    try:
                        receipt = json.loads(line.decode("utf-8", "strict"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise EgressPolicyError(f"legacy egress receipt {index} is malformed") from exc
                    if not isinstance(receipt, dict):
                        raise EgressPolicyError(f"legacy egress receipt {index} is not an object")
                    # Historical deployments could run without a signing
                    # seed. Preserve their hash-chain integrity during
                    # migration, while still verifying any signature that is
                    # present against the configured production key.
                    legacy_public_keys = self._public_keys() if "signature" in receipt else None
                    verified = verify_lines([line.decode("utf-8")], public_key=legacy_public_keys)
                    if not verified.ok:
                        raise EgressPolicyError(f"legacy egress receipt {index} is invalid: {verified.reason}")
                    entry = self._make_entry(receipt, sequence=index)
                    target.write((json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
                    self._tail_hash = str(entry["chain_hash"])
                    self.appended += 1
                    self._remember_digest(entry["receipt_digest"])
                target.flush()
                os.fsync(target.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            try:
                temporary.unlink()
            except OSError:
                pass
            self._tail_hash = None
            self.appended = 0
            self._receipt_digests.clear()
            raise

    def _make_entry(
        self,
        receipt: dict[str, Any],
        *,
        sequence: int,
    ) -> dict[str, Any]:
        try:
            receipt_digest = hashlib.sha256(jcs_canonical_json(receipt)).hexdigest()
        except (TypeError, ValueError) as exc:
            raise EgressPolicyError("receipt is not canonical JSON") from exc
        body: dict[str, Any] = {
            "feed_format": "northstar.egress-feed/2",
            "feed_sequence": sequence,
            "kind": receipt.get("kind", "egress-feed-entry/2"),
            "request_id": receipt.get("request_id", ""),
            "receipt_id": receipt.get("receipt_id", ""),
            "receipt_digest": receipt_digest,
            "receipt": receipt,
        }
        if self._tail_hash is None:
            entries = chain_records(
                [body],
                component="egress-sidecar",
                session_id=self._session_id,
                key_id=self.key_id,
            )
            chained = entries[0]
        else:
            body["chain"] = CHAIN_VERSION_V2
            if self.key_id is not None:
                body["key_id"] = self.key_id
            chained = chain_record(body, self._tail_hash, chain_version=CHAIN_VERSION_V2)
        if self.enforcer_seed is not None:
            from audit_chain import sign_record

            chained = sign_record(chained, self.enforcer_seed, key_id=self.key_id)
        return chained

    def _remember_digest(self, digest: str) -> None:
        self._receipt_digests[digest] = None
        if len(self._receipt_digests) > 4096:
            self._receipt_digests.pop(next(iter(self._receipt_digests)))

    def append(self, receipt: dict[str, Any]) -> bool:
        """Append one receipt. Returns True on success."""
        try:
            digest = hashlib.sha256(jcs_canonical_json(receipt)).hexdigest()
        except (TypeError, ValueError) as exc:
            self.last_error = f"serialize: {exc}"
            return False
        try:
            with self._lock:
                if digest in self._receipt_digests:
                    return True
                self.path.parent.mkdir(parents=True, exist_ok=True)
                entry = self._make_entry(receipt, sequence=self.appended + 1)
                data = (json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
                with open(self.path, "ab") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                self.appended += 1
                self._remember_digest(digest)
                self._tail_hash = str(entry["chain_hash"])
        except OSError as exc:
            self.last_error = f"write: {exc}"
            return False
        self.last_error = None
        return True


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
        receipt_feed: ReceiptFeed | None = None,
    ) -> None:
        self.policy = policy
        self.credentials = credentials
        self.approver_keys = approver_keys
        self.enforcer_seed = enforcer_seed
        self.key_id = key_id
        self.budgets = EgressBudgetLedger()
        self._resolver = resolver or _system_resolver
        self.receipt_feed = receipt_feed

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
    if isinstance(host, str) and not _valid_egress_hostname(host):
        errors.append("host must be a canonical DNS-style ASCII hostname")
    port = value.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        errors.append("port must be an integer 1-65535")
    method = need("method", (str,))
    if isinstance(method, str) and (len(method) > 16 or not _HTTP_TOKEN_RE.fullmatch(method)):
        errors.append("method malformed")
    path = need("path", (str,))
    if isinstance(path, str) and (
        not path.startswith("/") or path.startswith("//") or len(path) > 4_096
        or "#" in path or any(ord(char) < 0x21 or ord(char) > 0x7e for char in path)
    ):
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
            if not _HTTP_TOKEN_RE.fullmatch(k):
                errors.append("header name is malformed")
                break
            if k.lower() in FORBIDDEN_EGRESS_HEADERS:
                errors.append(f"header {k.lower()} is managed by the sidecar")
                break
            if any((ord(char) < 0x20 and char != "\t") or ord(char) > 0xff for char in v):
                errors.append("header value contains a control character")
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


def _scrub_bytes(value: bytes, secrets_: tuple[str, ...]) -> bytes:
    """Scrub UTF-8 credential reflections without corrupting binary bodies."""
    for secret in secrets_:
        encoded = secret.encode("utf-8") if secret else b""
        if encoded and encoded in value:
            value = value.replace(encoded, b"[REDACTED]")
    return value


def _run_one_inner(value: dict[str, Any], ctx: SidecarContext) -> dict[str, Any]:
    """Handle one validated wire request. Never raises: failures are
    encoded as ``status: denied | error`` with a receipt when one exists."""
    request_id = value.get("request_id") if isinstance(value, dict) else None
    validation = classify_request(value)
    if not validation.ok:
        return {
            "request_id": request_id,
            "status": "rejected",
            "errors": list(validation.errors),
            "receipt": build_rejection_receipt(
                raw_value=value,
                errors=list(validation.errors),
                request_id=request_id,
                now=time.time(),
                policy_revision=ctx.policy.revision,
                enforcer_seed=ctx.enforcer_seed,
                key_id=ctx.key_id,
            ),
        }
    try:
        request = _to_egress_request(value)
    except EgressPolicyError as exc:
        return {
            "request_id": request_id,
            "status": "rejected",
            "errors": [str(exc)],
            "receipt": build_rejection_receipt(
                raw_value=value,
                errors=[str(exc)],
                request_id=request_id,
                now=time.time(),
                policy_revision=ctx.policy.revision,
                enforcer_seed=ctx.enforcer_seed,
                key_id=ctx.key_id,
            ),
        }

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

    # The authorization decision is itself security-relevant. Make it
    # durable before any credential is attached or socket is opened; if the
    # audit sink is unavailable, do not perform the authorized side effect.
    if ctx.receipt_feed is not None and not ctx.receipt_feed.append(verdict.receipt):
        return {
            "request_id": request_id,
            "status": "error",
            "error": "authorization receipt could not be persisted; outbound request was not sent",
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
    headers["connection"] = "close"

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
    scrubbed_body = _scrub_bytes(resp_body, ctx.credentials.known_values())

    return {
        "request_id": request_id,
        "status": "ok",
        "http_status": status,
        "headers": scrubbed_headers,
        "body_b64": base64.b64encode(scrubbed_body).decode("ascii"),
        "truncated": truncated,
        "receipt": verdict.receipt,
    }


def run_one(value: dict[str, Any], ctx: SidecarContext) -> dict[str, Any]:
    """Handle one wire request and persist receipts not already prewritten.

    Allowed receipts are durably appended inside :func:`_run_one_inner`
    before network I/O. This wrapper records rejected and denied requests,
    which have no upstream side effect to guard. Keeping the two paths
    explicit avoids relying on a bounded digest cache to suppress a second
    append after slow, concurrent requests.
    """
    response = _run_one_inner(value, ctx)
    feed = ctx.receipt_feed
    receipt = response.get("receipt")
    if feed is not None and response.get("status") in {"rejected", "denied"} and isinstance(receipt, dict):
        feed.append(receipt)
    return response


def build_context(
    *,
    policy_dir: str | Path,
    approver_keys: dict[str, bytes] | None = None,
    enforcer_seed: bytes | None = None,
    key_id: str | None = None,
    trusted_public_keys: Mapping[str, bytes] | None = None,
    receipt_feed_path: str | Path | None = None,
) -> SidecarContext:
    """Build the sidecar context from on-disk config + environment.

    ``receipt_feed_path`` enables the persistent receipt feed; when None,
    receipts are returned to callers but not persisted (useful for tests).
    """
    policy = load_egress_policy(policy_dir)
    references = {rule.credential for rule in policy.destinations.values() if rule.credential}
    credentials = CredentialStore(references)
    missing = sorted(ref for ref in references if credentials.get(ref) is None)
    if missing:
        raise EgressPolicyError(
            "sidecar refuses to start: credential(s) not in the environment: "
            + ", ".join(f"NORTHSTAR_EGRESS_CRED_{re.sub(r'[^A-Za-z0-9]', '_', m).upper()}" for m in missing)
        )
    feed = (
        ReceiptFeed(
            receipt_feed_path,
            enforcer_seed=enforcer_seed,
            key_id=key_id,
            trusted_public_keys=trusted_public_keys,
        )
        if receipt_feed_path
        else None
    )
    return SidecarContext(
        policy=policy,
        credentials=credentials,
        approver_keys=dict(approver_keys or {}),
        enforcer_seed=enforcer_seed,
        key_id=key_id,
        receipt_feed=feed,
    )
