"""Per-call authorization and approval gateway for the durable-run slice.

The gateway treats model-produced ToolCall data and tool output as untrusted.
It validates the call, re-verifies a host authorization grant, enforces the
registered tool's exact capability/scope/resource contract, and only then
invokes a host-registered executor supplied by the caller. When a
``ToolAllowlist`` is bound, an OpenShell-style pre-execution validation
(tool name + parameter patterns, fail-closed) runs as the final gate before
the executor, and every decision is traced in ``enforcement_trace``.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import shutil
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from authorization import verify_authorization
from contract import _valid_id, validate_run_request
from tool_allowlist import (
    ENFORCEMENT_TRACE_MAX,
    EnforcementDecision,
    EnforcementGate,
    ToolAllowlist,
    make_enforcement_event,
)
from timelock import Timelock
from tool_receipt import make_tool_receipt, receipt_audit_record

TOOL_CALL_SCHEMA_VERSION = "northstar.tool-call.v1"
#: v3 binds the approval to the exact approved call identity: v2 approvals
#: pinned the arguments but not the idempotency key, so one approval token
#: could authorize the same payload to execute again under a new
#: idempotency key (the executor ran twice). v3 ties the token to the
#: single call identity; a replay with a different key is refused, and a
#: replay with the same key hits the idempotency cache, so the executor
#: runs at most once per approval.
APPROVAL_SCHEMA_VERSION = "northstar.approval.v3"
_ID_RE = re.compile(r"^[^\s/\\]+$")
_SCOPE_RE = re.compile(r"^[^\s/\\:]+:[^\s/\\:]+$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_SCOPE_ENTRIES = 64
_MAX_ARGUMENT_BYTES = 256_000

_TOOL_CALL_FIELDS = {
    "schema_version",
    "task_id",
    "thread_id",
    "run_id",
    "step_id",
    "actor_id",
    "workspace_id",
    "trace_id",
    "tool_name",
    "resource_id",
    "requested_scope",
    "arguments_digest",
    "idempotency_key",
    "deadline_at",
}
_APPROVAL_FIELDS = {
    "schema_version",
    "approval_id",
    "approver_id",
    "task_id",
    "thread_id",
    "run_id",
    "step_id",
    "actor_id",
    "tool_name",
    "resource_id",
    "arguments_digest",
    "idempotency_key",
    "decision",
    "expires_at",
}


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("value is not canonical JSON") from error


def _require_id(value: Any, field: str) -> str:
    errors = _valid_id(value, field)
    if errors:
        raise ValueError(errors[0])
    return value


def _require_positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if value <= 0:
        raise ValueError(f"{field} must be positive")
    return value


def _require_secret(secret: bytes) -> None:
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("approval_secret must be non-empty bytes")


def _require_scope(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("requested_scope must be a list")
    if len(value) > _MAX_SCOPE_ENTRIES:
        raise ValueError("requested_scope has too many entries")
    result: list[str] = []
    seen: set[str] = set()
    for index, scope in enumerate(value):
        if not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope):
            raise ValueError(f"requested_scope[{index}] is invalid")
        if scope in seen:
            raise ValueError(f"duplicate requested scope: {scope}")
        seen.add(scope)
        result.append(scope)
    return tuple(result)


def _decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value or not all(
        char.isalnum() or char in "-_" for char in value
    ):
        raise ValueError("invalid approval token segment")
    if len(value) % 4 == 1:
        raise ValueError("invalid approval token padding")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid approval token segment") from error


def _validate_approval(value: Any) -> tuple[str, ...]:
    if not isinstance(value, dict):
        return ("approval must be an object",)
    errors: list[str] = []
    unknown = sorted(set(value) - _APPROVAL_FIELDS)
    missing = sorted(_APPROVAL_FIELDS - set(value))
    if unknown:
        errors.append(f"unknown approval fields: {', '.join(unknown)}")
    if missing:
        errors.append(f"missing approval fields: {', '.join(missing)}")
    if value.get("schema_version") != APPROVAL_SCHEMA_VERSION:
        errors.append(f"schema_version must be {APPROVAL_SCHEMA_VERSION}")
    for field in (
        "approval_id",
        "approver_id",
        "task_id",
        "thread_id",
        "run_id",
        "step_id",
        "actor_id",
        "tool_name",
        "resource_id",
        "idempotency_key",
    ):
        errors.extend(_valid_id(value.get(field), field))
    if value.get("decision") not in {"approved", "denied"}:
        errors.append("decision must be approved or denied")
    digest = value.get("arguments_digest")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        errors.append("arguments_digest must be a lowercase sha256 digest")
    expiry = value.get("expires_at")
    if not isinstance(expiry, int) or isinstance(expiry, bool) or expiry <= 0:
        errors.append("expires_at must be a positive integer")
    return tuple(errors)


def sign_approval(approval: dict[str, Any], secret: bytes) -> str:
    _require_secret(secret)
    errors = _validate_approval(approval)
    if errors:
        raise ValueError(errors[0])
    payload = base64.urlsafe_b64encode(_canonical_json(approval)).decode("ascii").rstrip("=")
    signature = base64.urlsafe_b64encode(
        hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")
    return f"{payload}.{signature}"


class ApprovalDeniedError(ValueError):
    """A signed approval whose decision is ``denied``.

    Carries the structured denial (tool identity, reason, tier,
    retryability) so the caller can return it *as the tool's result* instead
    of crashing the run — the same propagation rule as
    byquexo/agent-approval-gate's ``ApprovalDeniedError`` ("catch this at
    the agent boundary and feed ``error.message`` back to the model as the
    tool result", ``errors.ts``). Subclasses ``ValueError`` so existing
    fail-closed handling keeps working.
    """

    def __init__(self, approval: dict[str, Any], reason: str = "") -> None:
        self.approval = dict(approval)
        self.tool_name = str(approval.get("tool_name", ""))
        self.call_id = str(approval.get("step_id", ""))
        self.arguments_digest = str(approval.get("arguments_digest", ""))
        self.reason = reason or "the approver denied this call"
        self.tier = "host_approval"
        self.retryable = True
        super().__init__(f"Tool call {self.tool_name!r} was denied: {self.reason}")

    def to_result(self) -> dict[str, Any]:
        """Structured tool-result payload for the denial."""
        return {
            "status": "denied",
            "tool": self.tool_name,
            "call_id": self.call_id,
            "arguments_digest": self.arguments_digest,
            "reason": self.reason,
            "tier": self.tier,
            "retryable": self.retryable,
            "message": str(self),
        }


def _verify_approval(token: str, secret: bytes, *, now: int) -> dict[str, Any]:
    _require_secret(secret)
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("now must be an integer")
    if not isinstance(token, str) or token.count(".") != 1:
        raise ValueError("approval token format is invalid")
    payload_segment, signature_segment = token.split(".")
    payload = _decode(payload_segment)
    supplied = _decode(signature_segment)
    expected = hmac.new(
        secret, payload_segment.encode("ascii"), hashlib.sha256
    ).digest()
    if len(supplied) != hashlib.sha256().digest_size or not hmac.compare_digest(
        supplied, expected
    ):
        raise ValueError("approval signature is invalid")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("approval payload is invalid") from error
    errors = _validate_approval(value)
    if errors:
        raise ValueError(errors[0])
    if now >= value["expires_at"]:
        raise ValueError("approval is expired")
    if value["decision"] != "approved":
        raise ApprovalDeniedError(value)
    return value


def digest_arguments(arguments: Any) -> str:
    encoded = _canonical_json(arguments)
    if len(encoded) > _MAX_ARGUMENT_BYTES:
        raise ValueError("tool arguments exceed the maximum size")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ToolCall:
    schema_version: str
    task_id: str
    thread_id: str
    run_id: str
    step_id: str
    actor_id: str
    workspace_id: str
    trace_id: str
    tool_name: str
    resource_id: str
    requested_scope: tuple[str, ...]
    arguments_digest: str
    idempotency_key: str
    deadline_at: int

    @classmethod
    def from_dict(cls, value: Any) -> "ToolCall":
        if not isinstance(value, dict):
            raise ValueError("tool call must be an object")
        missing = sorted(_TOOL_CALL_FIELDS - set(value))
        unknown = sorted(set(value) - _TOOL_CALL_FIELDS)
        if missing:
            raise ValueError(f"tool call missing fields: {', '.join(missing)}")
        if unknown:
            raise ValueError(f"tool call has unknown fields: {', '.join(unknown)}")
        if value["schema_version"] != TOOL_CALL_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {TOOL_CALL_SCHEMA_VERSION}")
        return cls(
            schema_version=TOOL_CALL_SCHEMA_VERSION,
            task_id=_require_id(value["task_id"], "task_id"),
            thread_id=_require_id(value["thread_id"], "thread_id"),
            run_id=_require_id(value["run_id"], "run_id"),
            step_id=_require_id(value["step_id"], "step_id"),
            actor_id=_require_id(value["actor_id"], "actor_id"),
            workspace_id=_require_id(value["workspace_id"], "workspace_id"),
            trace_id=_require_id(value["trace_id"], "trace_id"),
            tool_name=_require_id(value["tool_name"], "tool_name"),
            resource_id=_require_id(value["resource_id"], "resource_id"),
            requested_scope=_require_scope(value["requested_scope"]),
            arguments_digest=_require_digest(value["arguments_digest"]),
            idempotency_key=_require_id(value["idempotency_key"], "idempotency_key"),
            deadline_at=_require_positive_int(value["deadline_at"], "deadline_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "thread_id": self.thread_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "actor_id": self.actor_id,
            "workspace_id": self.workspace_id,
            "trace_id": self.trace_id,
            "tool_name": self.tool_name,
            "resource_id": self.resource_id,
            "requested_scope": list(self.requested_scope),
            "arguments_digest": self.arguments_digest,
            "idempotency_key": self.idempotency_key,
            "deadline_at": self.deadline_at,
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.to_dict())


def _require_digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError("arguments_digest must be a lowercase sha256 digest")
    return value


#: Largest binary hashed for a :class:`BinaryPin`.
_MAX_PINNED_BINARY_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class BinaryPin:
    """Pinned identity of the external binary behind a tool executor, if any.

    Red-team model: ``DavidCarliez/trustmebro``
    (https://github.com/DavidCarliez/trustmebro, MIT) — a PATH shim swaps
    the *binary* an agent invokes and returns fabricated output. The
    per-call approval binding (``call_id`` + ``arguments_digest``)
    authenticates the *request*, never the *output*, so a shim is invisible
    to it. The pin closes that gap: ``path`` is the ``realpath`` at
    registration time and ``digest`` the ``sha256:<hex>`` of the file bytes;
    :func:`verify_binary_pin` re-checks both before the executor runs, and a
    shim planted after pinning fails closed here instead of feeding
    fabricated output to the model.

    Parallel definition of the runtime's ``tools.path_integrity.BinaryPin``:
    the runtime never imports durable-run (see ``durable_bridge.py``), so
    only the field names and digest format are shared, never the class —
    exactly like ``digest_arguments``.
    """

    name: str
    path: str
    digest: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "path": self.path, "digest": self.digest}


def _hash_pinned_file(path: str) -> str:
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            total += len(chunk)
            if total > _MAX_PINNED_BINARY_BYTES:
                raise ValueError(f"binary {path!r} exceeds the hashable size limit")
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def verify_binary_pin(
    pin: BinaryPin, *, path: str | None = None
) -> tuple[bool, str]:
    """Re-resolve ``pin.name`` and compare ``(realpath, content digest)``.

    Returns ``(ok, reason)`` rather than raising so the gateway can refuse
    the execution with a clear message. A shim planted after pinning changes
    the resolved path, the file bytes, or both — any difference fails
    closed. Honest limit: a shim planted *before* pinning pins the shim
    itself; that case needs a PATH-shadow scan at install time (see the
    runtime's ``tools.path_integrity.scan_path_shadows``).
    """
    if not isinstance(pin, BinaryPin):
        return False, "pin is not a BinaryPin"
    if "/" in pin.name or "\\" in pin.name or "\x00" in pin.name or not pin.name:
        return False, f"invalid pinned binary name {pin.name!r}"
    found = shutil.which(pin.name, path=path if path is not None else os.environ.get("PATH"))
    if found is None:
        return False, f"tool binary {pin.name!r} no longer resolves on PATH"
    resolved = os.path.realpath(found)
    if resolved != pin.path:
        return (
            False,
            f"tool binary {pin.name!r} resolved to {resolved!r}, pinned to "
            f"{pin.path!r} (PATH shadowing suspected)",
        )
    try:
        digest = _hash_pinned_file(resolved)
    except (OSError, ValueError) as error:
        return False, f"could not hash {resolved!r}: {error}"
    if digest != pin.digest:
        return (
            False,
            f"tool binary {pin.name!r} content digest changed "
            "(binary replaced after pinning)",
        )
    return True, f"tool binary {pin.name!r} matches its pin"


def _digest_output(output: dict[str, Any]) -> str:
    """``sha256:<hex>`` of the canonical JSON of a tool output.

    Same wire format as the runtime's
    ``tools.path_integrity.digest_output`` (parallel implementation; only
    the format is shared).
    """
    return "sha256:" + hashlib.sha256(_canonical_json(output)).hexdigest()


def verify_output_receipt(result: "ToolExecutionResult") -> tuple[bool, str]:
    """Recompute the output digest and compare with the recorded receipt.

    Detects post-execution forgery of a recorded tool output: if the
    ``output`` dict was swapped after the receipt was written, the digest no
    longer matches. Returns ``(ok, reason)``.
    """
    if not isinstance(result, ToolExecutionResult):
        return False, "result is not a ToolExecutionResult"
    if not result.output_digest:
        return False, "receipt carries no output digest"
    actual = _digest_output(result.output)
    if actual != result.output_digest:
        return (
            False,
            "recorded tool output does not match its receipt digest "
            "(output forged after execution)",
        )
    return True, "recorded tool output matches its receipt digest"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    required_capability: str
    required_scope: str
    resource_kind: str
    risk_level: str
    executor: Callable[[dict[str, Any]], dict[str, Any]]
    binary_pin: BinaryPin | None = None
    irreversible: bool = False

    def __post_init__(self) -> None:
        _require_id(self.name, "tool name")
        _require_id(self.required_capability, "required capability")
        if not _SCOPE_RE.fullmatch(self.required_scope):
            raise ValueError("required_scope is invalid")
        _require_id(self.resource_kind, "resource kind")
        if self.risk_level not in {"low", "high"}:
            raise ValueError("risk_level must be low or high")
        if not callable(self.executor):
            raise ValueError("executor must be callable")
        if self.binary_pin is not None and not isinstance(self.binary_pin, BinaryPin):
            raise ValueError("binary_pin must be a BinaryPin or None")
        if not isinstance(self.irreversible, bool):
            raise ValueError("irreversible must be a boolean")
        if self.irreversible and self.risk_level != "high":
            # The irreversible tier sits above high-risk: the operation is
            # scheduled (parameters hash-bound), waits out the timelock
            # delay, and only then executes — cancellable by the host while
            # pending. It always needs the human approval that high-risk
            # requires, plus the delay.
            raise ValueError("irreversible tools must be high-risk")


@dataclass(frozen=True)
class ToolExecutionResult:
    status: str
    output: dict[str, Any]
    idempotency_key: str
    #: ``sha256:<hex>`` of the canonical output JSON, bound at execution
    #: time. ``verify_output_receipt`` re-checks it: a recorded output
    #: swapped after the fact no longer matches and is detected.
    output_digest: str = ""
    #: ``realpath`` of the binary the pin resolved to at execution time, or
    #: ``None`` for tools without a ``binary_pin``. Makes the receipt
    #: self-describing: *this output came from this binary*.
    binary_path: str | None = None


class ActionGateway:
    """Authorize and dispatch one exact registered tool call at a time.

    Idempotency is enforced by a two-tier bounded store, so a long-lived
    gateway cannot grow memory without limit:

    * hot tier: an LRU of full results, bounded by ``max_results``;
    * cold tier: a FIFO of tombstones, bounded by ``max_tombstones``,
      holding only the fingerprint of each evicted key.

    A replay of a tombstoned key inside its validity window fails closed
    instead of re-executing (the result is gone, so it cannot be served,
    and running it again would break at-most-once). Once the window lapses
    the key is forgotten entirely, which is safe: any replay carrying the
    same fingerprint shares the same ``deadline_at`` (it is hashed into the
    fingerprint) and is rejected by the deadline gate before the idempotency
    lookup, while a high-risk replay with a mutated deadline additionally
    needs an unexpired approval. If both tiers fill with unexpired keys the
    gateway refuses new executions rather than risk a double execution.

    Tools registered with ``irreversible=True`` form the irreversible tier
    (always high-risk): ``execute`` additionally requires a timelock
    operation id whose scheduled operation is ready — i.e. the operation
    was scheduled with its parameter digest bound, the delay elapsed, and
    the host did not cancel it meanwhile (see ``timelock.py``, absorbed
    from OpenZeppelin ``TimelockController``).

    Not thread-safe: drive one call at a time per instance.
    """

    def __init__(
        self,
        *,
        approval_secret: bytes,
        max_results: int = 1024,
        max_tombstones: int = 8192,
        tool_allowlist: ToolAllowlist | None = None,
        enforcement_failure_policy: str = "fail_closed",
        timelock: Timelock | None = None,
        audit_sink: Callable[[dict[str, Any]], None] | None = None,
    ):
        _require_secret(approval_secret)
        self._approval_secret = approval_secret
        self._max_results = _require_positive_int(max_results, "max_results")
        self._max_tombstones = _require_positive_int(max_tombstones, "max_tombstones")
        self._receipts: dict[str, dict[str, Any]] = {}
        self._audit_sink = audit_sink
        if tool_allowlist is not None and not isinstance(
            tool_allowlist, ToolAllowlist
        ):
            raise ValueError("tool_allowlist must be a ToolAllowlist or None")
        # OpenShell-style pre-execution validation (interceptor Validate phase):
        # when no allowlist is bound the gate is absent and execution is
        # unchanged; when bound, every call is checked before the executor.
        self._allowlist = tool_allowlist
        self._enforcement_gate = (
            EnforcementGate(
                tool_allowlist, failure_policy=enforcement_failure_policy
            )
            if tool_allowlist is not None
            else None
        )
        self._enforcement_trace: list[dict[str, Any]] = []
        self._enforcement_seq = 0
        if timelock is not None and not isinstance(timelock, Timelock):
            raise ValueError("timelock must be a Timelock or None")
        self._timelock = timelock
        self._tools: dict[str, ToolSpec] = {}
        self._results: OrderedDict[str, tuple[str, ToolExecutionResult, int]] = (
            OrderedDict()
        )
        self._tombstones: OrderedDict[str, tuple[str, int]] = OrderedDict()

    def register(self, spec: ToolSpec) -> None:
        if not isinstance(spec, ToolSpec):
            raise ValueError("tool spec is invalid")
        if spec.name in self._tools:
            raise ValueError("tool is already registered")
        self._tools[spec.name] = spec

    @property
    def enforcement_trace(self) -> tuple[dict[str, Any], ...]:
        """Append-only enforcement events (OCSF action/disposition analogue).

        One event per pre-execution validation, in check order. Empty when no
        allowlist is bound. Bounded at ``ENFORCEMENT_TRACE_MAX``.
        """
        return tuple(self._enforcement_trace)

    def _record_enforcement(
        self,
        tool_name: str,
        argument_digest: str,
        decision: EnforcementDecision,
    ) -> None:
        """Emit one enforcement trace event per validation (never silent)."""
        gate = self._enforcement_gate
        assert gate is not None  # only called when an allowlist is bound
        self._enforcement_seq += 1
        self._enforcement_trace.append(
            make_enforcement_event(
                seq=self._enforcement_seq,
                tool_name=tool_name,
                arguments_digest=argument_digest,
                decision=decision,
                allowlist_version=gate.allowlist.version,
                failure_policy=gate.failure_policy,
            )
        )
        if len(self._enforcement_trace) > ENFORCEMENT_TRACE_MAX:
            del self._enforcement_trace[
                : len(self._enforcement_trace) - ENFORCEMENT_TRACE_MAX
            ]

    def _prune_expired_idempotency(self, now: int) -> None:
        """Drop idempotency records that no live replay can reach.

        A replay carrying the same fingerprint shares the same deadline_at
        (it is hashed into the fingerprint) and is rejected by the deadline
        gate before the idempotency lookup; a high-risk replay with a mutated
        deadline additionally needs an unexpired approval. Past valid_until,
        forgetting the key cannot cause a re-execution.
        """
        for key, (_fingerprint, _result, valid_until) in list(
            self._results.items()
        ):
            if valid_until <= now:
                del self._results[key]
        for key, (_fingerprint, valid_until) in list(self._tombstones.items()):
            if valid_until <= now:
                del self._tombstones[key]

    def _reserve_idempotency_slot(self, now: int) -> None:
        """Make room for one new result, demoting the LRU entry to a tombstone.

        Runs before the executor is invoked: if the store is exhausted the
        call fails closed here, never after a side effect has happened.
        """
        self._prune_expired_idempotency(now)
        if len(self._results) < self._max_results:
            return
        # Every remaining tombstone is unexpired (pruned above): dropping one
        # could let a live replay re-execute, so refuse instead of forgetting.
        if len(self._tombstones) >= self._max_tombstones:
            raise ValueError("idempotency store exhausted; refusing to execute")
        old_key, (fingerprint, _result, valid_until) = self._results.popitem(
            last=False
        )
        self._tombstones[old_key] = (fingerprint, valid_until)

    def receipt_for(self, idempotency_key: str) -> dict[str, Any] | None:
        """Return the tool receipt for a completed call, if any."""
        return self._receipts.get(idempotency_key)

    def execute(
        self,
        call: ToolCall,
        arguments: dict[str, Any],
        *,
        authorization_token: str,
        authorization_secret: bytes,
        now: int,
        approval_token: str | None = None,
        current_policy_revision: str,
        run: dict[str, Any] | None = None,
        timelock_operation_id: str | None = None,
    ) -> ToolExecutionResult:
        if not isinstance(call, ToolCall):
            raise ValueError("tool call is invalid")
        if not isinstance(arguments, dict):
            raise ValueError("tool arguments must be an object")
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        _require_id(current_policy_revision, "current_policy_revision")
        if now >= call.deadline_at:
            raise ValueError("tool call deadline has expired")
        if run is not None:
            validation = validate_run_request(run)
            if not validation.ok:
                raise ValueError(validation.errors[0])
            for field in ("run_id", "actor_id", "workspace_id"):
                if run[field] != getattr(call, field):
                    raise ValueError(f"run does not match tool call {field}")

        authorization = verify_authorization(
            authorization_token, authorization_secret, now=now
        )
        if not authorization.ok or authorization.authorization is None:
            raise ValueError("authorization grant is not valid")
        grant = authorization.authorization
        if grant.get("policy_revision") != current_policy_revision:
            raise ValueError("authorization policy revision is stale")
        for field in ("run_id", "actor_id", "workspace_id"):
            if grant[field] != getattr(call, field):
                raise ValueError(f"authorization does not match tool call {field}")
        if call.resource_id != call.workspace_id or grant["workspace_id"] != call.resource_id:
            raise ValueError("tool resource is not the authorized workspace")

        argument_digest = digest_arguments(arguments)
        if argument_digest != call.arguments_digest:
            raise ValueError("tool arguments digest does not match call")
        spec = self._tools.get(call.tool_name)
        if spec is None:
            raise ValueError("tool is not registered")
        if spec.required_capability not in grant["capabilities"]:
            raise ValueError("tool capability is not authorized")
        requested_scope = set(call.requested_scope)
        if spec.required_scope not in requested_scope:
            raise ValueError("tool scope does not include the required scope")
        if not requested_scope.issubset(set(grant["capabilities"])):
            raise ValueError("tool scope exceeds the authorization grant")
        approval_expires_at: int | None = None
        if spec.risk_level == "high":
            if approval_token is None:
                raise ValueError("high-risk tool requires approval")
            approval = _verify_approval(
                approval_token, self._approval_secret, now=now
            )
            approval_expires_at = approval["expires_at"]
            for field in (
                "task_id",
                "thread_id",
                "run_id",
                "step_id",
                "actor_id",
                "tool_name",
                "resource_id",
                "arguments_digest",
                "idempotency_key",
            ):
                if approval[field] != getattr(call, field):
                    raise ValueError(f"approval does not match tool call {field}")

        fingerprint = hashlib.sha256(
            call.canonical_json() + b"\0" + argument_digest.encode("ascii")
        ).hexdigest()
        # valid_until bounds the window in which any replay of this key can
        # still pass the pre-cache gates: a same-fingerprint replay is cut off
        # by the deadline gate (deadline_at is hashed into the fingerprint),
        # and a high-risk replay with a mutated deadline additionally needs a
        # live approval. Forgetting the key past this point is provably safe.
        valid_until = call.deadline_at
        if approval_expires_at is not None:
            valid_until = max(valid_until, approval_expires_at)

        cached = self._results.get(call.idempotency_key)
        if cached is not None:
            self._results.move_to_end(call.idempotency_key)
            old_fingerprint, result, _valid_until = cached
            if old_fingerprint != fingerprint:
                raise ValueError("idempotency key conflicts with another tool call")
            return result
        tombstone = self._tombstones.get(call.idempotency_key)
        if tombstone is not None:
            old_fingerprint, _valid_until = tombstone
            if old_fingerprint != fingerprint:
                raise ValueError("idempotency key conflicts with another tool call")
            # The result was evicted but the key is still inside its replay
            # window: the result is gone so it cannot be served, and running
            # the executor again would break at-most-once. Fail closed.
            raise ValueError("idempotency result was evicted; refusing to re-execute")

        # OpenShell Validate-phase analogue: pre-execution allowlist check.
        # Runs after every authorization/approval gate and before the
        # executor — and before the idempotency slot is reserved, so a denied
        # call consumes nothing. The decision is always traced, allow or
        # deny (OpenShell's OCSF action/disposition emission).
        if self._enforcement_gate is not None:
            try:
                decision = self._enforcement_gate.check(
                    call.tool_name, arguments
                )
            except Exception as error:
                policy = self._enforcement_gate.failure_policy
                if policy == "fail_open":
                    decision = EnforcementDecision(
                        "allow",
                        f"enforcement gate errored; fail-open: {error}",
                    )
                else:
                    decision = EnforcementDecision(
                        "deny",
                        f"enforcement gate errored; fail-closed: {error}",
                    )
            self._record_enforcement(call.tool_name, argument_digest, decision)
            if decision.decision == "deny":
                raise ValueError(
                    f"tool allowlist denied execution: {decision.reason}"
                )
        # Genuine miss: for the irreversible tier the timelock must be ready
        # before any side effect can happen. The check runs after the
        # idempotency lookups on purpose: a same-key replay returns the
        # cached result without re-executing (and without touching the
        # timelock), while a new key for an already-executed operation fails
        # here because the operation is done, not ready — closing a
        # double-execution hole. A failed executor leaves the operation
        # ready (retryable); only a successful one is marked executed below.
        if spec.irreversible:
            if self._timelock is None:
                raise ValueError("irreversible tool requires a configured timelock")
            if timelock_operation_id is None:
                raise ValueError("irreversible tool requires a timelock operation id")
            self._timelock.authorize_execute(
                timelock_operation_id,
                tool_name=call.tool_name,
                arguments_digest=call.arguments_digest,
                now=now,
            )

        # Genuine miss: reserve the slot before invoking the executor, so a
        # full store fails closed here instead of after a side effect.
        # Genuine miss: verify the pinned binary (if any) before the executor
        # runs, so a PATH shim planted after registration fails closed here
        # and its fabricated output never reaches the model. Then reserve the
        # slot before invoking the executor, so a full store fails closed
        # here instead of after a side effect.
        binary_path: str | None = None
        if spec.binary_pin is not None:
            pin_ok, pin_reason = verify_binary_pin(spec.binary_pin)
            if not pin_ok:
                raise ValueError(f"tool binary integrity check failed: {pin_reason}")
            binary_path = os.path.realpath(
                shutil.which(spec.binary_pin.name) or spec.binary_pin.path
            )
        self._reserve_idempotency_slot(now)
        try:
            output = spec.executor(arguments)
        except Exception as error:
            raise ValueError("tool execution failed") from error
        if not isinstance(output, dict):
            raise ValueError("tool executor must return an object")
        if spec.irreversible:
            # The _afterCall analog: mark done only after a successful
            # executor, re-checking readiness.
            self._timelock.mark_executed(timelock_operation_id, now=now)
        result = ToolExecutionResult(
            status="ok",
            output=output,
            idempotency_key=call.idempotency_key,
            output_digest=_digest_output(output),
            binary_path=binary_path,
        )
        self._results[call.idempotency_key] = (fingerprint, result, valid_until)
        # Mint a per-call tool receipt: tamper-evident link between approval,
        # request, and outcome.
        receipt = make_tool_receipt(
            tool_name=call.tool_name,
            task_id=call.task_id,
            thread_id=call.thread_id,
            run_id=call.run_id,
            call_id=call.step_id,
            actor_id=call.actor_id,
            workspace_id=call.workspace_id,
            idempotency_key=call.idempotency_key,
            arguments=arguments,
            result=result.output,
            approval=approval,
            issued_at=now,
        )
        self._receipts[call.idempotency_key] = receipt
        while len(self._receipts) > self._max_results:
            self._receipts.pop(next(iter(self._receipts)))
        if self._audit_sink is not None:
            self._audit_sink(receipt_audit_record(receipt))
        return result
