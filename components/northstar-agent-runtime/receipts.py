"""Capability leases and tamper-evident action receipts.

The runtime's permission gate historically approved a tool name one call at a
time. This module adds the next control-plane primitive: a host can grant a
bounded capability lease scoped to one session and workspace, and the runtime
can emit an action receipt whose canonical bytes are HMAC-verifiable.

Nothing here executes a tool or decides policy on its own. A lease is only a
cacheable, expiring approval; the permission engine still applies its existing
hard-deny/allowlist ordering and mode semantics. A receipt is a claim about an
action, not proof that a hostile process could not have changed the filesystem.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from artifacts import ArtifactError, ArtifactManifest

APPROVAL_LEASE_SCHEMA_VERSION = "northstar.approval-lease.v1"
ACTION_RECEIPT_SCHEMA_VERSION = "northstar.action-receipt.v1"
MAX_ID_CHARS = 128
MAX_CAPABILITY_CHARS = 128
MAX_CAPABILITIES = 32
MAX_WORKSPACE_CHARS = 4096
MAX_ERROR_CHARS = 2000
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


class ReceiptError(ValueError):
    """A lease or receipt is malformed, expired, out of scope or unverifiable."""


def capability_for(kind: str, tool_name: str = "") -> str:
    """Map a tool class to a stable capability namespace.

    Tool names remain useful for UX and audit display; approval leases authorize
    these capability classes instead of an ever-growing list of tool names.
    """
    prefixes = {
        "read": "workspace.read",
        "edit": "workspace.write",
        "exec": "process.exec",
        "network": "network.access",
        "task": "agent.delegate",
    }
    if kind in prefixes:
        return prefixes[kind]
    normalized = re.sub(r"[^a-z0-9]+", ".", str(tool_name).strip().lower()).strip(".")
    return f"tool.{normalized or 'unknown'}"


def digest_value(value: Any) -> str:
    """Canonical SHA-256 digest for an input/output or structured receipt field."""
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ReceiptError(f"cannot canonicalize value for digest: {error}") from error
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ID_CHARS or not _ID_RE.fullmatch(value):
        raise ReceiptError(f"{field} is invalid")
    if value == "*":
        raise ReceiptError(f"wildcard {field} is not permitted")
    return value


def _require_capability(value: Any, field: str = "capability") -> str:
    if not isinstance(value, str) or len(value) > MAX_CAPABILITY_CHARS or not _CAPABILITY_RE.fullmatch(value):
        raise ReceiptError(f"{field} is invalid")
    if value == "*":
        raise ReceiptError("wildcard capability is not permitted")
    return value


def _require_capabilities(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > MAX_CAPABILITIES:
        raise ReceiptError("capabilities must be a bounded list")
    result = tuple(_require_capability(value, f"capabilities[{index}]") for index, value in enumerate(values))
    if len(set(result)) != len(result):
        raise ReceiptError("capabilities must not contain duplicates")
    return tuple(sorted(result))


def _require_time(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReceiptError(f"{field} must be a positive integer")
    return value


def _require_digest(value: Any, field: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ReceiptError(f"{field} must be a sha256 digest")
    return value


def _require_secret(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or len(secret) < 16:
        raise ReceiptError("receipt secret must be at least 16 bytes")
    return secret


def _encode_signature(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not _SIGNATURE_RE.fullmatch(value):
        raise ReceiptError("signature is invalid")
    try:
        return base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error) as error:
        raise ReceiptError("signature is invalid") from error


@dataclass(frozen=True)
class ApprovalLease:
    """A bounded approval scoped to one session, workspace and capability set."""

    lease_id: str
    session_id: str
    workspace: str
    capabilities: tuple[str, ...]
    issued_at: int
    expires_at: int
    max_uses: int
    uses: int = 0
    schema_version: str = APPROVAL_LEASE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != APPROVAL_LEASE_SCHEMA_VERSION:
            raise ReceiptError(f"schema_version must be {APPROVAL_LEASE_SCHEMA_VERSION}")
        _require_id(self.lease_id, "lease_id")
        _require_id(self.session_id, "session_id")
        if not isinstance(self.workspace, str) or not self.workspace or len(self.workspace) > MAX_WORKSPACE_CHARS:
            raise ReceiptError("workspace is invalid")
        capabilities = _require_capabilities(self.capabilities)
        object.__setattr__(self, "capabilities", capabilities)
        issued = _require_time(self.issued_at, "issued_at")
        expires = _require_time(self.expires_at, "expires_at")
        if expires <= issued:
            raise ReceiptError("expires_at must be after issued_at")
        if isinstance(self.max_uses, bool) or not isinstance(self.max_uses, int) or self.max_uses < 1:
            raise ReceiptError("max_uses must be a positive integer")
        if isinstance(self.uses, bool) or not isinstance(self.uses, int) or not 0 <= self.uses <= self.max_uses:
            raise ReceiptError("uses must be between zero and max_uses")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ApprovalLease":
        if not isinstance(value, Mapping):
            raise ReceiptError("lease must be an object")
        allowed = {"schema_version", "lease_id", "session_id", "workspace", "capabilities", "issued_at", "expires_at", "max_uses", "uses"}
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ReceiptError(f"lease has unknown fields: {', '.join(unknown)}")
        return cls(
            schema_version=value.get("schema_version", APPROVAL_LEASE_SCHEMA_VERSION),
            lease_id=value.get("lease_id", ""),
            session_id=value.get("session_id", ""),
            workspace=value.get("workspace", ""),
            capabilities=tuple(value.get("capabilities", ())),
            issued_at=value.get("issued_at", 0),
            expires_at=value.get("expires_at", 0),
            max_uses=value.get("max_uses", 0),
            uses=value.get("uses", 0),
        )

    from_dict = from_mapping

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "lease_id": self.lease_id,
            "session_id": self.session_id,
            "workspace": self.workspace,
            "capabilities": list(self.capabilities),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "max_uses": self.max_uses,
            "uses": self.uses,
        }

    to_dict = as_dict

    def allows(self, *, session_id: str, workspace: str, capability: str, now: int) -> bool:
        return (
            session_id == self.session_id
            and workspace == self.workspace
            and capability in self.capabilities
            and self.issued_at <= now < self.expires_at
            and self.uses < self.max_uses
        )

    def consumed(self) -> "ApprovalLease":
        if self.uses >= self.max_uses:
            raise ReceiptError("approval lease is exhausted")
        return replace(self, uses=self.uses + 1)


class ApprovalLeaseLedger:
    """In-memory lease store with deterministic selection and use accounting."""

    def __init__(self) -> None:
        self._leases: dict[str, ApprovalLease] = {}
        self._lock = threading.RLock()

    def add(self, lease: ApprovalLease | Mapping[str, Any]) -> ApprovalLease:
        normalized = lease if isinstance(lease, ApprovalLease) else ApprovalLease.from_mapping(lease)
        with self._lock:
            if normalized.lease_id in self._leases:
                raise ReceiptError(f"approval lease already exists: {normalized.lease_id}")
            self._leases[normalized.lease_id] = normalized
        return normalized

    def get(self, lease_id: str) -> ApprovalLease | None:
        with self._lock:
            return self._leases.get(lease_id)

    def revoke(self, lease_id: str) -> bool:
        """Revoke a lease before expiry; return whether it existed."""
        _require_id(lease_id, "lease_id")
        with self._lock:
            return self._leases.pop(lease_id, None) is not None

    def active(self, *, now: int) -> tuple[ApprovalLease, ...]:
        with self._lock:
            return tuple(lease for lease in self._leases.values() if lease.expires_at > now and lease.uses < lease.max_uses)

    def consume(self, *, session_id: str, workspace: str, capability: str, now: int) -> ApprovalLease | None:
        _require_capability(capability)
        with self._lock:
            candidates = sorted(self._leases.values(), key=lambda lease: (lease.expires_at, lease.lease_id))
            for lease in candidates:
                if lease.allows(session_id=session_id, workspace=workspace, capability=capability, now=now):
                    consumed = lease.consumed()
                    self._leases[lease.lease_id] = consumed
                    return consumed
        return None

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(lease.as_dict() for lease in sorted(self._leases.values(), key=lambda item: item.lease_id))


_RECEIPT_FIELDS = {
    "schema_version", "receipt_id", "action_id", "session_id", "tool", "capability",
    "status", "issued_at", "completed_at", "input_digest", "output_digest",
    "workspace_before", "workspace_after", "lease_id", "error", "artifact_manifest", "signature",
}
_RECEIPT_STATUSES = frozenset({"approved", "denied", "completed", "failed"})


@dataclass(frozen=True)
class ActionReceipt:
    """Canonical action result with an optional HMAC signature."""

    receipt_id: str
    action_id: str
    session_id: str
    tool: str
    capability: str
    status: str
    issued_at: int
    completed_at: int
    input_digest: str
    output_digest: str | None = None
    workspace_before: str | None = None
    workspace_after: str | None = None
    lease_id: str | None = None
    error: str = ""
    signature: str | None = None
    schema_version: str = ACTION_RECEIPT_SCHEMA_VERSION
    artifact_manifest: ArtifactManifest | None = None

    def __post_init__(self) -> None:
        if self.schema_version != ACTION_RECEIPT_SCHEMA_VERSION:
            raise ReceiptError(f"schema_version must be {ACTION_RECEIPT_SCHEMA_VERSION}")
        for field, value in (("receipt_id", self.receipt_id), ("action_id", self.action_id), ("session_id", self.session_id), ("tool", self.tool)):
            _require_id(value, field)
        _require_capability(self.capability)
        if self.status not in _RECEIPT_STATUSES:
            raise ReceiptError(f"status is invalid: {self.status!r}")
        issued = _require_time(self.issued_at, "issued_at")
        completed = _require_time(self.completed_at, "completed_at")
        if completed < issued:
            raise ReceiptError("completed_at cannot precede issued_at")
        _require_digest(self.input_digest, "input_digest")
        _require_digest(self.output_digest, "output_digest", optional=True)
        _require_digest(self.workspace_before, "workspace_before", optional=True)
        _require_digest(self.workspace_after, "workspace_after", optional=True)
        if self.lease_id is not None:
            _require_id(self.lease_id, "lease_id")
        if not isinstance(self.error, str) or len(self.error) > MAX_ERROR_CHARS:
            raise ReceiptError("error is invalid")
        if self.artifact_manifest is not None:
            try:
                manifest = (
                    self.artifact_manifest
                    if isinstance(self.artifact_manifest, ArtifactManifest)
                    else ArtifactManifest.from_mapping(self.artifact_manifest)
                )
            except (ArtifactError, TypeError, ValueError) as error:
                raise ReceiptError(f"artifact_manifest is invalid: {error}") from error
            object.__setattr__(self, "artifact_manifest", manifest)
        if self.signature is not None:
            _decode_signature(self.signature)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ActionReceipt":
        if not isinstance(value, Mapping):
            raise ReceiptError("receipt must be an object")
        unknown = sorted(set(value) - _RECEIPT_FIELDS)
        if unknown:
            raise ReceiptError(f"receipt has unknown fields: {', '.join(unknown)}")
        required = {"schema_version", "receipt_id", "action_id", "session_id", "tool", "capability", "status", "issued_at", "completed_at", "input_digest"}
        missing = sorted(required - set(value))
        if missing:
            raise ReceiptError(f"receipt is missing fields: {', '.join(missing)}")
        return cls(**{field: value.get(field) for field in _RECEIPT_FIELDS if field in value})

    from_dict = from_mapping

    def as_dict(self, *, include_signature: bool = True) -> dict[str, Any]:
        result = {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "session_id": self.session_id,
            "tool": self.tool,
            "capability": self.capability,
            "status": self.status,
            "issued_at": self.issued_at,
            "completed_at": self.completed_at,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "workspace_before": self.workspace_before,
            "workspace_after": self.workspace_after,
            "lease_id": self.lease_id,
            "error": self.error,
        }
        if self.artifact_manifest is not None:
            result["artifact_manifest"] = self.artifact_manifest.to_dict()
        if include_signature:
            result["signature"] = self.signature
        return result

    def to_dict(self) -> dict[str, Any]:
        return self.as_dict()

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.as_dict(include_signature=False), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, secret: bytes) -> "ActionReceipt":
        key = _require_secret(secret)
        signature = _encode_signature(hmac.new(key, self.canonical_bytes(), hashlib.sha256).digest())
        return replace(self, signature=signature)

    def verify(self, secret: bytes) -> bool:
        try:
            key = _require_secret(secret)
        except ReceiptError:
            return False
        if self.signature is None:
            return False
        expected = _encode_signature(hmac.new(key, self.canonical_bytes(), hashlib.sha256).digest())
        return hmac.compare_digest(self.signature, expected)

    def to_contract_receipt(self) -> dict[str, Any]:
        """Project into the existing ``northstar.receipt.v1`` result shape.

        The action extension remains strict and signed in ``as_dict``; this
        projection lets run-contract/durable-run consumers ingest the result
        without having to understand runtime-specific fields. It intentionally
        does not copy the signature into the old contract, because that contract
        has no signature field and therefore cannot verify it.
        """
        status = {
            "approved": "accepted",
            "denied": "rejected",
            "completed": "ok",
            "failed": "internal_error",
        }[self.status]
        postconditions = [
            {
                "name": "action_completed",
                "status": "verified" if self.status == "completed" else "failed",
            }
        ]
        if self.workspace_before is not None or self.workspace_after is not None:
            postconditions.append(
                {
                    "name": "workspace_observed",
                    "status": "verified" if self.workspace_after is not None else "unknown",
                }
            )
        if self.artifact_manifest is not None:
            postconditions.append(
                {
                    "name": "artifacts_observed",
                    "status": "verified" if self.artifact_manifest.artifacts else "unknown",
                }
            )
        receipt: dict[str, Any] = {
            "schema_version": "northstar.receipt.v1",
            "run_id": self.session_id,
            "status": status,
            "postconditions": postconditions,
        }
        if self.error:
            receipt["error_class"] = self.error[:2000]
        else:
            receipt["text"] = f"{self.tool} {self.status}"
        return receipt

    @classmethod
    def new(
        cls,
        *,
        session_id: str,
        action_id: str,
        tool: str,
        capability: str,
        status: str,
        issued_at: int | None = None,
        completed_at: int | None = None,
        input_value: Any = None,
        output_value: Any = None,
        workspace_before: str | None = None,
        workspace_after: str | None = None,
        lease_id: str | None = None,
        error: str = "",
        artifact_manifest: ArtifactManifest | Mapping[str, Any] | None = None,
    ) -> "ActionReceipt":
        now = int(time.time()) if issued_at is None else issued_at
        end = now if completed_at is None else completed_at
        return cls(
            receipt_id=f"rcpt-{uuid.uuid4().hex}",
            action_id=action_id,
            session_id=session_id,
            tool=tool,
            capability=capability,
            status=status,
            issued_at=now,
            completed_at=end,
            input_digest=digest_value(input_value),
            output_digest=digest_value(output_value) if output_value is not None else None,
            workspace_before=workspace_before,
            workspace_after=workspace_after,
            lease_id=lease_id,
            error=error,
            artifact_manifest=artifact_manifest,
        )


def sign_receipt(receipt: ActionReceipt | Mapping[str, Any], secret: bytes) -> ActionReceipt:
    """Sign an existing receipt after validating its canonical shape."""
    value = receipt if isinstance(receipt, ActionReceipt) else ActionReceipt.from_mapping(receipt)
    return value.sign(secret)


def verify_receipt(receipt: ActionReceipt | Mapping[str, Any], secret: bytes) -> bool:
    """Validate and verify a serialized action receipt."""
    value = receipt if isinstance(receipt, ActionReceipt) else ActionReceipt.from_mapping(receipt)
    return value.verify(secret)


__all__ = [
    "ACTION_RECEIPT_SCHEMA_VERSION",
    "APPROVAL_LEASE_SCHEMA_VERSION",
    "ActionReceipt",
    "ApprovalLease",
    "ApprovalLeaseLedger",
    "ReceiptError",
    "capability_for",
    "digest_value",
    "sign_receipt",
    "verify_receipt",
]
