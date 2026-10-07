"""Connector SDK (plugin interface) bookkeeping, simulated.

Research motivation: every extensible platform ends up with the same
three questions -- what is this plugin (manifest), how is it brought
up (init with validated config), and how do calls flow through it
(invoke with a pinned payload). Slack apps, MCP servers, OpenAI
plugins, and Home Assistant integrations all reduce to this shape:
declare capabilities up front, validate config against a schema at
init time, and route each invocation through the capability gate so a
rogue plugin cannot quietly widen its authority.

This module is the *lifecycle bookkeeping* half of that shape, pinned
so the runtime's plugin plumbing speaks one dialect:

- ``ConnectorSDK.manifest(connector_id, name, version, seq, ...)`` --
  register a connector's declared capabilities and config schema.
  Returns a frozen ``ConnectorManifest`` with a ``sha256:`` digest pin.
- ``ConnectorSDK.init(connector_id, config, seq, ...)`` -- bring up one
  instance: validates ``config`` against the manifest's schema
  (required keys present, pinned value types match). Returns a frozen
  ``InstanceRecord`` (``inst-N`` ids).
- ``ConnectorSDK.invoke(instance_id, operation, payload, seq)`` --
  route one call through the capability gate. The operation must be in
  the connector's declared capabilities; the payload is digest-pinned
  (never stored raw -- secrets can ride through a payload) and the
  call is booked as a frozen ``InvocationRecord``.
- ``ConnectorSDK.deactivate(instance_id, seq)`` -- terminal lifecycle
  transition; invoking a deactivated instance is refused fail-closed.
- ``connector_sdk_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``manifest-registered`` / ``initialized`` / ``invoked`` /
  ``deactivated`` / ``rejected``); caller-supplied seqs only. Config
  values and payloads are banned from the audit boundary (test-verified).

Fail-closed edges (fail loudly, never guess):

- Capability vocabulary is pinned: ``read`` / ``write`` / ``subscribe`` /
  ``unsubscribe`` / ``invoke`` / ``webhook`` / ``stream``. Unknown
  capabilities are refused at manifest time, and ``invoke`` on an
  undeclared operation raises ``CapabilityError``.
- Config schema types are pinned: ``str`` / ``int`` / ``bool`` /
  ``float`` (bool is not int -- ``True`` must not alias ``1``).
  Missing required keys or wrong value types raise ``BadConfigError``;
  extra keys are refused (the schema is closed, not open).
- Manifest ids and instance ids are never recycled; duplicate
  registrations raise fail-closed. All mutations require strictly
  increasing int seqs (bool refused, rewind refused); failed mutations
  consume their seq (batch-21 ledger discipline).
- Deactivation is terminal: double-deactivate raises
  ``AlreadyDeactivatedError``; invoke-after-deactivate raises
  ``DeactivatedError``.

Honest scope:

- This module books *lifecycle decisions*. It performs no actual
  plugin loading, no subprocess execution, and no network I/O --
  ``invoke`` records the call (operation, payload digest, seq), it
  does not run a plugin. Production needs a real sandbox around the
  code that answers these records.
- The manifest pins what the host *claims* a connector can do (GIGO
  boundary). Enforcement against a lying manifest is a code-review /
  signing concern, not something this ledger can prove.
- No persistence: the registry is in-memory. Pair with the durable
  audit writer if connector lifecycles must survive a restart.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
CONNECTOR_SDK_VERSION = "connector-sdk.v1"

#: Schema pin carried by records and audit events.
CONNECTOR_SDK_SCHEMA = "northstar.connector-sdk.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned capability vocabulary. A connector may only declare -- and
#: only be invoked through -- these operations.
CAP_READ = "read"
CAP_WRITE = "write"
CAP_SUBSCRIBE = "subscribe"
CAP_UNSUBSCRIBE = "unsubscribe"
CAP_INVOKE = "invoke"
CAP_WEBHOOK = "webhook"
CAP_STREAM = "stream"
_CAPABILITIES = (
    CAP_READ, CAP_WRITE, CAP_SUBSCRIBE, CAP_UNSUBSCRIBE,
    CAP_INVOKE, CAP_WEBHOOK, CAP_STREAM,
)

#: Pinned config-schema value types.
_TYPE_STR = "str"
_TYPE_INT = "int"
_TYPE_BOOL = "bool"
_TYPE_FLOAT = "float"
_CONFIG_TYPES = (_TYPE_STR, _TYPE_INT, _TYPE_BOOL, _TYPE_FLOAT)

#: Audit event kinds.
KIND_MANIFEST_REGISTERED = "manifest-registered"
KIND_INITIALIZED = "initialized"
KIND_INVOKED = "invoked"
KIND_DEACTIVATED = "deactivated"
KIND_REJECTED = "rejected"
_KINDS = (
    KIND_MANIFEST_REGISTERED, KIND_INITIALIZED, KIND_INVOKED,
    KIND_DEACTIVATED, KIND_REJECTED,
)


class ConnectorError(Exception):
    """Base error for the connector SDK (programming errors)."""


class DuplicateConnectorError(ConnectorError):
    """Raised when a connector_id is registered twice."""


class UnknownConnectorError(ConnectorError):
    """Raised when a connector_id names no registered manifest."""


class BadManifestError(ConnectorError):
    """Raised when the manifest declaration itself is malformed."""


class BadConfigError(ConnectorError):
    """Raised when init config fails schema validation."""


class DuplicateInstanceError(ConnectorError):
    """Raised when an instance_id is initialized twice."""


class UnknownInstanceError(ConnectorError):
    """Raised when an instance_id names no initialized instance."""


class CapabilityError(ConnectorError):
    """Raised when an operation is outside the connector's capabilities."""


class DeactivatedError(ConnectorError):
    """Raised when invoking a deactivated instance."""


class AlreadyDeactivatedError(ConnectorError):
    """Raised when deactivating an already-deactivated instance."""


class SeqOrderError(ConnectorError):
    """Raised when a caller-supplied seq is not strictly increasing."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


def _check_connector_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise BadManifestError("connector_id must be a non-empty str")
    return value


def _check_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise BadManifestError("name must be a non-empty str")
    return value


def _check_version(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise BadManifestError("version must be a non-empty str")
    return value


def _check_capabilities(caps: object) -> Tuple[str, ...]:
    if caps is None:
        raise BadManifestError("capabilities must be a non-empty sequence")
    if isinstance(caps, str) or not isinstance(caps, Sequence):
        raise BadManifestError("capabilities must be a non-empty sequence")
    seen: list[str] = []
    for cap in caps:
        if cap not in _CAPABILITIES:
            raise BadManifestError(f"unknown capability {cap!r}")
        if cap in seen:
            raise BadManifestError(f"duplicate capability {cap!r}")
        seen.append(cap)
    if not seen:
        raise BadManifestError("capabilities must be non-empty")
    return tuple(sorted(seen))


def _check_config_schema(schema: object) -> Tuple["ConfigField", ...]:
    if schema is None:
        return ()
    if not isinstance(schema, Sequence) or isinstance(schema, (str, bytes)):
        raise BadManifestError("config_schema must be a sequence of fields")
    fields: list[ConfigField] = []
    seen_names: set[str] = set()
    for entry in schema:
        if not isinstance(entry, Mapping):
            raise BadManifestError("config_schema entries must be mappings")
        name = entry.get("name")
        ftype = entry.get("type")
        required = entry.get("required", False)
        if not isinstance(name, str) or not name:
            raise BadManifestError("config field name must be a non-empty str")
        if name in seen_names:
            raise BadManifestError(f"duplicate config field {name!r}")
        seen_names.add(name)
        if ftype not in _CONFIG_TYPES:
            raise BadManifestError(f"unknown config type {ftype!r}")
        if not isinstance(required, bool):
            raise BadManifestError("config field required must be bool")
        fields.append(ConfigField(name=name, type=ftype, required=required))
    return tuple(sorted(fields, key=lambda f: f.name))


_TYPE_CHECKS = {
    _TYPE_STR: (lambda v: isinstance(v, str)),
    _TYPE_INT: (lambda v: isinstance(v, int) and not isinstance(v, bool)),
    _TYPE_BOOL: (lambda v: isinstance(v, bool)),
    _TYPE_FLOAT: (
        lambda v: isinstance(v, float)
        or (isinstance(v, int) and not isinstance(v, bool))
    ),
}


def _pin(prefix: str, *parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex({"p": prefix, "v": list(parts)})


@dataclass(frozen=True)
class ConfigField:
    """One declared config-schema field (closed schema)."""

    name: str
    type: str  # one of the pinned _CONFIG_TYPES
    required: bool

    def as_dict(self) -> dict:
        return {"name": self.name, "type": self.type,
                "required": self.required}


@dataclass(frozen=True)
class ConnectorManifest:
    """Frozen declaration of one connector's capabilities."""

    connector_id: str
    name: str
    version: str
    capabilities: Tuple[str, ...]
    config_schema: Tuple[ConfigField, ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == _pin(
            "manifest", self.connector_id, self.name, self.version,
            self.capabilities,
            [f.as_dict() for f in self.config_schema], self.seq,
        )

    def as_dict(self) -> dict:
        return {
            "connector_id": self.connector_id,
            "name": self.name,
            "version": self.version,
            "capabilities": list(self.capabilities),
            "config_schema": [f.as_dict() for f in self.config_schema],
            "seq": self.seq,
            "digest": self.digest,
            "version_pin": CONNECTOR_SDK_VERSION,
            "schema": CONNECTOR_SDK_SCHEMA,
        }


@dataclass(frozen=True)
class InstanceRecord:
    """Frozen record of one initialized connector instance."""

    instance_id: str
    connector_id: str
    state: str  # "initialized" | "deactivated"
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "instance", self.instance_id, self.connector_id,
            self.state, self.seq,
        )

    def as_dict(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "connector_id": self.connector_id,
            "state": self.state,
            "seq": self.seq,
            "digest": self.digest,
            "version_pin": CONNECTOR_SDK_VERSION,
            "schema": CONNECTOR_SDK_SCHEMA,
        }


@dataclass(frozen=True)
class InvocationRecord:
    """Frozen record of one routed invocation (payload digest-pinned)."""

    invocation_id: str
    instance_id: str
    connector_id: str
    operation: str
    payload_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "invoke", self.invocation_id, self.instance_id,
            self.connector_id, self.operation, self.payload_digest, self.seq,
        )

    def as_dict(self) -> dict:
        return {
            "invocation_id": self.invocation_id,
            "instance_id": self.instance_id,
            "connector_id": self.connector_id,
            "operation": self.operation,
            "payload_digest": self.payload_digest,
            "seq": self.seq,
            "digest": self.digest,
            "version_pin": CONNECTOR_SDK_VERSION,
            "schema": CONNECTOR_SDK_SCHEMA,
        }


class ConnectorSDK:
    """In-memory connector lifecycle registry (thread-safe)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._manifests: Dict[str, ConnectorManifest] = {}
        self._instances: Dict[str, InstanceRecord] = {}
        self._invocations: Dict[str, InvocationRecord] = {}
        self._audit: list[dict] = []
        self._last_seq = 0
        self._instance_counter = 0
        self._invocation_counter = 0

    # -- internal helpers -------------------------------------------------

    def _audit_event(self, kind: str, seq: int,
                     connector_id: Optional[str] = None,
                     instance_id: Optional[str] = None,
                     invocation_id: Optional[str] = None) -> None:
        self._audit.append(connector_sdk_audit_event(
            kind, seq, connector_id=connector_id, instance_id=instance_id,
            invocation_id=invocation_id))

    def _use_seq(self, seq: object) -> int:
        """Enforce strictly increasing mutation seqs (fail-closed)."""
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq {seq} must exceed last mutation seq {self._last_seq}"
                )
            self._last_seq = seq
        return seq

    # -- lifecycle ---------------------------------------------------------

    def manifest(self, connector_id: object, name: object,
                 version: object, capabilities: object, seq: object,
                 config_schema: object = None) -> ConnectorManifest:
        """Register a connector's manifest; returns the frozen record."""
        connector_id = _check_connector_id(connector_id)
        name = _check_name(name)
        version = _check_version(version)
        caps = _check_capabilities(capabilities)
        schema = _check_config_schema(config_schema)
        seq = self._use_seq(seq)
        digest = _pin(
            "manifest", connector_id, name, version, caps,
            [f.as_dict() for f in schema], seq,
        )
        record = ConnectorManifest(
            connector_id=connector_id, name=name, version=version,
            capabilities=caps, config_schema=schema, seq=seq, digest=digest,
        )
        with self._lock:
            if connector_id in self._manifests:
                raise DuplicateConnectorError(
                    f"connector_id {connector_id!r} already registered"
                )
            self._manifests[connector_id] = record
            self._audit_event(KIND_MANIFEST_REGISTERED, seq,
                              connector_id=connector_id)
        return record

    def init(self, connector_id: object, config: object, seq: object,
             instance_id: object = None) -> InstanceRecord:
        """Bring up one instance after closed-schema config validation."""
        connector_id = _check_connector_id(connector_id)
        if not isinstance(config, Mapping):
            raise BadConfigError("config must be a mapping")
        seq = self._use_seq(seq)
        with self._lock:
            manifest = self._manifests.get(connector_id)
            if manifest is None:
                raise UnknownConnectorError(
                    f"unknown connector_id {connector_id!r}"
                )
            self._validate_config(manifest, config)
            if instance_id is None:
                self._instance_counter += 1
                instance_id = f"inst-{self._instance_counter}"
            else:
                if not isinstance(instance_id, str) or not instance_id:
                    raise BadConfigError("instance_id must be a non-empty str")
                if instance_id in self._instances:
                    raise DuplicateInstanceError(
                        f"instance_id {instance_id!r} already initialized"
                    )
            digest = _pin("instance", instance_id, connector_id,
                          "initialized", seq)
            record = InstanceRecord(
                instance_id=instance_id, connector_id=connector_id,
                state="initialized", seq=seq, digest=digest,
            )
            self._instances[instance_id] = record
            self._audit_event(KIND_INITIALIZED, seq,
                              connector_id=connector_id,
                              instance_id=instance_id)
        return record

    def _validate_config(self, manifest: ConnectorManifest,
                         config: Mapping[str, Any]) -> None:
        """Closed-schema validation: no extras, required keys, types."""
        declared = {f.name: f for f in manifest.config_schema}
        for key in config:
            if key not in declared:
                raise BadConfigError(
                    f"unexpected config key {key!r} for "
                    f"{manifest.connector_id!r}"
                )
        for field in manifest.config_schema:
            if field.name not in config:
                if field.required:
                    raise BadConfigError(
                        f"missing required config key {field.name!r}"
                    )
                continue
            value = config[field.name]
            if not _TYPE_CHECKS[field.type](value):
                raise BadConfigError(
                    f"config key {field.name!r} must be {field.type}, "
                    f"got {type(value).__name__}"
                )

    def invoke(self, instance_id: object, operation: object,
               payload: object, seq: object) -> InvocationRecord:
        """Route one call through the capability gate (payload pinned)."""
        if not isinstance(instance_id, str) or not instance_id:
            raise UnknownInstanceError("instance_id must be a non-empty str")
        if not isinstance(operation, str) or not operation:
            raise CapabilityError("operation must be a non-empty str")
        seq = self._use_seq(seq)
        with self._lock:
            instance = self._instances.get(instance_id)
            if instance is None:
                raise UnknownInstanceError(
                    f"unknown instance_id {instance_id!r}"
                )
            if instance.state != "initialized":
                raise DeactivatedError(
                    f"instance_id {instance_id!r} is deactivated"
                )
            manifest = self._manifests[instance.connector_id]
            if operation not in manifest.capabilities:
                raise CapabilityError(
                    f"operation {operation!r} not in capabilities of "
                    f"{manifest.connector_id!r}"
                )
            payload_digest = "sha256:" + jcs_sha256_hex(
                _freeze_payload(payload))
            self._invocation_counter += 1
            invocation_id = f"inv-{self._invocation_counter}"
            digest = _pin(
                "invoke", invocation_id, instance_id,
                instance.connector_id, operation, payload_digest, seq,
            )
            record = InvocationRecord(
                invocation_id=invocation_id, instance_id=instance_id,
                connector_id=instance.connector_id, operation=operation,
                payload_digest=payload_digest, seq=seq, digest=digest,
            )
            self._invocations[invocation_id] = record
            self._audit_event(KIND_INVOKED, seq,
                              connector_id=instance.connector_id,
                              instance_id=instance_id,
                              invocation_id=invocation_id)
        return record

    def deactivate(self, instance_id: object, seq: object) -> InstanceRecord:
        """Terminally deactivate an instance; returns the new record."""
        if not isinstance(instance_id, str) or not instance_id:
            raise UnknownInstanceError("instance_id must be a non-empty str")
        seq = self._use_seq(seq)
        with self._lock:
            instance = self._instances.get(instance_id)
            if instance is None:
                raise UnknownInstanceError(
                    f"unknown instance_id {instance_id!r}"
                )
            if instance.state != "initialized":
                raise AlreadyDeactivatedError(
                    f"instance_id {instance_id!r} already deactivated"
                )
            record = InstanceRecord(
                instance_id=instance_id, connector_id=instance.connector_id,
                state="deactivated", seq=seq,
                digest=_pin("instance", instance_id, instance.connector_id,
                            "deactivated", seq),
            )
            self._instances[instance_id] = record
            self._audit_event(KIND_DEACTIVATED, seq,
                              connector_id=instance.connector_id,
                              instance_id=instance_id)
        return record

    # -- views --------------------------------------------------------------

    def manifest_of(self, connector_id: object) -> ConnectorManifest:
        """Read back one registered manifest."""
        connector_id = _check_connector_id(connector_id)
        with self._lock:
            record = self._manifests.get(connector_id)
        if record is None:
            raise UnknownConnectorError(
                f"unknown connector_id {connector_id!r}"
            )
        return record

    def instance(self, instance_id: object) -> InstanceRecord:
        """Read back one instance record."""
        if not isinstance(instance_id, str) or not instance_id:
            raise UnknownInstanceError("instance_id must be a non-empty str")
        with self._lock:
            record = self._instances.get(instance_id)
        if record is None:
            raise UnknownInstanceError(
                f"unknown instance_id {instance_id!r}"
            )
        return record

    def invocation(self, invocation_id: object) -> InvocationRecord:
        """Read back one invocation record."""
        if not isinstance(invocation_id, str) or not invocation_id:
            raise ValueError("invocation_id must be a non-empty str")
        with self._lock:
            record = self._invocations.get(invocation_id)
        if record is None:
            raise ValueError(f"unknown invocation_id {invocation_id!r}")
        return record

    def connector_ids(self) -> Tuple[str, ...]:
        """Sorted ids of registered connectors."""
        with self._lock:
            return tuple(sorted(self._manifests))

    def instance_ids(self) -> Tuple[str, ...]:
        """Sorted ids of initialized instances."""
        with self._lock:
            return tuple(sorted(self._instances))

    def audit_log(self) -> Tuple[dict, ...]:
        """Append-only audit trail."""
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> dict:
        """Snapshot of the whole registry (config/payloads excluded)."""
        with self._lock:
            return {
                "manifests": [m.as_dict() for m in self._manifests.values()],
                "instances": [i.as_dict() for i in self._instances.values()],
                "invocations": [i.as_dict()
                                for i in self._invocations.values()],
                "version": CONNECTOR_SDK_VERSION,
                "schema": CONNECTOR_SDK_SCHEMA,
            }


def _freeze_payload(payload: Any) -> Any:
    """Normalize a payload into a canonicalizable shape."""
    if payload is None or isinstance(payload, (bool, int, str)):
        if isinstance(payload, int) and not isinstance(payload, bool):
            if abs(payload) >= 2 ** 53:
                raise ValueError("payload int outside safe range")
        return payload
    if isinstance(payload, float):
        if payload != payload or payload in (float("inf"), float("-inf")):
            raise ValueError("payload float must be finite")
        return payload
    if isinstance(payload, Mapping):
        return {str(k): _freeze_payload(v) for k, v in payload.items()}
    if isinstance(payload, (list, tuple)):
        return [_freeze_payload(v) for v in payload]
    raise ValueError(f"payload of type {type(payload).__name__} "
                     "is not canonicalizable")


def connector_sdk_audit_event(kind: str, seq: object,
                              connector_id: Optional[str] = None,
                              instance_id: Optional[str] = None,
                              invocation_id: Optional[str] = None) -> dict:
    """Audit-shaped record for a connector-SDK observation.

    Carries ids and digest pins only -- config values and payload
    bodies are banned from the audit boundary.
    """
    if kind not in _KINDS:
        raise ValueError("unknown kind")
    _check_seq(seq)
    body: dict[str, Any] = {
        "event": "connector-sdk",
        "kind": kind,
        "audit_seq": seq,
        "schema": AUDIT_SCHEMA,
    }
    if connector_id is not None:
        body["connector_id"] = connector_id
    if instance_id is not None:
        body["instance_id"] = instance_id
    if invocation_id is not None:
        body["invocation_id"] = invocation_id
    return body


def main() -> None:
    sdk = ConnectorSDK()
    sdk.manifest(
        "weather", "Weather", "1.0",
        [CAP_READ, CAP_SUBSCRIBE], seq=1,
        config_schema=[
            {"name": "api_key", "type": "str", "required": True},
            {"name": "timeout_s", "type": "int", "required": False},
        ],
    )
    inst = sdk.init("weather", {"api_key": "k", "timeout_s": 30}, seq=2)
    inv = sdk.invoke(inst.instance_id, "read", {"city": "guangzhou"}, seq=3)
    assert inv.verify() and inst.verify()
    # Capability gate: write was never declared.
    try:
        sdk.invoke(inst.instance_id, "write", {}, seq=4)
    except CapabilityError:
        pass
    else:  # pragma: no cover
        raise AssertionError("undeclared operation must raise")
    rec = sdk.deactivate(inst.instance_id, seq=5)
    assert rec.state == "deactivated" and rec.verify()
    assert sdk.instance(inst.instance_id).state == "deactivated"
    print("connector-sdk OK: manifest, init, invoke gate, deactivate")


if __name__ == "__main__":
    main()
