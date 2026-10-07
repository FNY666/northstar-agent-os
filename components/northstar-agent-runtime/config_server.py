"""Spring-Cloud-Config-shaped central configuration server bookkeeping.

Research note: centralized configuration decouples *what a service runs with*
from *how it is deployed* (twelve-factor app, factor III: config in the
environment; Spring Cloud Config 2014). The load-bearing ideas are:

* **Multi-source resolution** — a property is looked up across an ordered
  list of *property sources* (Spring's ``PropertySource`` stack). The first
  source that holds the key wins, so a ``prod`` profile shadows the
  ``default`` profile without copying keys.
* **Label/version addressing** — Spring Config serves
  ``/{application}/{profile}/{label}`` where the label is usually a Git
  branch/commit. A *refresh* produces a new addressed snapshot; clients
  poll or get pushed the diff (``/refresh`` + Spring Cloud Bus).
* **Refresh scope** — Spring's ``@RefreshScope`` drops cached beans on
  refresh so the new value is *actually* picked up; a refresh that silently
  does nothing is the classic footgun.

What this module pins down, deterministically and in-process:

* **Precedence chain** — :meth:`ConfigServer.get` resolves
  ``(app, profile, label)`` → ``(app, default-profile, label)`` →
  ``(app, default-profile, default-label)``; the record says which source
  won, so a shadowing conflict is *auditable*, not invisible.
* **Version ledger** — every successful mutation bumps a per-``(app,
  label)`` version (monotonic ints, caller-supplied seqs, no wall-clock).
  :meth:`ConfigServer.refresh` emits a frozen :class:`RefreshReport` naming
  exactly which keys changed since the previous version — the "bus
  message", not the bus itself.
* **Fail-closed** — unknown applications on read, duplicate writes with a
  conflicting digest, NaN/inf/un-canonicalizable values, and
  bool/negative seqs raise instead of silently producing a config that a
  service will run with.

Honest scope: this is a *contract* for configuration resolution, not a
Git-backed server. It cannot prove a value is what operations intended,
detect a host lying about what it stored, or deliver refreshes to live
clients (there is no bus). A resolved value means "this server would
hand out this value for this (app, profile, label)", never "this is what
production should run". Values are pinned by ``sha256:`` digests over a
canonical encoding (bool ≠ int; NaN/inf and >2⁵³ integral floats refused).

Version pin: config-server.v1
Schema pin: northstar.config-server.v1
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

#: Module version.
CONFIG_SERVER_VERSION = "config-server.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.config-server.v1"

#: Audit record format.
AUDIT_FORMAT = "audit.ndjson/1"

_DEFAULT_PROFILE = "default"
_DEFAULT_LABEL = "main"

_MAX_NAME_LEN = 256
_MAX_KEY_LEN = 256
_MAX_VALUE_BYTES = 1 << 20  # 1 MiB guardrail.

_AUDIT_KINDS = frozenset(
    {
        "property-set",
        "property-read",
        "property-deleted",
        "refreshed",
        "rejected",
    }
)


class ConfigServerError(Exception):
    """Base error for malformed use of the config contract."""


class UnknownApplicationError(ConfigServerError):
    """Reading a key from an (app, label) pair that holds no properties."""


class UnknownKeyError(ConfigServerError):
    """The key resolves in no property source of the precedence chain."""


class DigestConflictError(ConfigServerError):
    """An explicit expected-digest on set did not match the stored value."""


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _check_name(name: object, what: str = "name") -> str:
    if isinstance(name, bool) or not isinstance(name, str):
        raise TypeError(f"{what} must be str, got {type(name).__name__}")
    if not name:
        raise ValueError(f"{what} must be non-empty")
    if len(name) > _MAX_NAME_LEN:
        raise ValueError(f"{what} exceeds {_MAX_NAME_LEN} chars")
    return name


def _check_key(key: object) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise TypeError(f"key must be str, got {type(key).__name__}")
    if not key:
        raise ValueError("key must be non-empty")
    if len(key) > _MAX_KEY_LEN:
        raise ValueError(f"key exceeds {_MAX_KEY_LEN} chars")
    return key


def _canonical(value: Any) -> str:
    """Deterministic canonical string for digest pins (type-tagged)."""
    if isinstance(value, bool):
        return f"bool:{value!r}"
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("NaN/inf cannot be canonicalized")
        if value.is_integer() and abs(value) > 2**53:
            raise ValueError("integral float beyond 2**53 loses precision")
        return f"float:{repr(value)}"
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise ValueError("int beyond 2**53 loses JCS precision")
        return f"int:{value}"
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_VALUE_BYTES:
            raise ValueError(f"value exceeds {_MAX_VALUE_BYTES} bytes")
        return f"str:{json.dumps(value, sort_keys=True)}"
    if value is None:
        return "null"
    if isinstance(value, Mapping):
        items = sorted(
            ((str(k), _canonical(v)) for k, v in value.items()),
            key=lambda kv: kv[0],
        )
        return "{" + ",".join(f"{k}:{v}" for k, v in items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(v) for v in value) + "]"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")


def _digest(*parts: str) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return "sha256:" + h.hexdigest()


@dataclass(frozen=True)
class PropertyRecord:
    """A stored property at (app, profile, label, key)."""

    app: str
    profile: str
    label: str
    key: str
    value_digest: str
    set_seq: int
    version: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "app": self.app,
            "profile": self.profile,
            "label": self.label,
            "key": self.key,
            "value_digest": self.value_digest,
            "set_seq": self.set_seq,
            "version": self.version,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class ResolvedValue:
    """The winning resolution for a get() call."""

    app: str
    profile: str
    label: str
    key: str
    value: Any
    source: str  # which precedence level won: "app+profile+label" | "app+default+label" | "app+default+main"
    value_digest: str
    record_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "app": self.app,
            "profile": self.profile,
            "label": self.label,
            "key": self.key,
            "value": self.value,
            "source": self.source,
            "value_digest": self.value_digest,
            "record_digest": self.record_digest,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class RefreshReport:
    """The outcome of a refresh() call: version bump + changed keys."""

    app: str
    label: str
    from_version: int
    to_version: int
    changed_keys: Tuple[str, ...]
    refresh_seq: int
    report_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "app": self.app,
            "label": self.label,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "changed_keys": list(self.changed_keys),
            "refresh_seq": self.refresh_seq,
            "report_digest": self.report_digest,
            "schema": SCHEMA_PIN,
        }


class ConfigServer:
    """Spring-Cloud-Config-shaped property registry with refresh versioning."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # app -> label -> profile -> key -> (value, PropertyRecord)
        self._props: Dict[str, Dict[str, Dict[str, Dict[str, Tuple[Any, PropertyRecord]]]]] = {}
        # (app, label) -> current version int
        self._versions: Dict[Tuple[str, str], int] = {}
        # (app, label) -> version at last refresh
        self._refreshed_at: Dict[Tuple[str, str], int] = {}
        # (app, label) -> list of (version, key) change log for refresh diffs
        self._changes: Dict[Tuple[str, str], list] = {}

    # -- internal ------------------------------------------------------

    def _version(self, app: str, label: str) -> int:
        return self._versions.get((app, label), 0)

    def _bump(self, app: str, label: str, key: str) -> int:
        version = self._version(app, label) + 1
        self._versions[(app, label)] = version
        self._changes.setdefault((app, label), []).append((version, key))
        return version

    def _lookup(self, app: str, label: str, profile: str, key: str):
        """Return (value, record, source) or None following the precedence chain."""
        labels = self._props.get(app, {})
        if not labels:
            return None
        chain = [
            (label, profile, "app+profile+label"),
            (label, _DEFAULT_PROFILE, "app+default-profile+label"),
            (_DEFAULT_LABEL, _DEFAULT_PROFILE, "app+default-profile+main"),
        ]
        for cand_label, cand_profile, source in chain:
            profiles = labels.get(cand_label)
            if not profiles:
                continue
            keys = profiles.get(cand_profile)
            if not keys:
                continue
            if key in keys:
                value, record = keys[key]
                return value, record, source
        return None

    # -- API ------------------------------------------------------------

    def set(
        self,
        app: str,
        profile: str,
        key: str,
        value: Any,
        seq: int,
        label: str = _DEFAULT_LABEL,
        expected_digest: Optional[str] = None,
    ) -> PropertyRecord:
        """Store a property; bumps the (app, label) version."""
        app = _check_name(app, "app")
        profile = _check_name(profile, "profile")
        label = _check_name(label, "label")
        key = _check_key(key)
        _check_seq(seq)
        canonical = _canonical(value)
        value_digest = _digest(canonical)
        with self._lock:
            if expected_digest is not None:
                existing = self._props.get(app, {}).get(label, {}).get(profile, {}).get(key)
                if existing is not None and existing[1].value_digest != expected_digest:
                    raise DigestConflictError(
                        f"digest conflict on {app}/{profile}/{key}@{label}"
                    )
            version = self._bump(app, label, key)
            record = PropertyRecord(
                app=app,
                profile=profile,
                label=label,
                key=key,
                value_digest=value_digest,
                set_seq=seq,
                version=version,
            )
            self._props.setdefault(app, {}).setdefault(label, {}).setdefault(
                profile, {}
            )[key] = (value, record)
            return record

    def get(
        self,
        app: str,
        profile: str,
        key: str,
        seq: int,
        label: str = _DEFAULT_LABEL,
    ) -> ResolvedValue:
        """Resolve a property through the precedence chain (fail-closed)."""
        app = _check_name(app, "app")
        profile = _check_name(profile, "profile")
        label = _check_name(label, "label")
        key = _check_key(key)
        _check_seq(seq)
        with self._lock:
            found = self._lookup(app, label, profile, key)
            if found is None:
                if app not in self._props:
                    raise UnknownApplicationError(f"unknown app: {app}")
                raise UnknownKeyError(
                    f"key {key!r} not found for {app}/{profile}@{label}"
                )
            value, record, source = found
            canonical = _canonical(value)
            value_digest = _digest(canonical)
            record_digest = _digest(
                value_digest, source, record.app, record.profile, record.label, record.key
            )
            return ResolvedValue(
                app=app,
                profile=profile,
                label=label,
                key=key,
                value=value,
                source=source,
                value_digest=value_digest,
                record_digest=record_digest,
            )

    def delete(
        self,
        app: str,
        profile: str,
        key: str,
        seq: int,
        label: str = _DEFAULT_LABEL,
    ) -> PropertyRecord:
        """Delete a property (tombstones the version, does not erase history)."""
        app = _check_name(app, "app")
        profile = _check_name(profile, "profile")
        label = _check_name(label, "label")
        key = _check_key(key)
        _check_seq(seq)
        with self._lock:
            keys = (
                self._props.get(app, {}).get(label, {}).get(profile, {})
            )
            if key not in keys:
                raise UnknownKeyError(f"key {key!r} not stored at {app}/{profile}@{label}")
            old_record = keys.pop(key)[1]
            version = self._bump(app, label, key)
            return PropertyRecord(
                app=app,
                profile=profile,
                label=label,
                key=key,
                value_digest=old_record.value_digest,
                set_seq=seq,
                version=version,
            )

    def refresh(
        self,
        app: str,
        seq: int,
        label: str = _DEFAULT_LABEL,
    ) -> RefreshReport:
        """Bump a client's refresh view; reports keys changed since last refresh."""
        app = _check_name(app, "app")
        label = _check_name(label, "label")
        _check_seq(seq)
        with self._lock:
            if app not in self._props:
                raise UnknownApplicationError(f"unknown app: {app}")
            from_version = self._refreshed_at.get((app, label), 0)
            to_version = self._version(app, label)
            changes = self._changes.get((app, label), [])
            changed = tuple(
                sorted({key for version, key in changes if version > from_version})
            )
            self._refreshed_at[(app, label)] = to_version
            report = RefreshReport(
                app=app,
                label=label,
                from_version=from_version,
                to_version=to_version,
                changed_keys=changed,
                refresh_seq=seq,
                report_digest=_digest(
                    app, label, str(from_version), str(to_version),
                    ",".join(changed),
                ),
            )
            return report

    def version(self, app: str, label: str = _DEFAULT_LABEL) -> int:
        """Current version of an (app, label) pair."""
        app = _check_name(app, "app")
        label = _check_name(label, "label")
        with self._lock:
            return self._version(app, label)

    def keys(
        self,
        app: str,
        profile: str,
        label: str = _DEFAULT_LABEL,
    ) -> Tuple[str, ...]:
        """Sorted keys stored at exactly (app, profile, label) — no precedence."""
        app = _check_name(app, "app")
        profile = _check_name(profile, "profile")
        label = _check_name(label, "label")
        with self._lock:
            keys = (
                self._props.get(app, {}).get(label, {}).get(profile, {})
            )
            return tuple(sorted(keys))


def config_server_audit_event(kind: str, seq: int = 0) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a config-server op.

    ``kind`` is one of ``"property-set"`` / ``"property-read"`` /
    ``"property-deleted"`` / ``"refreshed"`` / ``"rejected"``.
    """
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    return {
        "format": AUDIT_FORMAT,
        "schema": SCHEMA_PIN,
        "kind": kind,
        "seq": _check_seq(seq),
    }


def main() -> None:
    server = ConfigServer()
    server.set("billing", "default", "timeout_ms", 3000, seq=1)
    server.set("billing", "prod", "timeout_ms", 1500, seq=2)
    server.set("billing", "prod", "retries", 3, seq=3)
    # Profile shadows default.
    assert server.get("billing", "prod", "timeout_ms", seq=4).value == 1500
    # Default still visible for dev.
    assert server.get("billing", "dev", "timeout_ms", seq=5).value == 3000
    # Refresh reports exactly what changed.
    first = server.refresh("billing", seq=6)
    assert first.changed_keys == ("retries", "timeout_ms"), first.changed_keys
    second = server.refresh("billing", seq=7)
    assert second.changed_keys == ()
    # No-op refresh does not lose the version.
    assert second.to_version == first.to_version
    print("audit:", config_server_audit_event("refreshed", seq=6)["kind"])
    print("config-server OK: set, precedence, refresh diff")


if __name__ == "__main__":
    main()
