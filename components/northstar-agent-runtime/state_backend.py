"""RocksDB-style keyed state backend: put/get/delete plus digest-pinned snapshots.

A stream processor keeps *keyed state* -- per-key working memory that
survives restarts only if it can be snapshotted and restored. This module
is the state half of that contract (the durability half lives with the
host's checkpoint storage):

- :meth:`StateBackend.put` / :meth:`StateBackend.get` /
  :meth:`StateBackend.delete` operate on ``(namespace, key)`` pairs, so
  one backend can host many logical key groups without key collisions.
- :meth:`StateBackend.snapshot` freezes the entire content into an
  immutable, ``sha256:``-pinned :class:`Snapshot` record.
- :meth:`StateBackend.restore` reloads a snapshot, but *only* after the
  digest pin re-verifies -- a tampered or foreign snapshot is refused
  fail-closed, never partially applied.

Values are stored as deep copies (never by reference): the backend
copies on ``put`` and again on ``get``, so caller-side mutation can
never move a pinned digest and two ``get`` calls never alias the same
object. A value must be canonicalizable by the shared ``canonical_json``
module (NaN/inf, non-str dict keys, bytes, and other non-JSON values are
refused at the API boundary).

Honest scope: this is in-memory *interface bookkeeping*, not RocksDB. It
cannot survive a process crash (persistence is the host's checkpoint
store), cannot prove a value was true (the host chose it), and cannot
bound who saw intermediate states. A ``Snapshot`` proves only that
*these digests* were the content at snapshot time.
"""

from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

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
STATE_BACKEND_VERSION = "state-backend.v1"

#: Schema pin carried by records and audit events.
STATE_BACKEND_SCHEMA = "northstar.state-backend.v1"

#: Domain prefix for snapshot digest pins.
_SNAPSHOT_DOMAIN = b"northstar-state-backend.v1:snapshot:"


class StateBackendError(Exception):
    """Base error: any state-backend contract violation."""


class SnapshotVerificationError(StateBackendError):
    """Raised when a snapshot fails verification on restore."""


def _check_text(value: object, name: str, allow_empty: bool = False) -> str:
    """Validate a text field: str (never bool), optionally non-empty."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise ValueError(f"{name} must be non-empty")
    return value


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_value(value: Any) -> Any:
    """Validate a put value: canonicalizable by the shared canonicalizer."""
    if value is None:
        raise TypeError("value must not be None (use delete)")
    try:
        jcs_canonical_json(value)
    except Exception as exc:
        raise TypeError(f"value is not canonicalizable: {exc}") from exc
    return value


def _digest_of(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(_SNAPSHOT_DOMAIN + payload).hexdigest()


@dataclass(frozen=True)
class Snapshot:
    """An immutable, digest-pinned freeze of a :class:`StateBackend`."""

    backend_name: str
    seq: int
    entry_count: int
    digest: str
    payload: bytes = field(repr=False)
    schema: str = STATE_BACKEND_SCHEMA

    def __post_init__(self) -> None:
        _check_text(self.backend_name, "backend_name")
        _check_seq(self.seq)
        if isinstance(self.entry_count, bool) or not isinstance(self.entry_count, int):
            raise TypeError("entry_count must be int")
        if self.entry_count < 0:
            raise ValueError("entry_count must be >= 0")
        if not (isinstance(self.digest, str) and self.digest.startswith("sha256:")):
            raise ValueError("digest must be a sha256: pin")
        if not isinstance(self.payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        if self.schema != STATE_BACKEND_SCHEMA:
            raise ValueError("schema pin mismatch")

    def verify(self) -> bool:
        """Re-verify the digest pin against the payload (never raises)."""
        try:
            return _digest_of(bytes(self.payload)) == self.digest
        except Exception:
            return False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "backend_name": self.backend_name,
            "seq": self.seq,
            "entry_count": self.entry_count,
            "digest": self.digest,
            "payload_hex": bytes(self.payload).hex(),
            "schema": self.schema,
        }


class StateBackend:
    """RocksDB-style keyed state: ``(namespace, key)`` pairs, in-memory."""

    def __init__(self, name: str) -> None:
        self._name = _check_text(name, "name")
        self._store: Dict[Tuple[str, str], Any] = {}
        self._lock = threading.RLock()
        self._last_snapshot_seq = -1

    @property
    def name(self) -> str:
        return self._name

    def put(self, key: str, value: Any, namespace: str = "") -> None:
        """Store ``value`` under ``(namespace, key)`` (overwrites)."""
        ns = _check_text(namespace, "namespace", allow_empty=True)
        k = _check_text(key, "key")
        _check_value(value)
        with self._lock:
            self._store[(ns, k)] = copy.deepcopy(value)

    def get(self, key: str, namespace: str = "") -> Optional[Any]:
        """Return a copy of the value, or ``None`` when the key is absent."""
        ns = _check_text(namespace, "namespace", allow_empty=True)
        k = _check_text(key, "key")
        with self._lock:
            value = self._store.get((ns, k))
        return None if value is None else copy.deepcopy(value)

    def delete(self, key: str, namespace: str = "") -> bool:
        """Remove ``(namespace, key)``; ``True`` iff it existed."""
        ns = _check_text(namespace, "namespace", allow_empty=True)
        k = _check_text(key, "key")
        with self._lock:
            return self._store.pop((ns, k), None) is not None

    def contains(self, key: str, namespace: str = "") -> bool:
        ns = _check_text(namespace, "namespace", allow_empty=True)
        k = _check_text(key, "key")
        with self._lock:
            return (ns, k) in self._store

    def clear(self) -> None:
        """Drop all state (all namespaces)."""
        with self._lock:
            self._store.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._store)

    def keys(self, namespace: Optional[str] = None) -> Tuple[Tuple[str, str], ...]:
        """Sorted ``(namespace, key)`` pairs; optionally restricted."""
        if namespace is not None:
            _check_text(namespace, "namespace", allow_empty=True)
        with self._lock:
            items = sorted(self._store)
        if namespace is None:
            return tuple(items)
        return tuple((ns, k) for ns, k in items if ns == namespace)

    def namespaces(self) -> Tuple[str, ...]:
        """Sorted distinct namespaces present in the backend."""
        with self._lock:
            return tuple(sorted({ns for ns, _ in self._store}))

    def _payload(self) -> bytes:
        """Canonical encoding of the full sorted content."""
        with self._lock:
            entries: List[List[Any]] = [
                [ns, key, value] for (ns, key), value in sorted(self._store.items())
            ]
        return jcs_canonical_json(entries)

    def state_digest(self) -> str:
        """Live ``sha256:`` pin of the current content (namespace-ordered)."""
        return _digest_of(self._payload())

    def snapshot(self, seq: int) -> Snapshot:
        """Freeze current content into an immutable pinned :class:`Snapshot`."""
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_snapshot_seq:
                raise StateBackendError(
                    f"snapshot seq must strictly increase "
                    f"(last={self._last_snapshot_seq}, got={seq})"
                )
            payload = self._payload()
            count = len(self._store)
            self._last_snapshot_seq = seq
        return Snapshot(
            backend_name=self._name,
            seq=seq,
            entry_count=count,
            digest=_digest_of(payload),
            payload=payload,
        )

    def restore(self, snapshot: Snapshot, seq: int) -> None:
        """Replace all content with ``snapshot`` after verifying its digest."""
        seq = _check_seq(seq)
        if not isinstance(snapshot, Snapshot):
            raise TypeError("snapshot must be a Snapshot")
        if snapshot.backend_name != self._name:
            raise SnapshotVerificationError(
                f"snapshot belongs to {snapshot.backend_name!r}, not {self._name!r}"
            )
        payload = bytes(snapshot.payload)
        if _digest_of(payload) != snapshot.digest:
            raise SnapshotVerificationError("snapshot digest mismatch: refused")
        import json as _json

        try:
            entries = _json.loads(payload.decode("utf-8"))
        except Exception as exc:
            raise SnapshotVerificationError(
                f"snapshot payload undecodable: {exc}"
            ) from exc
        if not isinstance(entries, list):
            raise SnapshotVerificationError("snapshot payload malformed")
        store: Dict[Tuple[str, str], Any] = {}
        for item in entries:
            if (
                not isinstance(item, list)
                or len(item) != 3
                or not isinstance(item[0], str)
                or not isinstance(item[1], str)
                or not item[1]
            ):
                raise SnapshotVerificationError("snapshot payload malformed")
            ns, key, value = item
            _check_value(value)
            if (ns, key) in store:
                raise SnapshotVerificationError("snapshot has duplicate entries")
            store[(ns, key)] = copy.deepcopy(value)
        if len(store) != snapshot.entry_count:
            raise SnapshotVerificationError("snapshot entry count mismatch")
        with self._lock:
            self._store = store
            if seq > self._last_snapshot_seq:
                self._last_snapshot_seq = seq


def state_backend_audit_event(kind: str, seq: int, **kwargs: Any) -> dict:
    """Shape a state-backend lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("put", "got", "deleted", "snapshotted", "restored", "cleared", "rejected")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event = {
        "schema": "audit.ndjson/1",
        "kind": f"state-backend.{kind}",
        "module": STATE_BACKEND_SCHEMA,
        "version": STATE_BACKEND_VERSION,
        "seq": seq,
    }
    for key in ("namespace", "key", "backend", "digest", "entries"):
        if key in kwargs:
            event[key] = kwargs[key]
    return event


def main() -> None:
    be = StateBackend("demo")
    be.put("k1", {"a": 1, "b": [1, 2]}, namespace="ns1")
    be.put("k2", "hello", namespace="ns1")
    be.put("k1", 42, namespace="ns2")
    assert be.get("k1", namespace="ns1") == {"a": 1, "b": [1, 2]}
    assert be.get("missing", namespace="ns1") is None
    assert be.get("k1", namespace="ns2") == 42
    # no aliasing: caller mutation cannot move stored state
    v = be.get("k1", namespace="ns1")
    v["a"] = 999
    assert be.get("k1", namespace="ns1") == {"a": 1, "b": [1, 2]}
    snap = be.snapshot(1)
    assert snap.entry_count == 3
    assert snap.verify() is True
    assert be.state_digest() == snap.digest
    be.put("k3", "later", namespace="ns1")
    assert be.size() == 4
    be.restore(snap, 2)
    assert be.size() == 3 and be.get("k3", namespace="ns1") is None
    assert be.state_digest() == snap.digest
    # tampered snapshot refused
    tampered = Snapshot(
        backend_name="demo",
        seq=9,
        entry_count=0,
        digest="sha256:" + "0" * 64,
        payload=b"",
    )
    try:
        be.restore(tampered, 3)
        raise AssertionError("tampered restore must fail")
    except SnapshotVerificationError:
        pass
    # foreign snapshot refused
    other = StateBackend("other")
    try:
        other.restore(snap, 3)
        raise AssertionError("foreign restore must fail")
    except SnapshotVerificationError:
        pass
    print("state-backend OK: put/get/delete, snapshot, restore, refusal")


if __name__ == "__main__":
    main()
