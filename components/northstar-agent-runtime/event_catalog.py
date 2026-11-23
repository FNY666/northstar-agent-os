"""AsyncAPI-shaped event catalog: a ledger for event schema decisions.

An ``EventCatalog`` books host-reported event-schema decisions as a
deterministic single-host state machine:

- ``schema(event_id, name, topic, definition, seq)`` registers one event
  as a frozen ``EventRecord`` pinned by a ``sha256:`` digest. Topics are
  AsyncAPI-channel-shaped (``user/created`` or ``user.created``); the
  definition is a host-reported JSON-schema-shaped mapping whose
  ``properties`` use a pinned field-type vocabulary
  (``string``/``integer``/``number``/``boolean``/``array``/``object``/``null``).
  Duplicate ids are refused fail-closed.
- ``discover(query, seq)`` is a pure read view returning a frozen
  ``DiscoveryReport`` of matching event ids (topic-prefix or name-substring
  match); no match is data, never an error.
- ``validate(event_id, payload, seq)`` books a frozen ``ValidationReport``
  whose verdict is data — structural validation of the host-reported
  payload against the registered schema: required-field presence plus
  per-field type checks. Violations are listed as strings.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin ``event-catalog.v1``,
schema pin ``northstar.event-catalog.v1``, ``main()`` self-check.

Honest scope: this module books *declared* schemas and validates
*host-reported* payloads against them. It is not an AsyncAPI parser, it
cannot observe the wire, and a "valid" verdict means only "matches the
declared schema" — never that the payload was produced by a real
publisher. Payload bytes never cross the audit boundary (ids + digest
pins only).
"""

from __future__ import annotations

import ast
import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
EVENT_CATALOG_VERSION = "event-catalog.v1"

#: Schema pin carried by records and audit events.
EVENT_CATALOG_SCHEMA = "northstar.event-catalog.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned field-type vocabulary for event schema definitions.
FIELD_TYPES = (
    "string",
    "integer",
    "number",
    "boolean",
    "array",
    "object",
    "null",
)

#: Pin: only object-typed event schemas are supported for deterministic
#: structural validation (arrays-of-top-level etc. are refused at
#: registration; the honest boundary is documented above).
SUPPORTED_ROOT_TYPE = "object"

#: Pin: maximum event id / name / topic length in chars.
MAX_ID_CHARS = 128
MAX_NAME_CHARS = 256
MAX_TOPIC_CHARS = 253

#: Pin: maximum number of properties per schema definition.
MAX_PROPERTIES = 256

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_TOPIC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/{}/]*$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class EventCatalogError(Exception):
    """Base class for all event_catalog errors."""


class BadEventError(EventCatalogError):
    """The event id, name, or topic is malformed."""


class DuplicateEventError(EventCatalogError):
    """An event with this id is already registered."""


class UnknownEventError(EventCatalogError):
    """The referenced event id is unknown."""


class BadSchemaError(EventCatalogError):
    """The schema definition is malformed or uses unpinned types."""


class BadPayloadError(EventCatalogError):
    """The payload is not a mapping and cannot be structurally validated."""


class SeqOrderError(EventCatalogError):
    """The caller seq was not a strictly increasing non-negative int."""


class AuditKindError(EventCatalogError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Canonical encoding / pinning
# ---------------------------------------------------------------------------


def _tag_encode(value: Any) -> Any:
    """Tag-encode a value for deterministic canonical JSON pinning.

    ``bool`` is encoded distinctly from ``int`` and integers outside the
    safe range ``|n| < 2**53`` are refused (canonical_json precision
    discipline); floats are refused outright in pinned structures.
    """
    if value is True:
        return {"$bool": True}
    if value is False:
        return {"$bool": False}
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadSchemaError("integer out of safe range")
        return {"$int": value}
    if isinstance(value, float):
        raise BadSchemaError("floats are not permitted in pinned structures")
    if isinstance(value, (bytes, bytearray)):
        return {"$bytes": bytes(value).hex()}
    if isinstance(value, (list, tuple)):
        return [_tag_encode(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _tag_encode(v) for k, v in value.items()}
    if isinstance(value, (str, type(None))):
        return value
    raise BadSchemaError(f"unsupported value type: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    canonical = jcs_canonical_json(_tag_encode(list(parts)))
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _payload_encode(value: Any) -> Any:
    """Tag-encode a payload value for the digest pin.

    Mirrors :func:`_tag_encode` but permits floats (``number`` fields are
    legal in payloads); NaN/inf are refused. ``bool`` stays distinct from
    ``int`` and integers outside ``|n| < 2**53`` are refused.
    """
    if value is True:
        return {"$bool": True}
    if value is False:
        return {"$bool": False}
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadPayloadError("integer out of safe range")
        return {"$int": value}
    if isinstance(value, float):
        if value != value or abs(value) == float("inf"):
            raise BadPayloadError("NaN/inf not permitted in payload digests")
        return {"$float": repr(value)}
    if isinstance(value, (bytes, bytearray)):
        return {"$bytes": bytes(value).hex()}
    if isinstance(value, (list, tuple)):
        return [_payload_encode(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _payload_encode(v) for k, v in value.items()}
    if isinstance(value, (str, type(None))):
        return value
    raise BadPayloadError(f"unsupported payload type: {type(value).__name__}")


def _payload_digest(payload: Mapping[str, Any]) -> str:
    """Digest the payload for the audit boundary (payload never crosses)."""
    canonical = jcs_canonical_json(_payload_encode(dict(payload)))
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_id(event_id: Any) -> str:
    if not isinstance(event_id, str) or not event_id:
        raise BadEventError("event_id must be a non-empty str")
    if len(event_id) > MAX_ID_CHARS:
        raise BadEventError(f"event_id exceeds {MAX_ID_CHARS} chars")
    if not _ID_RE.match(event_id):
        raise BadEventError("event_id must match [A-Za-z0-9._-], start alnum")
    return event_id


def _check_name(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        raise BadEventError("name must be a non-empty str")
    if len(name) > MAX_NAME_CHARS:
        raise BadEventError(f"name exceeds {MAX_NAME_CHARS} chars")
    if _CONTROL_RE.search(name):
        raise BadEventError("name carries control characters")
    return name.strip()


def _check_topic(topic: Any) -> str:
    if not isinstance(topic, str) or not topic:
        raise BadEventError("topic must be a non-empty str")
    if len(topic) > MAX_TOPIC_CHARS:
        raise BadEventError(f"topic exceeds {MAX_TOPIC_CHARS} chars")
    if _CONTROL_RE.search(topic) or any(ch.isspace() for ch in topic):
        raise BadEventError("topic must not carry whitespace or control chars")
    if not _TOPIC_RE.match(topic):
        raise BadEventError("topic carries illegal characters")
    return topic


def _check_definition(definition: Any) -> Tuple[Tuple[str, str], ...]:
    """Validate a schema definition; return pinned (name, type) pairs."""
    if not isinstance(definition, Mapping):
        raise BadSchemaError("definition must be a mapping")
    root = definition.get("type")
    if root != SUPPORTED_ROOT_TYPE:
        raise BadSchemaError(
            f"only root type {SUPPORTED_ROOT_TYPE!r} is supported"
        )
    props = definition.get("properties", {})
    if not isinstance(props, Mapping):
        raise BadSchemaError("properties must be a mapping")
    if len(props) > MAX_PROPERTIES:
        raise BadSchemaError(f"properties exceeds {MAX_PROPERTIES} entries")
    pinned: List[Tuple[str, str]] = []
    for fname, fschema in props.items():
        if not isinstance(fname, str) or not fname or _CONTROL_RE.search(fname):
            raise BadSchemaError(f"bad property name: {fname!r}")
        if not isinstance(fschema, Mapping):
            raise BadSchemaError(f"property {fname!r} must be a mapping")
        ftype = fschema.get("type")
        if ftype not in FIELD_TYPES:
            raise BadSchemaError(
                f"property {fname!r} uses unpinned type {ftype!r}"
            )
        pinned.append((fname, ftype))
    required = definition.get("required", [])
    if not isinstance(required, (list, tuple)):
        raise BadSchemaError("required must be a list")
    prop_names = {p[0] for p in pinned}
    for req in required:
        if req not in prop_names:
            raise BadSchemaError(
                f"required field {req!r} not present in properties"
            )
    return tuple(pinned)


def _type_ok(value: Any, ftype: str) -> bool:
    """Structural type check for one payload value against a pinned type."""
    if ftype == "null":
        return value is None
    if value is None:
        return False
    if ftype == "string":
        return isinstance(value, str)
    if ftype == "boolean":
        return isinstance(value, bool)
    if ftype == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if ftype == "number":
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        if isinstance(value, float):
            return value == value and abs(value) != float("inf")
        return False
    if ftype == "array":
        return isinstance(value, list)
    if ftype == "object":
        return isinstance(value, dict)
    return False  # unreachable: pinned vocabulary


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "event-registered",
    "events-discovered",
    "event-validated",
    "rejected",
)


def event_catalog_audit_event(
    kind: str,
    seq: int,
    event_id: str = "",
    digest: str = "",
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event; ids and digest pins only.

    Schema definitions and payload bytes never cross the audit boundary —
    only the event id plus digest pins.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return {
        "schema": AUDIT_SCHEMA,
        "module": EVENT_CATALOG_VERSION,
        "kind": kind,
        "seq": seq,
        "event_id": event_id,
        "digest": digest,
    }


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EventRecord:
    """One registered event schema (frozen)."""

    event_id: str
    name: str
    topic: str
    properties: Tuple[Tuple[str, str], ...]
    required: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = EVENT_CATALOG_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "event",
            self.event_id,
            self.name,
            self.topic,
            list(self.properties),
            list(self.required),
            self.seq,
        )


@dataclass(frozen=True)
class DiscoveryReport:
    """Result of a discover() read view (frozen). No match is data."""

    query: str
    event_ids: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = EVENT_CATALOG_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "discover", self.query, list(self.event_ids), self.seq
        )


@dataclass(frozen=True)
class ValidationReport:
    """Result of a validate() call (frozen). Verdict is data."""

    event_id: str
    valid: bool
    violations: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = EVENT_CATALOG_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "validate",
            self.event_id,
            self.valid,
            list(self.violations),
            self.seq,
        )


# ---------------------------------------------------------------------------
# The catalog
# ---------------------------------------------------------------------------


class EventCatalog:
    """Deterministic AsyncAPI-shaped event schema ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume their
    seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: Dict[str, EventRecord] = {}
        self._last_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ---------------------------------------------------

    def _check_seq(self, seq: Any) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (got {seq}, last {self._last_seq})"
            )
        self._last_seq = seq

    def _read_seq(self, seq: Any) -> None:
        """Validate seq shape for read views; never consumes."""
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")

    def _reject(self, seq: int, reason: str, event_id: str = "") -> None:
        try:
            ev = event_catalog_audit_event("rejected", seq, event_id)
        except EventCatalogError:  # pragma: no cover - seq already validated
            ev = {"schema": AUDIT_SCHEMA, "kind": "rejected", "seq": seq}
        ev["reason"] = reason
        self._audit.append(ev)

    # -- mutation: schema() -----------------------------------------------

    def schema(
        self,
        event_id: str,
        name: str,
        topic: str,
        definition: Mapping[str, Any],
        seq: int,
    ) -> EventRecord:
        """Register one event schema as a frozen ``EventRecord``."""
        with self._lock:
            self._check_seq(seq)
            try:
                eid = _check_id(event_id)
                ename = _check_name(name)
                etopic = _check_topic(topic)
                props = _check_definition(definition)
                required = tuple(definition.get("required", []))
            except EventCatalogError as exc:
                self._reject(seq, str(exc))
                raise
            if eid in self._events:
                self._reject(seq, "duplicate event_id", eid)
                raise DuplicateEventError(f"event already registered: {eid!r}")
            rec = EventRecord(
                event_id=eid,
                name=ename,
                topic=etopic,
                properties=props,
                required=required,
                seq=seq,
                digest=_pin(
                    "event",
                    eid,
                    ename,
                    etopic,
                    list(props),
                    list(required),
                    seq,
                ),
            )
            self._events[eid] = rec
            self._audit.append(
                event_catalog_audit_event(
                    "event-registered", seq, eid, rec.digest
                )
            )
            return rec

    # -- read view: discover() --------------------------------------------

    def discover(self, query: str, seq: int) -> DiscoveryReport:
        """Pure read view: match events by topic-prefix or name-substring.

        The seq is validated for shape but not consumed; no audit row is
        written for an empty result (no match is data).
        """
        with self._lock:
            self._read_seq(seq)
            if not isinstance(query, str):
                raise BadEventError("query must be a str")
            q = query.strip().lower()
            hits: List[str] = []
            for eid, rec in self._events.items():
                if not q:
                    hits.append(eid)
                elif rec.topic.lower().startswith(q) or q in rec.name.lower():
                    hits.append(eid)
            hits.sort()
            report = DiscoveryReport(
                query=query,
                event_ids=tuple(hits),
                seq=seq,
                digest=_pin("discover", query, hits, seq),
            )
            if hits:
                self._audit.append(
                    event_catalog_audit_event(
                        "events-discovered", seq, "", report.digest
                    )
                )
            return report

    # -- mutation: validate() ----------------------------------------------

    def validate(
        self, event_id: str, payload: Mapping[str, Any], seq: int
    ) -> ValidationReport:
        """Book a frozen ``ValidationReport``; the verdict is data."""
        with self._lock:
            self._check_seq(seq)
            try:
                eid = _check_id(event_id)
            except EventCatalogError as exc:
                self._reject(seq, str(exc))
                raise
            rec = self._events.get(eid)
            if rec is None:
                self._reject(seq, "unknown event_id", eid)
                raise UnknownEventError(f"unknown event: {eid!r}")
            if not isinstance(payload, Mapping):
                self._reject(seq, "payload must be a mapping", eid)
                raise BadPayloadError("payload must be a mapping")
            violations: List[str] = []
            prop_map = dict(rec.properties)
            for req in rec.required:
                if req not in payload:
                    violations.append(f"missing required field: {req}")
            for fname, ftype in rec.properties:
                if fname in payload and not _type_ok(payload[fname], ftype):
                    violations.append(
                        f"field {fname!r} expected {ftype}, "
                        f"got {type(payload[fname]).__name__}"
                    )
            report = ValidationReport(
                event_id=eid,
                valid=not violations,
                violations=tuple(violations),
                seq=seq,
                digest=_pin(
                    "validate", eid, not violations, violations, seq
                ),
            )
            self._audit.append(
                event_catalog_audit_event(
                    "event-validated", seq, eid, _payload_digest(payload)
                )
            )
            return report

    # -- views ---------------------------------------------------------------

    def event(self, event_id: str) -> EventRecord:
        """Return the registered ``EventRecord`` for an id."""
        with self._lock:
            rec = self._events.get(_check_id(event_id))
            if rec is None:
                raise UnknownEventError(f"unknown event: {event_id!r}")
            return rec

    def event_ids(self) -> Tuple[str, ...]:
        """Sorted ids of all registered events."""
        with self._lock:
            return tuple(sorted(self._events))

    def stats(self) -> Dict[str, Any]:
        """Ledger counts."""
        with self._lock:
            return {
                "events": len(self._events),
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }

    def as_dict(self) -> Dict[str, Any]:
        """Full ledger snapshot as plain data."""
        with self._lock:
            return {
                "schema": EVENT_CATALOG_SCHEMA,
                "module": EVENT_CATALOG_VERSION,
                "events": [
                    {
                        "event_id": r.event_id,
                        "name": r.name,
                        "topic": r.topic,
                        "properties": [list(p) for p in r.properties],
                        "required": list(r.required),
                        "seq": r.seq,
                        "digest": r.digest,
                    }
                    for r in self._events.values()
                ],
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        """Copy of the audit rows booked so far."""
        with self._lock:
            return [dict(row) for row in self._audit]


# ---------------------------------------------------------------------------
# Module hygiene
# ---------------------------------------------------------------------------


def _stdlib_only(path: str) -> bool:
    """AST check: module imports must be stdlib-only (plus canonical_json)."""
    import sys

    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "ast",
        "hashlib",
        "re",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "__future__",
        "canonical_json",
        "sys",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    cat = EventCatalog()
    rec = cat.schema(
        "user.created.v1",
        "UserCreated",
        "user/created",
        {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "age": {"type": "integer"},
            },
            "required": ["user_id"],
        },
        1,
    )
    assert rec.verify()
    good = cat.validate("user.created.v1", {"user_id": "u-1", "age": 30}, 2)
    assert good.valid and good.verify()
    bad = cat.validate("user.created.v1", {"age": "thirty"}, 3)
    assert not bad.valid and len(bad.violations) == 2 and bad.verify()
    report = cat.discover("user/", 1)
    assert report.verify() and report.event_ids == ("user.created.v1",)
    assert event_catalog_audit_event("event-registered", 1).get("schema") == AUDIT_SCHEMA
    print("event-catalog OK: schema, discover, validate, pins, audit")


if __name__ == "__main__":
    main()
