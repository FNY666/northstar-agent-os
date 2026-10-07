"""Event bridge interface (event routing with input transformation, simulated).

Research motivation: in an event-driven fabric, producers and consumers
must stay decoupled -- a producer should not know who consumes its
events, and a consumer should not poll every producer. AWS EventBridge
is the canonical shape: producers emit events onto a bus; *rules* match
events by declarative JSON patterns; matched events are fanned out to
*targets* (queues, functions, webhooks) with optional *input
transformation* (extract ``$.detail.orderId`` into ``<order_id>`` and
reshape the payload per target). Failures that exhaust the retry budget
land in a dead-letter queue instead of looping forever.

This module is the *bookkeeping* half of that shape, pinned so the
runtime's event plumbing speaks one dialect:

- ``EventBridge`` -- owns the rule/target registry. ``put_rule()``
  registers an event pattern; ``add_target()`` attaches a delivery
  endpoint with an optional input transformer and retry budget;
  ``route()`` matches one event against every enabled rule, transforms
  per target, and books each delivery attempt; ``transform()`` applies
  a target's input transformer as a pure function; ``dlq()`` admits a
  failed event to the dead-letter ledger; ``replay()`` requeues a
  dead-lettered event for another routing pass.
- ``event_bridge_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``rule-put`` / ``rule-enabled`` / ``rule-disabled`` /
  ``target-added`` / ``target-removed`` / ``routed`` / ``transformed``
  / ``dead-lettered`` / ``replayed`` / ``rejected``); caller-supplied
  seqs only. Raw event payloads never cross the audit boundary.

Event pattern language (EventBridge-shaped subset, pinned):

- ``{"source": ["app.orders"], "detail-type": ["Order Placed"]}``
  -- every key in the pattern must be present in the event; a list
  value means "the event's value is one of these".
- Nested ``detail`` maps recurse: ``{"detail": {"state": ["pending"]}}``.
- ``{"anything-but": [...]}`` -- the value must not be one of these.
- ``{"prefix": "ord-"}`` -- the (string) value must start with this.
- Anything else in a pattern is refused fail-closed at ``put_rule()``.

Input transformers (EventBridge ``InputTransformer``-shaped):

- ``input_paths_map``: ``{"order_id": "$.detail.orderId"}`` -- a
  placeholder bound to a ``$.a.b.c`` path into the event (``$`` alone
  means the whole event).
- ``input_template``: ``'{"id": <order_id>}'`` -- ``<placeholder>``
  markers are substituted; non-string values render as canonical JSON.
  Every marker in the template must be defined in the paths map.
- Unresolvable paths raise ``TransformFailedError`` on ``transform()``;
  inside ``route()`` a transform failure is booked as a delivery
  failure (it never raises out of ``route()``).

Delivery semantics:

- ``route()`` performs exactly one attempt per (event, target). A
  target carries ``max_attempts`` and an operator-set
  ``simulate_failure`` flag (the ledger cannot observe a real wire, so
  failures are host-declared -- the honest-scope boundary).
- A failed attempt with budget remaining books ``retry-scheduled``;
  the same ``event_id`` routed again retries. A failed attempt with no
  budget left is admitted to the dead-letter ledger automatically and
  booked ``dead-lettered``.
- A transform failure inside ``route()`` counts as a delivery failure
  with reason ``transform-failed``.

Fail-closed edges (fail loudly, never guess):

- ``rule_id`` / ``target_id`` / ``event_id`` must be non-empty ``str``;
  duplicates are refused (history is never silently overwritten).
- Events must be mappings with non-empty ``"source"`` and
  ``"detail-type"`` strings; payloads must be JSON-canonicalizable
  (NaN/inf floats, non-str mapping keys, and integers with
  ``abs(n) >= 2**53`` are refused -- the batch-5 JCS discipline).
- Mutation seqs are ints (not bool) and must strictly increase across
  the whole ``EventBridge`` instance; failed mutations consume their
  seq (the batch-21 ledger discipline). ``transform()`` /
  ``describe_rule()`` are pure views: they validate the seq but do not
  consume it.
- ``max_attempts`` must be an int (not bool) >= 1.
- Manual ``dlq()`` refuses a duplicate (event_id, target_id) pair that
  is already dead-lettered and not yet replayed; ``replay()`` is
  terminal per dead-letter id.

Honest scope:

- This module books *host-reported* routing decisions. It cannot prove
  an event was really emitted, that a pattern match reflects a real
  business fact, or that a "delivered" target actually received bytes.
  ``simulate_failure`` is the explicit seam where the host declares
  wire truth; a host that lies about delivery gets a lying ledger.
- ``transform()`` is string surgery over host-supplied JSON paths, not
  a schema migration engine; templates cannot execute code.
- In-memory only: pair with the durable audit writer if routing
  records must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
EVENT_BRIDGE_VERSION = "event-bridge.v1"

#: Schema pin carried by records and audit events.
EVENT_BRIDGE_SCHEMA = "northstar.event-bridge.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Rule states.
RULE_ENABLED = "ENABLED"
RULE_DISABLED = "DISABLED"
_RULE_STATES = (RULE_ENABLED, RULE_DISABLED)

#: Delivery outcomes booked by route().
OUTCOME_DELIVERED = "delivered"
OUTCOME_RETRY_SCHEDULED = "retry-scheduled"
OUTCOME_DEAD_LETTERED = "dead-lettered"
_OUTCOMES = (OUTCOME_DELIVERED, OUTCOME_RETRY_SCHEDULED,
             OUTCOME_DEAD_LETTERED)

#: Audit event kinds.
_KINDS = (
    "rule-put",
    "rule-enabled",
    "rule-disabled",
    "target-added",
    "target-removed",
    "routed",
    "transformed",
    "dead-lettered",
    "replayed",
    "rejected",
)

#: Detail keys banned from crossing the audit boundary (raw payloads).
_BANNED_AUDIT_KEYS = frozenset(
    {"event", "payload", "transformed", "template", "paths_map"})

#: Placeholder syntax inside input templates: <name>.
_PLACEHOLDER_RE = re.compile(r"<([A-Za-z_][A-Za-z0-9_]*)>")
_PLACEHOLDER_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

#: Largest integer the JCS canonicalizer round-trips exactly.
_MAX_SAFE_INT = 2 ** 53


class EventBridgeError(Exception):
    """Base error for the event bridge (programming errors)."""


class BadEventError(EventBridgeError):
    """Raised when an event is malformed or not canonicalizable."""


class BadPatternError(EventBridgeError):
    """Raised when an event pattern is malformed."""


class BadTransformerError(EventBridgeError):
    """Raised when an input transformer definition is malformed."""


class TransformFailedError(EventBridgeError):
    """Raised when a transform cannot resolve its input paths."""


class UnknownRuleError(EventBridgeError):
    """Raised when a rule_id is not registered."""


class DuplicateRuleError(EventBridgeError):
    """Raised when a rule_id is registered twice."""


class UnknownTargetError(EventBridgeError):
    """Raised when a target_id is not registered on a rule."""


class DuplicateTargetError(EventBridgeError):
    """Raised when a target_id is added twice on a rule."""


class DuplicateDeadLetterError(EventBridgeError):
    """Raised when an (event_id, target_id) pair is already dead-lettered."""


class UnknownDeadLetterError(EventBridgeError):
    """Raised when a dead-letter id is unknown."""


class ReplayStateError(EventBridgeError):
    """Raised when a dead-letter id is replayed twice."""


class SeqOrderError(EventBridgeError):
    """Raised when a mutation seq does not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise EventBridgeError(f"seq must be an int >= 0, got {seq!r}")
    return seq


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise EventBridgeError(f"{name} must be a non-empty str, got {value!r}")
    return value


def _check_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EventBridgeError(f"{name} must be a mapping, got {type(value).__name__}")
    return value


def _check_scalar(value: Any, where: str) -> None:
    """Scalars allowed inside patterns and canonical payloads."""
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) >= _MAX_SAFE_INT:
            raise EventBridgeError(
                f"{where}: int magnitude >= 2**53 refused: {value!r}")
        return
    if isinstance(value, float):
        # NaN/inf and all floats refused in patterns (batch-5 JCS rule).
        raise EventBridgeError(f"{where}: floats refused in patterns: {value!r}")
    raise EventBridgeError(f"{where}: bad scalar {value!r}")


def _walk_canonicalizable(value: Any, where: str) -> None:
    """Fail-closed walk: the value must survive JCS canonicalization."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise BadEventError(f"{where}: non-str mapping key: {key!r}")
            _walk_canonicalizable(item, where)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk_canonicalizable(item, where)
    elif isinstance(value, float):
        # NaN and inf have no JSON representation.
        if value != value or value in (float("inf"), float("-inf")):
            raise BadEventError(f"{where}: NaN/inf float refused")
    elif isinstance(value, int) and not isinstance(value, bool):
        if abs(value) >= _MAX_SAFE_INT:
            raise BadEventError(
                f"{where}: int magnitude >= 2**53 refused: {value!r}")


def _check_event(event: Any) -> Mapping[str, Any]:
    event = _check_mapping(event, "event")
    source = event.get("source")
    if not isinstance(source, str) or not source:
        raise BadEventError("event['source'] must be a non-empty str")
    detail_type = event.get("detail-type")
    if not isinstance(detail_type, str) or not detail_type:
        raise BadEventError("event['detail-type'] must be a non-empty str")
    _walk_canonicalizable(event, "event")
    return event


def _validate_pattern_value(value: Any, where: str) -> None:
    if isinstance(value, dict):
        keys = set(value.keys())
        if keys == {"anything-but"}:
            banned = value["anything-but"]
            if not isinstance(banned, list) or not banned:
                raise BadPatternError(
                    f"{where}: 'anything-but' needs a non-empty list")
            for item in banned:
                _check_scalar(item, where)
        elif keys == {"prefix"}:
            prefix = value["prefix"]
            if not isinstance(prefix, str) or not prefix:
                raise BadPatternError(f"{where}: 'prefix' needs a non-empty str")
        else:
            if not value:
                raise BadPatternError(f"{where}: empty nested pattern")
            for key, item in value.items():
                if not isinstance(key, str) or not key:
                    raise BadPatternError(f"{where}: bad pattern key {key!r}")
                _validate_pattern_value(item, f"{where}.{key}")
    elif isinstance(value, list):
        if not value:
            raise BadPatternError(f"{where}: empty match list")
        for item in value:
            _check_scalar(item, where)
    else:
        raise BadPatternError(
            f"{where}: pattern values must be a list, nested dict, "
            f"'anything-but' or 'prefix'; got {value!r}")


def _validate_pattern(pattern: Any) -> Mapping[str, Any]:
    pattern = _check_mapping(pattern, "event_pattern")
    if not pattern:
        raise BadPatternError("event_pattern must be a non-empty mapping")
    for key, value in pattern.items():
        if not isinstance(key, str) or not key:
            raise BadPatternError(f"bad pattern key {key!r}")
        _validate_pattern_value(value, f"pattern[{key!r}]")
    return pattern


def _match_value(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        if set(expected.keys()) == {"anything-but"}:
            return actual not in expected["anything-but"]
        if set(expected.keys()) == {"prefix"}:
            return isinstance(actual, str) and actual.startswith(expected["prefix"])
        if not isinstance(actual, dict):
            return False
        for key, sub in expected.items():
            if key not in actual or not _match_value(sub, actual[key]):
                return False
        return True
    # validated at put_rule(): expected is a non-empty list of scalars.
    return actual in expected


def pattern_matches(pattern: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    """Pure predicate: does the event satisfy the pattern?"""
    for key, expected in pattern.items():
        if key not in event or not _match_value(expected, event[key]):
            return False
    return True


def _check_path(path: Any, where: str) -> str:
    if not isinstance(path, str) or not path.startswith("$"):
        raise BadTransformerError(f"{where}: path must start with '$': {path!r}")
    if path != "$":
        if not path.startswith("$."):
            raise BadTransformerError(
                f"{where}: path must be '$' or '$.a.b': {path!r}")
        for segment in path[2:].split("."):
            if not segment:
                raise BadTransformerError(
                    f"{where}: empty path segment in {path!r}")
    return path


def _resolve_path(event: Mapping[str, Any], path: str) -> Any:
    if path == "$":
        return dict(event)
    current: Any = event
    for segment in path[2:].split("."):
        if not isinstance(current, Mapping) or segment not in current:
            raise TransformFailedError(
                f"path {path!r} does not resolve in the event")
        current = current[segment]
    return current


def _validate_transformer(transformer: Any) -> Optional[Dict[str, Any]]:
    """Validate an input-transformer definition; None means pass-through."""
    if transformer is None:
        return None
    transformer = _check_mapping(transformer, "input_transformer")
    paths_map = transformer.get("input_paths_map", {})
    template = transformer.get("input_template", "")
    _check_mapping(paths_map, "input_paths_map")
    if not isinstance(template, str):
        raise BadTransformerError("input_template must be a str")
    for name, path in paths_map.items():
        if not isinstance(name, str) or not _PLACEHOLDER_NAME_RE.match(name):
            raise BadTransformerError(
                f"bad placeholder name {name!r}")
        _check_path(path, f"input_paths_map[{name!r}]")
    for marker in _PLACEHOLDER_RE.findall(template):
        if marker not in paths_map:
            raise BadTransformerError(
                f"template placeholder <{marker}> not in input_paths_map")
    return {"input_paths_map": dict(paths_map), "input_template": template}


def _render_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return jcs_canonical_json(value).decode("utf-8")


def _digest_pin(body: Mapping[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(dict(body))


@dataclass(frozen=True)
class RuleRecord:
    """A registered event pattern (immutable once registered)."""
    rule_id: str
    event_pattern: Tuple[Tuple[str, Any], ...]
    pattern_digest: str
    description: str
    state: str
    created_seq: int
    digest: str

    def verify(self) -> bool:
        body = {
            "type": "rule-record",
            "version": EVENT_BRIDGE_VERSION,
            "schema": EVENT_BRIDGE_SCHEMA,
            "rule_id": self.rule_id,
            "pattern_digest": self.pattern_digest,
            "description": self.description,
            "state": self.state,
            "created_seq": self.created_seq,
        }
        return _digest_pin(body) == self.digest


@dataclass(frozen=True)
class TargetRecord:
    """A delivery endpoint attached to a rule (immutable)."""
    rule_id: str
    target_id: str
    endpoint: str
    input_transformer: Optional[Tuple[Tuple[str, Any], ...]]
    max_attempts: int
    simulate_failure: bool
    added_seq: int
    digest: str

    def verify(self) -> bool:
        if self.input_transformer is None:
            transformer = None
        else:
            frozen = dict(self.input_transformer)
            template = frozen.pop("input_template")
            transformer = {
                "input_paths_map": frozen,
                "input_template": template,
            }
        body = {
            "type": "target-record",
            "version": EVENT_BRIDGE_VERSION,
            "schema": EVENT_BRIDGE_SCHEMA,
            "rule_id": self.rule_id,
            "target_id": self.target_id,
            "endpoint": self.endpoint,
            "transformer": transformer,
            "max_attempts": self.max_attempts,
            "simulate_failure": self.simulate_failure,
            "added_seq": self.added_seq,
        }
        return _digest_pin(body) == self.digest


@dataclass(frozen=True)
class TransformRecord:
    """The result of applying a target's input transformer (pure view)."""
    target_id: str
    event_digest: str
    transformed: str
    digest: str

    def verify(self) -> bool:
        body = {
            "type": "transform-record",
            "version": EVENT_BRIDGE_VERSION,
            "schema": EVENT_BRIDGE_SCHEMA,
            "target_id": self.target_id,
            "event_digest": self.event_digest,
            "transformed": self.transformed,
        }
        return _digest_pin(body) == self.digest


@dataclass(frozen=True)
class DeliveryRecord:
    """One booked delivery attempt for an (event, target) pair."""
    rule_id: str
    target_id: str
    outcome: str
    attempt: int
    payload_digest: str
    reason: str
    dead_letter_id: str
    routed_seq: int
    digest: str

    def verify(self) -> bool:
        body = {
            "type": "delivery-record",
            "version": EVENT_BRIDGE_VERSION,
            "schema": EVENT_BRIDGE_SCHEMA,
            "rule_id": self.rule_id,
            "target_id": self.target_id,
            "outcome": self.outcome,
            "attempt": self.attempt,
            "payload_digest": self.payload_digest,
            "reason": self.reason,
            "dead_letter_id": self.dead_letter_id,
            "routed_seq": self.routed_seq,
        }
        return _digest_pin(body) == self.digest


@dataclass(frozen=True)
class RouteReport:
    """The booked outcome of routing one event (immutable)."""
    event_id: str
    event_digest: str
    matched_rule_ids: Tuple[str, ...]
    deliveries: Tuple[DeliveryRecord, ...]
    routed_seq: int
    digest: str

    def verify(self) -> bool:
        body = {
            "type": "route-report",
            "version": EVENT_BRIDGE_VERSION,
            "schema": EVENT_BRIDGE_SCHEMA,
            "event_id": self.event_id,
            "event_digest": self.event_digest,
            "matched_rule_ids": list(self.matched_rule_ids),
            "delivery_digests": [d.digest for d in self.deliveries],
            "routed_seq": self.routed_seq,
        }
        return _digest_pin(body) == self.digest


@dataclass(frozen=True)
class DeadLetterRecord:
    """A failed event admitted to the dead-letter ledger (immutable)."""
    dead_letter_id: str
    event_id: str
    target_id: str
    reason: str
    attempts: int
    admitted_seq: int
    replayed: bool
    digest: str

    def verify(self) -> bool:
        body = {
            "type": "dead-letter-record",
            "version": EVENT_BRIDGE_VERSION,
            "schema": EVENT_BRIDGE_SCHEMA,
            "dead_letter_id": self.dead_letter_id,
            "event_id": self.event_id,
            "target_id": self.target_id,
            "reason": self.reason,
            "attempts": self.attempts,
            "admitted_seq": self.admitted_seq,
            "replayed": self.replayed,
        }
        return _digest_pin(body) == self.digest


@dataclass(frozen=True)
class ReplayRecord:
    """A dead-letter id requeued for another routing pass (terminal)."""
    dead_letter_id: str
    event_id: str
    target_id: str
    replayed_seq: int
    digest: str

    def verify(self) -> bool:
        body = {
            "type": "replay-record",
            "version": EVENT_BRIDGE_VERSION,
            "schema": EVENT_BRIDGE_SCHEMA,
            "dead_letter_id": self.dead_letter_id,
            "event_id": self.event_id,
            "target_id": self.target_id,
            "replayed_seq": self.replayed_seq,
        }
        return _digest_pin(body) == self.digest


class EventBridge:
    """Deterministic single-host event routing ledger (EventBridge-shaped)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq_high = -1
        self._rule_seq = 0
        self._target_seq = 0
        self._dlq_seq = 0
        self._rules: Dict[str, Dict[str, Any]] = {}
        # (rule_id, target_id) -> TargetRecord
        self._targets: Dict[Tuple[str, str], TargetRecord] = {}
        # (event_id, target_id) -> attempts so far
        self._attempts: Dict[Tuple[str, str], int] = {}
        self._dead_letters: Dict[str, DeadLetterRecord] = {}
        # (event_id, target_id) pairs currently dead-lettered (not replayed)
        self._dlq_live: set = set()
        self._routes: List[RouteReport] = []

    # -- internal seq handling -------------------------------------------
    def _consume_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._seq_high:
                raise SeqOrderError(
                    f"seq must strictly increase (high={self._seq_high}), "
                    f"got {seq}")
            # Consume up-front: failed mutations burn their seq
            # (the batch-21 ledger discipline).
            self._seq_high = seq
        return seq

    # -- rules -------------------------------------------------------------
    def put_rule(self, rule_id: str, event_pattern: Mapping[str, Any],
                 seq: int, description: str = "",
                 state: str = RULE_ENABLED) -> RuleRecord:
        rule_id = _check_id(rule_id, "rule_id")
        pattern = _validate_pattern(event_pattern)
        if not isinstance(description, str):
            raise EventBridgeError("description must be a str")
        if state not in _RULE_STATES:
            raise EventBridgeError(f"bad rule state {state!r}")
        seq = self._consume_seq(seq)
        with self._lock:
            if rule_id in self._rules:
                raise DuplicateRuleError(f"duplicate rule_id {rule_id!r}")
            self._rule_seq += 1
            pattern_digest = _digest_pin({
                "type": "event-pattern",
                "pattern": jcs_canonical_json(dict(pattern)).decode("utf-8"),
            })
            body = {
                "type": "rule-record",
                "version": EVENT_BRIDGE_VERSION,
                "schema": EVENT_BRIDGE_SCHEMA,
                "rule_id": rule_id,
                "pattern_digest": pattern_digest,
                "description": description,
                "state": state,
                "created_seq": seq,
            }
            record = RuleRecord(
                rule_id=rule_id,
                event_pattern=tuple(sorted(pattern.items())),
                pattern_digest=pattern_digest,
                description=description,
                state=state,
                created_seq=seq,
                digest=_digest_pin(body),
            )
            self._rules[rule_id] = {
                "record": record,
                "pattern": dict(pattern),
            }
            return record

    def _set_rule_state(self, rule_id: str, seq: int, state: str) -> RuleRecord:
        rule_id = _check_id(rule_id, "rule_id")
        seq = self._consume_seq(seq)
        with self._lock:
            entry = self._rules.get(rule_id)
            if entry is None:
                raise UnknownRuleError(f"unknown rule_id {rule_id!r}")
            old: RuleRecord = entry["record"]
            body = {
                "type": "rule-record",
                "version": EVENT_BRIDGE_VERSION,
                "schema": EVENT_BRIDGE_SCHEMA,
                "rule_id": rule_id,
                "pattern_digest": old.pattern_digest,
                "description": old.description,
                "state": state,
                "created_seq": old.created_seq,
            }
            record = RuleRecord(
                rule_id=rule_id,
                event_pattern=old.event_pattern,
                pattern_digest=old.pattern_digest,
                description=old.description,
                state=state,
                created_seq=old.created_seq,
                digest=_digest_pin(body),
            )
            entry["record"] = record
            return record

    def enable_rule(self, rule_id: str, seq: int) -> RuleRecord:
        """Re-enable a disabled rule."""
        return self._set_rule_state(rule_id, seq, RULE_ENABLED)

    def disable_rule(self, rule_id: str, seq: int) -> RuleRecord:
        """Disable a rule (it stops matching, stays registered)."""
        return self._set_rule_state(rule_id, seq, RULE_DISABLED)

    def describe_rule(self, rule_id: str, seq: int) -> RuleRecord:
        """Pure view: validate seq, do not consume it."""
        rule_id = _check_id(rule_id, "rule_id")
        _check_seq(seq)
        with self._lock:
            entry = self._rules.get(rule_id)
            if entry is None:
                raise UnknownRuleError(f"unknown rule_id {rule_id!r}")
            return entry["record"]

    def rule_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._rules))

    # -- targets -----------------------------------------------------------
    def add_target(self, rule_id: str, target_id: str, seq: int,
                   endpoint: str = "",
                   input_transformer: Optional[Mapping[str, Any]] = None,
                   max_attempts: int = 3,
                   simulate_failure: bool = False) -> TargetRecord:
        rule_id = _check_id(rule_id, "rule_id")
        target_id = _check_id(target_id, "target_id")
        if not isinstance(endpoint, str):
            raise EventBridgeError("endpoint must be a str")
        transformer = _validate_transformer(input_transformer)
        if (isinstance(max_attempts, bool) or not isinstance(max_attempts, int)
                or max_attempts < 1):
            raise EventBridgeError(
                f"max_attempts must be an int >= 1, got {max_attempts!r}")
        if not isinstance(simulate_failure, bool):
            raise EventBridgeError("simulate_failure must be a bool")
        seq = self._consume_seq(seq)
        with self._lock:
            if rule_id not in self._rules:
                raise UnknownRuleError(f"unknown rule_id {rule_id!r}")
            key = (rule_id, target_id)
            if key in self._targets:
                raise DuplicateTargetError(
                    f"duplicate target_id {target_id!r} on rule {rule_id!r}")
            self._target_seq += 1
            frozen_transformer = (
                None if transformer is None
                else tuple(sorted(transformer["input_paths_map"].items()))
                + (("input_template", transformer["input_template"]),))
            body = {
                "type": "target-record",
                "version": EVENT_BRIDGE_VERSION,
                "schema": EVENT_BRIDGE_SCHEMA,
                "rule_id": rule_id,
                "target_id": target_id,
                "endpoint": endpoint,
                "transformer": (
                    None if transformer is None else {
                        "input_paths_map": dict(transformer["input_paths_map"]),
                        "input_template": transformer["input_template"],
                    }),
                "max_attempts": max_attempts,
                "simulate_failure": simulate_failure,
                "added_seq": seq,
            }
            record = TargetRecord(
                rule_id=rule_id,
                target_id=target_id,
                endpoint=endpoint,
                input_transformer=frozen_transformer,
                max_attempts=max_attempts,
                simulate_failure=simulate_failure,
                added_seq=seq,
                digest=_digest_pin(body),
            )
            self._targets[key] = record
            return record

    def remove_target(self, rule_id: str, target_id: str, seq: int) -> None:
        rule_id = _check_id(rule_id, "rule_id")
        target_id = _check_id(target_id, "target_id")
        seq = self._consume_seq(seq)
        with self._lock:
            key = (rule_id, target_id)
            if key not in self._targets:
                raise UnknownTargetError(
                    f"unknown target_id {target_id!r} on rule {rule_id!r}")
            del self._targets[key]

    def target_ids(self, rule_id: str) -> Tuple[str, ...]:
        rule_id = _check_id(rule_id, "rule_id")
        with self._lock:
            return tuple(sorted(t for r, t in self._targets if r == rule_id))

    # -- transform (pure view) ----------------------------------------------
    def transform(self, rule_id: str, target_id: str,
                  event: Mapping[str, Any], seq: int) -> TransformRecord:
        """Apply a target's input transformer; pure view (seq validated,
        not consumed). No transformer means the canonical event passes
        through unchanged."""
        rule_id = _check_id(rule_id, "rule_id")
        target_id = _check_id(target_id, "target_id")
        event = _check_event(event)
        _check_seq(seq)
        with self._lock:
            target = self._targets.get((rule_id, target_id))
            if target is None:
                raise UnknownTargetError(
                    f"unknown target_id {target_id!r} on rule {rule_id!r}")
            event_digest = _digest_pin({
                "type": "event",
                "event": jcs_canonical_json(dict(event)).decode("utf-8"),
            })
            if target.input_transformer is None:
                transformed = jcs_canonical_json(dict(event)).decode("utf-8")
            else:
                frozen = dict(target.input_transformer)
                template = frozen.pop("input_template")
                values = {
                    name: _render_value(_resolve_path(event, path))
                    for name, path in frozen.items()
                }

                def _sub(match: "re.Match[str]") -> str:
                    return values[match.group(1)]

                transformed = _PLACEHOLDER_RE.sub(_sub, template)
            body = {
                "type": "transform-record",
                "version": EVENT_BRIDGE_VERSION,
                "schema": EVENT_BRIDGE_SCHEMA,
                "target_id": target_id,
                "event_digest": event_digest,
                "transformed": transformed,
            }
            return TransformRecord(
                target_id=target_id,
                event_digest=event_digest,
                transformed=transformed,
                digest=_digest_pin(body),
            )

    # -- route ---------------------------------------------------------------
    def route(self, event_id: str, event: Mapping[str, Any],
              seq: int) -> RouteReport:
        """Match one event against every enabled rule and book one
        delivery attempt per (rule, target). Transform failures inside
        routing never raise: they book a failed delivery."""
        event_id = _check_id(event_id, "event_id")
        event = _check_event(event)
        seq = self._consume_seq(seq)
        with self._lock:
            event_digest = _digest_pin({
                "type": "event",
                "event": jcs_canonical_json(dict(event)).decode("utf-8"),
            })
            matched = sorted(
                rule_id for rule_id, entry in self._rules.items()
                if entry["record"].state == RULE_ENABLED
                and pattern_matches(entry["pattern"], event))
            deliveries: List[DeliveryRecord] = []
            for rule_id in matched:
                for target_id in sorted(
                        t for r, t in self._targets if r == rule_id):
                    target = self._targets[(rule_id, target_id)]
                    key = (event_id, target_id)
                    attempt = self._attempts.get(key, 0) + 1
                    reason = ""
                    failed = False
                    try:
                        transformed = self.transform(
                            rule_id, target_id, event, seq).transformed
                        payload_digest = _digest_pin({
                            "type": "transformed-payload",
                            "transformed": transformed,
                        })
                    except TransformFailedError as exc:
                        failed = True
                        reason = f"transform-failed: {exc}"
                        payload_digest = event_digest
                    if not failed and target.simulate_failure:
                        failed = True
                        reason = "simulated-failure"
                    dead_letter_id = ""
                    if failed:
                        if attempt >= target.max_attempts:
                            dlq_record = self._admit_dead_letter_locked(
                                event_id, target_id, reason, attempt, seq)
                            dead_letter_id = dlq_record.dead_letter_id
                            outcome = OUTCOME_DEAD_LETTERED
                            self._attempts.pop(key, None)
                        else:
                            outcome = OUTCOME_RETRY_SCHEDULED
                            self._attempts[key] = attempt
                    else:
                        outcome = OUTCOME_DELIVERED
                        self._attempts.pop(key, None)
                    body = {
                        "type": "delivery-record",
                        "version": EVENT_BRIDGE_VERSION,
                        "schema": EVENT_BRIDGE_SCHEMA,
                        "rule_id": rule_id,
                        "target_id": target_id,
                        "outcome": outcome,
                        "attempt": attempt,
                        "payload_digest": payload_digest,
                        "reason": reason,
                        "dead_letter_id": dead_letter_id,
                        "routed_seq": seq,
                    }
                    deliveries.append(DeliveryRecord(
                        rule_id=rule_id,
                        target_id=target_id,
                        outcome=outcome,
                        attempt=attempt,
                        payload_digest=payload_digest,
                        reason=reason,
                        dead_letter_id=dead_letter_id,
                        routed_seq=seq,
                        digest=_digest_pin(body),
                    ))
            body = {
                "type": "route-report",
                "version": EVENT_BRIDGE_VERSION,
                "schema": EVENT_BRIDGE_SCHEMA,
                "event_id": event_id,
                "event_digest": event_digest,
                "matched_rule_ids": matched,
                "delivery_digests": [d.digest for d in deliveries],
                "routed_seq": seq,
            }
            report = RouteReport(
                event_id=event_id,
                event_digest=event_digest,
                matched_rule_ids=tuple(matched),
                deliveries=tuple(deliveries),
                routed_seq=seq,
                digest=_digest_pin(body),
            )
            self._routes.append(report)
            return report

    # -- dead-letter queue ----------------------------------------------------
    def _admit_dead_letter_locked(self, event_id: str, target_id: str,
                                  reason: str, attempts: int,
                                  seq: int) -> DeadLetterRecord:
        pair = (event_id, target_id)
        if pair in self._dlq_live:
            raise DuplicateDeadLetterError(
                f"event {event_id!r} already dead-lettered for "
                f"target {target_id!r}")
        self._dlq_seq += 1
        dead_letter_id = f"dlq-{self._dlq_seq}"
        body = {
            "type": "dead-letter-record",
            "version": EVENT_BRIDGE_VERSION,
            "schema": EVENT_BRIDGE_SCHEMA,
            "dead_letter_id": dead_letter_id,
            "event_id": event_id,
            "target_id": target_id,
            "reason": reason,
            "attempts": attempts,
            "admitted_seq": seq,
            "replayed": False,
        }
        record = DeadLetterRecord(
            dead_letter_id=dead_letter_id,
            event_id=event_id,
            target_id=target_id,
            reason=reason,
            attempts=attempts,
            admitted_seq=seq,
            replayed=False,
            digest=_digest_pin(body),
        )
        self._dead_letters[dead_letter_id] = record
        self._dlq_live.add(pair)
        return record

    def dlq(self, event_id: str, seq: int, reason: str,
            target_id: str = "", attempts: int = 0) -> DeadLetterRecord:
        """Manually admit a failed event to the dead-letter ledger."""
        event_id = _check_id(event_id, "event_id")
        if not isinstance(reason, str) or not reason:
            raise EventBridgeError("reason must be a non-empty str")
        if not isinstance(target_id, str):
            raise EventBridgeError("target_id must be a str")
        if (isinstance(attempts, bool) or not isinstance(attempts, int)
                or attempts < 0):
            raise EventBridgeError(
                f"attempts must be an int >= 0, got {attempts!r}")
        seq = self._consume_seq(seq)
        with self._lock:
            return self._admit_dead_letter_locked(
                event_id, target_id, reason, attempts, seq)

    def replay(self, dead_letter_id: str, seq: int) -> ReplayRecord:
        """Requeue a dead-lettered event for another routing pass
        (terminal per dead-letter id)."""
        dead_letter_id = _check_id(dead_letter_id, "dead_letter_id")
        seq = self._consume_seq(seq)
        with self._lock:
            record = self._dead_letters.get(dead_letter_id)
            if record is None:
                raise UnknownDeadLetterError(
                    f"unknown dead_letter_id {dead_letter_id!r}")
            if record.replayed:
                raise ReplayStateError(
                    f"dead_letter_id {dead_letter_id!r} already replayed")
            body = {
                "type": "replay-record",
                "version": EVENT_BRIDGE_VERSION,
                "schema": EVENT_BRIDGE_SCHEMA,
                "dead_letter_id": dead_letter_id,
                "event_id": record.event_id,
                "target_id": record.target_id,
                "replayed_seq": seq,
            }
            replayed = ReplayRecord(
                dead_letter_id=dead_letter_id,
                event_id=record.event_id,
                target_id=record.target_id,
                replayed_seq=seq,
                digest=_digest_pin(body),
            )
            marked_body = {
                "type": "dead-letter-record",
                "version": EVENT_BRIDGE_VERSION,
                "schema": EVENT_BRIDGE_SCHEMA,
                "dead_letter_id": record.dead_letter_id,
                "event_id": record.event_id,
                "target_id": record.target_id,
                "reason": record.reason,
                "attempts": record.attempts,
                "admitted_seq": record.admitted_seq,
                "replayed": True,
            }
            self._dead_letters[dead_letter_id] = DeadLetterRecord(
                dead_letter_id=record.dead_letter_id,
                event_id=record.event_id,
                target_id=record.target_id,
                reason=record.reason,
                attempts=record.attempts,
                admitted_seq=record.admitted_seq,
                replayed=True,
                digest=_digest_pin(marked_body),
            )
            self._dlq_live.discard((record.event_id, record.target_id))
            self._attempts.pop((record.event_id, record.target_id), None)
            return replayed

    def dead_letter_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._dead_letters))

    def dead_letter(self, dead_letter_id: str) -> DeadLetterRecord:
        dead_letter_id = _check_id(dead_letter_id, "dead_letter_id")
        with self._lock:
            record = self._dead_letters.get(dead_letter_id)
            if record is None:
                raise UnknownDeadLetterError(
                    f"unknown dead_letter_id {dead_letter_id!r}")
            return record

    def route_count(self) -> int:
        with self._lock:
            return len(self._routes)


def event_bridge_audit_event(kind: str, seq: int,
                             rule_id: Optional[str] = None,
                             target_id: Optional[str] = None,
                             detail: Optional[Mapping[str, Any]] = None) -> dict:
    """Shape an ``audit.ndjson/1`` record for an event-bridge event.

    Raw event payloads are banned from the audit boundary: detail keys
    ``event`` / ``payload`` / ``transformed`` / ``template`` /
    ``paths_map`` are refused fail-closed. Only ids and digest pins
    cross.
    """
    if kind not in _KINDS:
        raise EventBridgeError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    if rule_id is not None:
        _check_id(rule_id, "rule_id")
    if target_id is not None:
        _check_id(target_id, "target_id")
    if detail is not None:
        detail = _check_mapping(detail, "detail")
        for banned in _BANNED_AUDIT_KEYS:
            if banned in detail:
                raise EventBridgeError(
                    f"audit detail key {banned!r} is banned: raw payloads "
                    f"never cross the audit boundary")
    event = {
        "schema": AUDIT_SCHEMA,
        "kind": f"event-bridge.{kind}",
        "version": EVENT_BRIDGE_VERSION,
        "schema_ref": EVENT_BRIDGE_SCHEMA,
        "seq": seq,
    }
    if rule_id is not None:
        event["rule_id"] = rule_id
    if target_id is not None:
        event["target_id"] = target_id
    if detail is not None:
        event["detail"] = dict(detail)
    return event


def main() -> None:
    bridge = EventBridge()
    rule = bridge.put_rule(
        "orders", {"source": ["app.orders"],
                   "detail-type": ["Order Placed"],
                   "detail": {"state": ["pending"]}}, 0,
        description="new pending orders")
    assert rule.state == RULE_ENABLED and rule.verify()
    bridge.add_target("orders", "queue-a", 1, endpoint="queue://a")
    bridge.add_target(
        "orders", "queue-b", 2, endpoint="queue://b",
        input_transformer={
            "input_paths_map": {"order_id": "$.detail.orderId"},
            "input_template": '{"id": <order_id>}',
        },
        max_attempts=2, simulate_failure=True)
    event = {"source": "app.orders", "detail-type": "Order Placed",
             "detail": {"orderId": "ord-1", "state": "pending"}}
    view = bridge.transform("orders", "queue-b", event, 3)
    assert view.transformed == '{"id": ord-1}' and view.verify()
    first = bridge.route("evt-1", event, 4)
    by_target = {d.target_id: d for d in first.deliveries}
    assert by_target["queue-a"].outcome == OUTCOME_DELIVERED
    assert by_target["queue-b"].outcome == OUTCOME_RETRY_SCHEDULED
    second = bridge.route("evt-1", event, 5)
    failed = {d.target_id: d for d in second.deliveries}["queue-b"]
    assert failed.outcome == OUTCOME_DEAD_LETTERED and failed.attempt == 2
    assert len(bridge.dead_letter_ids()) == 1
    replayed = bridge.replay(failed.dead_letter_id, 6)
    assert replayed.event_id == "evt-1"
    # disabled rules stop matching
    bridge.disable_rule("orders", 7)
    third = bridge.route("evt-2", event, 8)
    assert third.matched_rule_ids == () and third.deliveries == ()
    audit = event_bridge_audit_event(
        "routed", 9, rule_id="orders",
        detail={"event_digest": third.event_digest})
    assert audit["kind"] == "event-bridge.routed"
    print("event-bridge OK: rule, target, transform, route, retry, dlq, replay")


if __name__ == "__main__":
    main()
