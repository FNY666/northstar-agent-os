"""Workflow automation: Zapier-shaped trigger-to-action chain bookkeeping.

Research note: trigger/action automation (Zapier, n8n, IFTTT) connects an
*event source* (trigger) to a *sequence of steps* (actions). When an event
arrives, the automation checks an optional filter, then runs each action in
order, passing the trigger's payload (plus prior actions' outputs) through
field mappings into each action's inputs. This module is the *bookkeeping
and decision logic* of that shape, not an integration runner: it defines
triggers, actions, filters, and automations as digest-pinned frozen records,
validates event payloads against the trigger's field schema, resolves field
mappings deterministically, and seals every run in a frozen ``RunReport``.

* **Triggers** — ``trigger(trigger_id, source, seq, field_schema=...)``
  pins an event source from a fixed vocabulary (``webhook``, ``schedule``,
  ``email_received``, ``form_submitted``, ``row_added``, ``payment_received``,
  ``file_uploaded``, ``ticket_created``). The field schema is the set of
  payload field names the trigger emits; it is pinned so schema drift is
  detectable.
* **Actions** — ``action(action_id, kind, seq, params=..., mappings=...)``
  pins an action from a fixed vocabulary (``http_post``, ``send_email``,
  ``send_sms``, ``create_row``, ``create_task``, ``notify``, ``delay``,
  ``filter_halt``). Field ``mappings`` bind action inputs to trigger data or
  earlier action outputs via dotted paths (``trigger.name``,
  ``action.<action_id>.row_id``). Mapping shapes are validated fail-closed
  at define time; a missing value at run time fails the run, it is never
  silently dropped.
* **Automations** — ``define_automation(automation_id, trigger_id,
  action_ids, seq)`` binds one trigger to an ordered, non-empty action
  list. Action ids must exist and be unique.
* **Filters** — ``define_filter(automation_id, rules, seq)`` attaches a
  conjunctive filter: each rule is ``(path, op, value)`` with a pinned op
  vocabulary (``eq``, ``ne``, ``gt``, ``gte``, ``lt``, ``lte``, ``in``,
  ``contains``, ``starts-with``). Paths resolve against the event payload.
  A non-matching event ends the run as ``filtered-out`` — a verdict as data,
  never an exception.
* **Runs** — ``run(automation_id, event, seq)`` validates the event against
  the trigger schema (missing fields and unexpected extra fields are both
  refused fail-closed), evaluates the filter, then executes the action
  chain. Each action resolves its mappings, then hands them to an executor
  callable. The default executor is a deterministic simulator; a
  host-injected executor returns the real output. Executor exceptions or
  non-canonicalizable outputs fail the action. ``run_on_error`` on the
  action (``stop`` / ``continue``) decides whether a failed action ends the
  run or is recorded and skipped. The result is a frozen ``RunReport`` with
  per-action ``ActionResult`` records and ``sha256:`` digest pins.

* **Audit** — ``workflow_automation_audit_event()`` builds
  ``audit.ndjson/1`` records for ``trigger-defined``, ``action-defined``,
  ``automation-defined``, ``filter-defined``, ``run-started``,
  ``run-filtered``, ``action-executed``, ``action-failed``, ``run-completed``
  and ``rejected``. Payload *values* never cross the audit boundary:
  only ids and digest pins.

* **Fail-closed ledger** — caller-supplied strictly-increasing int seqs on
  every mutation; failed mutations consume their seq (batch-21 discipline);
  frozen dataclasses; RLock-guarded; stdlib-only.

Honest scope: this module books automation *definitions* and *decisions*;
the executor is host-injected, so ``succeeded=True`` means "every action
returned an output", never "the HTTP call actually fired". Field mapping is
bookkeeping over host-reported payloads (GIGO boundary). Production needs a
real integration runner, idempotent actions, and retry budgets outside this
module.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version pin.
WORKFLOW_AUTOMATION_VERSION = "workflow-automation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.workflow-automation.v1"

#: Audit record format pin.
AUDIT_FORMAT = "audit.ndjson/1"

_AUDIT_KINDS = frozenset(
    {
        "trigger-defined",
        "action-defined",
        "automation-defined",
        "filter-defined",
        "run-started",
        "run-filtered",
        "action-executed",
        "action-failed",
        "run-completed",
        "rejected",
    }
)

#: Pinned trigger-source vocabulary.
TRIGGER_SOURCES: Tuple[str, ...] = (
    "webhook",
    "schedule",
    "email_received",
    "form_submitted",
    "row_added",
    "payment_received",
    "file_uploaded",
    "ticket_created",
)

#: Pinned action-kind vocabulary.
ACTION_KINDS: Tuple[str, ...] = (
    "http_post",
    "send_email",
    "send_sms",
    "create_row",
    "create_task",
    "notify",
    "delay",
    "filter_halt",
)

#: Pinned error-handling policy vocabulary for actions.
ERROR_POLICIES: Tuple[str, ...] = ("stop", "continue")

#: Pinned filter-operator vocabulary.
FILTER_OPS: Tuple[str, ...] = (
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "contains",
    "starts-with",
)

#: Guardrails against pathological registries.
_MAX_TRIGGERS = 1024
_MAX_ACTIONS = 4096
_MAX_AUTOMATIONS = 1024
_MAX_RUNS = 65536
_MAX_FIELDS = 256
_MAX_MAPPINGS = 256
_MAX_FILTER_RULES = 64
_MAX_ID_LEN = 128


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class WorkflowAutomationError(Exception):
    """Base class for all workflow-automation errors."""


class BadIdError(WorkflowAutomationError):
    """Malformed identifier."""


class DuplicateTriggerError(WorkflowAutomationError):
    """A trigger with this id is already defined."""


class UnknownTriggerError(WorkflowAutomationError):
    """No trigger with this id exists."""


class BadTriggerError(WorkflowAutomationError):
    """Trigger source or field schema is malformed."""


class DuplicateActionError(WorkflowAutomationError):
    """An action with this id is already defined."""


class UnknownActionError(WorkflowAutomationError):
    """No action with this id exists."""


class BadActionError(WorkflowAutomationError):
    """Action kind, params, or error policy is malformed."""


class BadMappingError(WorkflowAutomationError):
    """A field mapping has a bad shape or references a bad source path."""


class DuplicateAutomationError(WorkflowAutomationError):
    """An automation with this id is already defined."""


class UnknownAutomationError(WorkflowAutomationError):
    """No automation with this id exists."""


class BadAutomationError(WorkflowAutomationError):
    """Automation binding (trigger/action list) is malformed."""


class BadFilterError(WorkflowAutomationError):
    """A filter rule is malformed."""


class BadEventError(WorkflowAutomationError):
    """An event payload fails schema validation."""


class BadExecutorOutputError(WorkflowAutomationError):
    """An executor returned a non-canonicalizable output."""


class SeqOrderError(WorkflowAutomationError):
    """A mutation seq was not a strictly-increasing int."""


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TriggerRecord:
    trigger_id: str
    source: str
    field_schema: Tuple[str, ...]
    seq: int
    prev_digest: str
    digest: str

    def verify(self, mgr: "WorkflowAutomation") -> bool:
        return self.digest == mgr._trigger_digest(self)


@dataclass(frozen=True)
class ActionRecord:
    action_id: str
    kind: str
    params: Tuple[Tuple[str, Any], ...]
    mappings: Tuple[Tuple[str, str], ...]
    run_on_error: str
    seq: int
    prev_digest: str
    digest: str

    def verify(self, mgr: "WorkflowAutomation") -> bool:
        return self.digest == mgr._action_digest(self)


@dataclass(frozen=True)
class FilterRecord:
    filter_id: str
    automation_id: str
    rules: Tuple[Tuple[str, str, Any], ...]
    seq: int
    digest: str

    def verify(self, mgr: "WorkflowAutomation") -> bool:
        return self.digest == mgr._filter_digest(self)


@dataclass(frozen=True)
class AutomationRecord:
    automation_id: str
    trigger_id: str
    action_ids: Tuple[str, ...]
    seq: int
    prev_digest: str
    digest: str

    def verify(self, mgr: "WorkflowAutomation") -> bool:
        return self.digest == mgr._automation_digest(self)


@dataclass(frozen=True)
class ActionResult:
    action_id: str
    ok: bool
    output_digest: str
    error_type: str
    seq: int


@dataclass(frozen=True)
class RunReport:
    run_id: str
    automation_id: str
    trigger_id: str
    status: str  # succeeded | failed | filtered-out
    event_digest: str
    action_results: Tuple[ActionResult, ...]
    failed_action: str
    error_type: str
    seq: int
    digest: str

    def verify(self, mgr: "WorkflowAutomation") -> bool:
        return self.digest == mgr._run_digest(self)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


#: Executor signature: (action record, resolved inputs, seq) -> output mapping.
Executor = Callable[[ActionRecord, Dict[str, Any], int], Mapping[str, Any]]


class WorkflowAutomation:
    """Zapier-shaped trigger-to-action automation bookkeeping."""

    def __init__(
        self,
        seed: Optional[bytes] = None,
        executor: Optional[Executor] = None,
    ) -> None:
        self._salt = seed if seed is not None else secrets.token_bytes(16)
        self._executor: Executor = executor or self._default_executor
        self._lock = threading.RLock()
        self._seq = 0
        self._triggers: Dict[str, TriggerRecord] = {}
        self._actions: Dict[str, ActionRecord] = {}
        self._automations: Dict[str, AutomationRecord] = {}
        self._filters: Dict[str, FilterRecord] = {}
        self._runs: Dict[str, RunReport] = {}
        self._run_counter = 0
        self._filter_counter = 0
        self._audit_log: List[Dict[str, Any]] = []

    # -- digests ----------------------------------------------------

    def _pin(self, *parts: Any) -> str:
        payload = jcs_canonical_json(
            {"salt": self._salt.hex(), "parts": list(parts)}
        )
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _trigger_digest(self, rec: TriggerRecord) -> str:
        return self._pin(
            "trigger",
            rec.trigger_id,
            rec.source,
            list(rec.field_schema),
            rec.seq,
            rec.prev_digest,
        )

    def _action_digest(self, rec: ActionRecord) -> str:
        return self._pin(
            "action",
            rec.action_id,
            rec.kind,
            [[k, v] for k, v in rec.params],
            [[k, v] for k, v in rec.mappings],
            rec.run_on_error,
            rec.seq,
            rec.prev_digest,
        )

    def _filter_digest(self, rec: FilterRecord) -> str:
        return self._pin(
            "filter",
            rec.filter_id,
            rec.automation_id,
            [[p, op, v] for p, op, v in rec.rules],
            rec.seq,
        )

    def _automation_digest(self, rec: AutomationRecord) -> str:
        return self._pin(
            "automation",
            rec.automation_id,
            rec.trigger_id,
            list(rec.action_ids),
            rec.seq,
            rec.prev_digest,
        )

    def _run_digest(self, rep: RunReport) -> str:
        return self._pin(
            "run",
            rep.run_id,
            rep.automation_id,
            rep.trigger_id,
            rep.status,
            rep.event_digest,
            [
                [r.action_id, r.ok, r.output_digest, r.error_type, r.seq]
                for r in rep.action_results
            ],
            rep.failed_action,
            rep.error_type,
            rep.seq,
        )

    def _event_digest(self, event: Mapping[str, Any]) -> str:
        return self._pin("event", _freeze(event))

    # -- seq + audit -------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} is not strictly greater than {self._seq}"
            )
        self._seq = seq
        return seq

    def _audit(self, kind: str, payload: Dict[str, Any]) -> None:
        if kind not in _AUDIT_KINDS:
            raise WorkflowAutomationError(f"unknown audit kind: {kind!r}")
        self._audit_log.append(
            {
                "schema": AUDIT_FORMAT,
                "module": WORKFLOW_AUTOMATION_VERSION,
                "event": kind,
                "payload": payload,
            }
        )

    def _reject(self, seq: int, reason: str) -> None:
        self._audit(
            "rejected",
            {"seq": seq, "reason": reason},
        )

    # -- validation helpers ------------------------------------------

    @staticmethod
    def _check_id(value: Any, what: str) -> str:
        if not isinstance(value, str) or not value:
            raise BadIdError(f"{what} must be a non-empty str")
        if len(value) > _MAX_ID_LEN:
            raise BadIdError(f"{what} exceeds {_MAX_ID_LEN} chars")
        return value

    @staticmethod
    def _canonicalizable(value: Any) -> bool:
        try:
            jcs_canonical_json(value)
        except Exception:
            return False
        return True

    # -- trigger -----------------------------------------------------

    def trigger(
        self,
        trigger_id: str,
        source: str,
        seq: int,
        field_schema: Tuple[str, ...] = (),
    ) -> TriggerRecord:
        """Define a trigger (event source) with a pinned field schema."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._check_id(trigger_id, "trigger_id")
                if trigger_id in self._triggers:
                    raise DuplicateTriggerError(
                        f"trigger {trigger_id!r} already defined"
                    )
                if source not in TRIGGER_SOURCES:
                    raise BadTriggerError(f"unknown trigger source: {source!r}")
                if len(self._triggers) >= _MAX_TRIGGERS:
                    raise BadTriggerError("trigger registry full")
                fields = tuple(field_schema)
                if len(fields) > _MAX_FIELDS:
                    raise BadTriggerError("too many schema fields")
                if len(set(fields)) != len(fields):
                    raise BadTriggerError("duplicate schema field names")
                for f in fields:
                    if not isinstance(f, str) or not f or len(f) > _MAX_ID_LEN:
                        raise BadTriggerError(
                            f"bad schema field name: {f!r}"
                        )
                prev = (
                    self._triggers[max(self._triggers)].digest
                    if self._triggers
                    else "genesis"
                )
            except WorkflowAutomationError as exc:
                self._reject(seq, f"trigger:{type(exc).__name__}")
                raise
            rec = TriggerRecord(
                trigger_id=trigger_id,
                source=source,
                field_schema=fields,
                seq=seq,
                prev_digest=prev,
                digest="",
            )
            rec = TriggerRecord(
                trigger_id=rec.trigger_id,
                source=rec.source,
                field_schema=rec.field_schema,
                seq=rec.seq,
                prev_digest=rec.prev_digest,
                digest=self._trigger_digest(rec),
            )
            self._triggers[trigger_id] = rec
            self._audit(
                "trigger-defined",
                {
                    "trigger_id": trigger_id,
                    "source": source,
                    "digest": rec.digest,
                    "seq": seq,
                },
            )
            return rec

    # -- action ------------------------------------------------------

    @staticmethod
    def _check_mapping_shape(mapping: Any) -> Tuple[str, str]:
        if (
            not isinstance(mapping, (tuple, list))
            or len(mapping) != 2
            or not isinstance(mapping[0], str)
            or not mapping[0]
            or not isinstance(mapping[1], str)
            or not mapping[1]
        ):
            raise BadMappingError(f"bad mapping shape: {mapping!r}")
        target, source = mapping[0], mapping[1]
        if source == "trigger" or source.startswith("trigger."):
            return target, source
        if source.startswith("action."):
            rest = source[len("action."):]
            if "." not in rest:
                raise BadMappingError(
                    f"action mapping must be action.<id>.<field>: {source!r}"
                )
            return target, source
        raise BadMappingError(f"mapping source must start with trigger./action.: {source!r}")  # noqa: E501

    def action(
        self,
        action_id: str,
        kind: str,
        seq: int,
        params: Tuple[Tuple[str, Any], ...] = (),
        mappings: Tuple[Tuple[str, str], ...] = (),
        run_on_error: str = "stop",
    ) -> ActionRecord:
        """Define an action step with field mappings."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._check_id(action_id, "action_id")
                if action_id in self._actions:
                    raise DuplicateActionError(
                        f"action {action_id!r} already defined"
                    )
                if kind not in ACTION_KINDS:
                    raise BadActionError(f"unknown action kind: {kind!r}")
                if run_on_error not in ERROR_POLICIES:
                    raise BadActionError(
                        f"unknown run_on_error: {run_on_error!r}"
                    )
                if len(self._actions) >= _MAX_ACTIONS:
                    raise BadActionError("action registry full")
                plist = tuple(params)
                if len(plist) > _MAX_FIELDS:
                    raise BadActionError("too many params")
                seen_params = set()
                for p in plist:
                    if (
                        not isinstance(p, (tuple, list))
                        or len(p) != 2
                        or not isinstance(p[0], str)
                        or not p[0]
                    ):
                        raise BadActionError(f"bad param shape: {p!r}")
                    if p[0] in seen_params:
                        raise BadActionError(
                            f"duplicate param name: {p[0]!r}"
                        )
                    seen_params.add(p[0])
                    if not self._canonicalizable(p[1]):
                        raise BadActionError(
                            f"param {p[0]!r} is not canonicalizable"
                        )
                mlist = tuple(self._check_mapping_shape(m) for m in mappings)
                if len(mlist) > _MAX_MAPPINGS:
                    raise BadActionError("too many mappings")
                seen_targets = set()
                for target, _src in mlist:
                    if target in seen_targets:
                        raise BadMappingError(
                            f"duplicate mapping target: {target!r}"
                        )
                    seen_targets.add(target)
                prev = (
                    self._actions[max(self._actions)].digest
                    if self._actions
                    else "genesis"
                )
            except WorkflowAutomationError as exc:
                self._reject(seq, f"action:{type(exc).__name__}")
                raise
            rec = ActionRecord(
                action_id=action_id,
                kind=kind,
                params=tuple((k, v) for k, v in plist),
                mappings=mlist,
                run_on_error=run_on_error,
                seq=seq,
                prev_digest=prev,
                digest="",
            )
            rec = ActionRecord(
                action_id=rec.action_id,
                kind=rec.kind,
                params=rec.params,
                mappings=rec.mappings,
                run_on_error=rec.run_on_error,
                seq=rec.seq,
                prev_digest=rec.prev_digest,
                digest=self._action_digest(rec),
            )
            self._actions[action_id] = rec
            self._audit(
                "action-defined",
                {
                    "action_id": action_id,
                    "kind": kind,
                    "digest": rec.digest,
                    "seq": seq,
                },
            )
            return rec

    # -- automation --------------------------------------------------

    def define_automation(
        self,
        automation_id: str,
        trigger_id: str,
        action_ids: Tuple[str, ...],
        seq: int,
    ) -> AutomationRecord:
        """Bind one trigger to an ordered, non-empty action list."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._check_id(automation_id, "automation_id")
                if automation_id in self._automations:
                    raise DuplicateAutomationError(
                        f"automation {automation_id!r} already defined"
                    )
                if trigger_id not in self._triggers:
                    raise UnknownTriggerError(
                        f"unknown trigger: {trigger_id!r}"
                    )
                aids = tuple(action_ids)
                if not aids:
                    raise BadAutomationError("action list must be non-empty")
                if len(set(aids)) != len(aids):
                    raise BadAutomationError("duplicate action ids")
                for aid in aids:
                    if aid not in self._actions:
                        raise UnknownActionError(f"unknown action: {aid!r}")
                if len(self._automations) >= _MAX_AUTOMATIONS:
                    raise BadAutomationError("automation registry full")
                prev = (
                    self._automations[max(self._automations)].digest
                    if self._automations
                    else "genesis"
                )
            except WorkflowAutomationError as exc:
                self._reject(seq, f"automation:{type(exc).__name__}")
                raise
            rec = AutomationRecord(
                automation_id=automation_id,
                trigger_id=trigger_id,
                action_ids=aids,
                seq=seq,
                prev_digest=prev,
                digest="",
            )
            rec = AutomationRecord(
                automation_id=rec.automation_id,
                trigger_id=rec.trigger_id,
                action_ids=rec.action_ids,
                seq=rec.seq,
                prev_digest=rec.prev_digest,
                digest=self._automation_digest(rec),
            )
            self._automations[automation_id] = rec
            self._audit(
                "automation-defined",
                {
                    "automation_id": automation_id,
                    "trigger_id": trigger_id,
                    "digest": rec.digest,
                    "seq": seq,
                },
            )
            return rec

    # -- filter ------------------------------------------------------

    @staticmethod
    def _check_rule(rule: Any) -> Tuple[str, str, Any]:
        if (
            not isinstance(rule, (tuple, list))
            or len(rule) != 3
            or not isinstance(rule[0], str)
            or not rule[0]
            or rule[1] not in FILTER_OPS
        ):
            raise BadFilterError(f"bad filter rule: {rule!r}")
        path, op, value = rule[0], rule[1], rule[2]
        if op == "in" and not isinstance(value, (tuple, list)):
            raise BadFilterError("op 'in' requires a list/tuple value")
        if not WorkflowAutomation._canonicalizable(value):
            raise BadFilterError(f"rule value not canonicalizable: {path!r}")
        return path, op, tuple(value) if isinstance(value, list) else value

    def define_filter(
        self,
        automation_id: str,
        rules: Tuple[Tuple[str, str, Any], ...],
        seq: int,
    ) -> FilterRecord:
        """Attach a conjunctive filter to an automation."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                if automation_id not in self._automations:
                    raise UnknownAutomationError(
                        f"unknown automation: {automation_id!r}"
                    )
                rlist = tuple(self._check_rule(r) for r in rules)
                if not rlist:
                    raise BadFilterError("filter needs at least one rule")
                if len(rlist) > _MAX_FILTER_RULES:
                    raise BadFilterError("too many filter rules")
                self._filter_counter += 1
                filter_id = f"flt-{self._filter_counter}"
            except WorkflowAutomationError as exc:
                self._reject(seq, f"filter:{type(exc).__name__}")
                raise
            # Redefinition replaces: same automation gets one live filter.
            rec = FilterRecord(
                filter_id=filter_id,
                automation_id=automation_id,
                rules=rlist,
                seq=seq,
                digest="",
            )
            rec = FilterRecord(
                filter_id=rec.filter_id,
                automation_id=rec.automation_id,
                rules=rec.rules,
                seq=rec.seq,
                digest=self._filter_digest(rec),
            )
            self._filters[automation_id] = rec
            self._audit(
                "filter-defined",
                {
                    "filter_id": filter_id,
                    "automation_id": automation_id,
                    "digest": rec.digest,
                    "seq": seq,
                },
            )
            return rec

    # -- run ---------------------------------------------------------

    @staticmethod
    def _resolve_path(data: Mapping[str, Any], path: str) -> Tuple[bool, Any]:
        cur: Any = data
        for part in path.split("."):
            if not isinstance(cur, Mapping) or part not in cur:
                return False, None
            cur = cur[part]
        return True, cur

    @staticmethod
    def _op_matches(actual: Any, op: str, expected: Any) -> bool:
        try:
            if op == "eq":
                return actual == expected and type(actual) is type(expected)
            if op == "ne":
                return not (
                    actual == expected and type(actual) is type(expected)
                )
            if op in ("gt", "gte", "lt", "lte"):
                if isinstance(actual, bool) or isinstance(expected, bool):
                    return False
                if not isinstance(actual, (int, float)) or not isinstance(
                    expected, (int, float)
                ):
                    return False
                if op == "gt":
                    return actual > expected
                if op == "gte":
                    return actual >= expected
                if op == "lt":
                    return actual < expected
                return actual <= expected
            if op == "in":
                return any(
                    actual == item and type(actual) is type(item)
                    for item in expected
                )
            if op == "contains":
                return isinstance(actual, str) and isinstance(
                    expected, str
                ) and expected in actual
            if op == "starts-with":
                return isinstance(actual, str) and isinstance(
                    expected, str
                ) and actual.startswith(expected)
        except Exception:
            return False
        return False

    def _validate_event(
        self, trigger: TriggerRecord, event: Mapping[str, Any]
    ) -> Dict[str, Any]:
        if not isinstance(event, Mapping):
            raise BadEventError("event must be a mapping")
        if len(event) > _MAX_FIELDS:
            raise BadEventError("event has too many fields")
        schema = set(trigger.field_schema)
        keys = set(event.keys())
        missing = schema - keys
        if missing:
            raise BadEventError(
                f"event missing required fields: {sorted(missing)}"
            )
        extra = keys - schema
        if extra:
            raise BadEventError(
                f"event has unexpected fields: {sorted(extra)}"
            )
        for key in keys:
            if not self._canonicalizable(event[key]):
                raise BadEventError(
                    f"event field {key!r} is not canonicalizable"
                )
        return dict(event)

    def _filter_matches(
        self, filt: FilterRecord, event: Mapping[str, Any]
    ) -> bool:
        for path, op, expected in filt.rules:
            found, actual = self._resolve_path(event, path)
            if not found:
                return False
            if not self._op_matches(actual, op, expected):
                return False
        return True

    def _default_executor(
        self,
        action: ActionRecord,
        inputs: Dict[str, Any],
        seq: int,
    ) -> Dict[str, Any]:
        return {
            "action_id": action.action_id,
            "kind": action.kind,
            "status": "ok-simulated",
            "input_digest": self._pin("inputs", _freeze(inputs)),
        }

    def run(
        self, automation_id: str, event: Mapping[str, Any], seq: int
    ) -> RunReport:
        """Execute an automation against one event; returns a frozen report."""
        with self._lock:
            automation = self._automations.get(automation_id)
            if automation is None:
                raise UnknownAutomationError(
                    f"unknown automation: {automation_id!r}"
                )
            trigger = self._triggers[automation.trigger_id]
            seq = self._next_seq(seq)
            try:
                clean_event = self._validate_event(trigger, event)
            except WorkflowAutomationError as exc:
                self._reject(seq, f"run:{type(exc).__name__}")
                raise
            if len(self._runs) >= _MAX_RUNS:
                self._reject(seq, "run:registry-full")
                raise BadEventError("run registry full")
            self._run_counter += 1
            run_id = f"run-{self._run_counter}"
            event_digest = self._event_digest(clean_event)
            self._audit(
                "run-started",
                {
                    "run_id": run_id,
                    "automation_id": automation_id,
                    "event_digest": event_digest,
                    "seq": seq,
                },
            )
            filt = self._filters.get(automation_id)
            if filt is not None and not self._filter_matches(filt, clean_event):
                self._audit(
                    "run-filtered",
                    {
                        "run_id": run_id,
                        "automation_id": automation_id,
                        "filter_id": filt.filter_id,
                        "seq": seq,
                    },
                )
                rep = RunReport(
                    run_id=run_id,
                    automation_id=automation_id,
                    trigger_id=trigger.trigger_id,
                    status="filtered-out",
                    event_digest=event_digest,
                    action_results=(),
                    failed_action="",
                    error_type="",
                    seq=seq,
                    digest="",
                )
                rep = RunReport(
                    run_id=rep.run_id,
                    automation_id=rep.automation_id,
                    trigger_id=rep.trigger_id,
                    status=rep.status,
                    event_digest=rep.event_digest,
                    action_results=rep.action_results,
                    failed_action=rep.failed_action,
                    error_type=rep.error_type,
                    seq=rep.seq,
                    digest=self._run_digest(rep),
                )
                self._runs[run_id] = rep
                return rep

            # Sequential action execution.
            context: Dict[str, Any] = {"trigger": clean_event, "action": {}}
            results: List[ActionResult] = []
            failed_action = ""
            error_type = ""

            def _record_failure(aid: str, etype: str) -> bool:
                """Record an action failure; returns True if the run stops."""
                results.append(
                    ActionResult(
                        action_id=aid,
                        ok=False,
                        output_digest="",
                        error_type=etype,
                        seq=seq,
                    )
                )
                self._audit(
                    "action-failed",
                    {
                        "run_id": run_id,
                        "action_id": aid,
                        "error_type": etype,
                        "seq": seq,
                    },
                )
                action = self._actions[aid]
                if action.run_on_error == "stop":
                    return True
                return False

            for aid in automation.action_ids:
                action = self._actions[aid]
                inputs: Dict[str, Any] = dict(action.params)
                unresolvable = False
                for target, source in action.mappings:
                    found, value = self._resolve_path(context, source)
                    if not found:
                        unresolvable = True
                        break
                    inputs[target] = value
                if unresolvable:
                    if _record_failure(aid, "UnresolvableMapping"):
                        failed_action = aid
                        error_type = "UnresolvableMapping"
                        break
                    continue
                try:
                    output = self._executor(action, inputs, seq)
                    if not isinstance(output, Mapping):
                        raise BadExecutorOutputError(
                            "executor must return a mapping"
                        )
                    output_dict = dict(output)
                    if not self._canonicalizable(output_dict):
                        raise BadExecutorOutputError(
                            "executor output not canonicalizable"
                        )
                except BadExecutorOutputError:
                    raise
                except Exception as exc:  # noqa: BLE001 - host executor
                    if _record_failure(aid, type(exc).__name__):
                        failed_action = aid
                        error_type = type(exc).__name__
                        break
                    continue
                out_digest = self._pin("output", _freeze(output_dict))
                context["action"][aid] = output_dict
                results.append(
                    ActionResult(
                        action_id=aid,
                        ok=True,
                        output_digest=out_digest,
                        error_type="",
                        seq=seq,
                    )
                )
                self._audit(
                    "action-executed",
                    {
                        "run_id": run_id,
                        "action_id": aid,
                        "output_digest": out_digest,
                        "seq": seq,
                    },
                )
            status = "failed" if failed_action else "succeeded"
            rep = RunReport(
                run_id=run_id,
                automation_id=automation_id,
                trigger_id=trigger.trigger_id,
                status=status,
                event_digest=event_digest,
                action_results=tuple(results),
                failed_action=failed_action if status == "failed" else "",
                error_type=error_type if status == "failed" else "",
                seq=seq,
                digest="",
            )
            rep = RunReport(
                run_id=rep.run_id,
                automation_id=rep.automation_id,
                trigger_id=rep.trigger_id,
                status=rep.status,
                event_digest=rep.event_digest,
                action_results=rep.action_results,
                failed_action=rep.failed_action,
                error_type=rep.error_type,
                seq=rep.seq,
                digest=self._run_digest(rep),
            )
            self._runs[run_id] = rep
            self._audit(
                "run-completed",
                {
                    "run_id": run_id,
                    "automation_id": automation_id,
                    "status": status,
                    "digest": rep.digest,
                    "seq": seq,
                },
            )
            return rep

    # -- views -------------------------------------------------------

    def get_trigger(self, trigger_id: str) -> TriggerRecord:
        with self._lock:
            rec = self._triggers.get(trigger_id)
            if rec is None:
                raise UnknownTriggerError(f"unknown trigger: {trigger_id!r}")
            return rec

    def get_action(self, action_id: str) -> ActionRecord:
        with self._lock:
            rec = self._actions.get(action_id)
            if rec is None:
                raise UnknownActionError(f"unknown action: {action_id!r}")
            return rec

    def get_automation(self, automation_id: str) -> AutomationRecord:
        with self._lock:
            rec = self._automations.get(automation_id)
            if rec is None:
                raise UnknownAutomationError(
                    f"unknown automation: {automation_id!r}"
                )
            return rec

    def get_run(self, run_id: str) -> RunReport:
        with self._lock:
            rep = self._runs.get(run_id)
            if rep is None:
                raise WorkflowAutomationError(f"unknown run: {run_id!r}")
            return rep

    def trigger_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._triggers))

    def action_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._actions))

    def automation_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._automations))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)


def _freeze(value: Any) -> Any:
    """Convert mappings to sorted-pair lists so digests are deterministic."""
    if isinstance(value, Mapping):
        return [[k, _freeze(value[k])] for k in sorted(value.keys())]
    if isinstance(value, (tuple, list)):
        return [_freeze(v) for v in value]
    return value


def workflow_automation_audit_event(
    event: str, payload: Dict[str, Any]
) -> Dict[str, Any]:
    """Build an audit event envelope for the workflow automation module."""
    if event not in _AUDIT_KINDS:
        raise WorkflowAutomationError(f"unknown audit kind: {event!r}")
    return {
        "schema": AUDIT_FORMAT,
        "module": WORKFLOW_AUTOMATION_VERSION,
        "event": event,
        "payload": payload,
    }


def main() -> None:
    mgr = WorkflowAutomation(seed=b"workflow-automation-selfcheck")
    trig = mgr.trigger("t1", "form_submitted", 1, ("name", "email"))
    assert trig.trigger_id == "t1" and trig.verify(mgr)
    mgr.action(
        "a1",
        "send_email",
        2,
        params=(("subject", "welcome"),),
        mappings=(("to", "trigger.email"),),
    )
    mgr.action(
        "a2",
        "create_row",
        3,
        mappings=(("name", "trigger.name"), ("email", "trigger.email")),
    )
    auto = mgr.define_automation("z1", "t1", ("a1", "a2"), 4)
    assert auto.verify(mgr)
    rep = mgr.run("z1", {"name": "Ada", "email": "ada@example.com"}, 5)
    assert rep.status == "succeeded", rep
    assert rep.verify(mgr)
    assert [r.action_id for r in rep.action_results] == ["a1", "a2"]
    kinds = [e["event"] for e in mgr.audit_log()]
    assert kinds == [
        "trigger-defined",
        "action-defined",
        "action-defined",
        "automation-defined",
        "run-started",
        "action-executed",
        "action-executed",
        "run-completed",
    ], kinds
    print("workflow-automation OK: trigger, action, automation, run, pins")


if __name__ == "__main__":
    main()
