"""Concrete audit-sink alert trigger registry.

The registry is deliberately a source artifact (and therefore a check-input
candidate), not an opaque runtime dict.  Its pin is a tripwire: the host loop
can notice a changed or silenced trigger, but that check remains in the same
trust domain as the writer and is not proof against a malicious host.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

ALERT_TRIGGER_REGISTRY_VERSION = "alert-trigger-registry.v1"
REGISTRY_PATH = "components/northstar-agent-runtime/alert_trigger_registry.py"
KNOWN_ALERT_KINDS = ("kill-switch", "config-drift")


@dataclass(frozen=True)
class AlertTrigger:
    name: str
    kind: str
    outcomes: tuple[str, ...]
    detail_fields: tuple[str, ...] = ()
    enabled: bool = True


DEFAULT_TRIGGERS = (
    AlertTrigger("permission-deny-kill-switch", "kill-switch", ("permission.deny",), ("intent", "subject", "authorization")),
    AlertTrigger("permission-config-drift", "config-drift", ("permission.config-drift", "config-drift"), ("intent", "subject", "authorization")),
)


class AlertTriggerRegistryError(ValueError):
    pass


class AlertTriggerRegistry:
    def __init__(self, triggers: tuple[AlertTrigger, ...] = DEFAULT_TRIGGERS) -> None:
        self.triggers = tuple(triggers)
        for trigger in self.triggers:
            if trigger.kind not in KNOWN_ALERT_KINDS:
                raise AlertTriggerRegistryError(f"unknown alert kind: {trigger.kind}")
            if not trigger.name or not trigger.outcomes:
                raise AlertTriggerRegistryError("trigger requires name and outcomes")

    def matches(self, record: Mapping[str, Any]) -> tuple[AlertTrigger, ...]:
        outcome = record.get("outcome")
        intent = str(record.get("intent", ""))
        return tuple(t for t in self.triggers if t.enabled and (outcome in t.outcomes or (t.kind == "config-drift" and "config-drift" in intent)))

    def detail(self, trigger: AlertTrigger, record: Mapping[str, Any]) -> dict[str, Any]:
        return {"trigger": trigger.name, "outcome": record.get("outcome"), **{
            key: record.get(key) for key in trigger.detail_fields if key in record
        }}

    def digest(self) -> str:
        payload = [{"name": t.name, "kind": t.kind, "outcomes": t.outcomes,
                    "detail_fields": t.detail_fields, "enabled": t.enabled} for t in self.triggers]
        return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


DEFAULT_REGISTRY = AlertTriggerRegistry()
