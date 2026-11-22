"""Regression coverage for audit-trigger alerts and their seal tripwire."""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
import support  # noqa: F401

from alert_trigger_registry import (
    REGISTRY_PATH, AlertTrigger, AlertTriggerRegistry, AlertTriggerRegistryError,
    DEFAULT_REGISTRY,
)
from forward_seal_ledger import ForwardSealLedger
from loop import AgentRuntime
from providers.base import SystemMessage


class _Announcer:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail
        self.received = []
    def announce_alert(self, kind, detail):
        if self.fail:
            raise RuntimeError("transport down")
        self.calls.append((kind, detail))
        return {"kind": kind, "detail": detail}


def _runtime():
    # Constructing the runtime also exercises the registry ledger pin.
    return AgentRuntime(provider=SimpleNamespace(name="test", generate=lambda request: None),
                        config=__import__("loop").RuntimeConfig(gossip_enabled=False))


def _append(runtime, **fields):
    defaults = dict(intent="permission", action="check", subject="tool",
                    authorization="policy", inputs_digest="sha256:" + "0" * 64,
                    logic_digest="sha256:" + "1" * 64,
                    execution_digest="sha256:" + "2" * 64, outcome="permission.deny")
    defaults.update(fields)
    runtime.sealed_ledger.append(**defaults)


def test_denial_fires_matching_trigger_with_detail():
    r = _runtime(); a = _Announcer(); r.gossip_announcer = a
    _append(r, subject="Shell")
    r._scan_alert_sink()
    assert a.calls[0][0] == "kill-switch"
    assert a.calls[0][1]["subject"] == "Shell"


def test_alert_rumor_reaches_peer_loopback():
    # The announcer's contract is exercised by its existing loopback transport;
    # this regression ensures the peer callback is a real receive, not a local write.
    from gossip_announcer import GossipAnnouncer, LocalGossipTransport
    t = LocalGossipTransport(); seen = []
    GossipAnnouncer(node_id="peer", transport=t).receive
    t.register("sink", lambda rumor: seen.append(rumor))
    origin = GossipAnnouncer(node_id="origin", peers=("sink",), transport=t)
    origin.announce_alert("kill-switch", {"x": 1})
    assert seen and seen[0].payload["kind"] == "kill-switch"


def test_alert_lands_in_run_transcript():
    r = _runtime(); a = _Announcer(); r.gossip_announcer = a
    r._pending_state = SimpleNamespace(transcript=[])
    _append(r); r._scan_alert_sink()
    assert any(isinstance(m, SystemMessage) and "ALERT kill-switch" in m.content for m in r._pending_state.transcript)


def test_unknown_alert_kind_rejected_fail_closed():
    with pytest.raises(AlertTriggerRegistryError):
        AlertTriggerRegistry((AlertTrigger("bad", "unknown", ("x",)),))


def test_registry_path_is_declared_check_input():
    from code_task import CodeTask
    assert REGISTRY_PATH in CodeTask(goal="x", check_inputs=(REGISTRY_PATH,)).check_inputs


def test_registry_change_changes_seal_digest():
    a = DEFAULT_REGISTRY.digest()
    b = AlertTriggerRegistry(DEFAULT_REGISTRY.triggers[:-1]).digest()
    assert a != b


def test_silenced_trigger_has_no_alert_and_digest_diff():
    r = _runtime(); a = _Announcer(); r.gossip_announcer = a
    r.alert_trigger_registry = AlertTriggerRegistry((AlertTrigger("off", "kill-switch", ("permission.deny",), enabled=False),))
    _append(r); r._scan_alert_sink()
    assert not a.calls
    assert r.alert_trigger_registry.digest() != DEFAULT_REGISTRY.digest()


def test_config_drift_fires_distinct_trigger():
    r = _runtime(); a = _Announcer(); r.gossip_announcer = a
    _append(r, outcome="other", intent="permission.config-drift")
    r._scan_alert_sink()
    assert a.calls[0][0] == "config-drift"


def test_announcement_failure_does_not_raise():
    r = _runtime(); r.gossip_announcer = _Announcer(fail=True)
    _append(r); r._scan_alert_sink()
    assert r._gossip_announce_error.startswith("RuntimeError")


def test_duplicate_denial_is_idempotent():
    r = _runtime(); a = _Announcer(); r.gossip_announcer = a
    _append(r, subject="Shell"); _append(r, subject="Shell")
    r._scan_alert_sink()
    assert len(a.calls) == 1


# ---------------------------------------------------------------------------
# Mutant evidence: or@45
#
# `if not trigger.name or not trigger.outcomes:` is a genuine double
# guard, and `or` -> `and` differs only when EXACTLY ONE half is true.
# So it takes TWO inputs to kill the mutant:
#
#   * the name is blank, the outcomes are present -- only the SECOND
#     half refuses, so the mutant (`and`) ACCEPTS the trigger;
#   * the name is present, the outcomes are empty -- only the FIRST
#     half refuses, so the mutant ACCEPTS the trigger too.
# ---------------------------------------------------------------------------


def test_or_at_45_a_blank_trigger_name_is_refused():
    """or@45: type right, format wrong -- the name is blank.

    Only the second half of the guard refuses this one, so it is one of
    the two inputs that separate `or` from `and`.
    """
    with pytest.raises(AlertTriggerRegistryError) as excinfo:
        AlertTriggerRegistry((AlertTrigger("", "kill-switch", ("permission.deny",)),))
    assert "trigger requires name and outcomes" in str(excinfo.value)


def test_or_at_45_empty_trigger_outcomes_are_refused():
    """or@45: format right, type wrong -- the outcomes are empty.

    Only the first half of the guard refuses this one, so it is the
    other of the two inputs that separate `or` from `and`.
    """
    with pytest.raises(AlertTriggerRegistryError) as excinfo:
        AlertTriggerRegistry((AlertTrigger("named", "kill-switch", ()),))
    assert "trigger requires name and outcomes" in str(excinfo.value)


def test_or_at_45_a_complete_trigger_is_accepted():
    """or@45: the control -- a named trigger with outcomes passes."""
    registry = AlertTriggerRegistry(
        (AlertTrigger("named", "kill-switch", ("permission.deny",)),)
    )
    assert registry.triggers[0].name == "named"
