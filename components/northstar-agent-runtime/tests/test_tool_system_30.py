"""Tests for tool_system_30."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_30")
import pytest

def _eng():
    e = m.PolicyEngine()
    e.add_policy(m.Policy(name="allow-web", tool_pattern=r"^web",
                          action=m.ALLOW))
    e.add_policy(m.Policy(name="deny-secret", tool_pattern=r"secret",
                          action=m.DENY))
    return e

def test_allow():
    d = _eng().evaluate("web_fetch")
    assert d.action == m.ALLOW and d.matched_policy == "allow-web"

def test_deny_wins_over_allow():
    e = _eng()
    e.add_policy(m.Policy(name="deny-web", tool_pattern=r"^web",
                          action=m.DENY))
    d = e.evaluate("web_fetch")
    assert d.action == m.DENY and d.matched_policy == "deny-web"

def test_require_approval_beats_allow():
    e = m.PolicyEngine()
    e.add_policy(m.Policy(name="a", tool_pattern=r"^db", action=m.ALLOW))
    e.add_policy(m.Policy(name="b", tool_pattern=r"^db",
                          action=m.REQUIRE_APPROVAL))
    assert e.evaluate("db_query").action == m.REQUIRE_APPROVAL

def test_default_deny_unlisted():
    d = _eng().evaluate("shell_exec")
    assert d.action == m.DENY and d.matched_policy is None

def test_default_allow_configurable():
    e = m.PolicyEngine(default_action=m.ALLOW)
    assert e.evaluate("anything").action == m.ALLOW

def test_audit_trail():
    tick = {"t": 42.0}
    e = m.PolicyEngine(clock=lambda: tick["t"])
    e.add_policy(m.Policy(name="p", tool_pattern=r"x", action=m.ALLOW))
    e.evaluate("x_tool")
    e.evaluate("other")
    trail = e.audit_trail()
    assert len(trail) == 2
    assert [t.action for t in trail] == [m.ALLOW, m.DENY]
    assert trail[0].at == 42.0 and trail[0].seq == 1

def test_bad_policy_rejected():
    e = m.PolicyEngine()
    with pytest.raises(m.ToolSystem30Error):
        e.add_policy(m.Policy(name="x", tool_pattern="t", action="nuke"))
    with pytest.raises(m.ToolSystem30Error):
        e.add_policy(m.Policy(name="y", tool_pattern="([",
                              action=m.ALLOW))

def test_stdlib():
    assert m.stdlib_only() is True
