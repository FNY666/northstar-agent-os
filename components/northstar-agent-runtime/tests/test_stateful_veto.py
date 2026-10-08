"""Stateful veto tests."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sv = _load("stateful_veto")


def test_record_deny():
    v = sv.StatefulVeto()
    s = v.record_deny("s1", "tool1")
    assert s.denial_count == 1
    assert s.risk_score == 10


def test_risk_caps():
    v = sv.StatefulVeto(risk_per_deny=60, max_risk=100)
    v.record_deny("s1", "t")
    v.record_deny("s1", "t")
    assert v.risk_score("s1") == 100  # capped


def test_rate_limit_tool():
    v = sv.StatefulVeto(retry_limit=2)
    v.record_deny("s1", "tool1")
    v.record_deny("s1", "tool1")
    limited, _ = v.should_rate_limit("s1", "tool1")
    assert limited is True


def test_semantic_retry():
    v = sv.StatefulVeto(retry_limit=2)
    v.record_deny("s1", "tool_a", "exfil")
    v.record_deny("s1", "tool_b", "exfil")
    limited, reason = v.should_rate_limit("s1", "tool_c", "exfil")
    assert limited is True
    assert "semantic" in reason


def test_no_rate_limit():
    v = sv.StatefulVeto()
    limited, _ = v.should_rate_limit("s1", "tool1")
    assert limited is False


def test_postcondition():
    ok, _ = sv.verify_postcondition(lambda: True, "desc")
    assert ok is True
    ok, _ = sv.verify_postcondition(lambda: False, "desc")
    assert ok is False


def test_postcondition_exception():
    def bad():
        raise RuntimeError("oops")

    ok, reason = sv.verify_postcondition(bad, "desc")
    assert ok is False
    assert "raised" in reason


def test_stdlib_only():
    assert sv.stdlib_only() is True


def test_version_pin():
    assert sv.STATEFUL_VETO_VERSION == "stateful-veto.v1"
