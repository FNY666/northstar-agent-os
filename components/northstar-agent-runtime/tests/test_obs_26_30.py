"""Tests for obs_26..obs_30."""
import importlib.util, sys
from pathlib import Path
import pytest
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
o26 = _load("obs_26"); o27 = _load("obs_27"); o28 = _load("obs_28")
o29 = _load("obs_29"); o30 = _load("obs_30")

def test_o26_lifecycle():
    inc = o26.Incident("I-1", "db down", "sev1")
    inc.acknowledge(); inc.mitigate(); inc.resolve()
    assert inc.state == "resolved"
    tl = inc.timeline()
    assert [e["to"] for e in tl] == ["open", "acknowledged", "mitigated", "resolved"]
def test_o26_open_to_mitigated():
    inc = o26.Incident("I-2", "slow", "sev4")
    inc.mitigate()
    assert inc.state == "mitigated"
def test_o26_bad_transition():
    inc = o26.Incident("I-3", "x", "sev2")
    with pytest.raises(o26.Obs26Error): inc.resolve()
def test_o26_bad_severity():
    with pytest.raises(o26.Obs26Error): o26.Incident("I-4", "x", "sev9")
def test_o26_empty_title():
    with pytest.raises(o26.Obs26Error): o26.Incident("I-5", "  ", "sev2")
def test_o26_stdlib(): assert o26.stdlib_only()
def test_o26_version(): assert o26.OBS26_VERSION == "obs-26.v1"

def test_o27_build():
    doc = o27.build_postmortem(
        "I-1", "db down", "sev1",
        [("t1", "alert"), ("t2", "failover")],
        "disk full",
        [("alice", "add alerts", "2026-10-15")],
    )
    assert "Root cause" in doc["markdown"] and "Timeline" in doc["markdown"]
    assert doc["action_items"][0]["owner"] == "alice"
def test_o27_missing_root_cause():
    with pytest.raises(o27.Obs27Error):
        o27.build_postmortem("I-2", "t", "sev2", [("t1", "e")], "", [("a", "b", "c")])
def test_o27_empty_action_items():
    with pytest.raises(o27.Obs27Error):
        o27.build_postmortem("I-3", "t", "sev2", [("t1", "e")], "cause", [])
def test_o27_stdlib(): assert o27.stdlib_only()
def test_o27_version(): assert o27.OBS27_VERSION == "obs-27.v1"

def test_o28_run_hypothesis_held():
    exp = o28.ChaosExperiment(
        "e", "holds", lambda: True,
        [("f1", lambda: "effect-1")],
        lambda: None,
    )
    res = exp.run()
    assert res["hypothesis_held"] is True and res["rolled_back"] is True
    assert res["fault_effects"][0]["effect"] == "effect-1"
def test_o28_abort_not_steady():
    exp = o28.ChaosExperiment("e", "h", lambda: False, [("f", lambda: 1)], lambda: None)
    res = exp.run()
    assert res["aborted"] is True and res["hypothesis_held"] is False
def test_o28_non_callable_fault():
    with pytest.raises(o28.Obs28Error):
        o28.ChaosExperiment("e", "h", lambda: True, [("f", 123)], lambda: None)  # type: ignore
def test_o28_stdlib(): assert o28.stdlib_only()
def test_o28_version(): assert o28.OBS28_VERSION == "obs-28.v1"

def test_o29_schedule_sorted():
    gd = o29.GameDay("g", ["a", "b"], [(30, "x", "y"), (10, "p", "q")])
    assert [s["at_minute"] for s in gd.schedule()] == [10, 30]
def test_o29_score():
    gd = o29.GameDay("g", ["a", "b"], [(10, "x", "y"), (30, "p", "q")])
    gd.record_response(12, 0, "did x", True, participant="a")
    gd.record_response(40, 1, "did q", False, participant="b")
    sc = gd.score()
    assert sc["injects_resolved"] == 1 and sc["injects_total"] == 2
    assert sc["avg_response_delay_min"] == 6.0 and sc["participants"] == 2
def test_o29_duplicate_participant():
    with pytest.raises(o29.Obs29Error):
        o29.GameDay("g", ["a", "a"], [(5, "x", "y")])
def test_o29_bad_inject_idx():
    gd = o29.GameDay("g", ["a"], [(5, "x", "y")])
    with pytest.raises(o29.Obs29Error): gd.record_response(6, 3, "z", True)
def test_o29_stdlib(): assert o29.stdlib_only()
def test_o29_version(): assert o29.OBS29_VERSION == "obs-29.v1"

def test_o30_latency():
    inj = o30.FaultInjector(max_targets=3)
    inj.inject("svc", "latency", {"delay_ms": 50})
    out = inj.apply("svc", lambda: "ok")()
    assert out["result"] == "ok" and out["injected_delay_ms"] == 50
def test_o30_error_raises():
    inj = o30.FaultInjector()
    inj.inject("svc", "error", {"message": "boom"})
    with pytest.raises(o30.Obs30Error, match="boom"):
        inj.apply("svc", lambda: "ok")()
def test_o30_kill_and_guardrail():
    inj = o30.FaultInjector(max_targets=1)
    inj.inject("svc", "kill", {})
    res = inj.apply("svc", lambda: "x")()
    assert res["dead"] is True and inj.is_dead("svc") is True
    with pytest.raises(o30.Obs30Error): inj.inject("svc2", "latency", {})
def test_o30_unknown_type():
    inj = o30.FaultInjector()
    with pytest.raises(o30.Obs30Error): inj.inject("svc", "warp", {})
def test_o30_blast_radius():
    inj = o30.FaultInjector(max_targets=4)
    inj.inject("a", "latency", {}); inj.inject("b", "error", {})
    assert inj.blast_radius() == 2
def test_o30_stdlib(): assert o30.stdlib_only()
def test_o30_version(): assert o30.OBS30_VERSION == "obs-30.v1"
