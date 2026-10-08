"""Tests for monitor_03 (Grafana dashboards)."""
import importlib.util, json, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


gd = _load("monitor_03")


def test_gate_dashboard_spec():
    d = gd.gate_dashboard()
    spec = json.loads(d.to_json())
    assert spec["uid"] == "northstar-gates"
    assert len(spec["panels"]) == 3
    assert all(p["id"] for p in spec["panels"])


def test_bad_panel_type():
    import pytest

    with pytest.raises(gd.DashboardError):
        gd.Panel(title="t", panel_type="bogus", expr="x")


def test_bad_dashboard():
    import pytest

    with pytest.raises(gd.DashboardError):
        gd.Dashboard(title="", uid="u")


def test_variable():
    d = gd.Dashboard(title="t", uid="u")
    d.add_variable("env", "label_values(up, env)")
    assert len(json.loads(d.to_json())["templating"]["list"]) == 1


def test_stdlib_only():
    assert gd.stdlib_only() is True
