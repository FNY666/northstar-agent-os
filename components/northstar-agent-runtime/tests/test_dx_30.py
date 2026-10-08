"""Tests for dx_30. plugin system."""
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

dx = _load("dx_30")

def _bus():
    b = dx.PluginBus()
    b.register_plugin("git")
    b.register_plugin("lint")
    b.subscribe("lint", "on_save")
    b.subscribe("git", "on_save")
    return b


def test_emit_registration_order():
    got = _bus().emit("on_save")
    assert [(d.plugin, d.hook) for d in got] == [
        ("git", "on_save"), ("lint", "on_save")
    ]


def test_unknown_hook_broadcast():
    assert _bus().emit("on_idle") == []


def test_unsubscribe():
    b = _bus()
    b.unsubscribe("git", "on_save")
    assert [d.plugin for d in b.emit("on_save")] == ["lint"]


def test_unknown_plugin_raises():
    with pytest.raises(dx.PluginsError):
        _bus().subscribe("nope", "on_save")


def test_bad_unsubscribe_raises():
    with pytest.raises(dx.PluginsError):
        _bus().unsubscribe("lint", "on_idle")


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX30_PLUGINS_VERSION == "dx-plugins.v1"
