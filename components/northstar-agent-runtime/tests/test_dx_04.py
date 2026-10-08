"""Tests for dx_04 hot reload."""
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

dx = _load("dx_04")


def test_no_change_no_event():
    hr = dx.MockHotReload()
    hr.track("a.py", "x = 1\n")
    assert hr.poll() == []


def test_change_reloads_ok():
    hr = dx.MockHotReload()
    hr.track("a.py", "x = 1\n")
    hr.touch("a.py", "x = 2\n")
    evs = hr.poll()
    assert len(evs) == 1 and evs[0].ok and evs[0].path == "a.py"


def test_broken_source_kept_safe():
    hr = dx.MockHotReload()
    hr.track("a.py", "x = 1\n")
    hr.touch("a.py", "def broken(:\n")
    evs = hr.poll()
    assert len(evs) == 1 and not evs[0].ok and evs[0].error


def test_untracked_touch_raises():
    hr = dx.MockHotReload()
    with pytest.raises(dx.HotReloadError):
        hr.touch("nope.py", "x = 1\n")


def test_bad_initial_source_raises():
    hr = dx.MockHotReload()
    with pytest.raises(dx.HotReloadError):
        hr.track("a.py", "def broken(:\n")


def test_on_reload_callback():
    seen = []
    hr = dx.MockHotReload()
    hr.on_reload(seen.append)
    hr.track("a.py", "x = 1\n")
    hr.touch("a.py", "x = 2\n")
    hr.poll()
    assert len(seen) == 1 and seen[0].ok


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX04_HOTRELOAD_VERSION == "dx-hotreload.v1"
