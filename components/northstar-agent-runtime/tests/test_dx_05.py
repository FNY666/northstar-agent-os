"""Tests for dx_05 watch mode."""
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

dx = _load("dx_05")


def test_runs_on_notify():
    w = dx.MockWatch(lambda p: f"ran {p}", debounce_s=0.0)
    w.notify("a.py")
    runs = w.flush()
    assert len(runs) == 1 and runs[0].ok and runs[0].result == "ran a.py"


def test_debounce_collapses():
    now = [0.0]
    w = dx.MockWatch(lambda p: p, debounce_s=10.0, clock=lambda: now[0])
    w.notify("a.py")
    w.notify("b.py")
    runs = w.flush()
    assert len(runs) == 1 and runs[0].trigger == "b.py"
    w.notify("c.py")
    assert w.flush() == []  # still debouncing
    now[0] += 11.0
    assert len(w.flush()) == 1


def test_task_failure_captured():
    def boom(p):
        raise RuntimeError("x")

    w = dx.MockWatch(boom, debounce_s=0.0)
    w.notify("z.py")
    runs = w.flush()
    assert len(runs) == 1 and not runs[0].ok and runs[0].error == "RuntimeError"
    # watcher survives: can run again
    w.notify("z.py")
    assert len(w.flush()) == 1


def test_bad_task_raises():
    with pytest.raises(dx.WatchError):
        dx.MockWatch("not-callable")  # type: ignore


def test_empty_path_raises():
    w = dx.MockWatch(lambda p: p, debounce_s=0.0)
    with pytest.raises(dx.WatchError):
        w.notify("")


def test_flush_without_pending():
    w = dx.MockWatch(lambda p: p, debounce_s=0.0)
    assert w.flush() == []


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX05_WATCH_VERSION == "dx-watch.v1"
