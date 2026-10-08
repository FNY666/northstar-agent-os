"""Tests for dx_28. release automation."""
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

dx = _load("dx_28")

def _rel():
    return dx.Release("1.2.3")


def test_plan_order():
    assert _rel().plan() == ["validate", "tag", "publish", "announce"]


def test_full_run():
    r = _rel()
    assert r.complete("validate") == "tag"
    assert r.complete("tag") == "publish"
    assert r.complete("publish") == "announce"
    assert r.complete("announce") is None
    assert r.done is True


def test_skip_rejected():
    r = _rel()
    r.complete("validate")
    with pytest.raises(dx.ReleaseError):
        r.complete("publish")


def test_bad_version_rejected():
    with pytest.raises(dx.ReleaseError):
        dx.Release("1.2")


def test_double_complete_rejected():
    r = _rel()
    for s in r.plan():
        r.complete(s)
    with pytest.raises(dx.ReleaseError):
        r.complete("announce")


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX28_RELEASE_VERSION == "dx-release.v1"
