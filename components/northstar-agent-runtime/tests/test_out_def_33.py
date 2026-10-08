"""Covert channel (size/timing anomaly) detection tests."""

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


d33 = _load("out_def_33")


def test_oversize_fails():
    ok, reason = d33.check_size_channel("x" * 101, 100)
    assert ok is False
    assert "max_chars" in reason


def test_size_channel_flagged():
    # >3x baseline with dense base64-like token.
    ok, reason = d33.check_size_channel("A" * 100, 1000, baseline=10)
    assert ok is False
    assert "size channel" in reason


def test_normal_size_passes():
    ok, _ = d33.check_size_channel("hello world", 100, baseline=50)
    assert ok is True


def test_padding_anomaly_flagged():
    ok, reason = d33.detect_padding_anomaly("data\nline" + " " * 60)
    assert ok is False
    assert "padding anomaly" in reason


def test_no_padding_clean():
    ok, _ = d33.detect_padding_anomaly("normal\ntext")
    assert ok is True


def test_base64_ratio():
    assert d33.base64_ratio("abc123") == 1.0
    assert d33.base64_ratio("!!!") == 0.0


def test_negative_max_chars_fail_closed():
    try:
        d33.check_size_channel("x", -1)
    except d33.OutDef33Error:
        pass
    else:
        raise AssertionError("negative max_chars should fail closed")


def test_stdlib_only():
    assert d33.stdlib_only() is True


def test_version_pin():
    assert d33.OUT_DEF_33_VERSION == "out-def-33.v1"
    assert d33.SCHEMA_PIN == "northstar.out-def-33.v1"
