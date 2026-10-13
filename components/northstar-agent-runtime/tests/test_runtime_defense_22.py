"""Runtime defense 22 tests."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rd = _load("runtime_defense_22")


def test_allowlisted():
    policy = rd.SyscallPolicy()
    assert rd.is_allowed("read", policy) is True
    assert rd.is_allowed("mmap", policy) is True


def test_default_deny():
    policy = rd.SyscallPolicy()
    assert rd.is_allowed("execve", policy) is False
    assert rd.is_allowed("ptrace", policy) is False
    assert rd.is_allowed("clone3", policy) is False


def test_deny_wins():
    policy = rd.SyscallPolicy(
        allowed=frozenset({"read", "write"}),
        denied=frozenset({"write"}),
    )
    assert rd.is_allowed("write", policy) is False
    assert rd.is_allowed("read", policy) is True


def test_filter_calls():
    policy = rd.SyscallPolicy(allowed=frozenset({"read"}))
    assert rd.filter_calls(["read", "write"], policy) == ["write"]


def test_rejects_empty_allowlist():
    with pytest.raises(rd.SyscallFilterError):
        rd.SyscallPolicy(allowed=frozenset())


def test_rejects_empty_name():
    with pytest.raises(rd.SyscallFilterError):
        rd.is_allowed("", rd.SyscallPolicy())


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_22_VERSION == "runtime-defense-22.v1"
