"""nsjail sandbox config tests."""

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


nj = _load("sandbox_nsjail")


def test_generate_defaults():
    cfg = nj.generate_config("/usr/bin/python3")
    assert cfg.env_deny_all is True
    assert cfg.rlimit_cpu == 30
    assert cfg.seccomp_policy == "default"


def test_rejects_empty_binary():
    with pytest.raises(nj.NsjailError):
        nj.generate_config("")


def test_rejects_writable_sensitive_mount():
    cfg = nj.NsjailConfig(binary="/bin/sh")
    cfg.mounts = [{"src": "/", "dst": "/etc", "readonly": False}]
    with pytest.raises(nj.NsjailError):
        nj.validate_config(cfg)


def test_rejects_bad_seccomp():
    cfg = nj.NsjailConfig(binary="/bin/sh", seccomp_policy="bogus")
    with pytest.raises(nj.NsjailError):
        nj.validate_config(cfg)


def test_cmdline():
    cfg = nj.generate_config("/usr/bin/python3", ["--version"])
    cmd = nj.to_cmdline(cfg)
    assert cmd[0] == "nsjail"
    assert "--" in cmd
    assert "/usr/bin/python3" in cmd


def test_version_pin():
    assert nj.NSJAIL_VERSION == "sandbox-nsjail.v1"
