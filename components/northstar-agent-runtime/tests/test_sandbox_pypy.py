"""PyPy sandbox policy tests."""

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


pp = _load("sandbox_pypy")


def test_generate_defaults():
    cfg = pp.generate_config("/workspace/run.py")
    assert cfg.timeout_sec == 30
    assert cfg.vfs_mounts["/workspace"]["mode"] == "rw"


def test_rejects_dangerous_module():
    cfg = pp.PypySandboxConfig(script_path="/x", allowed_modules=["os"])
    with pytest.raises(pp.PypyError):
        pp.validate_config(cfg)


def test_rejects_sensitive_mount():
    cfg = pp.PypySandboxConfig(
        script_path="/x",
        vfs_mounts={"/e": {"host": "/etc", "mode": "ro"}},
    )
    with pytest.raises(pp.PypyError):
        pp.validate_config(cfg)


def test_policy_dict():
    cfg = pp.generate_config("/workspace/run.py")
    policy = pp.to_policy_dict(cfg)
    assert "vfs" in policy
    assert "limits" in policy


def test_version_pin():
    assert pp.PYPY_VERSION == "sandbox-pypy.v1"
