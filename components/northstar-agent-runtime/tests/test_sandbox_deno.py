"""Deno sandbox config tests."""

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


dn = _load("sandbox_deno")


def test_generate_defaults():
    cfg = dn.generate_config("/workspace/main.ts")
    assert cfg.allow_net == []
    assert cfg.allow_read == ["/workspace"]


def test_rejects_allow_deny_overlap():
    cfg = dn.DenoConfig(script="/x", allow_read=["/a"], deny_read=["/a"])
    with pytest.raises(dn.DenoError):
        dn.validate_config(cfg)


def test_rejects_sensitive_write():
    cfg = dn.DenoConfig(script="/x", allow_write=["/etc"])
    with pytest.raises(dn.DenoError):
        dn.validate_config(cfg)


def test_deno_args():
    cfg = dn.generate_config("/workspace/main.ts")
    args = dn.to_deno_args(cfg)
    assert args[0] == "deno"
    assert "--allow-net=none" in args


def test_version_pin():
    assert dn.DENO_VERSION == "sandbox-deno.v1"
