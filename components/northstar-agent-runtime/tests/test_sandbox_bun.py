"""Bun sandbox config tests."""

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


bn = _load("sandbox_bun")


def test_generate_defaults():
    cfg = bn.generate_config("/workspace/app.ts")
    assert cfg.allow_net == []
    assert cfg.allow_spawn == []


def test_rejects_shell_spawn():
    cfg = bn.BunConfig(script="/x", allow_spawn=["sh"])
    with pytest.raises(bn.BunError):
        bn.validate_config(cfg)


def test_rejects_sensitive_write():
    cfg = bn.BunConfig(script="/x", allow_fs_write=["/root"])
    with pytest.raises(bn.BunError):
        bn.validate_config(cfg)


def test_bun_args():
    cfg = bn.generate_config("/workspace/app.ts")
    args = bn.to_bun_args(cfg)
    assert args[0] == "bun"
    assert "--deny-net" in args


def test_version_pin():
    assert bn.BUN_VERSION == "sandbox-bun.v1"
