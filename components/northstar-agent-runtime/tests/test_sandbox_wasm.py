"""WASM sandbox config tests."""

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


wm = _load("sandbox_wasm")


def test_generate_defaults():
    cfg = wm.generate_config("/tmp/mod.wasm")
    assert cfg.allow_network is False
    assert cfg.fuel == 10_000_000


def test_rejects_unlimited_fuel():
    cfg = wm.WasmConfig(module_path="/x", fuel=None)
    with pytest.raises(wm.WasmError):
        wm.validate_config(cfg)


def test_rejects_sensitive_preopen():
    with pytest.raises(wm.WasmError):
        wm.generate_config("/x", preopened_dirs={"/e": "/etc"})


def test_wasmtime_args():
    cfg = wm.generate_config("/tmp/mod.wasm")
    args = wm.to_wasmtime_args(cfg)
    assert args[0] == "wasmtime"


def test_version_pin():
    assert wm.WASM_VERSION == "sandbox-wasm.v1"
