"""gVisor sandbox config tests."""

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


gv = _load("sandbox_gvisor")


def test_generate_defaults():
    cfg = gv.generate_config()
    assert cfg.network == "none"
    assert cfg.platform == "ptrace"
    assert cfg.drop_caps is True


def test_rejects_bad_platform():
    with pytest.raises(gv.GvisorError):
        gv.generate_config(platform="bogus")


def test_rejects_root_exposure():
    with pytest.raises(gv.GvisorError):
        gv.generate_config(allowed_paths=["/"])


def test_runsc_args():
    cfg = gv.generate_config()
    args = gv.to_runsc_args(cfg)
    assert args[0] == "runsc"
    assert "--network=none" in args


def test_version_pin():
    assert gv.GVISOR_VERSION == "sandbox-gvisor.v1"
