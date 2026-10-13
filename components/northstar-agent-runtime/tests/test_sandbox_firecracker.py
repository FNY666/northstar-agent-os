"""Firecracker sandbox config tests."""

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


fc = _load("sandbox_firecracker")


def test_generate_defaults():
    cfg = fc.generate_config("/opt/fc/rootfs.ext4")
    assert cfg.drives[0].is_read_only is True
    assert cfg.enable_networking is False


def test_rejects_writable_root():
    cfg = fc.FirecrackerConfig()
    cfg.drives = [fc.DriveConfig("r", "/x", is_root_device=True, is_read_only=False)]
    with pytest.raises(fc.FirecrackerError):
        fc.validate_config(cfg)


def test_network_consistency():
    cfg = fc.FirecrackerConfig()
    cfg.drives = [fc.DriveConfig("r", "/x", is_root_device=True, is_read_only=True)]
    cfg.enable_networking = True  # no interfaces
    with pytest.raises(fc.FirecrackerError):
        fc.validate_config(cfg)


def test_api_payload():
    cfg = fc.generate_config("/opt/fc/rootfs.ext4")
    payload = fc.to_api_payload(cfg)
    assert "machine-config" in payload
    assert "boot-source" in payload


def test_version_pin():
    assert fc.FIRECRACKER_VERSION == "sandbox-firecracker.v1"
