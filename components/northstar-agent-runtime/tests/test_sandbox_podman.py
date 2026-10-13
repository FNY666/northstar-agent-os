"""Podman sandbox config tests."""

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


pm = _load("sandbox_podman")


def test_generate_defaults():
    cfg = pm.generate_config("python:3.12-slim")
    assert cfg.rootless is True
    assert cfg.privileged is False
    assert cfg.userns == "auto"


def test_rejects_userns_host():
    cfg = pm.PodmanConfig(image="x", userns="host")
    with pytest.raises(pm.PodmanError):
        pm.validate_config(cfg)


def test_rejects_privileged():
    cfg = pm.PodmanConfig(image="x")
    cfg.privileged = True  # bypass generate_config enforcement
    with pytest.raises(pm.PodmanError):
        pm.validate_config(cfg)


def test_podman_args():
    cfg = pm.generate_config("python:3.12-slim")
    args = pm.to_podman_args(cfg)
    assert args[0] == "podman"
    assert "--network=none" in args


def test_version_pin():
    assert pm.PODMAN_VERSION == "sandbox-podman.v1"
