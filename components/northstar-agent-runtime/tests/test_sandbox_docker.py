"""Docker sandbox config tests."""

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


dk = _load("sandbox_docker")


def test_generate_defaults():
    cfg = dk.generate_config("python:3.12-slim")
    assert cfg.network == "none"
    assert cfg.no_new_privileges is True
    assert cfg.readonly_rootfs is True


def test_seccomp_default_deny():
    profile = dk.generate_seccomp_profile()
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"


def test_rejects_added_caps():
    cfg = dk.DockerConfig(image="x", add_caps=["SYS_ADMIN"])
    with pytest.raises(dk.DockerError):
        dk.validate_config(cfg)


def test_rejects_sensitive_volume():
    cfg = dk.DockerConfig(
        image="x",
        volumes=[{"src": "/etc", "dst": "/etc", "mode": "rw"}],
        seccomp_profile=dk.generate_seccomp_profile(),
    )
    with pytest.raises(dk.DockerError):
        dk.validate_config(cfg)


def test_run_args():
    cfg = dk.generate_config("python:3.12-slim", ["echo", "hi"])
    args = dk.to_run_args(cfg)
    assert args[0] == "docker"
    assert "--network=none" in args


def test_version_pin():
    assert dk.DOCKER_VERSION == "sandbox-docker.v1"
