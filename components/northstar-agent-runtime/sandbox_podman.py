"""Podman rootless sandbox config (config/policy layer only), Simulated.

Generates and validates Podman rootless container configurations.
Rootless by default: user namespaces, no daemon, no-new-privileges.

Does NOT run Podman.  Config/policy layer only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Module version.
PODMAN_VERSION = "sandbox-podman.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sandbox-podman.v1"


class PodmanError(Exception):
    """Fail-closed: invalid configs raise."""


@dataclass
class PodmanConfig:
    """Podman run configuration (rootless)."""

    image: str
    command: List[str] = field(default_factory=list)
    # Rootless: always true (enforced).
    rootless: bool = True
    userns: str = "auto"  # auto | keep-id | host
    no_new_privileges: bool = True
    readonly_rootfs: bool = True
    network: str = "none"
    memory_mb: int = 512
    pids_limit: int = 64
    volumes: List[Dict[str, str]] = field(default_factory=list)
    seccomp: str = "default"
    # No privileged, no host pid/ipc.
    privileged: bool = False
    host_pid: bool = False
    host_ipc: bool = False


def generate_config(
    image: str,
    command: List[str] = None,
    **overrides: Any,
) -> PodmanConfig:
    """Generate a locked-down rootless podman config."""
    if not image:
        raise PodmanError("image required")
    cfg = PodmanConfig(image=image, command=list(command or []))
    cfg.volumes = [{"src": "/workspace", "dst": "/workspace", "mode": "rw"}]
    for key, value in overrides.items():
        if not hasattr(cfg, key):
            raise PodmanError(f"unknown config key '{key}'")
        setattr(cfg, key, value)
    # Enforce rootless invariants.
    cfg.rootless = True
    cfg.privileged = False
    cfg.host_pid = False
    cfg.host_ipc = False
    validate_config(cfg)
    return cfg


def validate_config(cfg: PodmanConfig) -> None:
    """Validate.  Raises PodmanError."""
    if not isinstance(cfg, PodmanConfig):
        raise PodmanError("cfg must be PodmanConfig")
    if not cfg.rootless:
        raise PodmanError("rootless is mandatory")
    if cfg.privileged:
        raise PodmanError("privileged is forbidden")
    if cfg.host_pid or cfg.host_ipc:
        raise PodmanError("host pid/ipc namespaces forbidden")
    if cfg.userns not in ("auto", "keep-id", "host"):
        raise PodmanError("userns must be auto, keep-id, or host")
    if cfg.userns == "host":
        raise PodmanError("userns=host defeats rootless isolation")
    if not cfg.image:
        raise PodmanError("image required")
    if cfg.network not in ("none", "slirp4netns"):
        raise PodmanError("network must be 'none' or 'slirp4netns'")
    if cfg.memory_mb <= 0 or cfg.memory_mb > 16384:
        raise PodmanError("memory_mb out of range")
    for vol in cfg.volumes:
        if vol.get("dst") in ("/", "/etc", "/root"):
            raise PodmanError(f"sensitive volume target '{vol.get('dst')}'")


def to_podman_args(cfg: PodmanConfig) -> List[str]:
    """Render as podman run args (not executed)."""
    validate_config(cfg)
    args = [
        "podman", "run", "--rm",
        f"--userns={cfg.userns}",
        "--read-only" if cfg.readonly_rootfs else "--read-write",
        f"--memory={cfg.memory_mb}m",
        f"--pids-limit={cfg.pids_limit}",
        f"--network={cfg.network}",
    ]
    if cfg.no_new_privileges:
        args += ["--security-opt", "no-new-privileges"]
    args += ["--security-opt", f"seccomp={cfg.seccomp}"]
    for vol in cfg.volumes:
        args += ["-v", f"{vol['src']}:{vol['dst']}:{vol.get('mode', 'ro')}"]
    args += [cfg.image] + cfg.command
    return args


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    cfg = generate_config("python:3.12-slim")
    assert cfg.rootless is True
    args = to_podman_args(cfg)
    assert "--userns=auto" in args
    try:
        bad = PodmanConfig(image="x", userns="host")
        validate_config(bad)
        raise AssertionError("should raise")
    except PodmanError:
        pass
    assert stdlib_only()
    print("sandbox-podman OK")


if __name__ == "__main__":
    main()
