"""Docker sandbox config + seccomp profile (config/policy layer only), Simulated.

Generates and validates Docker run configurations and seccomp profiles.
Default: no-new-privileges, read-only rootfs, dropped capabilities,
custom seccomp profile, no network.

Does NOT run Docker.  Config/policy layer only.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Module version.
DOCKER_VERSION = "sandbox-docker.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sandbox-docker.v1"


class DockerError(Exception):
    """Fail-closed: invalid configs raise."""


# Minimal seccomp allowlist for code execution.
DEFAULT_SECCOMP_SYSCALLS = [
    "read", "write", "open", "openat", "close", "mmap", "mprotect",
    "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "exit",
    "exit_group", "arch_prctl", "set_tid_address", "set_robust_list",
    "futex", "getpid", "gettid", "clone", "wait4", "execve",
]


def generate_seccomp_profile(
    allowed_syscalls: List[str] = None,
) -> Dict[str, Any]:
    """Generate a default-deny seccomp profile."""
    allowed = allowed_syscalls or DEFAULT_SECCOMP_SYSCALLS
    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": ["SCMP_ARCH_X86_64"],
        "syscalls": [
            {
                "names": sorted(set(allowed)),
                "action": "SCMP_ACT_ALLOW",
            }
        ],
    }


@dataclass
class DockerConfig:
    """Docker run configuration."""

    image: str
    command: List[str] = field(default_factory=list)
    readonly_rootfs: bool = True
    no_new_privileges: bool = True
    drop_caps: List[str] = field(default_factory=lambda: ["ALL"])
    add_caps: List[str] = field(default_factory=list)
    network: str = "none"
    memory_mb: int = 512
    cpu_shares: int = 512
    pids_limit: int = 64
    volumes: List[Dict[str, str]] = field(default_factory=list)
    seccomp_profile: Dict[str, Any] = field(default_factory=dict)
    user: str = "65534:65534"  # nobody


def generate_config(
    image: str,
    command: List[str] = None,
    **overrides: Any,
) -> DockerConfig:
    """Generate a locked-down docker run config."""
    if not image:
        raise DockerError("image required")
    cfg = DockerConfig(image=image, command=list(command or []))
    cfg.seccomp_profile = generate_seccomp_profile()
    cfg.volumes = [{"src": "/workspace", "dst": "/workspace", "mode": "rw"}]
    for key, value in overrides.items():
        if not hasattr(cfg, key):
            raise DockerError(f"unknown config key '{key}'")
        setattr(cfg, key, value)
    validate_config(cfg)
    return cfg


def validate_config(cfg: DockerConfig) -> None:
    """Validate.  Raises DockerError."""
    if not isinstance(cfg, DockerConfig):
        raise DockerError("cfg must be DockerConfig")
    if not cfg.image:
        raise DockerError("image required")
    if cfg.network not in ("none", "bridge"):
        raise DockerError("network must be 'none' or 'bridge'")
    if "ALL" not in cfg.drop_caps and cfg.add_caps:
        raise DockerError("cannot add caps without dropping ALL first")
    if cfg.add_caps:
        raise DockerError("adding capabilities is not allowed")
    if cfg.memory_mb <= 0 or cfg.memory_mb > 16384:
        raise DockerError("memory_mb out of range")
    # Seccomp profile must be default-deny.
    profile = cfg.seccomp_profile
    if profile.get("defaultAction") != "SCMP_ACT_ERRNO":
        raise DockerError("seccomp profile must default-deny")
    # Volumes must not expose sensitive paths.
    for vol in cfg.volumes:
        if vol.get("dst") in ("/", "/etc", "/root"):
            raise DockerError(f"sensitive volume target '{vol.get('dst')}'")


def to_run_args(cfg: DockerConfig) -> List[str]:
    """Render as docker run args (not executed)."""
    validate_config(cfg)
    args = [
        "docker", "run", "--rm",
        "--read-only" if cfg.readonly_rootfs else "--read-write",
        f"--memory={cfg.memory_mb}m",
        f"--pids-limit={cfg.pids_limit}",
        f"--network={cfg.network}",
        f"--user={cfg.user}",
    ]
    if cfg.no_new_privileges:
        args += ["--security-opt", "no-new-privileges:true"]
    for cap in cfg.drop_caps:
        args += ["--cap-drop", cap]
    for vol in cfg.volumes:
        args += ["-v", f"{vol['src']}:{vol['dst']}:{vol.get('mode', 'ro')}"]
    args += [cfg.image] + cfg.command
    return args


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "json", "pathlib", "typing"}
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
    cfg = generate_config("python:3.12-slim", ["python", "-c", "print(1)"])
    assert cfg.no_new_privileges is True
    args = to_run_args(cfg)
    assert "--network=none" in args
    profile = generate_seccomp_profile()
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    try:
        bad = DockerConfig(image="x", add_caps=["SYS_ADMIN"])
        validate_config(bad)
        raise AssertionError("should raise")
    except DockerError:
        pass
    assert stdlib_only()
    print("sandbox-docker OK")


if __name__ == "__main__":
    main()
