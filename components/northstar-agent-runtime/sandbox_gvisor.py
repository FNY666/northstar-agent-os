"""gVisor (runsc) config generator (config/policy layer only), Simulated.

Generates and validates gVisor runsc sandbox configurations:
platform selection, network stack, file access, capabilities.

Does NOT execute runsc.  Config/policy layer only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Module version.
GVISOR_VERSION = "sandbox-gvisor.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sandbox-gvisor.v1"


class GvisorError(Exception):
    """Fail-closed: invalid configs raise."""


@dataclass
class GvisorConfig:
    """runsc sandbox configuration."""

    # Platform: ptrace (universal) or kvm (faster, needs /dev/kvm).
    platform: str = "ptrace"
    # Network: none (isolated), host, or user (gVisor netstack).
    network: str = "none"
    # File access: host paths exposed into the sandbox.
    file_access: str = "shared"  # shared | exclusive
    allowed_paths: List[str] = field(default_factory=list)
    # Capabilities to drop (default: all).
    drop_caps: bool = True
    # Resource limits.
    memory_mb: int = 512
    cpu_count: int = 1
    # Debug/logging.
    debug: bool = False
    strace: bool = False


VALID_PLATFORMS = ("ptrace", "kvm")
VALID_NETWORKS = ("none", "host", "user")


def generate_config(
    allowed_paths: List[str] = None,
    *,
    network: str = "none",
    platform: str = "ptrace",
    **overrides: Any,
) -> GvisorConfig:
    """Generate a locked-down runsc config."""
    cfg = GvisorConfig(
        allowed_paths=list(allowed_paths or ["/workspace"]),
        network=network,
        platform=platform,
    )
    for key, value in overrides.items():
        if not hasattr(cfg, key):
            raise GvisorError(f"unknown config key '{key}'")
        setattr(cfg, key, value)
    validate_config(cfg)
    return cfg


def validate_config(cfg: GvisorConfig) -> None:
    """Validate.  Raises GvisorError."""
    if not isinstance(cfg, GvisorConfig):
        raise GvisorError("cfg must be GvisorConfig")
    if cfg.platform not in VALID_PLATFORMS:
        raise GvisorError(f"platform must be one of {VALID_PLATFORMS}")
    if cfg.network not in VALID_NETWORKS:
        raise GvisorError(f"network must be one of {VALID_NETWORKS}")
    if cfg.memory_mb <= 0 or cfg.memory_mb > 16384:
        raise GvisorError("memory_mb out of range")
    if cfg.cpu_count <= 0 or cfg.cpu_count > 64:
        raise GvisorError("cpu_count out of range")
    if cfg.network == "none" and not cfg.allowed_paths:
        raise GvisorError("isolated sandbox needs at least one allowed path")
    # Sensitive host paths must never be exposed writable.
    for path in cfg.allowed_paths:
        if path in ("/", "/etc", "/root", "/proc", "/sys"):
            raise GvisorError(f"sensitive path '{path}' must not be exposed")


def to_runsc_args(cfg: GvisorConfig) -> List[str]:
    """Render as runsc flags (not executed)."""
    validate_config(cfg)
    args = [
        "runsc", "do",
        f"--platform={cfg.platform}",
        f"--network={cfg.network}",
        f"--file-access={cfg.file_access}",
    ]
    for path in cfg.allowed_paths:
        args += ["--allowed-path", path]
    if cfg.drop_caps:
        args += ["--drop-caps"]
    if cfg.debug:
        args += ["--debug"]
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
    cfg = generate_config()
    assert cfg.network == "none"
    args = to_runsc_args(cfg)
    assert "--network=none" in args
    try:
        generate_config(allowed_paths=["/"])
        raise AssertionError("should raise")
    except GvisorError:
        pass
    assert stdlib_only()
    print("sandbox-gvisor OK")


if __name__ == "__main__":
    main()
