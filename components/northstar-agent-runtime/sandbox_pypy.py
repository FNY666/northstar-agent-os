"""PyPy sandbox policy file generator (config/policy layer only), Simulated.

Generates and validates PyPy sandbox policy configurations:
virtualized filesystem layout, allowed host paths, resource limits,
included/excluded modules.

Does NOT run PyPy.  Config/policy layer only.

The PyPy sandbox runs untrusted code in a fully virtualized process;
this module generates the policy that controls what the virtualized
process may access.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Module version.
PYPY_VERSION = "sandbox-pypy.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sandbox-pypy.v1"


class PypyError(Exception):
    """Fail-closed: invalid configs raise."""


@dataclass
class PypySandboxConfig:
    """PyPy sandbox policy configuration."""

    script_path: str
    # Virtual filesystem: guest path -> host path (read-only unless noted).
    vfs_mounts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # Temp dir inside sandbox.
    tmp_dir: str = "/tmp"
    # Environment variables exposed.
    env: Dict[str, str] = field(default_factory=dict)
    # Resource limits.
    timeout_sec: int = 30
    memory_mb: int = 256
    # Modules allowed in the sandbox (default: minimal).
    allowed_modules: List[str] = field(
        default_factory=lambda: ["math", "json", "re"]
    )


def generate_config(
    script_path: str,
    *,
    workspace: str = "/workspace",
    **overrides: Any,
) -> PypySandboxConfig:
    """Generate a locked-down PyPy sandbox policy."""
    if not script_path:
        raise PypyError("script_path required")
    cfg = PypySandboxConfig(script_path=script_path)
    cfg.vfs_mounts = {
        "/workspace": {"host": workspace, "mode": "rw"},
        "/tmp": {"host": "/tmp/pypy-sandbox", "mode": "rw"},
        "/lib": {"host": "/usr/lib/pypy", "mode": "ro"},
    }
    cfg.env = {"PATH": "/usr/bin", "HOME": "/tmp"}
    for key, value in overrides.items():
        if not hasattr(cfg, key):
            raise PypyError(f"unknown config key '{key}'")
        setattr(cfg, key, value)
    validate_config(cfg)
    return cfg


def validate_config(cfg: PypySandboxConfig) -> None:
    """Validate.  Raises PypyError."""
    if not isinstance(cfg, PypySandboxConfig):
        raise PypyError("cfg must be PypySandboxConfig")
    if not cfg.script_path:
        raise PypyError("script_path required")
    if cfg.timeout_sec <= 0 or cfg.timeout_sec > 3600:
        raise PypyError("timeout_sec out of range")
    if cfg.memory_mb <= 0 or cfg.memory_mb > 4096:
        raise PypyError("memory_mb out of range")
    # Host paths in mounts must not be sensitive.
    for guest, spec in cfg.vfs_mounts.items():
        host = str(spec.get("host", ""))
        if host in ("/", "/etc", "/root", "/proc", "/sys"):
            raise PypyError(f"sensitive host path '{host}' in vfs_mounts")
        if spec.get("mode") not in ("ro", "rw"):
            raise PypyError(f"mount mode must be ro/rw, got '{spec.get('mode')}'")
        if ".." in host:
            raise PypyError("path traversal in vfs_mounts")
    # Dangerous modules must not be allowed.
    for mod in cfg.allowed_modules:
        if mod in ("os", "sys", "subprocess", "socket", "ctypes"):
            raise PypyError(f"dangerous module '{mod}' in allowed_modules")


def to_policy_dict(cfg: PypySandboxConfig) -> Dict[str, Any]:
    """Render as a policy dict (for the sandbox controller)."""
    validate_config(cfg)
    return {
        "script": cfg.script_path,
        "vfs": cfg.vfs_mounts,
        "tmp": cfg.tmp_dir,
        "env": cfg.env,
        "limits": {
            "timeout_sec": cfg.timeout_sec,
            "memory_mb": cfg.memory_mb,
        },
        "allowed_modules": sorted(cfg.allowed_modules),
    }


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
    cfg = generate_config("/workspace/run.py")
    policy = to_policy_dict(cfg)
    assert policy["limits"]["timeout_sec"] == 30
    try:
        bad = PypySandboxConfig(
            script_path="/x", allowed_modules=["os"]
        )
        validate_config(bad)
        raise AssertionError("should raise")
    except PypyError:
        pass
    assert stdlib_only()
    print("sandbox-pypy OK")


if __name__ == "__main__":
    main()
