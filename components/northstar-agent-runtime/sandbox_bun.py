"""Bun permission model config (config/policy layer only), Simulated.

Generates and validates Bun runtime permission configurations.
Bun's permission model: explicit grants for fs/network/process.

Default: deny-all, explicit allowlist only.

Does NOT execute Bun.  Config/policy layer only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Module version.
BUN_VERSION = "sandbox-bun.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sandbox-bun.v1"


class BunError(Exception):
    """Fail-closed: invalid configs raise."""


@dataclass
class BunConfig:
    """Bun permission configuration."""

    script: str
    # Filesystem.
    allow_fs_read: List[str] = field(default_factory=list)
    allow_fs_write: List[str] = field(default_factory=list)
    # Network.
    allow_net: List[str] = field(default_factory=list)
    # Process spawning.
    allow_spawn: List[str] = field(default_factory=list)
    # Environment variables.
    allow_env: List[str] = field(default_factory=list)


def generate_config(
    script: str,
    *,
    allow_fs_read: List[str] = None,
    **overrides: Any,
) -> BunConfig:
    """Generate a deny-by-default Bun config."""
    if not script:
        raise BunError("script required")
    cfg = BunConfig(
        script=script,
        allow_fs_read=list(allow_fs_read or ["/workspace"]),
    )
    for key, value in overrides.items():
        if not hasattr(cfg, key):
            raise BunError(f"unknown config key '{key}'")
        setattr(cfg, key, value)
    validate_config(cfg)
    return cfg


def validate_config(cfg: BunConfig) -> None:
    """Validate.  Raises BunError."""
    if not isinstance(cfg, BunConfig):
        raise BunError("cfg must be BunConfig")
    if not cfg.script:
        raise BunError("script required")
    for path in cfg.allow_fs_write:
        if path in ("/", "/etc", "/root"):
            raise BunError(f"sensitive path '{path}' in allow_fs_write")
    # Spawn allowlist must be explicit binaries, not shells.
    for binary in cfg.allow_spawn:
        if binary in ("sh", "bash", "zsh", "/bin/sh"):
            raise BunError(f"shell '{binary}' must not be in allow_spawn")


def to_bun_args(cfg: BunConfig) -> List[str]:
    """Render as bun run permission flags (not executed)."""
    validate_config(cfg)
    args = ["bun", "run"]
    if cfg.allow_fs_read:
        args.append(f"--allow-fs-read={','.join(cfg.allow_fs_read)}")
    else:
        args.append("--deny-fs-read")
    if cfg.allow_fs_write:
        args.append(f"--allow-fs-write={','.join(cfg.allow_fs_write)}")
    else:
        args.append("--deny-fs-write")
    if cfg.allow_net:
        args.append(f"--allow-net={','.join(cfg.allow_net)}")
    else:
        args.append("--deny-net")
    if cfg.allow_spawn:
        args.append(f"--allow-spawn={','.join(cfg.allow_spawn)}")
    else:
        args.append("--deny-spawn")
    args.append(cfg.script)
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
    cfg = generate_config("/workspace/app.ts")
    args = to_bun_args(cfg)
    assert "--deny-net" in args
    assert "--deny-spawn" in args
    try:
        bad = BunConfig(script="/x", allow_spawn=["sh"])
        validate_config(bad)
        raise AssertionError("should raise")
    except BunError:
        pass
    assert stdlib_only()
    print("sandbox-bun OK")


if __name__ == "__main__":
    main()
