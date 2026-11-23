"""Deno permission flags config (config/policy layer only), Simulated.

Generates and validates Deno runtime permission flags:
--allow-read, --allow-write, --allow-net, --allow-run, --allow-env, etc.

Deny takes precedence.  Default: deny-all, explicit allowlist only.

Does NOT execute Deno.  Config/policy layer only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Module version.
DENO_VERSION = "sandbox-deno.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sandbox-deno.v1"


class DenoError(Exception):
    """Fail-closed: invalid configs raise."""


# Deno permission categories.
PERM_CATEGORIES = (
    "read", "write", "net", "run", "env", "sys", "ffi",
)


@dataclass
class DenoConfig:
    """Deno permission configuration."""

    script: str
    # Per-category allowlists.  Empty = denied.
    allow_read: List[str] = field(default_factory=list)
    allow_write: List[str] = field(default_factory=list)
    allow_net: List[str] = field(default_factory=list)
    allow_run: List[str] = field(default_factory=list)
    allow_env: List[str] = field(default_factory=list)
    allow_sys: List[str] = field(default_factory=list)
    allow_ffi: List[str] = field(default_factory=list)
    # Explicit denies (take precedence).
    deny_read: List[str] = field(default_factory=list)
    deny_write: List[str] = field(default_factory=list)
    deny_net: List[str] = field(default_factory=list)


def generate_config(
    script: str,
    *,
    allow_read: List[str] = None,
    **overrides: Any,
) -> DenoConfig:
    """Generate a deny-by-default Deno config."""
    if not script:
        raise DenoError("script required")
    cfg = DenoConfig(
        script=script,
        allow_read=list(allow_read or ["/workspace"]),
    )
    for key, value in overrides.items():
        if not hasattr(cfg, key):
            raise DenoError(f"unknown config key '{key}'")
        setattr(cfg, key, value)
    validate_config(cfg)
    return cfg


def validate_config(cfg: DenoConfig) -> None:
    """Validate.  Raises DenoError."""
    if not isinstance(cfg, DenoConfig):
        raise DenoError("cfg must be DenoConfig")
    if not cfg.script:
        raise DenoError("script required")
    # Deny must not overlap allow for the same category.
    for cat in ("read", "write", "net"):
        allow = set(getattr(cfg, f"allow_{cat}"))
        deny = set(getattr(cfg, f"deny_{cat}"))
        if allow & deny:
            raise DenoError(f"allow_{cat} and deny_{cat} overlap")
    # Sensitive paths must never be in allow_write.
    for path in cfg.allow_write:
        if path in ("/", "/etc", "/root"):
            raise DenoError(f"sensitive path '{path}' in allow_write")


def to_deno_args(cfg: DenoConfig) -> List[str]:
    """Render as deno run flags (not executed)."""
    validate_config(cfg)
    args = ["deno", "run"]
    mapping = {
        "allow_read": "--allow-read",
        "allow_write": "--allow-write",
        "allow_net": "--allow-net",
        "allow_run": "--allow-run",
        "allow_env": "--allow-env",
        "allow_sys": "--allow-sys",
        "allow_ffi": "--allow-ffi",
        "deny_read": "--deny-read",
        "deny_write": "--deny-write",
        "deny_net": "--deny-net",
    }
    for attr, flag in mapping.items():
        values = getattr(cfg, attr)
        if values:
            args.append(f"{flag}={','.join(values)}")
        elif attr.startswith("allow_"):
            args.append(f"{flag}=none")  # explicit deny-all marker
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
    cfg = generate_config("/workspace/main.ts")
    args = to_deno_args(cfg)
    assert "--allow-net=none" in args
    assert "--allow-read=/workspace" in args
    try:
        bad = DenoConfig(script="/x", allow_read=["/a"], deny_read=["/a"])
        validate_config(bad)
        raise AssertionError("should raise")
    except DenoError:
        pass
    assert stdlib_only()
    print("sandbox-deno OK")


if __name__ == "__main__":
    main()
