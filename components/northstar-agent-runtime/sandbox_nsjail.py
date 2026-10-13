"""nsjail config generator (config/policy layer only), Simulated.

Generates and validates nsjail sandbox configurations:
seccomp filters, namespaces, mounts, rlimits, env controls.

Does NOT execute nsjail.  Config/policy layer only.

What this IS: safe config generation for nsjail-based code execution.

What this IS NOT:
* Not a sandbox runner -- no subprocess, no nsjail invocation.
* Seccomp policy is expressed as nsjail Kafel policy text.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Module version.
NSJAIL_VERSION = "sandbox-nsjail.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sandbox-nsjail.v1"


class NsjailError(Exception):
    """Fail-closed: invalid configs raise."""


@dataclass
class NsjailConfig:
    """nsjail sandbox configuration."""

    # Execution.
    binary: str
    args: List[str] = field(default_factory=list)
    # Isolation.
    mode: str = "o"  # o=once, l=listening
    hostname: str = "sandbox"
    cwd: str = "/workspace"
    # Mounts: list of (src, dst, readonly).
    mounts: List[Dict[str, Any]] = field(default_factory=list)
    # Env: explicit allowlist only.
    env_allow: List[str] = field(default_factory=list)
    env_deny_all: bool = True
    # Resource limits.
    rlimit_cpu: int = 30  # seconds
    rlimit_as_mb: int = 512  # address space MB
    rlimit_fsize_mb: int = 64
    rlimit_nofile: int = 64
    time_limit_sec: int = 60
    # Network.
    disable_clone_newnet: bool = False  # False = new net namespace (isolated)
    # Seccomp.
    seccomp_policy: str = "default"
    skip_setsid: bool = False


# Kafel policy templates (nsjail --seccomp_string).
KAFEL_POLICIES = {
    "default": "POLICY nsjail_default { ALLOW { read, write, open, openat, close, mmap, mprotect, brk, rt_sigaction, rt_sigprocmask, exit, exit_group, arch_prctl, set_tid_address, set_robust_list, futex, getpid, gettid } }",
    "strict": "POLICY nsjail_strict { ALLOW { read, write, openat, close, mmap, mprotect, brk, exit, exit_group, futex } }",
}


def generate_config(
    binary: str,
    args: List[str] = None,
    *,
    readonly_root: bool = True,
    workspace: str = "/workspace",
    **overrides: Any,
) -> NsjailConfig:
    """Generate a locked-down nsjail config.

    Defaults: no network, readonly root, only workspace writable,
    no env passthrough, strict rlimits.
    """
    if not binary or not isinstance(binary, str):
        raise NsjailError("binary required")
    cfg = NsjailConfig(binary=binary, args=list(args or []))
    mounts = [
        {"src": "/", "dst": "/", "readonly": readonly_root},
        {"src": workspace, "dst": workspace, "readonly": False},
        {"src": "/tmp", "dst": "/tmp", "readonly": False, "tmpfs": True},
    ]
    cfg.mounts = mounts
    for key, value in overrides.items():
        if not hasattr(cfg, key):
            raise NsjailError(f"unknown config key '{key}'")
        setattr(cfg, key, value)
    validate_config(cfg)
    return cfg


def validate_config(cfg: NsjailConfig) -> None:
    """Validate a config.  Raises NsjailError on any problem."""
    if not isinstance(cfg, NsjailConfig):
        raise NsjailError("cfg must be NsjailConfig")
    if not cfg.binary:
        raise NsjailError("binary required")
    if cfg.mode not in ("o", "l"):
        raise NsjailError("mode must be 'o' or 'l'")
    if cfg.rlimit_cpu <= 0 or cfg.rlimit_cpu > 3600:
        raise NsjailError("rlimit_cpu out of range")
    if cfg.rlimit_as_mb <= 0 or cfg.rlimit_as_mb > 16384:
        raise NsjailError("rlimit_as_mb out of range")
    if cfg.time_limit_sec <= 0 or cfg.time_limit_sec > 3600:
        raise NsjailError("time_limit_sec out of range")
    if cfg.seccomp_policy not in KAFEL_POLICIES:
        raise NsjailError(f"unknown seccomp_policy '{cfg.seccomp_policy}'")
    # Writable mounts must not include sensitive paths.
    sensitive = ("/etc", "/root", "/home", "/proc", "/sys")
    for mnt in cfg.mounts:
        dst = str(mnt.get("dst", ""))
        if not mnt.get("readonly", True) and dst in sensitive:
            raise NsjailError(f"writable mount on sensitive path '{dst}'")
    if not cfg.env_deny_all and not cfg.env_allow:
        raise NsjailError("env passthrough requires explicit allowlist")


def to_cmdline(cfg: NsjailConfig) -> List[str]:
    """Render config as nsjail command-line args (not executed)."""
    validate_config(cfg)
    cmd = ["nsjail", "-Mo", f"--hostname={cfg.hostname}", f"--cwd={cfg.cwd}"]
    for mnt in cfg.mounts:
        flag = "-R" if mnt.get("readonly") else "-B"
        cmd += [flag, f"{mnt['src']}:{mnt['dst']}"]
    if cfg.env_deny_all:
        cmd += ["--env", "*"]  # nsjail: clear env (placeholder form)
    for var in cfg.env_allow:
        cmd += ["--keep_env", var]
    cmd += [
        f"--rlimit_cpu={cfg.rlimit_cpu}",
        f"--rlimit_as={cfg.rlimit_as_mb * 1024 * 1024}",
        f"--rlimit_fsize={cfg.rlimit_fsize_mb * 1024 * 1024}",
        f"--rlimit_nofile={cfg.rlimit_nofile}",
        f"--time_limit={cfg.time_limit_sec}",
        "--seccomp_string", KAFEL_POLICIES[cfg.seccomp_policy],
        "--", cfg.binary,
    ] + cfg.args
    return cmd


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
    cfg = generate_config("/usr/bin/python3", ["-c", "print(1)"])
    assert cfg.env_deny_all is True
    cmd = to_cmdline(cfg)
    assert "nsjail" in cmd[0]
    try:
        bad = NsjailConfig(binary="/bin/sh")
        bad.mounts = [{"src": "/", "dst": "/etc", "readonly": False}]
        validate_config(bad)
        raise AssertionError("should raise")
    except NsjailError:
        pass
    assert stdlib_only()
    print("sandbox-nsjail OK")


if __name__ == "__main__":
    main()
