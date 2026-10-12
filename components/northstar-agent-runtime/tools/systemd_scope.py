"""Root-managed systemd scopes for aggregate Shell process-tree limits.

Northstar deliberately does not create a writable delegated cgroup next to an
untrusted command: the command would share the runtime UID and could loosen its
own limits. A system-manager-owned transient scope keeps cgroup control files
outside the workload's write authority. This module builds the command and
performs bounded cleanup; it never falls back to process-local rlimits.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
import sys
import uuid
from typing import Sequence


class SystemdScopeError(RuntimeError):
    """The requested aggregate resource boundary cannot be established."""


_SCOPE_NAME = re.compile(r"northstar-[0-9a-f]{32}\.scope\Z")


def validate_systemd_scope_host() -> None:
    """Refuse hosts without the protected system cgroup-v2 control plane."""
    if not sys.platform.startswith("linux"):
        raise SystemdScopeError("aggregate Shell limits require Linux cgroup v2")
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        raise SystemdScopeError("aggregate systemd scopes require a non-root runtime")
    if not shutil.which("systemd-run") or not shutil.which("systemctl"):
        raise SystemdScopeError("aggregate Shell limits require systemd-run and systemctl")
    controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    try:
        available = set(controllers.read_text(encoding="ascii").split())
    except OSError as error:
        raise SystemdScopeError("aggregate Shell limits require a visible cgroup-v2 hierarchy") from error
    missing = {"cpu", "memory", "pids"} - available
    if missing:
        raise SystemdScopeError(
            "aggregate Shell limits require cgroup-v2 cpu, memory, and pids controllers "
            f"(missing: {', '.join(sorted(missing))})"
        )


def systemd_scope_argv(
    argv: Sequence[str],
    *,
    memory_max_bytes: int,
    tasks_max: int,
    systemd_run: str | None = None,
    unit_name: str | None = None,
) -> tuple[tuple[str, ...], str]:
    """Wrap argv in a PID-1-owned scope with aggregate memory/task/CPU limits."""
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise SystemdScopeError("systemd scope command must be a non-empty argv")
    if isinstance(memory_max_bytes, bool) or not isinstance(memory_max_bytes, int) or memory_max_bytes < 1:
        raise SystemdScopeError("systemd scope MemoryMax must be a positive integer")
    if isinstance(tasks_max, bool) or not isinstance(tasks_max, int) or tasks_max < 1:
        raise SystemdScopeError("systemd scope TasksMax must be a positive integer")
    validate_systemd_scope_host()
    manager = systemd_run or shutil.which("systemd-run")
    assert manager is not None
    name = unit_name or f"northstar-{uuid.uuid4().hex}.scope"
    if not _SCOPE_NAME.fullmatch(name):
        raise SystemdScopeError("invalid generated systemd scope unit name")
    command = (
        manager,
        "--scope",
        "--pipe",
        "--quiet",
        f"--unit={name}",
        f"--property=MemoryMax={memory_max_bytes}",
        f"--property=TasksMax={tasks_max}",
        "--property=CPUQuota=100%",
        "--",
        *argv,
    )
    return command, name


def cleanup_systemd_scope(
    unit_name: str,
    *,
    systemctl: str | None = None,
    timeout_seconds: float = 2.0,
) -> tuple[bool, str]:
    """Kill all scope members and wait for systemd to deactivate the scope.

    A completed command can leave a detached descendant behind. The manager
    owns the scope lifetime, so cleanup targets the whole cgroup rather than
    relying on process-group membership. Missing/inactive units mean the scope
    already has no workload and are successful cleanup outcomes.
    """
    if not _SCOPE_NAME.fullmatch(unit_name):
        return False, "refused unsafe systemd unit name during cleanup"
    manager = systemctl or shutil.which("systemctl")
    if not manager:
        return False, "systemctl unavailable; aggregate scope descendants may remain"
    kill_error = ""
    try:
        kill = subprocess.run(
            [manager, "kill", "--kill-whom=all", "--signal=SIGKILL", unit_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        kill = None
        kill_error = f"scope kill request failed ({type(error).__name__})"
    try:
        stop = subprocess.run(
            [manager, "stop", unit_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, f"systemd scope cleanup failed: {type(error).__name__}; descendants may remain"
    if stop.returncode == 0:
        return True, ""
    try:
        state = subprocess.run(
            [manager, "is-active", unit_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, f"cannot confirm systemd scope teardown: {type(error).__name__}; descendants may remain"
    if state.returncode != 0:
        return True, ""  # already inactive/collected after the command exited
    detail = "systemd scope cleanup failed; workload may still have descendants"
    if kill is None or kill.returncode != 0:
        detail += "; scope kill request also failed"
    if kill_error:
        detail += f" ({kill_error})"
    return False, detail


__all__ = [
    "SystemdScopeError",
    "cleanup_systemd_scope",
    "systemd_scope_argv",
    "validate_systemd_scope_host",
]
