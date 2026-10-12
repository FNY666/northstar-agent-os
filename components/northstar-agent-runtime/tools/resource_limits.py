"""Per-process resource ceilings for Shell child processes.

This deliberately uses a tiny exec launcher instead of ``Popen(preexec_fn=...)``:
the runtime can be multithreaded, and Python documents preexec hooks as unsafe in
that setting. Limits are inherited across exec and tightened against any limits
already imposed by the parent. File-descriptor and core-dump limits reduce
descriptor exhaustion and persistence of secrets from process memory. Limits
are per process, not aggregate process-tree or filesystem quotas; callers must
not report them as cgroup enforcement.
"""
from __future__ import annotations

import base64
import json
import sys
from typing import Mapping, Sequence

MAX_OPEN_FILES = 256


_LOADER = r'''
import base64, json, os, sys
try:
    import resource
    limits = json.loads(base64.b64decode(sys.argv[1]))
    targets = {
        "cpu_seconds": resource.RLIMIT_CPU,
        "memory_bytes": resource.RLIMIT_AS,
        "file_size_bytes": resource.RLIMIT_FSIZE,
        "open_files": resource.RLIMIT_NOFILE,
    }
    for name, resource_id in targets.items():
        requested = limits[name]
        soft, hard = resource.getrlimit(resource_id)
        infinity = resource.RLIM_INFINITY
        hard_cap = requested if hard == infinity else min(hard, requested)
        soft_cap = requested if soft == infinity else min(soft, requested)
        resource.setrlimit(resource_id, (min(soft_cap, hard_cap), hard_cap))
    # Core dumps can persist credentials and prompt data from process memory.
    # Zero is always tighter than the inherited hard limit.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.execvp(sys.argv[2], sys.argv[2:])
except Exception as error:
    print("northstar resource limit setup failed: " + str(error), file=sys.stderr)
    raise SystemExit(126)
'''


def resource_limits_loader_argv(
    argv: Sequence[str],
    limits: Mapping[str, int],
    *,
    python: str | None = None,
) -> tuple[str, ...]:
    """Return an exec wrapper applying CPU, address-space and file-size caps."""
    expected = {"cpu_seconds", "memory_bytes", "file_size_bytes", "open_files"}
    if set(limits) != expected:
        raise ValueError("resource limits must define CPU, memory, and file-size ceilings")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in limits.values()):
        raise ValueError("resource limits must be positive integers")
    encoded = base64.b64encode(
        json.dumps(dict(limits), sort_keys=True, separators=(",", ":")).encode("ascii")
    ).decode("ascii")
    return (python or sys.executable, "-c", _LOADER, encoded, *argv)


__all__ = ["resource_limits_loader_argv"]
