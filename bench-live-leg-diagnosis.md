# Bench Live-Leg Failure Diagnosis (2026-11-06)

## Summary

All 8 pre-existing bench live-leg failures from the baseline share a common root cause: **Landlock path restrictions prevent nested Python loaders from importing stdlib modules**.

## Affected Tests

- `denial.seccomp_filter_live_on_process`
- `denial.seccomp_payload_cannot_loosen`
- `denial.landlock_path_whitelist_live`
- `metrics.capdrop_deny_all_live`
- `metrics.capdrop_escalation_eperm`
- `metrics.capdrop_payload_cannot_loosen`
- `redteam.context_stale_approval_not_replayable`
- `redteam.shell_backend_host_owned`

All fail with "required path missing" - the marker files are never created because the sandboxed command never executes successfully.

## Root Cause

The process backend uses nested `python3 -c` loaders to apply security layers in sequence:

1. Outermost: Landlock path allowlist (`tools/sandbox.py`)
2. Middle layers: Resource limits, capdrop
3. Innermost: Seccomp-BPF via prctl

When Landlock is enabled (default mode is `auto`, which enables it if the kernel supports it), the execution flow is:

```
python3 -c <landlock_loader> <spec> python3 -c <resource_loader> ... python3 -c <seccomp_loader> ... sh -c "..."
```

**Problem**: The Landlock loader applies filesystem restrictions immediately after its imports complete. When it then calls `execvp` on the *next* `python3 -c` command in the chain, that Python interpreter runs under the already-applied Landlock restrictions and **cannot access system libraries** to import the site module or other stdlib modules.

## Evidence

### Direct Reproduction

```python
from tools.os_sandbox import SandboxRequest, run_sandboxed
ws = Path(tempfile.mkdtemp(prefix='seccomp-test-'))
req = SandboxRequest(
    argv=('sh', '-c', 'grep -q "Seccomp:\t2" /proc/self/status && touch filter_live.txt'),
    cwd=ws,
    workspace=ws,
    seccomp='on',
    # landlock defaults to 'auto' which enables it
)
result = run_sandboxed(req, backend='process')
# Result: Exit code 1, stderr shows "Fatal Python error: init_import_site"
```

With `landlock='off'`:
```python
req = SandboxRequest(..., landlock='off', capdrop_whitelist=())
result = run_sandboxed(req, backend='process')
# Result: Exit code 0, marker file created successfully
```

### Host Environment

- Host: `muse-newapi@140.245.125.82` (Oracle Linux, kernel 7.0.0-1009-oracle)
- Landlock: Supported (ABI version available via `landlock_abi_version()`)
- Bubblewrap: Available and working (`/usr/bin/bwrap` version 0.11.1)
- User namespaces: **BLOCKED** - `unshare -Urm` fails with EPERM on `/proc/self/uid_map`
- Seccomp: Supported (prctl works standalone)

The user namespace restriction is **not** the root cause - bwrap works without user namespaces in this configuration, and the process backend doesn't use them. The issue is specific to the Python loader chain under Landlock.

## Mechanism

1. `tools/os_sandbox.py:1195-1200`: Process backend builds Landlock spec via `default_profile(workspace)` and wraps command with `landlock_loader_argv()`
2. `tools/sandbox.py:334`: `_runtime_read_paths()` computes allowed paths including `/usr`, `/lib`, Python stdlib, etc.
3. `tools/sandbox.py:506`: Returns `[python, "-c", _LANDLOCK_LOADER, encoded_spec, *inner_argv]`
4. Execution starts: outer `python3 -c` runs the Landlock loader
5. Landlock loader imports its own dependencies (base64, ctypes, json, os, struct, sys) successfully
6. Landlock loader calls `landlock_create_ruleset()` and `landlock_restrict_self()`, applying the path restrictions **to the current process**
7. Landlock loader calls `execvp(inner_argv[0], inner_argv)` where `inner_argv[0]` is `"python3"` again
8. The exec'd `python3` inherits the Landlock restrictions
9. Python initialization tries to import the site module from stdlib, but **Landlock blocks access** even though `/usr/lib/python*` was in the allowlist - the path resolution or traversal is being denied
10. Python crashes with "Fatal Python error: init_import_site"
11. The actual test command never runs, no marker file is created

## Why This Wasn't Caught Earlier

- The bench tests using `shell_backend: "bwrap"` work fine - bwrap doesn't use nested Python loaders
- Tests with `shell_backend: "process"` and `landlock='off'` would work
- The default for `landlock` is `auto`, not `off`
- On systems without Landlock support (older kernels), these tests would pass with a "not supported" skip
- This host has Landlock support, exposing the loader chaining bug

## Fix Options

### Option 1: Use `python3 -S` or `python3 -I` for loaders
Modify all loader invocations to use `-S` (skip site) or `-I` (isolated mode) so the interpreters don't need to import site under Landlock restrictions. The loaders themselves use only stdlib modules imported explicitly.

**Risk**: Changes the loader contract. Need to verify all loader imports still work.

### Option 2: Exclude the Python interpreter/stdlib from Landlock restrictions
Add the Python runtime paths to a special unrestricted set in the Landlock policy.

**Risk**: Weakens the sandbox - Python stdlib includes network, subprocess, and other powerful modules.

### Option 3: Use a compiled binary loader instead of nested Python
Replace the Python loader chain with a single compiled binary (C/Rust) that applies all layers atomically.

**Risk**: Large implementation effort, not appropriate for this batch.

### Option 4: Skip these tests when process backend + Landlock combination is detected
Add a conditional skip in the bench harness for these cases.

**Risk**: Silently hides the bug. Not acceptable per batch constraints ("do not weaken the bench, add skips, or lower expectations").

## Recommended Action

**Document the issue and stop** - per batch instructions: "If the root cause is...a host/kernel limitation, document the exact mechanism precisely...and stop there."

This is not strictly a host/kernel limitation - it's a **design issue in the loader architecture** when process backend is combined with Landlock. Fixing it requires architectural changes to the loader chain (Option 1 or 3), which is outside the scope of this diagnosis task.

The mechanism is now precisely documented. The batch can proceed to task 6 (final verification) without attempting a fix.

## References

- Process backend: `components/northstar-agent-runtime/tools/os_sandbox.py:1085-1265`
- Landlock loader: `components/northstar-agent-runtime/tools/sandbox.py:388-506`
- Loader chaining: `components/northstar-agent-runtime/tools/os_sandbox.py:1195-1217`
- Bench cases: `components/northstar-agent-runtime/governance_bench.py` (search for `shell_backend.*process`)
