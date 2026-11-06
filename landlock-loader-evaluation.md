# Landlock loader evaluation (batch-172)

Date: 2026-11-06. Host: 140 (Oracle Cloud Singapore, aarch64, Ubuntu 26.04).
Repo: `northstar-agent-os`, branch `batch-172-claude-absorb-p1p2` (from main `2db42e93`).
Question (from batch-171): the 8 live legs fail because the Landlock loader breaks
nested Python. Two candidate fixes were to be evaluated, not applied:

- **Option A** — `python3 -S` / `-I` on every loader invocation.
- **Option B** — a compiled (non-Python) loader.

**Nothing in this evaluation changed the repository.** All experiments ran in
`/tmp/ll-scratch-S` and `/tmp/ll-scratch-I` (full copies of
`components/northstar-agent-runtime`), driven by the venv interpreter
`/opt/northstar-dev/.venv/bin/python` — the same interpreter `make bench` uses.
This document is the only repo change from this evaluation.

## 1. Refined root cause (batch-171's diagnosis was right, but incomplete)

Batch-171 diagnosed: "Landlock path restrictions break the nested Python loader
(`init_import_site`)". The precise mechanism, reproduced 2026-11-06:

1. `make bench` runs under the venv Python (`/opt/northstar-dev/.venv/bin/python`).
2. `tools/os_sandbox.py:1117` sets `python = sys.executable`, so every loader
   in the chain is the **venv Python**, not `/usr/bin/python3`.
3. The venv Python's `site` module, at startup, calls `site.venv()`, which reads
   `/opt/northstar-dev/.venv/pyvenv.cfg`.
4. The Landlock allowlist (`tools/sandbox.py:_runtime_read_paths()`) grants the
   venv's `lib/` directory but **not the venv root**, so `pyvenv.cfg` is denied.
5. The inner interpreter dies before any loader code runs:

   ```
   Fatal Python error: init_import_site: Failed to import the site module
   ...
   File "<frozen site>", line 642, in venv
   PermissionError: [Errno 13] Permission denied: '/opt/northstar-dev/.venv/pyvenv.cfg'
   ```

Proof that the caller matters, not Landlock alone:

- Same reproduction under **system** `python3` (`/usr/bin/python3`, stdlib under
  `/usr/lib/python3.14`, which the allowlist covers): **passes**, landlock=auto.
- Same reproduction under the **venv** Python: **fails** with the error above.
- A single Landlock layer with a plain inner `python3 -c "import site"` passes;
  the failure needs the venv interpreter **and** the full loader chain.

The loader chain (outermost first) is: resource-limits → Landlock → capdrop →
seccomp (prctl) → pledge → target. The `python` in every loader argv is
`sys.executable` of the calling process. The first interpreter that runs under
Landlock restrictions is the capdrop loader; with the site import broken, the
command never reaches the target.

## 2. Experiment matrix (8 live legs)

Legs: `denial.seccomp_filter_live_on_process`,
`denial.seccomp_payload_cannot_loosen`, `denial.landlock_path_whitelist_live`,
`metrics.capdrop_deny_all_live`, `metrics.capdrop_escalation_eperm`,
`metrics.capdrop_payload_cannot_loosen`,
`redteam.context_stale_approval_not_replayable`,
`redteam.shell_backend_host_owned`.

Run with: `/opt/northstar-dev/.venv/bin/python -m cli bench --only <each leg>`.

| Configuration | Result |
|---|---|
| Pristine repo (baseline) | **0/8** — all "required path missing" |
| `-S` on 4 loaders (resource, landlock, capdrop, seccomp) | **0/8** — site error gone from direct `run_sandboxed` repro, but bench legs still fail |
| `-S` on 5 loaders (+ pledge) | **0/8** — site error gone; new error `[Errno 2] No such file or directory: '/lib64'` |
| `-S` on 5 loaders + `/lib64` fix (§3) | **7/8** — only `redteam.context_stale_approval_not_replayable` fails (bwrap path, §4) |
| `-S` on 5 loaders + `/lib64` fix + `seek(0)` fix (§4) | **8/8 PASS** |
| `-I` on 5 loaders + `/lib64` fix + `seek(0)` fix | **1/8** — only the bwrap leg passes |

## 3. Latent bug #1 (required regardless of loader choice): `/lib64`

`tools/sandbox.py:_SYSTEM_READ_PATHS = ("/usr", "/bin", "/lib", "/lib64", "/sbin")`
is hardcoded and `_runtime_read_paths()` returns it **unfiltered**. This host
(aarch64 Ubuntu) has no `/lib64` (`ls: cannot access '/lib64'`).

- `default_profile()` filters by `os.path.isdir` — safe.
- `tools/pledge.py:filesystem_rules()` uses `_runtime_read_paths()` **unfiltered**
  and emits a Landlock rule for `/lib64`; the pledge loader then tries to open
  it and dies with `ENOENT`.
- `tools/os_sandbox.py:853` (bwrap `--ro-bind`) already filters with
  `Path(host_path).exists()` — only the pledge path was unfiltered.

Fix used in the experiment: filter `_runtime_read_paths()` by `isdir` before
returning, so both call sites are covered at once. This bug was masked by the
site-import failure (the chain died before reaching the pledge loader).

## 4. Latent bug #2 (required regardless of loader choice): seccomp fd at EOF

Both bwrap `--seccomp FD` handoffs write the BPF program to a temp file, flush,
and hand the fd to bwrap **without seeking back to offset 0**:

- `tools/os_sandbox.py:316-319` — capability probe.
- `tools/os_sandbox.py:1007-1014` — the real bwrap run.

bwrap reads the filter from the **current** file offset (EOF) → empty program →
`prctl(PR_SET_SECCOMP)` returns `EINVAL` → "bwrap seccomp was requested but its
live filter probe failed; refusing to run without the configured syscall boundary".

Proof: a trivial allow-all filter and the real filter both fail under bwrap
without `seek(0)`; both pass with `seek(0)`. The direct prctl loader installs
the same filter fine (rc 0), so the filter itself is valid and the kernel
supports seccomp. (User namespaces are restricted on this host — `unshare -r`
fails on `uid_map` — but that is unrelated: plain bwrap works and the probe
does not need a user namespace.)

Fix used in the experiment: `seek(0)` after `flush()` at both sites. This bug
is also independent of the loader implementation: it is in the calling code
that hands the fd to bwrap.

## 5. Option A: `python3 -S` — works. `python3 -I` — does not.

- **`-S` (skip `site` entirely): 8/8** (with the §3 and §4 fixes, which are
  needed in any case). The five loader argv sites are:
  `tools/resource_limits.py:64`, `tools/sandbox.py:506`,
  `tools/capdrop.py:472`, `tools/seccomp.py:299`, `tools/pledge.py:457`
  — each `[python, "-c", LOADER, ...]` becomes `[python, "-S", "-c", LOADER, ...]`.
  The loaders import only stdlib (`base64`, `ctypes`, `json`, `os`, `struct`,
  `sys`, `platform`); none of them needs `site` or site-packages. The target
  command (`sh -c`) needs no Python at all. The systemd-scope marker loader
  (`tools/os_sandbox.py:731`) runs **outside** the sandbox and needs no change.
- **`-I` (isolated): 1/8.** `-I` implies `-E` and `-s` but **still imports
  `site.py`**, and `site.venv()` still runs and still dies on `pyvenv.cfg`.
  The only leg it passes is the bwrap-backend one (fixed by the `seek(0)` fix
  alone). `-I` is not a viable fix for this failure.

Residual risk of `-S`: it also drops `sitecustomize`/`usercustomize` and any
`PYTHONSTARTUP`/`PYTHONPATH`-injected behaviour from the loader interpreters.
The loaders are self-contained inline strings with no such dependency, so this
is a non-issue for the current chain — but any future loader that imports from
site-packages would silently break. A comment at the five sites should say why
`-S` is there.

## 6. Option B: compiled loader — feasible, but the expensive way to fix this

Feasibility evidence:

- `gcc`/`cc` are present on 140 (`/usr/bin/gcc`, `/usr/bin/cc`).
- The repo has **no C build infrastructure**: no `Makefile` in the runtime
  component, no C references in `pyproject.toml` / root `Makefile`, no compiled
  artifact anywhere. Adding one means a new build step, per-architecture
  binaries (aarch64 here, x86_64 elsewhere), and a distribution story for a
  pure-Python package that currently installs with `pip install .`.
- The five loaders' logic (Landlock `landlock_restrict_self` + ruleset fd,
  seccomp prctl + BPF, capset zeroing, rlimits, pledge filesystem rules) would
  have to be reimplemented in C — a new, unaudited bug surface replacing five
  small, already-reviewed Python strings.

What it would and would not fix:

- **Would** fix the site-import failure (no interpreter in the chain at all).
- **Would not** fix §3 (`/lib64`) or §4 (`seek(0)`): both are in the calling
  Python code (rule construction, fd handoff), not in the loaders. Any loader
  implementation still needs those two fixes for 8/8.
- **Would not** change the security posture of the chain in a way these legs
  measure: the legs test observable behaviour (filter live, allowlist enforced,
  capdrop zeroed, approval not replayable), all of which pass with `-S`.

## 7. Recommendation

**Adopt Option A (`-S` on all five loader argv) plus the two independent fixes
(§3 filter nonexistent paths in `_runtime_read_paths()`; §4 `seek(0)` before
handing the seccomp fd to bwrap).** That combination is the smallest change
that makes all 8 legs pass (8/8, measured), with no new build dependency and no
new binary to ship. Do **not** adopt `-I` — it provably does not fix the
failure. Defer the compiled loader: it is a legitimate defence-in-depth goal
(remove the interpreter from the sandbox chain entirely), but it is a separate,
larger project (build infra + C reimplementation + per-arch distribution) that
buys nothing on these 8 legs beyond what `-S` already delivers. If the compiled
loader is ever built, §3 and §4 still have to be fixed first.

## 8. Open points for review

- The `-S` change touches five loader argv sites; confirm there is no sixth
  `python -c` invocation in the sandbox path (searched: `command_hooks.py:188`
  builds a `[interpreter, "-c", bootstrap, ...]` but is not called from
  `shell.py` / `os_sandbox.py` / `loop.py` / `governed_action_runner.py`;
  `tools/shell.py:144` is the `sh -c` target, not Python).
- The §3 fix changes `_runtime_read_paths()` for all callers; `default_profile`
  already filtered, so its behaviour is unchanged, but the unit tests for
  `build_landlock_spec` / `filesystem_rules` should get a case with a
  nonexistent path in the list.
- The §4 fix should get a regression test: write a filter to a temp file,
  flush, hand the fd to bwrap without seeking, and assert the probe fails —
  or, more robustly, assert the fd offset is 0 at handoff.
- The bwrap backend's seccomp probe failure message ("refusing to run without
  the configured syscall boundary") is fail-closed and correct; after the
  `seek(0)` fix the probe passes on this host.
- The 8 legs were verified only on 140 (aarch64, venv Python, kernel with
  Landlock + seccomp). The `/lib64` fix matters on any host without `/lib64`;
  the `-S` fix matters wherever the calling interpreter is a venv Python.
