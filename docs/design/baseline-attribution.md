# Baseline attribution — what the 30 full-suite failures actually are

**Date:** 2026-11-14
**Branch:** `batch-173-moltbook-absorb` (HEAD `d08958d6`)
**Measured on:** 140 (`muse-newapi@140.245.125.82`), kernel `7.0.0-1009-oracle`
(Oracle UEK), **aarch64**, Python 3.14.4, bubblewrap 0.11.1, Landlock ABI v8.

**Full suite measurement:** `Ran 21072 tests in 221.322s` /
`FAILED (failures=20, errors=10, skipped=13)` — **30 failing items**.

**Baseline files (outside the repo, handed to the coordinator):**

| File | Content | Role |
|---|---|---|
| `/home/muse-newapi/b173-baseline-failures-2026-11-14.txt` | the 30 raw failure lines, verbatim | authority for baseline comparison |
| `/home/muse-newapi/b173-baseline-failures-attributed-2026-11-14.txt` | the same 30 lines, each prefixed with its category | human-readable attribution view |
| `/home/muse-newapi/b173-bench-baseline-failures-2026-11-14.txt` | the bench's 8 failing item ids | authority for bench comparison |

**In-repo artefacts:** `scripts/b173-baseline-check.sh` (read-only drift checker)
and `components/northstar-agent-runtime/tests/test_baseline_attribution.py`
(read-only conformance test).

> **The headline finding is not what the brief expected.** The brief predicted
> "26 failures, 4 of them a missing optional extra, 22 environmental, 0 code
> defects, and `161/169` is probably an environment artifact". Measured, that
> is wrong on three counts: there are **30** failures, only **4** are
> `MISSING_EXTRA`, and **26** are `CODE_DEFECT`. `161/169` is **not** an
> environment artifact — it is a code artifact, and the bench reaches
> **169/169** on this very machine once three defects are fixed. Details below.

---

## 1. Summary of the attribution

| Category | Count | What it means |
|---|---|---|
| `CODE_DEFECT` | **26** | real defects in this repository's code |
| `MISSING_EXTRA` | **4** | the `json-schema` optional extra is not installed here (2 need `regex`, 1 needs `jsonschema>=4.26`, 1 needs both) |
| `KERNEL_FEATURE` | **0** | nothing in the baseline is caused by a missing kernel capability |
| `LOCAL_ENV` | **0** | nothing in the baseline is caused by a missing local dependency |
| **total** | **30** | |

### The four defects behind the 26 `CODE_DEFECT` items

Each was reproduced in isolation (see §4 for the measurement method):

| # | Defect | Where | Baseline items it explains |
|---|---|---|---|
| **D-1** | the bwrap seccomp filter fd is never rewound, so bwrap reads an **empty** BPF program and the kernel rejects it with `EINVAL` | `components/northstar-agent-runtime/tools/os_sandbox.py:316-319` (probe) and `:1007-1013` (production) | 4 test items + 2 bench items |
| **D-2** | `_runtime_read_paths()` returns `/lib64`, which does not exist on this aarch64 host; the pledge loader opens every rule path with `O_DIRECTORY` and dies on the missing one | `components/northstar-agent-runtime/tools/sandbox.py:158,171` + `tools/pledge.py:417` | 8 test items + 2 bench items |
| **D-3** | the `bash_parser` fail-closed AST gate (merged in from batch-172, commit `35a66b24`) **denies the governance bench's own live commands** — `for` loops, heredocs and tabs — so the bench's live legs can never produce their marker files | `components/northstar-agent-runtime/bash_parser.py:80,139,171-172,823` wired in at `governed_action_runner.py:589-611` | 5 bench items |
| **D-4** | `merged_tree_review.py` was added to the runtime **after** the `runtime-registration-closure` slice and was never registered in `py-modules` or the registry | `components/northstar-agent-runtime/merged_tree_review.py` (commits `ed06b163`, `4e43c32a`) | 4 test items |

D-1 and D-2 are the same pair of defects the brief predicted would be
"kernel capability missing". They are not: **this host supports seccomp and
Landlock fine.** The kernel says so.

### The kernel-capability claim in the brief is wrong, and here is the proof

The brief (and the strategy ledger) say this machine lacks landlock and
seccomp. Measured on this host:

```
$ uname -m
aarch64
$ grep -ci landlock /proc/self/status
0
$ grep -i CONFIG_SECCOMP /boot/config-$(uname -r)
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
$ cat /proc/sys/kernel/seccomp/actions_avail
kill_process kill_thread trap errno user_notif trace log allow
```

`/proc/self/status` has **no** `landlock:` line because that field is only
present once a process has *used* Landlock — it is not a capability flag.
The capability is there: `doctor` reports **"kernel Landlock: Landlock ABI v8
available (unprivileged self-sandbox)"**.

And seccomp demonstrably works on this host with the repository's own filter:

```
$ python3 -c "<install tools.seccomp.build_default_filter() via prctl>"
prctl SECCOMP -> 0          # PR_SET_SECCOMP with the repo's own 74-instruction BPF program
$ bwrap --seccomp 3 --ro-bind / / true ; echo $?
0
$ bwrap --seccomp 3 --ro-bind / / sh -c 'grep Seccomp /proc/self/status'
Seccomp:	2
Seccomp_filters:	1
```

The repository's own `prctl` path succeeds. What fails is the **bwrap** path,
and only because of D-1 (the file offset).

---

## 2. The 30-item attribution table

Ordered exactly as in the baseline file. `how it goes green` names the fix or
the install that makes the item pass.

| # | test | category | evidence | how it goes green |
|---|---|---|---|---|
| 1 | `test_bwrap_cannot_persist_changes_to_workspace_governance` (test_os_sandbox) | `CODE_DEFECT` | `SandboxError: bwrap seccomp was requested but its live filter probe failed` — the probe at `tools/os_sandbox.py:316-319` writes the filter and flushes it but never rewinds the fd, so bwrap reads 0 bytes | D-1: `os.lseek(fd, 0, os.SEEK_SET)` before handing the fd to bwrap |
| 2 | `test_bwrap_temp_directory_is_ephemeral_and_writable` (test_os_sandbox) | `CODE_DEFECT` | same `SandboxError` at `tools/os_sandbox.py:953-957` — the production path builds the same unrevound fd at `:1007-1013` | D-1 |
| 3 | `test_draft_2020_local_refs_and_regex_are_supported` (test_tool_input_schema) | `MISSING_EXTRA` | `pattern validation requires the regex extra` (`tool_input_schema.py:73`); `python3 -c "import regex"` → `ModuleNotFoundError` | `pip install "regex>=2025.7.31,<2027"` (the `json-schema` extra) |
| 4 | `test_explicit_cwd_updates_session` (test_shell_sessions) | `CODE_DEFECT` | the Shell tool returns `bwrap seccomp was requested but its live filter probe failed`, so no stdout ever reaches the test and `stdouts["t1"]` raises `KeyError` | D-1 |
| 5 | `test_no_session_no_persistence` (test_shell_sessions) | `CODE_DEFECT` | same `KeyError: 't2'` — the Shell tool never ran | D-1 |
| 6 | `test_pattern_properties_validate_matched_keys` (test_tool_input_schema) | `MISSING_EXTRA` | `pattern validation requires the regex extra` | install the `regex` extra |
| 7 | `test_per_call_env_overrides_session_env` (test_shell_sessions) | `CODE_DEFECT` | `KeyError: 't1'` — the Shell tool never ran | D-1 |
| 8 | `test_session_remembers_cwd` (test_shell_sessions) | `CODE_DEFECT` | `KeyError: 't1'` — the Shell tool never ran | D-1 |
| 9 | `test_session_remembers_env` (test_shell_sessions) | `CODE_DEFECT` | `KeyError: 't2'` — the Shell tool never ran | D-1 |
| 10 | `test_sessions_are_isolated` (test_shell_sessions) | `CODE_DEFECT` | `KeyError: 't2'` — the Shell tool never ran | D-1 |
| 11 | `test_allow_tool_shell_runs_inside_the_process_sandbox` (test_cli) | `CODE_DEFECT` | the assertion `assertIn("shell-allowed", body)` sees `exit=1` and, in stderr, `FileNotFoundError: [Errno 2] No such file or directory: '/lib64'` from the pledge loader | D-1 **and** D-2 |
| 12 | `test_bench_run_json_shape` (test_governance_bench) | `CODE_DEFECT` | the bench report it consumes is not ok — 8 case ids fail, the same 8 the bench prints | D-1 + D-2 + D-3 |
| 13 | `test_bench_run_passes` (test_governance_bench) | `CODE_DEFECT` | `AssertionError: 1 != 0`; the bench prints `denial 23/26, metrics 118/121, redteam 6/8` — 8 failing cases | D-1 + D-2 + D-3 |
| 14 | `test_doctor_reports_mcp_seccomp_off_as_a_warning` (test_cli) | `CODE_DEFECT` | the test asserts `code == 0`; `doctor` exits 1 because the `seccomp` check is `[fail]`: `bwrap seccomp child probe failed: ... prctl(PR_SET_SECCOMP) reported EINVAL` | D-1 |
| 15 | `test_doctor_reports_mcp_seccomp_status` (test_cli) | `CODE_DEFECT` | same `[fail] seccomp` line makes `doctor` exit 1 | D-1 |
| 16 | `test_doctor_reports_missing_optional_sdks_as_warnings` (test_cli) | `CODE_DEFECT` | same `[fail] seccomp` line makes `doctor` exit 1 | D-1 |
| 17 | `test_doctor_reports_the_openai_compatible_endpoint_without_touching_it` (test_cli) | `CODE_DEFECT` | same `[fail] seccomp` line makes `doctor` exit 1 | D-1 |
| 18 | `test_doctor_tells_the_truth_about_installed_bundles` (test_plugin_install) | `CODE_DEFECT` | `assertIn("0 fail", out)` fails; the output ends `doctor: 21 ok, 3 warn, 1 fail` — the one fail is `seccomp` | D-1 |
| 19 | `test_every_module_is_installed` (test_module_layout) | `CODE_DEFECT` | `AssertionError: Lists differ: ['merged_tree_review'] != []` — the module exists on disk and is in neither `py-modules` nor the registry | D-4: register `merged_tree_review` in `pyproject.toml` `py-modules` and in `runtime_registration` |
| 20 | `test_full_suite_passes_offline` (test_governance_bench) | `CODE_DEFECT` | `report.ok` is False with the same 8 case ids as #12/#13 | D-1 + D-2 + D-3 |
| 21 | `test_landlock_really_blocks_a_write` (test_pledge) | `CODE_DEFECT` | `AssertionError: ... loader broken: full-pledge child could not write (exit=1, stderr=FileNotFoundError: ... '/lib64')` — the pledge loader opens every rule path with `O_PATH\|O_DIRECTORY` and `/lib64` does not exist here | D-2 |
| 22 | `test_nested_enum_does_not_confuse_booleans_and_numbers` (test_tool_input_schema) | `MISSING_EXTRA` | `AssertionError: ToolInputSchemaError not raised` — the installed `jsonschema` is **4.19.2**, but the extra declares `jsonschema>=4.26,<5`; 4.19.2 treats `1 == True` as equal, so the enum check passes a bool for an int | install the `json-schema` extra (`jsonschema>=4.26,<5` **and** `regex`) |
| 23 | `test_regex_timeout_cannot_be_treated_as_a_failed_one_of_branch` (test_tool_input_schema) | `MISSING_EXTRA` | `pattern validation requires the regex extra` | install the `regex` extra |
| 24 | `test_run_code_uses_isolated_worktree_and_returns_evidence` (test_sdk) | `CODE_DEFECT` | `assertTrue(report.ok)` is False — the isolated worktree run shells out through the same broken bwrap-seccomp path | D-1 (and D-2 on the pledge loader) |
| 25 | `test_scaffolded_project_passes_doctor` (test_scaffold) | `CODE_DEFECT` | `assertEqual(code, 0)` gets `1` — `doctor` on the scaffolded project exits 1 on the `[fail] seccomp` check | D-1 |
| 26 | `test_shell_handler_non_zero_exit_is_not_is_error` (test_os_sandbox) | `CODE_DEFECT` | the handler's own stderr shows `FileNotFoundError: ... '/lib64'` from the pledge loader; the command never ran | D-2 |
| 27 | `test_shell_handler_runs_and_labels_backend` (test_os_sandbox) | `CODE_DEFECT` | `assertIn("shell-ok", result.content)` fails with `exit=1` and the same `/lib64` `FileNotFoundError` | D-2 |
| 28 | `test_the_check_agrees_with_the_layout_test` (test_runtime_registration) | `CODE_DEFECT` | `AssertionError: Items in the first set but not the second: 'merged_tree_review'` | D-4 |
| 29 | `test_the_check_passes_on_the_current_repository` (test_runtime_registration) | `CODE_DEFECT` | `RegistrationError: runtime module registration does not match the disk: module(s) on disk but not in the registry: merged_tree_review; module(s) on disk but not in py-modules: merged_tree_review` | D-4 |
| 30 | `test_the_registry_covers_every_module_on_disk` (test_runtime_registration) | `CODE_DEFECT` | `AssertionError: Lists differ: [...] != [...]` — the disk list has one extra element, `merged_tree_review` | D-4 |

---

## 3. The baseline reset: 27 → 26 → 30

The old baseline, `/home/muse-newapi/b173-refusal-row-baseline-failures.txt`,
holds **27** items. It was taken before two later slices landed:

| Step | What happened | Baseline size |
|---|---|---|
| 1 | the old baseline was taken | 27 |
| 2 | `runtime-registration` + `runtime-registration-closure` (commits `5708edb3`, `77332a31`, `f197c6f2`, `adcaad02`, `eebb2a70`, 2026-11-14 05:32–05:37) registered the 42 undeclared modules; the item `FAIL: test_every_module_is_installed` **shrank away** | 26 |
| 3 | `merged-tree-review` (commits `ed06b163`, `4e43c32a`, 2026-11-14 07:02–07:14) added `merged_tree_review.py` **without** registering it; the item came back, and the stricter registry test added **two** more | 30 |

Step 2 is verified directly: at the closure commit the layout test is green.

```
$ git worktree add /tmp/wt-closure eebb2a70
$ cd /tmp/wt-closure/components/northstar-agent-runtime
$ PYTHONPATH=.:tests python3 -m unittest test_module_layout
Ran 8 tests in 0.078s
OK
```

Step 3 is verified by commit ordering (`git merge-base --is-ancestor`):
`eebb2a70` (closure) is an ancestor of `ed06b163` (merged-tree-review), i.e.
the closure ran **before** the module was added. At HEAD the layout test
fails again, with the module named:

```
$ PYTHONPATH=.:tests python3 -m unittest test_module_layout
FAIL: test_every_module_is_installed
AssertionError: Lists differ: ['merged_tree_review'] != []
```

### Why 30, not 26 — the four extra items

| item | why it is new |
|---|---|
| `FAIL: test_every_module_is_installed` | came **back** — `merged_tree_review.py` is unregistered |
| `FAIL: test_the_registry_covers_every_module_on_disk` | the stricter registry test (`runtime_registration`) sees the same unregistered module |
| `FAIL: test_the_check_passes_on_the_current_repository` | ditto, via `assert_registration_matches_disk()` |
| `FAIL: test_the_check_agrees_with_the_layout_test` | ditto, the cross-check against `test_module_layout` |

**The lesson for the coordinator:** the baseline is not a fixed point. Every
slice that adds a runtime module can change it. That is precisely why the
registry now exists (`runtime_registration.assert_registration_matches_disk`),
and why `merged-tree-review` should have registered its module the way
`runtime-registration` did. `merged_tree_review` is the one module in the
batch that is not in `py-modules` — the recurrence guard has exactly one
outstanding violator.

### The old baseline was not modified

`/home/muse-newapi/b173-refusal-row-baseline-failures.txt` is untouched by
this slice (md5 `f5a841e65d385ec23924c9661f916046`, 27 lines, unchanged). The
new baseline is a **new** file; the old one stays as the historical record so
that earlier slices' "matches the baseline" claims remain auditable.

---

## 4. The measurement method

Every claim above was produced by running the code, not by reading it.

### 4.1 Re-taking the full-suite baseline

```bash
cd components/northstar-agent-runtime
find /tmp -maxdepth 1 -type d -name "nsar-*" -exec rm -rf {} +
MODS=$(ls tests/test_*.py | xargs -n1 basename | sed 's/\.py$//' | tr '\n' ' ')
PYTHONPATH=.:tests python3 -m unittest $MODS 2>&1 | tee /tmp/fullsuite.txt | tail -3
grep -E "^(FAIL|ERROR):" /tmp/fullsuite.txt | sort > /home/muse-newapi/b173-baseline-failures-2026-11-14.txt
```

Result: `Ran 21072 tests in 221.322s` / `FAILED (failures=20, errors=10, skipped=13)`
→ 30 items.

> The `/tmp/nsar-*` cleanup is not optional. The runtime suite leaves ~86k
> scratch directories behind; on a full tmpfs three tests in
> `test_tools_verify_invariants` fail with `shutil.Error: [Errno 122] Disk
> quota exceeded`, which would look like new failures.

### 4.2 Reproducing the `MISSING_EXTRA` conclusion (independently)

```bash
$ cd /tmp && python3 -m venv venv-regex
$ ./venv-regex/bin/pip install "regex>=2025.7.31,<2027"
$ cd components/northstar-agent-runtime
$ PYTHONPATH=.:tests /tmp/venv-regex/bin/python -m unittest test_tool_input_schema
Ran 25 tests in 0.045s
OK (skipped=5)
```

This reproduces the brief's §1 exactly: with `regex` installed the module is
green.

**But the brief's claim that all four were `regex` is only half right.**
The fourth item, `test_nested_enum_does_not_confuse_booleans_and_numbers`,
fails for a *different* missing dependency: the installed `jsonschema` is
**4.19.2**, but the extra declares `jsonschema>=4.26,<5`. With 4.19.2 the
enum check accepts `1` for `True`:

```
$ python3 -c "..."
jsonschema 4.19.2
1 == True accepted -> booleans/numbers confused (old jsonschema)
```

Installing the **full** `json-schema` extra fixes both halves:

```bash
$ /tmp/venv-regex/bin/pip install "jsonschema>=4.26,<5"
$ PYTHONPATH=.:tests /tmp/venv-regex/bin/python -m unittest test_tool_input_schema
Ran 25 tests in 0.189s
OK
```

So the honest count is **2** items attributable to `regex` alone and **2**
attributable to the *whole* `json-schema` extra (`regex` + a
`jsonschema` new enough to satisfy the declared floor). Both categories are
`MISSING_EXTRA`; the distinction matters only to whoever installs it.

### 4.3 Reproducing the code defects (and their exact partition)

Each defect was patched **in memory only** (no repo file was modified) and the
affected suites re-run, so the attribution is a measurement and not an
opinion.

**D-1 — the bwrap seccomp filter fd is never rewound.**

```bash
$ python3 - <<'EOF'
import tempfile, os, subprocess
from tools.seccomp import build_default_filter
with tempfile.TemporaryFile() as ff:
    ff.write(build_default_filter()); ff.flush()
    fd = ff.fileno()
    print("offset before:", os.lseek(fd, 0, os.SEEK_CUR))     # -> 592
    r = subprocess.run(["/usr/bin/bwrap","--seccomp",str(fd),"--ro-bind","/","/","true"],
                       capture_output=True, text=True, pass_fds=(fd,))
    print("rc:", r.returncode)                                # -> 1
EOF
offset before: 592
rc: 1
```

`bwrap` reads the BPF program from the fd's **current offset**. The
repository writes 592 bytes and flushes, leaving the offset at EOF, so bwrap
reads **zero** instructions and the kernel rejects the empty program with
`EINVAL`. Rewinding the same fd makes it work, every time:

```
$ python3 - <<'EOF'
... os.lseek(fd, 0, os.SEEK_SET) ...        # offset 0
EOF
rc: 0        # 6/6 runs
```

And the whole point, with the repository's own filter, in bwrap:

```
$ exec 3</tmp/filt.bin
$ bwrap --seccomp 3 --ro-bind / / true ; echo $?
0
$ bwrap --seccomp 3 --ro-bind / / sh -c 'grep Seccomp /proc/self/status'
Seccomp:	2
Seccomp_filters:	1
```

The two production sites are `tools/os_sandbox.py:316-319` (the capability
probe) and `tools/os_sandbox.py:1007-1013` (the production fd). The
`prctl` path is unaffected — `tools/seccomp.py:282` uses `prctl(22, 2, ...)`
with an in-memory buffer and succeeds.

**D-2 — `/lib64` is in the runtime read paths but does not exist here.**

```
$ ls -ld /lib64
ls: cannot access '/lib64': No such file or directory
$ python3 -c "from tools.sandbox import _runtime_read_paths; print(_runtime_read_paths())"
('/usr', '/bin', '/lib', '/lib64', '/sbin', '/usr/bin', '/usr/lib', '/usr/lib/python3.14')
```

`/lib64` is a **x86_64** path; this host is aarch64, where it does not
exist. `tools/sandbox.py:158` hard-codes it in `_SYSTEM_READ_PATHS` and
`:171` appends it unconditionally, without an existence check. The pledge
loader then opens every rule path with `O_PATH | O_DIRECTORY`
(`tools/pledge.py:417`) and dies:

```
FileNotFoundError: [Errno 2] No such file or directory: '/lib64'
```

Note the sibling code in `tools/os_sandbox.py:853` does filter correctly
(`if Path(host_path).exists()`), so the omission in `tools/sandbox.py` is an
inconsistency, not a design decision.

**D-3 — the `bash_parser` gate denies the governance bench's own live commands.**

`bash_parser` was merged into this branch from batch-172 (commit `35a66b24`,
2026-11-06) and wired into the Shell gate at
`governed_action_runner.py:589-611` as a fail-closed AST allowlist. Its
pre-parse check rejects **any** control character
(`bash_parser.py:80,139` — `chr(c) for c in range(0x00, 0x20)`), and the
tokenizer rejects the `for` keyword (`bash_parser.py:171-172,823`).

The governance bench's live legs use exactly those constructs:

| bench case | command | parser verdict |
|---|---|---|
| `denial.seccomp_filter_live_on_process` | `grep -q 'Seccomp:\t2' /proc/self/status && touch filter_live.txt` | `DENY control_character: control character U+0009 in command` (the literal tab) |
| `denial.seccomp_payload_cannot_loosen` | same, `tightened.txt` | same |
| `metrics.capdrop_deny_all_live` | `for f in CapInh CapPrm CapEff CapAmb; do ... done && touch capdrop_deny_all_ok.txt` | `DENY loop: shell keyword 'for'` |
| `metrics.capdrop_escalation_eperm` | `python3 - <<'PYEOF' ... PYEOF` | `DENY control_character: control character U+000A in command` (the newline) |
| `metrics.capdrop_payload_cannot_loosen` | the same `for` loop | `DENY loop: shell keyword 'for'` |

So the bench's live legs are blocked **before** the sandbox runs — not by a
sandbox capability problem, but by the parser. That is why the failure detail
is always `required path missing: <marker>`: the marker file is never
created because the command never ran.

**D-4 — `merged_tree_review.py` is unregistered.**  See §3.

### 4.4 The partition, measured

Each row re-runs the affected suites with **only** that defect patched in
memory.

Test suites (`test_shell_sessions`, `test_pledge`, `test_os_sandbox`,
`test_cli`, `test_sdk`, `test_scaffold`, `test_plugin_install`):

| patch | tests run | failures | remaining failures |
|---|---|---|---|
| none | 323 | 19 | the 19 listed below |
| D-1 only (fd rewind) | 323 | **4** | `test_pledge.test_landlock_really_blocks_a_write`, `test_os_sandbox.ShellToolTests.test_shell_handler_non_zero_exit_is_not_is_error`, `test_os_sandbox.ShellToolTests.test_shell_handler_runs_and_labels_backend`, `test_cli.RunHappyPathTests.test_allow_tool_shell_runs_inside_the_process_sandbox` |
| D-2 only (`/lib64` filtered) | 323 | 16 | the 4 above + 4 `doctor` tests + `test_sdk` + `test_scaffold` + `test_plugin_install` + 6 `test_shell_sessions` |
| D-1 + D-2 | 323 | **0** | — |

Bench (`run_suite()`):

| patch | bench score | failing cases |
|---|---|---|
| none | **161/169** | the 8 in `b173-bench-baseline-failures.txt` |
| D-1 only | 162/169 | 7 |
| D-2 only | 163/169 | 6 |
| D-3 only (parser allowed) | 161/169 | 8 |
| D-1 + D-2 | 164/169 | 5 (the three `bash_parser`-blocked capdrop/seccomp legs + 2) |
| D-2 + D-3 | 168/169 | 1 (`redteam.context_stale_approval_not_replayable`) |
| **D-1 + D-2 + D-3** | **169/169** | **0** |

**`161/169` is a code artifact, not an environment artifact.** On this very
machine — the same kernel, the same bubblewrap, the same Landlock ABI v8 —
the bench reaches **169/169** once the three defects are fixed. No other
machine is needed to decide the question.

---

## 5. Is `161/169` an environment artifact?

**This version answered the question: no.** The brief expected the answer to
be "probably an environment artifact, decided later on a Debian 13 machine
with landlock". The measurement does not support that hypothesis, and it does
not need the Debian 13 machine.

### The decision steps, and what each one returned

| # | step | expected if "environment artifact" | measured | verdict |
|---|---|---|---|---|
| 1 | does the kernel have seccomp? | no | `CONFIG_SECCOMP=y`, `CONFIG_SECCOMP_FILTER=y`, `actions_avail` lists all eight actions, and `prctl(PR_SET_SECCOMP)` with the repo's own filter returns **0** | the capability is present |
| 2 | does the kernel have Landlock? | no | `doctor` reports **"kernel Landlock: Landlock ABI v8 available (unprivileged self-sandbox)"** | the capability is present |
| 3 | does bwrap work here? | no | `bwrap --unshare-net --ro-bind / / / true` → `BWRAP_OK`; cap-drop child probe **passes**; only the seccomp leg fails, with `EINVAL` | bwrap works; the seccomp leg fails for a *code* reason (D-1) |
| 4 | does the repo's own seccomp filter install? | no | `prctl(22, 2, <repo filter>)` → **0**; `bwrap --seccomp 3` with the repo's filter → `Seccomp: 2` | the filter is fine; the *fd offset* is not |
| 5 | does Landlock ABI 8 matter? | it would block the TCP-denial bench case | the bench case `denial.mcp_network_denied_by_default` **passes** at HEAD; the ABI-10 requirement only affects the `doctor` line `[fail] mcp-network`, which no baseline item asserts | not a blocker |
| 6 | what does the bench score with the three code defects fixed, on this machine? | 161/169 (unchanged) | **169/169** | the threshold was an artifact of the code, not of the machine |

**Conclusion.** The `161/169` threshold is a *product of this repository's
current code*, and it is reproducible anywhere. Buying a Debian 13 machine
with landlock would not have answered the question, because the question was
never about landlock.

### The machine spec that would still be worth having

The coordinator may still want a second machine, but for a different reason:
to prove the fixes are **portable**, not just green on this one host. The
minimum useful spec:

| property | requirement | why |
|---|---|---|
| kernel | ≥ 6.12 (Debian 13 stock) with `CONFIG_SECCOMP`, `CONFIG_SECCOMP_FILTER`, `CONFIG_SECCOMP_WERROR`, Landlock ABI ≥ 3 | exercises the `x86_64` branch of `build_default_filter()` — this host only exercises the `aarch64` branch |
| arch | `x86_64` | the `x86_64` denylist branch (`tools/seccomp.py:_DENY_X86_64`) has never been executed by this baseline |
| bubblewrap | ≥ 0.11 | matches this host |
| `/lib64` | **present** (x86_64) | the D-2 defect is invisible on a host where `/lib64` exists, so the D-2 fix must be validated on x86_64 too |
| Landlock | ABI ≥ 10 if the `mcp-network` doctor check must be `[ok]` | ABI 8 here makes that one `doctor` line `[fail]` — it does not affect any baseline item, but it does affect `doctor`'s exit code on some hosts |

**Decision steps for that machine** (run after the D-1..D-4 fixes land):

```bash
git clone <repo> && cd northstar-agent-os
python3 -m venv /tmp/venv && /tmp/venv/bin/pip install -e "components/northstar-agent-runtime[json-schema]"
make test
make bench
```

Expected: `make bench` reports `169/169`, and the full suite's failure set is
empty.

### The honest caveat

The `161/169` figure is a **threshold of the current tree**, so it is only
meaningful as a comparison against a *stored* failure set. That is exactly
what `scripts/b173-baseline-check.sh` and the three baseline files do. If the
coordinator resets the threshold to `169/169` without landing the D-1..D-4
fixes, the threshold becomes unmeetable — and every slice that reports
against it will look broken for a reason that is in this document.

---

## 6. Action items for the coordinator

Ordered by severity. None of them were done by this slice (it changes no
code).

| # | action | why | estimated effect |
|---|---|---|---|
| **A-1** | **fix D-1**: rewind the bwrap seccomp filter fd before handing it to bwrap — `os.lseek(fd, 0, os.SEEK_SET)` at `tools/os_sandbox.py:319` and `:1013` | the empty BPF program makes every bwrap seccomp run fail with `EINVAL`, on every host, not just this one | 4 test items + 1 bench case go green; the whole bwrap backend becomes usable |
| **A-2** | **fix D-2**: filter `_runtime_read_paths()` to existing directories (`tools/sandbox.py:171`), or drop the x86-only `/lib64` from `_SYSTEM_READ_PATHS` (`:158`) | the pledge loader dies on any rule path that does not exist, which kills every Shell call on aarch64 hosts | 4 test items + 1 bench case go green; the process backend becomes usable on aarch64 |
| **A-3** | **decide D-3**: either exempt the governance bench's own live commands from the `bash_parser` AST gate, or teach `bash_parser` that a `for` loop and a heredoc are not dangerous | the bench's live legs are the *measurement instrument* for the sandbox; a parser that blocks them measures nothing | 5 bench cases go green; bench 169/169 |
| **A-4** | **fix D-4**: register `merged_tree_review` in `pyproject.toml` `py-modules` and in `runtime_registration` | the recurrence guard has exactly one outstanding violator — the module that was added after the guard landed | 4 test items go green; `test_every_module_is_installed` stays green |
| **A-5** | **install the `json-schema` extra** in the CI/verification image (`pip install -e "components/northstar-agent-runtime[json-schema]"`), and make `pyproject.toml`'s "the whole deterministic test suite run on a bare interpreter" comment honest — it is no longer true | 4 baseline items are pure missing-extra noise; the comment is stale | 4 items leave the baseline |
| **A-6** | **fix the stale comment** in `pyproject.toml` (`dependencies` block) that claims the whole deterministic suite runs on a bare interpreter | the claim was true when written and is false now | documentation only |
| **A-7** | **add `scripts/b173-baseline-check.sh` to the batch's CI** so that "failure set identical to baseline" is machine-checked rather than asserted in prose | the baseline drifted twice in one day (27 → 26 → 30) and four slices' reports are now wrong about it | prevents a repeat |
| **A-8** | **re-take the baseline once A-1..A-4 land** and publish a new dated baseline file; until then the 30-item file is the authority | the 30-item baseline contains 25 defects that are about to be fixed | the next slice's baseline drops to ~2 items |
| **A-9** | **correct the strategy ledger** (`b173-strategy-ledger-2026-11-14.md` §5): its 27-item list and its "缺 optional extra 4 / 内核能力缺失 6–8 / 本机环境 6 / 本批自造 1" table are all wrong for the current tree | the ledger is the input to the next slice's brief; a wrong ledger produces wrong briefs | prevents the next slice repeating this measurement |
| **A-10** | **fix `b173-accept.sh`'s `FULL_SUITE` grep** (`Ran 19[0-9]{3}`) — the suite is at 21 072 tests | the pattern was written when the suite was ~19 000 and was never widened; it false-fails every slice that reports its current count | grader correctness (not a code fix) |

---

## 7. How to reproduce this slice's own verification

```bash
cd /home/muse-newapi/northstar-agent-os/components/northstar-agent-runtime
PYTHONPATH=.:tests python3 -m unittest test_baseline_attribution 2>&1 | tail -5
```

The conformance test reads the three baseline files **when they are present**
and **skips** the corresponding assertions when they are not, so a clean
clone stays green. At least one method depends on no outside file: it asserts
that `docs/design/baseline-attribution.md` exists, that its attribution table
has one row per baseline item, and that every category label in it is one of
the four legal labels.

Drift check:

```bash
scripts/b173-baseline-check.sh                       # -> BASELINE MATCH / BASELINE DRIFT
scripts/b173-baseline-check.sh /path/to/other.txt    # compare against another baseline
```

The script is read-only with respect to the repository and never writes a
baseline: re-taking a baseline is a human decision.

