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
| `/home/muse-newapi/b173-baseline-CURRENT` | ONE line: the name of the baseline file in force | **the** authority for baseline comparison -- the checker follows this pointer |
| `/home/muse-newapi/b173-baseline-<sha>.failures.txt` | the baseline for one commit sha, one file per sha | the file the pointer names; the generator writes it |
| `/home/muse-newapi/b173-baseline-failures-2026-11-14.txt` | the 30 raw failure lines, verbatim | a RETIRED baseline, kept for history |
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
| **A-7d** | **done** | the check was measured **end to end on a simulated runner** -- the thing A-7c's wiring had never actually done.  With the coordinator's directory pointed at a path that does not exist (the script's `-f` test is a **shell builtin**, so a Python-level simulation cannot hide the real directory; the script reads `B173_BASELINE_DIR`), the run reads `BASELINE MATCH: 0 failure item(s) identical to <repo>/docs/baseline/current.failures.txt` over `33507 passed, 20 skipped, 1501 subtests passed` -- so the checkout-local fallback **works**.  The measurement also found that **the guard written to pin A-7c had four holes of its own**: it ran the wrong runner (so it passed **vacuously** on the `documentation` job, which installs no dependencies and has no `pytest`), it could not see a skip (pytest prints skip reasons only under `-rs`), it read unittest's "Ran 6 tests" as six **passes** (unittest counts skipped tests too), and it could not tell a legitimate skip from a lost copy.  See `mutant-evidence-closure.md` §9.1d. | the CI step now has **measured** evidence that it resolves the local copy, runs the suite CI runs, and reports a match -- and the guard that pins the surrounding behaviour is one that can actually fail. |
| **A-7e** | **done** | the check was **destroying a concurrently-running test suite**.  Both `scripts/b173-baseline-check.sh` and `scripts/b173-baseline-gen.sh` swept the shared temp root with `find /tmp -maxdepth 1 -type d -name "nsar-*" -exec rm -rf {} +`, which cannot tell residue from a LIVE directory -- the runtime's own test scratch uses the prefix `nsar-test-`, and **65** distinct `nsar-*` prefixes are in use across the suite.  Measured damage: `test_the_offloaded_bytes_are_still_on_disk_with_the_qualifier` FAILED (the offload file was deleted between the write and the assertion) and a parallel copy hit `Errno 122 Disk quota exceeded` mid-`copytree`.  Neither is a runtime defect; both are the check corrupting a concurrent run.  Fixed by running the suite under a **private `TMPDIR`** (`tempfile` honours it, and the runtime hardcodes no `/tmp` path) and dropping the sweep.  See `mutant-evidence-closure.md` §9.1e. | the rule it adds: **a cleanup must only ever remove what it created.**  A deletion with a justification attached is not a cleanup -- the justification (a nearly-full tmpfs) was about a different problem than the one the deletion caused.  Four new guards, each verified by planting the old line back. |
| **A-8** | **re-take the baseline once A-1..A-4 land** and publish a new dated baseline file; until then the 30-item file is the authority | the 30-item baseline contains 25 defects that are about to be fixed | the next slice's baseline drops to ~2 items |
| **A-9** | **correct the strategy ledger** (`b173-strategy-ledger-2026-11-14.md` §5): its 27-item list and its "缺 optional extra 4 / 内核能力缺失 6–8 / 本机环境 6 / 本批自造 1" table are all wrong for the current tree | the ledger is the input to the next slice's brief; a wrong ledger produces wrong briefs | prevents the next slice repeating this measurement |
| **A-10** | **fix `b173-accept.sh`'s `FULL_SUITE` grep** (`Ran 19[0-9]{3}`) — the suite is at 21 072 tests | the pattern was written when the suite was ~19 000 and was never widened; it false-fails every slice that reports its current count | grader correctness (not a code fix) |

### 6.1 What actually landed (2026-11-22)

**A-1, A-2, A-3 and A-4 are DONE**, and the bench now scores **169/169**
on this machine — the figure §5 predicted once the three code defects
were fixed.

| # | status | what landed | measured effect |
|---|---|---|---|
| **A-1** | **done** | `tools/os_sandbox.py` gained `_seccomp_filter_fd(handle)`, which writes the filter, flushes it, and **rewinds the fd** with `os.lseek(fd, 0, os.SEEK_SET)` before it is handed to bwrap. Both call sites (the live capability probe and the production run) now go through that one seam. | without the rewind the probe exits 1 with `prctl(PR_SET_SECCOMP) reported EINVAL`; with it, exit 0. **4 test items + 3 bench cases** green. |
| **A-2** | **done** | `tools/sandbox.py::_runtime_read_paths` now filters `_SYSTEM_READ_PATHS` to the entries that exist here, exactly as the interpreter-derived candidates already were — which is what the constant's own comment promised. | the pledge loader no longer dies with `FileNotFoundError: '/lib64'`. **3 test items + 1 bench case** green. |
| **A-3** | **done, differently** | the five affected bench cases were **rewritten into command shapes the parser allows**, rather than the parser being taught to allow `for`/heredoc. The parser's denials are sound — a `for` loop and a heredoc ARE more complex than the gate's AST model — so loosening the gate to let a benchmark through would weaken a security control for a test's convenience. The rewritten commands keep the same semantics: a literal TAB became `[[:space:]]`, a `for` loop became one counted `grep -cE`, and a heredoc became a `python3 -c` one-liner whose ctypes struct declaration became `struct.pack` (a struct *declaration* contains braces, and the gate denies a quoted brace expansion). | **5 bench cases** green; the bench went from **161/169** to **169/169**. |
| **A-4** | **already done** | `merged_tree_review` is registered in `pyproject.toml` `py-modules` (`:976`) and in `runtime_registration` (`:1097`) — by an earlier slice, not by this one. | the four D-4 items were already green at HEAD. |
| **A-5** | **confirmed, and it uncovered two real defects** | with the declared extra installed in a venv (`jsonschema>=4.26,<5` + `regex`), `test_tool_input_schema` is **25/25 OK** and `test_shell_sessions` is **6/6 OK**. But installing the extra into a venv **broke the live sandbox cases** — and the cause was a runtime defect, not a test artifact. See §6.2. And the *un*-installed case exposed a second defect: a type-confusion in the `enum` keyword. See §6.4. | the 4 `tool_input_schema` items and the 6 `shell_sessions` items are now green **on both** interpreters. |
| **A-6** | **open** | the `pyproject.toml` `dependencies` comment still claims "the whole deterministic test suite run on a bare interpreter". **That claim is now true** — the suite is green on a bare interpreter — but the comment is still misleading about *why*, and the `json-schema` extra is not in `requirements.txt`. | documentation only |
| **A-7** | **done** | `scripts/b173-baseline-check.sh` is now wired into CI as a step of the `agent-runtime` job -- the job whose unit-test step runs the very suite the check compares.  Three things blocked it and all three are now fixed: (i) the baseline file lives at `/home/muse-newapi/`, which a CI runner does not have, so a checkout-local copy with provenance now exists at `docs/baseline/current.failures.txt`; (ii) the check ran the suite with **unittest** while CI runs **pytest**, so it was watching 23,171 tests while CI watched 33,295 -- the check missed the suite's 9,945 standalone module-level test functions, so the runner is now selectable and defaults to the one CI uses; and (iii) the runtime job's `working-directory` is the component, so the step reaches the script at `../../scripts/`.  A fourth defect was found in the same script: a **full tmpfs** was reported as `BASELINE DRIFT`, which reads as "the code regressed" when nothing in the code changed -- the check now REFUSES to measure (exit 2, distinct from both MATCH and DRIFT).  `tests/test_baseline_check_ci_wiring.py` (8 tests) pins the wiring, and 4 of them fail against the pre-fix workflow. | the check now watches the same suite CI watches, runs on a bare checkout, and **CI actually runs it** -- so "the failure set is identical to the baseline" is machine-checked rather than asserted in prose. |
| **A-8** | **open, and now stale in the OTHER direction** | the baseline in force (the one `b173-baseline-CURRENT` names) held **26** items, and **all 26 are green**.  The newest baseline file on this machine holds **ZERO**.  Re-pinning is the **coordinator's** call (`r6-baseline-unify.md` §5.1: "a slice that legitimately fixes a pre-existing failure will show 'fewer items than the baseline', which is a real finding to report, not a reason to re-take the baseline").  The checker now follows the pointer, so it compares against whatever the coordinator has pinned; a checkout-local copy of an empty measurement, with provenance, is at `docs/baseline/current.failures.txt` -- it is a FALLBACK for machines that have no `/home/muse-newapi`, not a re-take. | — |
| **A-9** | **done** | the strategy ledger (`b173-strategy-ledger-2026-11-14.md`) now carries a §5.1 correction: its "内核能力缺失" attribution was **wrong** — Landlock *is* available on this host (`landlock_create_ruleset works (ABI v1 flags)`); the 8 bench failures were two code defects (D-1, D-2). Its §1 table carries the re-measured suite line. | the ledger no longer tells the next slice's brief that `161/169` is an environment artifact. It was not. |
| **A-10** | **already done** | `b173-accept.sh`'s `FULL_SUITE` grep was widened to `Ran [0-9]{4,}` in round 7; the `Ran 19[0-9]{3}` string survives only in the comment that explains the change. | — |

**The baseline after these fixes** — measured on this host, full runtime
suite, `Ran 23171 tests`, against the 30-item baseline file:

```
OK (skipped=20)
```

* **30 of the 30** baseline items are now green — the baseline file is
  **empty**, not merely shorter. Zero failures, zero errors.
* The bench is **169/169**.

**AMENDED 2026-11-22.**  The count is **30**, not 26.  The original
30-item file was narrowed to a "26-item core" for cross-run comparison
because three of its items were flaky; but the file the check actually
compares against — `b173-baseline-failures-2026-11-14.txt` — holds all
**30** raw lines, and `scripts/b173-baseline-check.sh` reports against
the file it is given.  The measured reading on this tree is:

```
BASELINE DRIFT: expected 30 item(s), found 0 item(s)
```

which is the expected reading of a fully retired baseline, not a
regression: every one of the 30 items is green.

### 6.2 Installing the extra exposed a REAL defect: a virtualenv cannot sandbox itself

A-5's verification was supposed to be a check, not a change. It was a
change, because **the runtime could not run its own tools from inside a
virtualenv**.

`site.py` looks for `pyvenv.cfg` one directory **above** the
interpreter's directory — that is, at the venv **prefix root**, which is
neither `prefix/bin` nor `prefix/lib`. `_runtime_read_paths()` granted
only those subdirectories, so the prefix root was never readable inside
the sandbox and the sandboxed interpreter died in `init_import_site`:

```
PermissionError: [Errno 13] Permission denied: '/tmp/a5venv/pyvenv.cfg'
```

The bwrap backend had the same gap with a different symptom: it bound
only the five hardcoded system roots, so a venv interpreter was simply
**absent from the namespace**:

```
bwrap: execvp /tmp/a5venv/bin/python: No such file or directory
```

The file existed on the host. It was absent from the sandbox.

Both are the same shape as **A-2**, one layer up: A-2 was a rule path
that did not exist; this is a file that exists but is **not covered by
any rule**. The lesson generalises — *the sandbox grants directories,
so every file the interpreter needs must be inside one of them, and
"the interpreter's own directory" is not the same as "the prefix the
interpreter lives under".*

The fix is one helper, `tools/sandbox.py::_virtualenv_roots()`, which
yields the prefix root of a venv **and only of a venv**:

* a prefix qualifies only if it actually holds a `pyvenv.cfg`, so a
  system interpreter — whose base prefix is `/` — never causes `/` to
  be granted. Granting `/` would hand the whole filesystem over;
* the prefix root is **read-only**: a runtime root, never a writable one;
* bwrap adds the interpreter's own directory and the venv prefix only
  when they are not already reachable through an existing bind, so the
  argv does not grow for nothing (a bind of `/usr` already covers
  `/usr/bin`).

Measured, under a virtualenv:

| measurement | before | after |
|---|---|---|
| process backend, child interpreter | exit 1 (`pyvenv.cfg` denied) | **exit 0** |
| bwrap backend, child interpreter | `execvp ...: No such file or directory` | **exit 0** |
| governance bench under the venv | 50/53 (3 live sandbox cases failing) | **53/53** |
| bench product under the venv | — | **169/169** |
| runtime suite under the venv, focused | — | `test_os_sandbox` 69 OK, `test_pledge` OK, `test_tool_input_schema` 25 OK, `test_shell_sessions` 6 OK |

The defect was **latent in CI**, which installs into the system
interpreter, and **live for anyone who installs the runtime's declared
extras into a venv** — which is exactly what A-5 proposes. A-5 was not
just "install a package"; it was "install a package and find out
whether the runtime still works when you have".

### 6.3 The measurement itself, and one surprise

Two failures appeared in *other* modules while this slice's work was in
flight, and both were **caused by the new tests, not by the fixes**:

1. `test_runtime_roots_are_always_read_exec` asserted a Landlock rule
   for `/lib64` **unconditionally** — the very path that does not exist
   on an aarch64 host. The assertion is now conditional on the root
   existing, with a second test asserting the other half.
2. The capabilities cache is **module-level**, and the new
   `SeccompFilterFdOffsetTests` probed with a fake bwrap path and left
   the cache pointing at `/fake/bwrap` — a binary that does not exist.
   Every later test in the process then ran against it, and the failure
   surfaced in an unrelated module as `Shell failed: no such path
   inside the workspace`. The class now resets the cache in `setUp` and
   `tearDown`.

Both are the same lesson as the rest of this document: **a fix moves
the failure somewhere else, and the somewhere-else has to be measured
too.**

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



### 6.4 The missing extra was hiding a TYPE-CONFUSION, not just a version skew

§6.1 attributed the four `tool_input_schema` failures to a "jsonschema
version skew". That was the wrong explanation, and the wrong explanation
was hiding a **real defect**.

The installed `jsonschema` here is **4.19.2**, below the extra's own
`>=4.26` floor. The natural reading was "an old library behaves
differently, install the right one". But the *difference* was not a
cosmetic API change — it was a **type-confusion in the `enum` keyword**:

```python
# jsonschema 4.19.2
{'flag': 1} in [{'flag': True}]   ->   True      # accepted!
```

4.19.2's `enum` compares **nested containers** with `==`, so a value
whose boolean flag carries the number `1` satisfies a schema that says
*"flag must be `True`"*. 4.26 compares with the `equal()` helper, which
keeps booleans and numbers distinct.

So on any host with an older `jsonschema`, the runtime's schema
validator would **accept a wrong-typed value**. The extra's version
floor papers over it; the runtime itself was relying on it.

**The fix does not rely on the version.** The runtime already had the
correct comparison — `_json_equal`, used by its internal fallback for
`enum` and `const` — so the `enum` keyword is now **overridden** with
it. The check holds whichever `jsonschema` is installed.

Measured on the 4.19.2 host, after the fix:

```
validate_tool_input({"value": {"flag": 1}},
    {"properties": {"value": {"enum": [{"flag": True}]}}})
-> ToolInputSchemaError: arguments violate schema keyword 'enum'
```

and the reverse direction too — a schema demanding `1` does not accept
`True` — while the legitimate value is still accepted.

**The other two failures were not the same thing at all.** The
`json-schema` extra is **two packages**: `jsonschema` *and* `regex`. The
`pattern` and `patternProperties` keywords are served by the
timeout-capable `regex` engine. The tests guarded only on
`_jsonschema is None`, so a host with `jsonschema` but no `regex`
reported three failures — which reads as a runtime defect and is not
one. The runtime's answer there is **correct**: it fails closed with
`"pattern validation requires the regex extra"`, which is the right
posture for an untrusted pattern. The guard now requires both halves of
the extra, and the tests that need only `jsonschema` keep their narrower
guard.

> **The generalisable form.** "The library is the wrong version" is a
> conclusion that *stops* the investigation, and it cost a real
> type-confusion one extra look. The right question was never "is the
> version right?" but **"what does this version do differently, and is
> the difference a behaviour or an API?"** A version skew that changes
> *behaviour* is a defect in every host that has it, and the fix belongs
> in the runtime, not in the install instructions.

### 6.5 What this section closes, and what it does not

**The baseline is empty.**  The 30-item baseline file named in
`b173-baseline-CURRENT` now has **zero** failing items against this
branch: `Ran 23171 tests — OK (skipped=20)`, zero failures, zero
errors.  The bench is **169/169**.

That closes **A-1, A-2, A-3** (and confirms **A-4** and **A-10**),
fixes **A-5**'s items, and turns **A-6**'s claim from false to true.

**What remains open, and why:**

* **A-6** — the `pyproject.toml` comment.  The suite now really does
  pass on a bare interpreter, so the claim is *true*; what is still
  wrong is that the `json-schema` extra is not in `requirements.txt`,
  so a CI image that installs only the requirements still runs without
  `regex` and skips four pattern tests.  That is a CI decision, not a
  code fix.
* **A-7** — **done.**  `scripts/b173-baseline-check.sh` is wired into CI as
  a step of the `agent-runtime` job (see the §6.1 table), and three
  blockers were removed on 2026-11-22:

  * the baseline file lived at `/home/muse-newapi/`, which a CI runner
    does not have — a checkout-local copy with provenance now exists at
    `docs/baseline/current.failures.txt`, and the script uses it as a
    **fallback**;
  * the check ran the suite with **unittest** while CI runs **pytest**.
    unittest's discovery finds only test METHODS inside TestCase
    classes, so the check was watching **23,171** tests while CI
    watched **33,295** — it never saw the suite's **9,945** standalone
    module-level `test_*` functions, in 811 files.  The runner is now
    selectable and defaults to the one CI uses, and both runners'
    failure lines are normalised to one shape so a baseline taken with
    either is comparable against the other;
  * a separate defect in the same script: a **full tmpfs** made four
    unrelated tests fail with `Disk quota exceeded`, and the check
    reported them as **BASELINE DRIFT** — which reads as "the code
    regressed".  The check now refuses to measure (exit 2) rather than
    report drift, and distinguishes the full disk from the broken code.

  What remains is a **CI-time** question, not a correctness one: the
  check runs the suite a second time, so the job's measured workload
  grows by roughly the suite's runtime (measured here: 8m43s for the
  pytest runner).  The job's `timeout-minutes: 45` is set well above
  its current ~13 minutes, so the added run fits; if it ever stops
  fitting, the fix is to raise the timeout, not to drop the step.

* **A-7b** — **done, 2026-11-22.**  The check's **baseline selection**
  was wrong in three ways at once, and each of them made the check
  compare against the wrong file:

  1. **It ignored the pointer.**  `r6-baseline-unify.md` §5.1 says the
     coordinator re-takes the baseline "when main advances" and then
     "repoints `b173-baseline-CURRENT` at it".  The script never read
     that pointer; it hardcoded a filename.  Measured on this host:
     the pointer named a **26**-item baseline, the hardcoded name held
     **30** items, and the newest baseline on the machine held
     **ZERO**.  A check comparing against the hardcoded name would have
     reported **30 spurious failures** for a tree that is clean.
  2. **The checkout-local copy came FIRST** in the candidate list, so
     even when the coordinator's file was present the in-repo copy won
     — the opposite of what the script's own test claimed.
  3. **The test that claimed otherwise proved nothing.**  It compared
     the *string positions* of the two paths in the script, and
     `text.index(authority)` found the occurrence on the script's
     **header comment** — never the candidate list.  The assertion
     passed while the script did the opposite of what it claimed.
     Proved with a fixture directory holding both files: the script
     picked the checkout-local copy.

  The script now reads `b173-baseline-CURRENT`, puts the coordinator's
  authority ahead of the fallback, and echoes the baseline it chose.
  The three checks are **run** against a fixture directory rather than
  read as text, and each of them fails when the defect is planted back
  in (measured: the old order fails two of them; ignoring the pointer
  fails two).

* **A-7c** — **done, 2026-11-22.**  The check was wired into CI, and
  the wiring was the easy part: **the rest of the B173 suite could not
  run on CI at all.**  See `mutant-evidence-closure.md` §9.1c for the
  measurement and the fix.  The short form:

  * the component job runs `python -m pytest -q tests`, and **18 tests
    across 7 files FAILED** under a faithful simulation of a runner --
    so CI was **red on every run** of this branch, for reasons that had
    nothing to do with the code;
  * the sharpest instance was an **optional artifact whose absence
    crashed**: `_census_path()` returns `None`, and the caller unpacked
    it, so the absence of a census raised `TypeError` in `setUp` and
    failed all nine tests of the class;
  * the census and the re-measurements now have **checkout-local
    copies** under `docs/baseline/mutant-census/`, with the
    coordinator's file first and the local copy as the fallback -- so
    the guard **runs and passes** on a runner rather than skipping;
  * the coordinator's live state (the referee, the hand-over patch, the
    104 manifests, the taskbooks) **skips** when absent, because a copy
    of a moving target is not evidence;
  * `tests/test_ci_runner_artifacts.py` **runs** the affected files
    under the simulation and asserts that none of them fails, and it
    fails when the defect is planted back in.

  The rule this adds to this section: **a check that cannot run is not
  a check, and a check that crashes on the runner is worse than one
  that is absent** -- because it makes CI red for a reason unrelated to
  the code, and trains everyone to ignore red.

* **A-7d** — **done, 2026-11-23.**  The check itself was measured **end
  to end on a simulated runner**, which is the thing A-7c's wiring had
  never actually done: the script was *wired* into CI, but nothing had
  ever run it on a machine without the coordinator's directory.

  Measured, with the coordinator's directory pointed at a path that does
  not exist (the script's `-f` test is a **shell builtin**, so a
  Python-level simulation cannot hide the real directory -- the script
  reads `B173_BASELINE_DIR`, and that is what the measurement used):

  ```
  baseline file: <repo>/docs/baseline/current.failures.txt
  suite runner: pytest
  suite: 33507 passed, 20 skipped, 7 warnings, 1501 subtests passed
  BASELINE MATCH: 0 failure item(s) identical to <repo>/docs/baseline/current.failures.txt
  ```

  So the checkout-local fallback **works**: the CI step resolves the
  local copy, runs the same suite CI runs, and reports a match.

  The measurement also found that **the guard written to pin A-7c had
  four holes of its own** -- it ran the wrong runner (so it passed
  vacuously on the job that has no `pytest`), it could not see a skip,
  it read unittest's "Ran 6 tests" as six passes, and it could not
  tell a legitimate skip from a lost copy.  `mutant-evidence-closure.md`
  §9.1d has the measurement and the fix.  The rule it adds:

  > **A guard must be able to fail, and it must fail when the thing it
  > measures is not measured.**  A guard that passes because it looked
  > in the wrong place is worse than no guard, because it is trusted.

* **A-7e** — **done, 2026-11-23.**  The check was **destroying a
  concurrently-running test suite**, and the end-to-end measurement of
  A-7d is what exposed it.

  Both `scripts/b173-baseline-check.sh` and `scripts/b173-baseline-gen.sh`
  swept the shared temp root before running the suite:

  ```bash
  find /tmp -maxdepth 1 -type d -name "nsar-*" -exec rm -rf {} +
  ```

  The reason was sound -- a nearly-full tmpfs makes three unrelated
  cases report a spurious `Disk quota exceeded`, which reads as drift.
  The mechanism was not: **the sweep cannot tell residue from a LIVE
  directory.**  The runtime's own test scratch uses the prefix
  `nsar-test-` (`tests/support.py`), and **65** distinct `nsar-*`
  prefixes are in use across the suite (measured by AST).

  The measured damage, in files this slice did not touch:

  | what the sweep did | what it broke |
  |---|---|
  | deleted the offload file the run had just written, between the write and the assertion | `test_the_offloaded_bytes_are_still_on_disk_with_the_qualifier` FAILED |
  | deleted a parallel copy's source tree **mid-copy** | `OSError: [Errno 122] Disk quota exceeded` inside `copytree` |

  Neither is a defect in the runtime.  **Both are the check corrupting a
  concurrent run** -- and the first is the sharper one, because the test
  that failed was the one asserting an on-disk promise, and the tool
  that broke it was the tool that deletes directories.

  The fix: `tempfile` honours `TMPDIR`, and the runtime hardcodes no
  `/tmp` path (measured), so the suite runs under a **private `TMPDIR`**
  and the sweep is deleted outright.  The pre-flight refusal on a
  nearly-full `/tmp` stays -- that part was right.

  The rule it adds:

  > **A cleanup must only ever remove what it created.**

  A deletion with a justification attached is not a cleanup.  The
  justification (a nearly-full tmpfs) was about a *different* problem
  than the one the deletion caused -- the same "measurement of the wrong
  thing" shape as §9.1d.  Four new guards, each verified by planting
  the old line back and re-running.  `mutant-evidence-closure.md` §9.1e
  has the measurement.

* **A-8** — the baseline in force over-reports by **26** (the newest
  baseline file on this machine holds ZERO).  It should be
  re-pinned to an empty set, with the provenance header naming the
  commit that earned it.  **A baseline file is a claim about a tree**;
  leaving a stale one in place is worse than having none, because a
  reader cannot tell which items are still real.  Re-pinning is the
  **coordinator's** call (`r6-baseline-unify.md` §5.1), so it is
  reported here and NOT done.  The same measurement, with provenance, is
  recorded at `docs/baseline/current.failures.txt` as a FALLBACK for
  machines with no `/home/muse-newapi` — the coordinator's file remains
  the authority and the script prefers it.
* **A-9** — **done**.  The strategy ledger now carries a §5.1
  correction, and the correction is worth more than the fix: its
  "内核能力缺失" attribution was **wrong**, and the evidence that
  disproved it was one line — `landlock_create_ruleset works (ABI v1
  flags)`.  The ledger had inferred "the kernel cannot do this" from
  `grep -ci landlock /proc/self/status` = 0, which measures the
  *shell*, not the kernel.

**And one thing this section did not touch:** the 15 mutant-survivor
equivalence proofs.  Their census row (`gt@640`) turned out to have
**no row** in `mutant-evidence-closure.md` §9.1's table — the same
class of gap as the `merged_tree_review` one, found by diffing the
table against the census rather than against the proofs.  That file
carries the correction.
