# ci-compile-coverage — CI must compile every module every component ships

**Slice:** `ci-compile-coverage`
**Date:** 2026-11-17
**Files:**
`.github/workflows/test.yml` (modified),
`tests/ci_compile_coverage.py` (new),
`tests/test_ci_compile_coverage.py` (new),
`docs/design/ci-compile-coverage.md` (new)

Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. The defect, measured

A compile step is what catches a module that does not parse. It is the
cheapest check in the whole pipeline and the one most likely to be
narrowed by accident.

The repository's CI jobs do not all compile the same way. Some use a
glob; some name every module by hand:

```yaml
# runtime -- a glob, with a comment saying why:
python -m py_compile *.py providers/*.py tools/*.py \
  tests/support.py tests/fixtures/*.py tests/test_*.py

# durable-run -- a hand-maintained list:
python -m py_compile durable_contract.py event_store.py \
  action_gateway.py runner.py verifier.py trace_metrics.py \
  evaluation.py durable_audit.py tests/test_*.py
```

Measured against the modules each component actually ships, **9 shipped
modules were not compile-checked by CI at all**:

| component | shipped | compiled by CI | missing |
|---|---|---|---|
| `northstar-agent-runtime` | 1636 | 1635 | **1** |
| `northstar-durable-run` | 16 | 8 | **8** |
| `northstar-agent-interop` | 8 | 8 | 0 |
| `northstar-host` | 4 | 4 | 0 |
| `northstar-run-contract` | 5 | 5 | 0 |
| `northstar-run-evidence` | 6 | 6 | 0 |

### 1.1 The runtime's one missing module

`policy/__init__.py` — the package the `runtime-data-files` slice created
so that the runtime's data files could ship in the wheel. **That slice's
own change made the gap.** The compile step's glob was written for a
component whose packages were `providers` and `tools`, and the new
package was not added to it.

The consequence is small in effect and large in kind: `policy/__init__.py`
is 4 lines of registry code, and a syntax error in it would be caught by
nobody. It happened to be correct.

### 1.2 durable-run's eight missing modules

```
blob_store.py  event_migration.py  governed_memory.py
receipt_gate.py  timelock.py  tool_allowlist.py
tool_ledger.py  tool_receipt.py
```

Half of the component. The list was written when the component had 8
modules; 8 more landed and the list was never extended.

## 2. Why it survived

### 2.1 The comment promised a property the command did not have

The runtime's compile step carries this comment:

```yaml
# Every module the component ships, by glob rather than by hand: a curated list
# here silently stopped covering new modules the moment they landed, which is the
# opposite of what a compile step is for.
```

The runtime did the right thing. **It then added a package and did not
extend the glob** — so the comment promised a property the command did
not have. The comment was the reason the gap was invisible: a reader
checking the workflow would see the glob, read the comment, and conclude
the runtime was covered.

### 2.2 The automation reached one component and stopped

`docs/history/next-gen-agent-blueprint-v1-2026-09.zh-CN.md` records the
decision:

> CI 编译行改为整目录 glob（手抄清单已漏掉数个新模块，正是它该被自动化的原因）

— "the CI compile line was changed to a whole-directory glob; the
hand-copied list had already missed several new modules, which is exactly
why it needed to be automated."

The automation happened in the runtime. It never reached durable-run,
which still names every module by hand.

### 2.3 No guard checked this at all

The repository has
`test_the_ci_compile_list_and_the_install_list_agree` — but it reads the
interop component's lines and checks that the **install smoke check**
imports what the **compile step** compiles. It is about the interop
component's install check. It says nothing about what CI compiles, and
nothing about any component but interop.

## 3. The fix

### 3.1 The two compile steps

The runtime's glob gains `policy/*.py`, with a comment that says what the
rule is:

```yaml
# Every PACKAGE the component ships must be in the glob too, and that
# is a separate list from the flat modules -- `providers/` and
# `tools/` were here from the start, and `policy/` was added when
# the policy package became real.  A package missing from this line
# is a module whose syntax errors nobody would ever see.
# `tests/test_ci_compile_coverage.py` checks this from the outside.
python -m py_compile *.py providers/*.py tools/*.py policy/*.py \
  tests/support.py tests/fixtures/*.py tests/test_*.py
```

durable-run's hand-maintained list becomes a glob:

```yaml
# By glob, not by hand: the hand-maintained list was written when the
# component had eight modules, and eight more landed without the
# list being extended -- so half the component was never
# syntax-checked.  `tests/test_ci_compile_coverage.py` checks that
# every module the component ships is covered.
run: python -m py_compile *.py tests/test_*.py
```

### 3.2 The guard

`tests/test_ci_compile_coverage.py` pins the rule at the repository
level:

> **Every module a component ships is compiled by that component's CI
> compile step.**

It covers all eight components — the six that ship a wheel (measured
against the modules the wheel ships) and the two sidecars that do not
(measured against the files on disk).

The logic lives in `tests/ci_compile_coverage.py` rather than in the
test, for the same reason `tests/py_modules_guard.py` does: the mutant
probe mutates a **module** and reruns the slice's tests, and a test file
is excluded from the probe by name. A guard whose logic lives entirely
inside a test file cannot be mutation-probed at all — the probe skipped
with "manifest lacks module/test" until the logic was extracted.

### 3.3 The guard must be tested against crafted workflows

The repository-wide checks read the REAL workflow, which — after the fix
— covers everything. So on their own they cannot tell a working detector
from one that never fires.

The tests therefore give the detector **crafted workflow files**: a glob
that misses a package, a hand-maintained list that misses a module, a
compile command wrapped over several lines with a trailing backslash, a
workflow with no compile step at all.

**Those tests found a real defect in the detector while being written.**
The first version counted any file a glob matched, not only `.py` files.
But `py_compile` compiles Python source and nothing else — a glob that
also matched a `.toml` file would make the compile step **fail**, so such
a file is not "covered", it *breaks* the step. The detector now counts
only `.py` files.

## 4. What did NOT change

* **No module changed.** The fix is to CI configuration and to a new
  test.
* **The runtime's other CI steps are untouched** — install, unit tests,
  the TypeScript face, the CLI smoke, the packaging smoke.
* **The interop component's compile step is untouched.** Its list names
  all 8 of its modules, so it is already complete; converting it to a
  glob would be a change with no defect behind it.
* **No version change, no tag, no release, no push, no merge.**

## 5. Verification

See the slice report for the full-suite, bench, mutant and fresh-clone
numbers.

## 6. What this slice does not do

* **It does not check that CI compiles the TESTS of every component.**
  The `tests/test_*.py` pattern is present in every job, but the
  repository-level rule is about the shipped modules.
* **It does not check the other CI steps' coverage.** The install smoke
  checks are covered by
  `test_the_ci_compile_list_and_the_install_list_agree`, for the interop
  component; the generalisation of THAT rule is a separate slice.
* **It does not add a lint step, a type checker, or a coverage
  threshold.** A compile step catches syntax errors. It does not catch
  style, and this slice does not pretend it does.
