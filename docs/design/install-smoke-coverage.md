# install-smoke-coverage — the CI packaging smoke check must import every module the component ships

**Slice:** `install-smoke-coverage`
**Date:** 2026-11-17
**Files:**
`.github/workflows/test.yml` (modified),
`scripts/check_installed_surface.py` (new),
`tests/install_smoke_coverage.py` (new),
`tests/test_install_smoke_coverage.py` (new),
`tests/test_component_packaging_closure.py` (modified),
`docs/design/install-smoke-coverage.md` (new)

Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. The defect, measured

Every wheel-shipping component has a CI "packaging smoke" step. It
installs the wheel, moves to a directory that is not the source tree, and
imports the component's modules. That step is what proves the **installed
surface** works — that the wheel ships what it claims, and that the
modules import from anywhere.

Those steps named their modules by hand. Measured against the modules each
component actually ships:

| component | shipped | reached by the smoke step | coverage |
|---|---|---|---|
| `northstar-agent-runtime` | 1636 | 66 | **4.0%** |
| `northstar-durable-run` | 16 | 13 | **81.2%** |
| `northstar-host` | 4 | 2 | **50.0%** |
| `northstar-run-contract` | 5 | 3 | **60.0%** |
| `northstar-run-evidence` | 6 | 4 | **66.7%** |
| `northstar-agent-interop` | 8 | 8 | 100.0% |

"Reached" is measured transitively: the modules the smoke step's import
roots pull in, directly or through the component's own import graph. It
is not a string match — the smoke step names roots, and the roots reach
other modules.

**The runtime's 4.0% is the defect.** Its step was:

```yaml
python -c "import cli, loop, tools, tools.verify_invariants, governance_bench, memory, product_path; print('northstar-agent-runtime core imports OK')"
```

Seven names. They reach 66 of the runtime's 1636 installed modules. The
other 1570 — 96% of the installed surface — were outside the check that
exists to prove the installed surface works.

### 1.1 The decisive experiment

Three shipped modules given deliberately broken content and removed from
the wheel, then the CI smoke command run verbatim against the installed
wheel:

```
OLD CI SMOKE CHECK   rc=0   "core imports OK"

import ab_testing    rc=1   ModuleNotFoundError
import abac_engine   rc=1   ModuleNotFoundError
import abuse_limits  rc=1   ModuleNotFoundError
```

Three modules can vanish from the shipped wheel, with syntax errors in
the ones that remained, and CI stays green.

The same experiment on `northstar-durable-run`: `governed_memory` and
`receipt_gate` removed from `py-modules` — the CI smoke check returned
`rc=0`, "durable-run imports OK", while both modules were gone.

## 2. Why it survived

### 2.1 The steps were named after what they checked, not what they covered

Each step was a one-line `python -c` naming a handful of modules the
author believed represented the component. Nothing compared that handful
against the shipped list. When a module was added, the list did not
follow.

### 2.2 The one generalisation that existed was interop-only, and checked the wrong side

`tests/test_component_packaging_closure.py` had
`test_the_ci_compile_list_and_the_install_list_agree`. It reads the
interop component's lines and checks that the install smoke check imports
what the **compile step** compiles. That is a compile-list rule, not a
shipped-surface rule, and it covered one component of six.

The interop component was the only one at 100% — because it was the only
one anyone had checked. The omission was invisible there and obvious
everywhere else.

### 2.3 The runtime's modules are dynamically loaded, so static analysis alone cannot judge them

Every one of the runtime's 1613 flat module names appears as a **string
literal** somewhere in the repository (measured: 1613/1613), and
`runtime_registration.py` alone holds 1622 of them. They are loaded by
name at runtime, not by `import` statements.

That is why a reachability analysis of the source is the wrong tool: it
would call 1438 of the runtime's modules "unreachable" when they are in
fact the whole point of the component. The check that is needed is an
**import** check on the installed surface, not a reachability check.

## 3. The fix

### 3.1 `scripts/check_installed_surface.py`

A small script that takes a distribution's name, asks
`importlib.metadata` which modules the **installed** distribution ships,
and imports every one of them.

```python
python "$REPO/scripts/check_installed_surface.py" northstar-agent-runtime
```

Nothing is listed by hand, so nothing can be left out by omission, and a
module that leaves the wheel is caught.

The set of modules a wheel ships is decided by the packaging
configuration at build time, not by anything written next to the workflow.
Asking the installed distribution is the only way to ask the question that
matters: "what can a user of this wheel actually import?"

### 3.2 The six CI steps

| step | before | after |
|---|---|---|
| `northstar-run-contract` | 3 named | surface check |
| `northstar-run-evidence` | 4 named | surface check |
| `northstar-host` | 2 named | surface check |
| `northstar-durable-run` | 8 named | surface check |
| `northstar-agent-interop` | 8 named | surface check |
| `northstar-agent-runtime` | 7 named | surface check |

The runtime's step, verbatim:

```yaml
REPO="$(git rev-parse --show-toplevel)"
python -m pip install --quiet --no-deps .
cd /tmp
...
python "$REPO/scripts/check_installed_surface.py" northstar-agent-runtime
```

`REPO` is captured before the `cd /tmp`, because the whole point of the
step is that the source tree is *not* on `sys.path`.

### 3.3 The guard

`tests/test_install_smoke_coverage.py` pins the rule at the repository
level:

> **Every module a component ships is imported by that component's CI
> packaging smoke step.**

The logic lives in `tests/install_smoke_coverage.py` rather than in the
test, for the same reason `tests/py_modules_guard.py` and
`tests/ci_compile_coverage.py` do: the mutant probe mutates a **module**
and reruns the slice's tests, and a test file is excluded from the probe
by name. A guard whose logic lives entirely inside a test file cannot be
mutation-probed at all.

The detector follows **import-time edges only**. An import inside a
function body runs when the function is called, not when the module is
imported, so it is not an edge the smoke step exercises.

### 3.4 The detector must be tested against crafted workflows

The repository-wide checks read the REAL workflow, which — after the fix
— covers everything. On their own they cannot tell a working detector
from one that never fires.

The tests therefore give the detector **crafted workflow files**: a smoke
step that imports nothing, a step in the wrong working directory, a
component with no smoke step at all, a `from X import Y` command whose
module name is `X` and not `Y`.

**Those tests found a real defect in the detector while being written.**
The first version treated *any* surface step as covering the whole
surface. But a surface step asks the installed distribution which modules
it ships — if it names a **different** distribution (a copy-paste error),
it checks somebody else's surface while looking complete, which is worse
than a step that names too little. The detector now checks the
distribution name, and the crafted test proves a mismatched step covers
nothing.

## 4. What did NOT change

* **No module's content changed.** The fix is to CI configuration and to
  new tests.
* **The runtime's other CI steps are untouched** — install, unit tests,
  the TypeScript face, the CLI smoke, the data-files check.
* **The data-files check stays where it was.** It runs
  `deny_monotonicity` against the *source* tree, because that check is
  about a data file that the wheel must carry; moving it would change
  what it proves.
* **No version change, no tag, no release, no push, no merge.**

## 5. Verification

See the slice report for the full-suite, bench, mutant and fresh-clone
numbers.

## 6. What this slice does not do

* **It does not import every module of the runtime in the CI *test* step.**
  The runtime's 1636 modules are imported against the installed wheel by
  the smoke step; the unit-test suite is unchanged.
* **It does not check the two sidecars.** They ship no wheel, so they
  have no installed surface to check.
* **It does not check the console-script entry points.** The runtime's
  `northstar --version` and `doctor` checks are untouched.
* **It does not add a lint step, a type checker, or a coverage
  threshold.** An import check catches a module that cannot be loaded. It
  does not catch a module that loads and behaves wrongly.
