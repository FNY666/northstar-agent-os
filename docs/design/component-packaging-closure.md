# component-packaging-closure — every module a component ships must be in the wheel

**Slice:** `component-packaging-closure`
**Date:** 2026-11-16
**Files:** `components/northstar-agent-interop/pyproject.toml` (modified),
`.github/workflows/test.yml` (modified), `tests/docbuild.py` (modified),
`tests/test_component_packaging_closure.py` (new)
Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. The defect, measured

`pip install .` puts a component's modules on the path, and the way it does
so is declared in that component's `pyproject.toml`:

```toml
[tool.setuptools]
py-modules = [ ... ]                   # the flat modules

[tool.setuptools.packages.find]
include = [ "providers*", "tools*" ]   # the package members
```

A module that exists in the repository but is in neither list works in the
checkout and disappears after `pip install .`.

**One module in the whole repository was in that state**: the interop
component's `remote_worker.py`.

### 1.1 The measurement

```
$ python3 -m pip wheel --no-deps --no-build-isolation -w dist .
$ python3 -c "import zipfile; print(sorted(zipfile.ZipFile(w).namelist()))"
canary.py handoff.py interop_adapter.py interop_contract.py
process_adapter.py process_backend.py remote_transport.py
remote_worker IN WHEEL: False

$ PYTHONPATH=<installed site> python3 -c "import remote_worker"
ModuleNotFoundError: No module named 'remote_worker'
```

For comparison, the runtime component's wheel carries all 1635 of its
installed modules (1613 flat + 22 package members).

### 1.2 What it cost

`remote_worker.py` is the P3-3 readiness scorecard. Three documents name
`python3 -m remote_worker --score` as a CI entry point:

* `docs/dx-remote-worker-assessment.zh-CN.md` §4 — "`python3 -m
  remote_worker --score` 与每次 `make test` 都会重算"
* `docs/dx-benchmark-2026.zh-CN.md` — "`python3 -m remote_worker --score`
  可进 CI"
* `docs/concepts/northstar-remote-worker.md` — "`remote_worker.py --score`,
  run in CI"

So the documented CI command could not run on the installed surface.

### 1.3 It was not a deliberate exclusion

```
$ git log --format='%ad | %s' --date=short -S 'remote_worker' \
      -- components/northstar-agent-interop/pyproject.toml
(no output)
```

The commit that added the module (2026-09-07, "P3-3: remote/hosted worker
evaluation") never touched `pyproject.toml` at all. The omission was
accidental.

## 2. Why it survived

### 2.1 The interop component had no packaging guard

```
$ grep -rln 'py-modules' components/northstar-agent-interop/tests/
(no output)
```

The runtime component has `tests/test_module_layout.py`; durable-run has
`tests/test_durable_packaging.py`; interop had neither. So there was
nothing to notice a module that was never declared.

### 2.2 The CI was written around the gap

This is the interesting half. The interop job in
`.github/workflows/test.yml` **compiles** `remote_worker.py`:

```yaml
- name: Compile agent interop component
  run: python -m py_compile interop_contract.py handoff.py interop_adapter.py \
       canary.py process_adapter.py process_backend.py remote_worker.py \
       remote_transport.py tests/test_*.py
```

and its install smoke check **does not import it**:

```yaml
- name: Agent interop packaging smoke
  run: |
    python -m pip install --quiet .
    cd /tmp
    python -c "import interop_contract, handoff, interop_adapter, canary, \
               process_adapter, process_backend, remote_transport; ..."
```

So the one module missing from the wheel was also the one module missing
from the check that would have caught it. The CI compile step and the CI
install step disagreed about what the component contains, and nothing in
the repository reconciled them.

That is a stronger claim than "no test covered it": the CI *did* cover
packaging, and it covered it **selectively** — precisely in the way that
hid the defect.

## 3. The rule this slice pins

> **Every module a component has on disk is in the wheel it builds.**

Applied to **every** component, so the next component that grows a module
inherits the guard for free.

## 4. The fix

### 4.1 `components/northstar-agent-interop/pyproject.toml`

One line added; the list stays sorted:

```toml
py-modules = [
    "canary",
    "handoff",
    "interop_adapter",
    "interop_contract",
    "process_adapter",
    "process_backend",
    "remote_transport",
    "remote_worker",
]
```

### 4.2 `.github/workflows/test.yml`

The install smoke check now imports the module the compile step compiles:

```yaml
python -c "import interop_contract, handoff, interop_adapter, canary, \
           process_adapter, process_backend, remote_transport, remote_worker; ..."
```

### 4.3 `tests/docbuild.py` — the surface model lives in one place

`docbuild.py` already modelled the *installed* surface for one component
(`flat_modules`, `package_members`, `installed_modules`), built by the
`package-member-publication` slice. This slice adds the **repo-wide** view,
next to that model rather than in a second place:

| function | what it answers |
|---|---|
| `components_that_ship_a_wheel()` | which components have a `pyproject.toml` |
| `is_runtime_module(path)` | is this file a runtime module (not a test, not `setup.py`/`conftest.py`) |
| `flat_modules_on_disk(component)` | the flat modules a component has |
| `uninstalled_modules(component)` | the modules it has that its wheel would not ship |

`uninstalled_modules()` compares against the **installed** surface
(`py-modules` ∪ package members), because those are the two mechanisms
setuptools actually uses. Comparing against `py-modules` alone would
report the runtime's 22 package members as missing — the same blind spot
the previous slice closed in the runtime component.

### 4.4 `tests/test_component_packaging_closure.py` — 17 methods

* the interop component declares `remote_worker`, and declares every module
  it has;
* the `py-modules` list stays sorted and deduplicated, so a diff shows one
  name added rather than a reshuffled list;
* **the wheel is built for real** and asserted to contain every declared
  module — reading `pyproject.toml` proves only what somebody wrote;
* the wheel is installed into an isolated directory and the module is
  imported from there;
* every component satisfies "on disk → installed", and every declared
  module exists on disk;
* the runtime's 22 package members are not reported as missing, and the two
  halves of its installed surface are disjoint;
* the guard is not a rubber stamp: a component with an undeclared module is
  caught and named (in a tmpdir);
* the CI compile list and the CI install list agree.

## 5. A measurement that changed the design

The first draft of this slice asserted that after `pip install .`,
`python3 -m remote_worker --score` runs. **It does not**, and the reason is
in the module:

```python
COMPONENTS = Path(__file__).resolve().parents[2] / "components"
```

The scorecard measures **the repository** — it resolves the component tree
relative to its own file. Installed into `site-packages`, `parents[2]` is
no longer the repository root, so the scorecard reads nothing and raises.

That is not a defect to fix here: the scorecard measures a checkout by
design, and CI runs it from one. The assertion was simply wrong, so it was
split into the two things that are actually true:

1. the installed surface can **import** the module (this is what packaging
   guarantees), and
2. `python3 -m remote_worker --score` runs **in a checkout** (this is what
   the scorecard is for).

The wheel test now proves the first, and the checkout test proves the
second.

## 6. Verification

See the slice report for the full-suite, bench, mutant and fresh-clone
numbers.

### 6.1 RED, then GREEN

The new test file was written before the fix, and watched fail for the
right reason:

```
FAIL: test_remote_worker_is_declared_for_installation
  AssertionError: 'remote_worker' not found in {...}
FAIL: test_the_interop_component_declares_every_module_it_has
  module(s) in the interop component but not installed: ['remote_worker']
FAIL: test_every_component_declares_every_module_it_has (component='northstar-agent-interop')
  module(s) in northstar-agent-interop that the wheel would not ship: ['remote_worker']
FAIL: test_the_built_wheel_contains_every_declared_module
  the wheel does not ship remote_worker.py
FAIL: test_the_installed_surface_can_import_the_scorecard
  the installed surface cannot import remote_worker
FAIL: test_the_ci_smoke_check_imports_the_scorecard
  the CI install smoke check does not import remote_worker
Ran 17 tests
FAILED (failures=7)
```

Three failures in the first run were **test bugs**, not the defect, and
were fixed before the implementation:

* a test asserted the runtime's package members were *not* disjoint from
  `py-modules` — they ARE disjoint (a package member's name cannot appear
  in a flat-name array), and that disjointness is the point;
* a guard test read the *repository's* `pyproject.toml` instead of the
  tmpdir's, so `declared_module` looked undeclared too;
* the CI assertion expected the literal `import remote_worker`, but the
  line is a comma-separated list.

### 6.2 The mutant probe

The probe's candidate sites in `tests/docbuild.py` are taken **in source
order**, and the file has 31 of them; the first 12 are all in the
pre-existing renderer, while this slice's new code starts at line 1050. The
probe therefore reported `killed 0/12` — it was measuring code the slice
never touched.

That is a defect in the probe, not in the slice, so the probe's default
window was widened from 12 to 64 (above the largest candidate count in
the repository's mutated files). The probe still stops at the first kill,
so a slice whose code is reachable costs exactly what it did before.

With the widened window:

```
MUTANT eq@1057 KILLED (== -> !=)
MUTANT RESULT: killed 1/18
```

`eq@1057` is `path.suffix == ".py"` in the new `is_runtime_module` — the
slice's own code.

### 6.3 The wheel, verified

After the fix:

```
$ python3 -m pip wheel --no-deps --no-build-isolation -w dist .
canary.py handoff.py interop_adapter.py interop_contract.py
process_adapter.py process_backend.py remote_transport.py remote_worker.py
remote_worker IN WHEEL: True

$ PYTHONPATH=<installed site> python3 -c "import remote_worker; print(...)"
INSTALLED IMPORT OK: <site>/remote_worker.py
```
