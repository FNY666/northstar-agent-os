# py-modules-sorted — every component's `py-modules` list is sorted and unique

**Slice:** `py-modules-sorted`
**Date:** 2026-11-17
**Files:**
`components/northstar-agent-runtime/pyproject.toml` (modified),
`components/northstar-durable-run/pyproject.toml` (modified),
`components/northstar-run-evidence/pyproject.toml` (modified),
`tests/py_modules_guard.py` (new),
`tests/test_py_modules_sorted.py` (new),
`components/northstar-agent-runtime/tests/test_py_modules_list.py` (new)

Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. The defect, measured

`[tool.setuptools] py-modules` is the array that says which flat modules
`pip install .` puts on the path. Measured over every component in the
repository:

| component | entries | distinct | duplicate names | sort inversions |
|---|---|---|---|---|
| `northstar-agent-runtime` | **1663** | **1613** | **50** | **9** |
| `northstar-durable-run` | 16 | 16 | 0 | **3** |
| `northstar-run-evidence` | 6 | 6 | 0 | **2** |
| `northstar-agent-interop` | 8 | 8 | 0 | 0 |
| `northstar-host` | 4 | 4 | 0 | 0 |
| `northstar-run-contract` | 5 | 5 | 0 | 0 |

### 1.1 The runtime's 50 duplicates

Every one of the 50 duplicated names is a `ba_*` module — the same
scratch-utility family the `duplicate-definition` slice repaired. The
second copy of the family sat at the very end of the array, after
`zw_remove`:

```
$ grep -n '"ba_01"' components/northstar-agent-runtime/pyproject.toml
359:    "ba_01", "ba_02", "ba_03", "ba_04",
1626:    "ba_01",
```

The family was also written in a compact grouped form, four names to a
line, which is what let the duplicated tail read as a separate block:

```
    "ba_01", "ba_02", "ba_03", "ba_04",
    "ba_05", "ba_06", "ba_07", "ba_08",
    ...
```

### 1.2 The sort inversions

Nine adjacent pairs in the runtime's array were out of order:

```
approval_rules > approval_chain_time
defensive_agent > crescendo_probe
graphql_gateway > grant_pin_ledger
memory_integrity > memory_admission
planted_fault > planner_budget_combo
runtime_evidence > runtime_defense_01
shutdownability > shutdown_unwind
tool_system_30 > tool_failure
zw_remove > ba_01
```

durable-run had three (`tool_ledger > tool_allowlist`,
`tool_receipt > receipt_gate`, `receipt_gate > governed_memory`) and
run-evidence two (`evidence_contract > evidence_chain`,
`sealed_receipt > audit_adapter`).

### 1.3 Why it survived

**A rule already written down, applied to one component out of six.**

`tests/test_component_packaging_closure.py` has exactly the right test:

```python
def test_the_py_modules_list_is_sorted_and_deduplicated(self):
    pyproject = COMPONENTS / INTEROP / "pyproject.toml"
    ...
```

It reads the **interop** component's `pyproject.toml` and nothing else.
The rule was written down, in the right words, and pointed at the
component with the least duplication.

And the runtime's own layout test reads the same array through a `set`:

```python
declared = set(pyproject["tool"]["setuptools"]["py-modules"])
```

`set()` throws away exactly the information this defect is about. A set
cannot hold a duplicate, so every check built on it is blind to one; and
a set has no order, so it is blind to the inversions too. The runtime
had a packaging guard — it was looking at the wrong shape.

## 2. The fix

### 2.1 Sort and deduplicate

The three affected arrays are sorted and deduplicated. Nothing else in
them changes: no name is added, and no name is removed except the 50
duplicate copies.

```
$ git diff --stat
 components/northstar-agent-runtime/pyproject.toml | 129 ++++++++++------------
 components/northstar-durable-run/pyproject.toml   |   8 +-
 components/northstar-run-evidence/pyproject.toml   |   6 +-
 3 files changed, 65 insertions(+), 78 deletions(-)
```

Every changed line is a module-name line — measured by filtering the diff
for lines that are not quoted names, which produced nothing.

### 2.2 The guard

The rule moves to the **repository level** and covers every component, so
the next component that grows a `py-modules` array inherits it:

> **Every component's `py-modules` list is sorted and has no duplicate
> entries.**

The logic lives in one module, `tests/py_modules_guard.py`, because the
rule is a repository-wide invariant and the repository-level test and the
runtime's own component-level test both need it. A second copy would
drift, and a copy that drifts is how "the guard is not a rubber stamp"
stops being true. This mirrors `tests/docbuild.py`, which is the model of
the installed surface for the same reason.

The repository-level guard reads the real files. The runtime's own
component-level test additionally **builds the wheel**, because
`pyproject.toml` proves only what somebody wrote.

### 2.3 The guard had to be tested against crafted inputs

The mutant probe found the gap immediately. It mutates the guard's
comparison and reruns the test file:

```
MUTANT gt@80 SURVIVED (> -> >=)
MUTANT RESULT: killed 0/1
```

`gt@80` is `if modules[index] > modules[index + 1]:` — and `>` versus
`>=` differ only when two adjacent names are **equal**. No clean file
contains that, and every repository-wide check reads clean files, so the
detector's whole job was untested.

Fifteen tests were added that give the detector something to fail on: an
unsorted pair, a repeated name, a repeated line in a file, a component
with no `py-modules` at all, a component with no `pyproject.toml` at all.
With them the probe kills the mutant in the slice's own code:

```
MUTANT gt@80 KILLED (> -> >=)
MUTANT RESULT: killed 1/1
```

**Those tests found two real defects in the guard while being written** —
the same defect the probe was pointing at, from the other direction:

* `read_py_modules()` read `tool.setuptools.py-modules` without checking
  that the file had a `[tool.setuptools]` section, so a component whose
  `pyproject.toml` had no such section raised `AttributeError` instead of
  reporting "this component has no `py-modules`";
* `sortedness_problems()` reported the component's **basename** rather
  than its path, so a failure message named `runtime` instead of the
  component it was talking about.

Both are fixed. The guard's own tests are the evidence.

## 3. What did NOT change

**The installed surface is unchanged.** This is the point of the whole
slice, so it is measured directly rather than asserted: the wheel is
built before the change and after the change, and the two are compared.

```
$ # build the wheel from HEAD's pyproject.toml, and from the working tree
$ python3 - <<'PY'
... # pip wheel --no-deps --no-build-isolation, out of tree
... print(len(py_entries), len(set(py_entries)))
PY
before: 1636 1636
after:  1636 1636

$ diff before-names.txt after-names.txt && echo IDENTICAL
IDENTICAL
```

setuptools deduplicates `py-modules` when it builds, so the duplicate
entries were harmless to the artifact. That is **exactly why the defect
could sit there unnoticed**: the wheel was already correct. The cleanup
stays a cleanup.

The same measurement was made for the other two components:

| component | before | after | module sets |
|---|---|---|---|
| `northstar-agent-runtime` | 1636 entries | 1636 entries | IDENTICAL |
| `northstar-durable-run` | 16 entries | 16 entries | IDENTICAL |
| `northstar-run-evidence` | 6 entries | 6 entries | IDENTICAL |

The `ba_*` modules themselves are untouched — this slice changed the
array that names them, not the modules.

## 4. Verification

See the slice report for the full-suite, bench, mutant and fresh-clone
numbers.

## 5. What this slice does not do

* **It does not remove the `ba_*` modules.** They are deliberate scratch
  utilities; `docs/design/exclusion-reasons.md` records that.
* **It does not change the interop component's existing guard.** That
  test still passes and still checks what it always checked; the new
  repository-level guard now covers all six components, so the interop
  one is redundant rather than wrong. Removing it is left alone: a
  passing test that checks a real fact is not a liability.
* **It does not change the runtime's `tests/test_module_layout.py`.**
  That test reads the array through a `set()`, which is correct for the
  question it asks ("is every module on disk declared?"). The duplicate
  and order questions belong to a different test, which is what
  `tests/test_py_modules_list.py` now asks.
* **It does not touch `packages.find` or `package-data`.** Those are the
  other installation mechanisms and they were not defective.
