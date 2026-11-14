# Runtime module registration — the closure and the recurrence guard

**Slice:** `runtime-registration-closure`
**Date:** 2026-11-14
**Files:** `components/northstar-agent-runtime/pyproject.toml`,
`components/northstar-agent-runtime/runtime_registration.py`,
`components/northstar-agent-runtime/tests/test_runtime_registration.py`

## The problem

Every B173 slice added a new top-level module to
`components/northstar-agent-runtime/`. Not one of them added that module
to `pyproject.toml`'s `[tool.setuptools] py-modules` array. The reason is
structural, not accidental: each slice's taskbook listed `pyproject.toml`
as *not* in that slice's writable list, so the slice could not register its
own module even if it wanted to.

The consequence is the failure mode `tests/test_module_layout.py` calls out
by name, in that file's own docstring:

> A module that exists in the repository but is not packaged works in the
> checkout and disappears after ``pip install .`` — the failure mode nobody
> notices until a user hits it, so it is asserted here instead.

`test_every_module_is_installed` has therefore been red for the whole
batch. It is a **baseline** failure — it is present in
`/home/muse-newapi/b173-refusal-row-baseline-failures.txt`, written
before any B173 slice started — which is why every slice's report could
truthfully say "the failure set matches the baseline, no new failures".
The set matched; one of the 28 entries in it was created by the batch.

## The measurement

The diff is computed, not guessed:

```python
declared = set(pyproject["tool"]["setuptools"]["py-modules"])
present  = {p.stem for p in COMPONENT.glob("*.py")
            if p.name not in {"setup.py", "conftest.py"}
            and not p.name.startswith("test_")}
sorted(present - declared)
```

On this branch that returns **44** modules, not the 42 the taskbook
lists. The two extra ones are not new findings but the taskbook going
stale:

| Extra module | Why it is not in the taskbook's list of 42 |
| --- | --- |
| `refusal_hold` | landed in commit `0cae6f95` (`B173 refusal-hold`), after the taskbook was written |
| `runtime_registration` | this slice's own module; a registry that does not register itself has a hole in it |

The taskbook's list of 42 was correct when it was written. The brief's
instruction to "verify with step 1" is what caught the drift.

The reverse direction was checked as the taskbook requires:
`declared - present` is **empty** — no `py-modules` entry names a file
that is no longer on disk, so `test_no_packaged_module_is_missing_from_disk`
needed no fix.

## The fix

### 1. `pyproject.toml` — 44 lines, 0 deletions

The 44 module names are inserted at their alphabetically correct positions
in the array. The diff is `44 insertions(+), 0 deletions(-)`: no other
`pyproject.toml` field changed by one character, which `git diff` shows
directly.

Two properties of the array made a mechanical insert necessary rather than
sufficient:

* the array is **mostly** sorted, but not entirely — eight adjacent pairs
  are out of order (`approval_rules` / `approval_chain_time`,
  `defensive_agent` / `crescendo_probe`, and six more). Those are
  pre-existing and were left alone.
* the array ends with a **duplicate tail**: `ba_01` … `ba_50` appear
  twice, once inside the sorted region and once again as a block of
  one-per-line entries after `zw_remove`. The raw array therefore holds
  1661 entries for 1611 distinct modules. The insert was performed against
  the sorted region only; the duplicate tail was left exactly as it was.

### 2. `runtime_registration.py` — the single source of truth

The registry is **data**, not code:

```python
REGISTRY = (
    _registration("_domain_base", "domain packs", "2026-10-06", "Shared base for the 39 domain packs."),
    _registration("_version", "dx foundations", "2026-09-07", "Single source of truth for the runtime version."),
    ...
    _registration("runtime_registration", "runtime-registration-closure", "2026-11-14",
                  "Single source of truth for runtime module registration."),
)
```

One line per module, four fields:

| Field | Meaning | How it was derived |
| --- | --- | --- |
| `module` | the importable top-level name | the file stem |
| `slice_slug` | the slice that introduced the module | the subject of the commit that added the file, reduced to its slug (`B173 refusal-row: …` → `refusal-row`) |
| `registered_on` | the date the module entered `py-modules` | the date of the commit that first put the name into the `py-modules` array — **not** the date the `.py` file appeared |
| `description` | one sentence on what the module is for | the module's own docstring, first sentence |

Two of those columns are worth spelling out, because they are the ones a
reader might otherwise assume are guesses:

* **`registered_on` is the packaging date, not the authoring date.** For
  the 42 modules this slice registers, the file and the `py-modules` entry
  have different dates: the file landed on 2026-11-13 or 2026-11-14 and
  the entry landed on 2026-11-14, when this slice added it. For the 1567
  pre-existing modules the two dates usually coincide.
* **`slice_slug` is reduced, not truncated.** The reduction rules are
  ordered: a `B173 <slug>:` prefix wins, then a `P<n>-<slug>:` prefix,
  then a conventional-commit prefix (whose message is cut at the first
  ` - ` or `, `), then a `… batch` / `… modules` prefix, then a
  `slug: …` prefix, then a `slug - …` prefix. The result is 234 distinct
  slugs over 1611 modules — the big `ba_01`…`ba_50` families share the
  slug `ba`.

### 3. The recurrence guard

```python
def assert_registration_matches_disk(component=COMPONENT, pyproject=PYPROJECT, registry=REGISTRY):
```

Three sets must be equal:

1. the module names in the registry,
2. the module names declared in `pyproject.toml`'s `py-modules`,
3. the `*.py` files in the component directory.

The function raises `RegistrationError` (a subclass of `AssertionError`,
so a caller that only knows about assertions still catches it) and the
message **names every offending module**, sorted:

```
runtime module registration does not match the disk: module(s) on disk but
not in the registry: forgotten_module; module(s) on disk but not in
py-modules: unpackaged_module
```

A guard that fails without naming the module is a guard nobody can act
on, so the four failure directions each have a negative test.

The module reads `pyproject.toml` and never writes it, and never reads the
wall clock: `registered_on` is a field the caller supplies. The registry
is a tuple of frozen records; assigning to a record attribute raises
`AttributeError`, and mutating the tuple raises `TypeError`.

## The tests

`tests/test_runtime_registration.py` — 37 test methods:

* **shape** (7): registry ⊆ `py-modules` item by item, `py-modules` ⊆
  registry, every registry entry exists on disk, no duplicates, sorted,
  registry == disk, and the registry registers itself;
* **metadata** (6): every record has a non-empty slug, a non-empty
  description and an ISO date; a record missing a field, with a malformed
  date, or with a non-identifier name is rejected at construction;
* **immutability** (4): the tuple cannot be mutated, a record attribute
  cannot be reassigned or deleted, the query returns the same tuple;
* **queries** (3): `registration_for` raises `KeyError` naming an
  unregistered module; `declared_py_modules` reads the real
  `pyproject.toml`; `modules_on_disk` excludes the two layout exclusions;
* **equality** (6): equal records compare equal, any differing field
  breaks the comparison, a record is not equal to a non-record, equal
  records hash equally, distinct records do not collapse in a set, and
  `as_dict` reports the four fields;
* **three-way check** (8): the check passes when the three views agree,
  and raises *naming the module* when a file is unregistered, when a file
  is not in `py-modules`, when a registry entry's file is gone, when a
  `py-modules` entry is not registered, when `pyproject.toml` is missing,
  when it has no `py-modules` array, and that `RegistrationError` is
  catchable as `AssertionError`;
* **real repository** (3): the check passes on the real repository, the
  registry knows `refusal_row`, and the registry agrees with the layout
  test.

The negative cases run in a `tempfile.mkdtemp()` directory, never in the
working tree: planting a file in the checkout would leave the next test
run dirty.

### Two findings from the mutation probe

`b173-mutant.sh` plants up to three small semantic faults in the new
module and requires the new tests to catch at least one. The first run
reported `killed 1/3`, and the two survivors were worth reading rather
than re-running:

* **`eq@102` — a real gap.** Nothing asserted that two records with the
  same fields compare equal, that a differing field breaks the
  comparison, or that equal records hash equally. Since the three-way
  check compares records, a broken `__eq__` would have made a broken
  registry look consistent. Closed by the six equality tests.
* **`eq@1768` — not a gap, a trap.** Python reuses a cached `.pyc` when
  the source changes without changing size or second-resolution mtime —
  which is *exactly* what a mutation probe does. The probe mutated the
  file, ran the tests against the stale bytecode, and scored the mutant as
  surviving. The test module now deletes
  `__pycache__/runtime_registration.*.pyc` before importing the module, so
  the tests always run the source that is on disk right now.

After both fixes the probe reports `killed 3/3`.

## What this does not do

* It does not make `pyproject.toml` writable by other slices. The next
  slice still has to edit `pyproject.toml` to register its module; this
  slice makes the *omission* loud instead of silent.
* It does not remove the duplicate `ba_01`…`ba_50` tail from the
  `py-modules` array. That tail is pre-existing, harmless to packaging
  (setuptools deduplicates), and removing it would be a change to
  `pyproject.toml` that this slice's scope does not authorise.
* It does not assert anything about a *live provider*. The check is
  about the shape of the package on disk; nothing here was run against a
  live model.
