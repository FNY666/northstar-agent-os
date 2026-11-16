# runtime-data-files — every data file a module reads must be in the wheel

**Slice:** `runtime-data-files`
**Date:** 2026-11-16
**Files:**
`components/northstar-agent-runtime/deny_monotonicity.py` (modified),
`components/northstar-agent-runtime/pyproject.toml` (modified),
`components/northstar-agent-runtime/runtime_registration.py` (modified),
`components/northstar-agent-runtime/policy/__init__.py` (new),
`components/northstar-agent-runtime/policy/deny_monotonicity_baseline.json`
(moved from the component root),
`components/northstar-agent-runtime/tests/test_runtime_data_files.py` (new),
`tests/docbuild.py` (modified),
`tests/test_package_member_publication.py` (modified),
`tests/test_component_packaging_closure.py` (modified),
`.github/workflows/test.yml` (modified)

Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. The defect, measured

`pip install .` installs **modules**. Both of setuptools' mechanisms are
module-shaped:

```toml
[tool.setuptools]
py-modules = [ ... ]                   # flat .py modules

[tool.setuptools.packages.find]
include = [ "providers*", "tools*" ]   # package members
```

A **data file** — a `.json` or `.toml` a module reads at runtime — is in
neither mechanism. It exists in the checkout and disappears after
`pip install .`.

### 1.1 The measurement

```
$ python3 -m pip wheel --no-deps --no-build-isolation -w dist .
$ python3 -c "import zipfile; print([n for n in z.namelist()
                                   if not n.endswith('.py') and 'dist-info' not in n])"
[]                       <-- the wheel carried NO data file at all
```

The runtime component has exactly two data files:

| file | read by | embedded fallback? |
|---|---|---|
| `deny_monotonicity_baseline.json` | `deny_monotonicity.py` | **no** |
| `policy/dataflow.toml` | `dataflow_policy.py` | yes (`_DEFAULT_POLICY_TOML`) |

### 1.2 What it cost

`deny_monotonicity.py`'s docstring calls it "Deny-monotonicity check for
the **governance bench**", and it **fails closed by design**:

> A missing baseline fails closed: without a pin there is nothing to be
> monotone against, so the bench must not silently pass.

Measured on the installed surface:

```
$ cd <installed site> && python3 -c "import deny_monotonicity as dm;
    print(dm.baseline_path().exists()); print(dm.deny_monotonicity_check())"
False
(False, 'deny-monotonicity baseline missing: regenerate with
 deny_monotonicity.regenerate_baseline() after review')
```

The same call in the checkout:

```
(True, 'deny-monotonicity holds: 5 denials, 0 added since baseline, 0 lost')
```

So on every installed surface the check **cannot pass**, no matter what the
gate does. And CI's "Installed full benchmark smoke" runs `northstar
bench --json` from `/tmp`, i.e. against the installed surface.

The dataflow policy was already correct — its embedded copy is byte-identical
to the shipped TOML, and `tests/test_dataflow_policy.py::
test_default_policy_matches_shipped_toml` pins that. Measured: six sources
and six sinks in both places.

### 1.3 Why it survived

The same shape as the previous slice (`component-packaging-closure`): **the
guards looked at modules, not at data files.**

* `tests/docbuild.py`'s `flat_modules` / `package_members` /
  `installed_modules` count `.py` files only.
* `tests/test_component_packaging_closure.py` really builds the wheel, but
  asserts only that every *declared module* is in it.
* CI's "Packaging smoke" imports modules and nothing else.

So "the wheel carries no data file at all" had never been checked.

## 2. The mechanism: why the obvious options do not work

Measured on this machine (setuptools 78.1.1) and, where it matters, on the
CI's build-isolation setuptools (84.2.1):

| option | result |
|---|---|
| `py-modules` | installs `.py` files only — a `.json` beside them is not copied (measured: a test wheel contained only `mod_a.py`) |
| `[tool.setuptools] data-files = ["."]` | **invalid** on this setuptools: `configuration error: tool.setuptools.data-files must be object`. With the object form it installs into `sys.prefix`'s data directory — not next to the module, so `Path(__file__).with_name(...)` still finds nothing, and it pollutes a path outside the package |
| `package-data` | **works** — `[tool.setuptools.package-data]` names a package and globs inside it, and the files land in the wheel at the package's path |

So the fix uses the mechanism the component already has: a **package**
directory, with `package-data` naming its contents.

## 3. The fix

### 3.1 `policy/` becomes a package

`policy/` already held `dataflow.toml`, read by
`dataflow_policy.py` as `Path(__file__).resolve().parent / "policy" /
"dataflow.toml"`. It becomes a real package (`policy/__init__.py`), and
the deny-monotonicity baseline moves into it.

```toml
[tool.setuptools.packages.find]
where = ["."]
include = ["providers*", "tools*", "policy*"]

[tool.setuptools.package-data]
"policy" = ["*.toml", "*.json"]
```

`deny_monotonicity.py` resolves the baseline there instead of beside
itself:

```python
def baseline_path() -> Path:
    return Path(__file__).resolve().parent / "policy" / BASELINE_FILENAME
```

### 3.2 Why a real package and not a namespace directory

`policy/` could have stayed a directory with no `__init__.py`. setuptools'
`find_namespace_packages` finds it, `package-data` ships its files, and the
installed surface imports `policy` as a namespace package. **Measured —
that route works too.**

It was rejected on a measured ground: a namespace directory puts a
top-level name (`policy`) on `sys.path` that the registry does not name.
`runtime_registration.assert_registration_matches_installed()` requires
the registry to cover the whole installed surface, and slice 6
(`installed-surface-registration`) exists precisely because a registered
surface that could not name its own modules was a live hazard. A namespace
directory would have re-created that hazard for one directory to save one
registry entry.

So `policy/__init__.py` exists, and `policy.__init__` is registered:

```python
_registration("policy.__init__", "runtime-data-files", "2026-11-16",
              "Runtime data files: the package that ships them in the wheel."),
```

### 3.3 The counts moved, and the tests that pinned them moved with them

The runtime's installed surface is now **1636** (1613 flat + 23 package
members), up from 1635 (1613 + 22). Four tests across three files pinned
the old numbers, and each is updated with the re-measured value and a note
saying why:

* `tests/test_package_member_publication.py` — the published package-member
  count 22 → 23; the installed count 1635 → 1636.
* `tests/test_component_packaging_closure.py` — the same two numbers.

One of those tests was not a count but a **frozen list**, and it is
instructive:

```python
self.assertEqual(sorted(include), ["providers*", "tools*"])
```

Freezing the `include` list meant that *any* slice adding a package to it
had to edit an unrelated test to be accepted. That freeze was the defect:
it made a legitimate packaging change look like a regression. The
assertion now pins the **rule** — every named pattern has modules on
disk, every package member is covered by a pattern, no duplicates — and
reads the list from the configuration instead of restating it.

### 3.4 The CI smoke check now looks at data files

```yaml
python -c "import deny_monotonicity as dm; assert dm.baseline_path().exists(), dm.baseline_path(); ok, msg = dm.deny_monotonicity_check(); assert ok, msg; print('northstar-agent-runtime data files OK')"
```

CI's install smoke check now exercises what the previous one missed: that
the **data** files are there, not only the modules.

## 4. The repo-wide view

`tests/docbuild.py` gains the data-file half of the packaging surface,
next to the module half added by the previous slice:

| function | what it answers |
|---|---|
| `data_files_on_disk(component)` | the data files the component has |
| `installed_data_files(component)` | the data files its wheel ships (via `package-data`) |
| `missing_data_files(component)` | the difference |

The scan covers the **whole component directory**, not only its package
directories — a data file in the component root is in neither installation
mechanism, and that is exactly the shape that slipped through: the
baseline sat next to its module in the component root, where no
`package-data` entry could reach it.

The scan skips `pyproject.toml` (packaging configuration), the
`sdk-ts/` build manifests, `build/`, `dist/` and `tests/`: none of them is
read by a Python module at runtime.

Measured before the fix, against a reconstructed pre-fix tree:

```
PRE-FIX disk   : ['deny_monotonicity_baseline.json', 'policy/dataflow.toml']
PRE-FIX missing: ['deny_monotonicity_baseline.json', 'policy/dataflow.toml']
```

and after it: `missing: []`.

## 5. Verification

See the slice report for the full-suite, bench, mutant and fresh-clone
numbers.

### 5.1 RED, then GREEN

The test file was written before the fix and watched fail for the right
reason — 6 failures, all of them the defect:

```
FAIL: test_the_wheel_carries_the_deny_monotonicity_baseline
  'deny_monotonicity_baseline.json' not found in {...}
FAIL: test_the_wheel_carries_every_data_file_the_modules_read (data_file='deny_monotonicity_baseline.json')
FAIL: test_the_wheel_carries_every_data_file_the_modules_read (data_file='policy/dataflow.toml')
FAIL: test_the_installed_surface_finds_the_deny_baseline
FAIL: test_the_installed_baseline_is_byte_identical_to_the_checkout_one
FAIL: test_the_deny_monotonicity_check_passes_on_the_installed_surface
Ran 12 tests
FAILED (failures=6)
```

Two **test bugs** were found and fixed before the implementation:

* two assertions named the baseline at the **component root**, which is
  where it lived *before* the fix — the wheel path after the fix is
  `policy/deny_monotonicity_baseline.json`;
* the `docbuild` loader raised at decoration time, because `dataclass`
  resolves a decorated class's module by name and the module was not
  registered in `sys.modules`.

### 5.2 The mutant probe

The slice's changed non-test module is
`components/northstar-agent-runtime/deny_monotonicity.py`, and its test
file is `components/northstar-agent-runtime/tests/test_runtime_data_files.py`.
The probe's candidate sites are taken in source order; this module has few
enough of them that the default window reaches its new code.

### 5.3 Two defects the first full-suite run found

The slice was committed and then verified against the **whole runtime
component suite**. That run had 16 failures and 10 errors the baseline
did not have. Two of them were real, and both are recorded here because
both were introduced *by this slice's own test file* — the slice's first
version of the world was not the repo's.

**Defect A: the wheel was built in-tree.**

The first version of the test built the wheel with `pip wheel
<component>`. setuptools runs the build backend with the *source
directory* as the working directory and writes its scratch tree there:

```
<component>/build/bdist.<platform>/wheel/
<component>/<name>.egg-info/
```

That scratch tree is **state**. It is not cleaned between builds, and a
stale `build/bdist.<platform>/wheel/<name>.dist-info` makes every
subsequent in-tree build die:

```
error: [Errno 17] File exists:
  'build/bdist.linux-aarch64/wheel/northstar_agent_runtime-0.1.0.dev0.dist-info'
ERROR: Failed building wheel for northstar-agent-runtime
```

Reproduced directly (the poison is a single stray file in the scratch
tree):

```
$ mkdir -p build/bdist.linux-aarch64/wheel/northstar_agent_runtime-0.1.0.dev0.dist-info
$ python3 -m pip wheel --no-deps --no-build-isolation -w /tmp/w .
error: [Errno 17] File exists: 'build/bdist.linux-aarch64/wheel/northstar_agent_runtime-0.1.0.dev0.dist-info'
exit=1
```

Measured impact on the component's own suite: **7** of this slice's
wheel tests failed on that error, and **10** further errors elsewhere in
the same suite were the same build failure seen from other tests.

The fix is to build **out of tree**: the sources are copied to a scratch
directory first (without `tests/`, `sdk-ts/`, `build/` and `dist/`), and
the wheel is built there. The artifact is then a function of the source
and nothing else, and the checkout is left untouched.

Pinned by `WheelBuildIsolationTests`:

* `test_building_the_wheel_leaves_the_checkout_unchanged` — the build
  writes no `build/` and no `*.egg-info/` into the component. Verified
  RED against the in-tree build (it reported exactly `['build',
  'northstar_agent_runtime.egg-info']`) and GREEN after.
* `test_two_wheel_builds_in_a_row_both_succeed` — two builds in a row
  both succeed and carry the same contents.

**Defect B: the runtime component's own tests pinned 22 package members.**

This slice updated the counts in the **repository-level** `tests/`, and
forgot the runtime component's **own** `tests/`. Two files there pinned
the old numbers:

* `tests/test_installed_surface_registration.py` — `22` package members
  and `1635` installed modules;
* `tests/test_module_layout.py` — the same `22` in prose.

Both are updated to the re-measured `23` and `1636`, with a note saying
why.

**The lesson, and it is the second time in this batch:** a count is
re-measured *wherever it is pinned*. The repository-level suite and the
component-level suite are two different places to pin the same fact, and
fixing one does not fix the other. The first version of this slice
looked at the first and declared the second updated.

### 5.4 What the runtime suite looks like now

Measured, after the two fixes above:

```
Ran 21343 tests in 303.690s
FAILED (failures=16, errors=10, skipped=14)
```

The **failure set is byte-identical to the baseline** — 26 names, compared
on the name part only (unittest's parenthetical suffix carries the test
class, which differs between runs):

```
$ comm -23 new-fails.txt baseline-fails.txt     # NEW  -> (empty)
$ comm -13 new-fails.txt baseline-fails.txt     # GONE -> (empty)
$ diff -q new-fails.txt baseline-fails.txt
IDENTICAL
```

The count is 21343 against the slice-7 baseline's 21326: **+17**, which
is exactly this slice's 17 tests in the component suite (15 for the data
files, 2 for the build isolation).

The first run, before the two fixes, was `Ran 21341 tests` with 25
failures and 10 errors — 16 names beyond the baseline. After the fixes
it is 16 failures and 10 errors, and every one of those 26 names is a
pre-existing baseline failure.

