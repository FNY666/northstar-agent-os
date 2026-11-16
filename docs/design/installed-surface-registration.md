# installed-surface-registration — the registry must name what is installed

Module: `components/northstar-agent-runtime/runtime_registration.py`
(modified — **no new module**, so the packaging registration does not apply)
Tests: `components/northstar-agent-runtime/tests/test_installed_surface_registration.py`
(new), plus `test_runtime_registration.py`, `test_registration_closure.py` and
`test_module_layout.py` (modified)
Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. What was missing (read from the code, not from the ledger)

`runtime_registration.py` is the runtime's single source of truth for which
modules are runtime modules.  It has to agree with two other views:

```
registry  <->  pyproject.toml's `py-modules`  <->  the `*.py` on disk
```

and `assert_registration_matches_disk()` is the check that enforces the
three-way agreement.  The `runtime-registration-closure` slice built it and
closed it, and the closure test passes.

**All three views are blind to the package members.**

`py-modules` lists **flat** module names only:

```toml
[tool.setuptools]
py-modules = [ "_domain_base", "_version", ... ]   # 1613 flat names
```

A package's members cannot appear there.  setuptools installs them through a
second mechanism:

```toml
[tool.setuptools.packages.find]
where = ["."]
include = ["providers*", "tools*"]
```

So the runtime ships **22 package members** that `pip install .` puts on the
path and that `from tools.shell import ...` imports — and that no view of the
registration closure could see.

### 1.1 The measurement, before any change

```
$ PYTHONPATH=. python3 - <<'PY'
import runtime_registration as rr
reg = {r.module for r in rr.REGISTRY}
print("registry:      ", len(reg))
print("flat py-modules:", len(rr.declared_py_modules()))
print("package members:", len(rr.package_members_on_disk()))
print("installed:      ", len(set(rr.declared_py_modules()) | set(rr.package_members_on_disk())))
print("installed but not registered:", len(
    (set(rr.declared_py_modules()) | set(rr.package_members_on_disk())) - reg))
PY
registry:       1613
flat py-modules: 1613
package members:   22
installed:       1635
installed but not registered: 22
```

The 22 are:

```
providers.__init__   providers.anthropic        providers.base
providers.http_response_limits                  providers.openai_compat
providers.scripted    tools.__init__             tools.capdrop
tools.code            tools.effect_envelope      tools.fetch
tools.os_sandbox      tools.parallel             tools.path_integrity
tools.pledge          tools.resource_limits      tools.sandbox
tools.seccomp         tools.shell                tools.skill_scripts
tools.systemd_scope   tools.verify_invariants
```

These are not incidental modules.  `tools.shell` is the governed command
executor; `tools.sandbox` is the Landlock self-sandbox; `tools.seccomp` is the
seccomp denylist; `tools.pledge` is the pledge-style self-restriction;
`providers.base` holds the message vocabulary every provider derives from.
The registry that is supposed to name *every runtime module* named none of
them.

### 1.2 The hole was in the registry's *ability*, not just its contents

The registry could not name a package member even if it wanted to.  The
constructor validated the name with `str.isidentifier()`:

```python
if not module.isidentifier():
    raise ValueError("module name %r is not an importable identifier" % (module,))
```

and `tools.shell` is not an identifier:

```
>>> rr._registration("tools.shell", "s", "2026-11-16", "d")
ValueError: module name 'tools.shell' is not an importable identifier
```

So this was not an omission that a careful slice would have caught.  The
registry's data model could not express a package member at all.

### 1.3 Why the gap was invisible

The closure slice framed the registry as *top-level* modules, and says so in
its design doc:

> **`module`** | the importable top-level name | the file stem

A package member is importable, and it is a runtime module, but it is not
top-level — so the framing excluded 22 modules by definition, and no test
could have complained.

### 1.4 The same blind spot was in the layout test

`tests/test_module_layout.py::test_every_module_is_installed` states the rule
"every module is installed".  It reads `py-modules` and the flat `*.py`
files, so the rule it stated could not cover a package member either.  The
rule was true and incomplete at the same time.

## 2. The rule this slice pins

> **The registration closure covers the whole installed surface — flat
> modules and package members alike.**

```
registry  ==  installed  ==  (py-modules  ∪  package members)

installed  ⊆  disk
```

## 3. What changed

### 3.1 `runtime_registration.py` — the registry can name a package member

`_is_importable_module_name()` replaces the bare `isidentifier()` check.  It
accepts a dotted name whose every segment is a valid identifier, and refuses
everything else (an empty segment, a path, whitespace).  The check is
*structural* rather than "does it import": it must never execute component
code, and it must never let a name smuggle a path.

### 3.2 `runtime_registration.py` — the installed surface is derivable

Five new functions, all reading the packaging configuration rather than a
hand-maintained list:

| function | what it answers |
|---|---|
| `declared_package_patterns(pyproject)` | the `packages.find` `include` patterns |
| `package_members_on_disk(component, pyproject)` | the installed members of those packages |
| `flat_modules_on_disk(component)` | the flat `*.py` files (the old `modules_on_disk`) |
| `modules_on_disk(component, pyproject)` | **both** shapes — every runtime module on disk |
| `installed_modules(component, pyproject)` | what `pip install .` puts on the path |
| `assert_registration_matches_installed(component, pyproject, registry)` | the closure check over that surface |

A package added to `pyproject.toml`'s `include` is covered **automatically** —
there is no second list of package names to keep in step, which is the shape
of the defect this slice fixes.

`modules_on_disk()` keeps its name and now returns the package members too.
That is a deliberate widening: the old name said "the `*.py` files", and the
new one says "the runtime modules on disk", which is what every caller
actually meant.

### 3.3 `runtime_registration.py` — the closure check is now a four-way agreement

`assert_registration_matches_disk()` compares four views instead of three,
and names each failure direction:

* a module on disk but not registered;
* a registry entry not installed;
* a module on disk but in neither installation mechanism;
* a `py-modules` entry with no file;
* **a package member on disk but not installed**;
* **an installed module not in the registry** — the direction this slice
  closes;
* **a registry entry that names no module on disk**.

`assert_registration_matches_installed()` is the narrower check: the registry
must cover every installed module.  It exists separately because it is the
invariant that matters — "the registry names everything `pip install .`
ships" — and it is the one a reader can state in one sentence.

### 3.4 The registry gains the 22 package members

Each entry's metadata is **derived**, not invented:

* `module` — the importable name (`tools.shell`);
* `registered_on` — the date of the commit that **first added the file**
  (`git log --diff-filter=A`), which is the date the module entered the
  installed surface;
* `slice_slug` — the subject of that commit, reduced to a slug, using the
  same reduction rules the closure slice documented;
* `description` — the module's own docstring, first sentence.

The registry stays sorted by module name and free of duplicates: 1613 → 1635
entries, and the two tests that check those properties still pass.

### 3.5 The layout test learns about packages

`test_module_layout.py` gains two methods: `test_every_package_member_is_installed`
(the packaging configuration must *select* every package directory on disk)
and `test_every_installed_package_member_is_registered`.  The existing
`test_every_module_is_installed` is unchanged — it is still true of the flat
half.

### 3.6 The three existing registration test files

Their invariant legitimately changed, so they were updated rather than
weakened:

| test | was | now |
|---|---|---|
| `test_runtime_registration.py::test_every_registered_module_is_declared_in_py_modules` | registry ⊆ `py-modules` | registry ⊆ **installed** |
| `test_registration_closure.py::test_every_module_on_disk_is_in_py_modules` | on disk ⊆ `py-modules` | on disk ⊆ **installed** |
| `test_registration_closure.py::test_every_registry_entry_is_in_py_modules` | registry ⊆ `py-modules` | registry ⊆ **installed** |

Each was updated for the same reason and with the same reasoning: the rule
was "every module is *installed*", and `py-modules` was only ever the flat
half of how a module gets installed.

## 4. Verification

See the slice report (`b173-installed-surface-registration-cc-final.txt`) for
the full-suite, bench, mutant and fresh-clone numbers.

### 4.1 RED, then GREEN

The three methods that exercise the new behaviour were written before the
implementation and watched fail for the right reason:

```
FAIL: test_the_runtime_ships_package_members_that_the_registry_cannot_name
  Lists differ: ['providers.__init__', 'providers.anthropi[413 chars]nts'] != []
FAIL: test_the_check_names_an_unregistered_package_member
  False is not true : the registration module has no installed-surface check
FAIL: test_the_layout_test_rule_covers_the_packages
  'packages' not found in '...' : the layout test does not mention packages
  at all, so its 'every module is installed' rule cannot cover a package
  member
Ran 6 tests ... FAILED (failures=3)
```

The first three of those were *characterization* tests — they pinned the
defect.  They were rewritten to pin the **fixed** invariant once the fix was
in, which is the honest order: a test that states the desired behaviour must
fail against the unfixed code, and the fixed code must satisfy it.

### 4.2 The mutant probe

The referee plants small semantic faults in the module the slice changed
(`runtime_registration.py`) and runs the slice's own tests against them.  The
probe's candidate sites in that file are five:

```
bool 55  if not isinstance(name, str) or not name:      <- the slice's new code
bool 92  if not isinstance(value, str) or not value.strip()
bool 1853 if path.is_file()
cmp 126  if self.as_dict() == other.as_dict()
cmp 1816 if record.module == module:
ret 56   return False                                     <- the slice's new code
```

The result:

```
MUTANT or@55 KILLED (or -> and)
MUTANT RESULT: killed 1/1
```

and at maximum depth (`--tries 3000 --no-early-stop`):

```
MUTANT RESULT: killed 5/5
```

Both of the slice's own candidates are killed, and so are the three
pre-existing ones.

### 4.3 The API page

`runtime_registration.py` is a published module, so its new public functions
appear in `docs/api/northstar-agent-runtime.md`.  The page is regenerated;
the other seven pages are byte-identical.
