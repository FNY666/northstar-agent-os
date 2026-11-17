# duplicate-definition — a module must not define the same top-level name twice

**Slice:** `duplicate-definition`
**Date:** 2026-11-17
**Files:**
`components/northstar-agent-runtime/ba_01.py` .. `ba_50.py` (modified),
`tests/test_duplicate_definitions.py` (new),
`docs/design/duplicate-definition.md` (new)

Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. The defect, measured

Fifty of the runtime's shipped modules -- the whole `ba_01`..`ba_50` family
-- carried a duplicated block of source. Each defined `_tests` twice, and
the `if __name__ == "__main__":` block twice, with the second copy
byte-identical to the first.

```
$ cat -n components/northstar-agent-runtime/ba_01.py
     1  """ba_01: add_two utility."""
     2
     3  def add_two(x):
     4      return x + 2
     5
     6  def _tests():
     7      assert add_two(1) == 3
     8      assert add_two(0) == 2
     9
    10  if __name__ == "__main__":
    11      _tests(); print('ok')
    12
    13  def _tests():          <-- the SECOND copy
    14      assert add_two(1) == 3
    15      assert add_two(0) == 2
    16
    17  if __name__ == "__main__":
    18      _tests(); print('ok')
```

### 1.1 What a duplicated definition means in Python

A module's namespace holds **one** entry per name. The second definition
replaces the first: the first is **dead code** that can never be called,
and the only way to know which half is live is to read the file and notice
that the second one wins.

The observable effect is not cosmetic:

```
$ python3 components/northstar-agent-runtime/ba_01.py
ok
ok
```

The module's own self-test runs **twice** on every invocation. Measured for
all 50: `ba_01`..`ba_50` each printed two lines before the fix and one
line after.

### 1.2 The scope is exact

Measured over every `.py` file in the repository -- `components/`, `tests/`,
`tools/`, `scripts/`, `examples/`:

| measurement | value |
|---|---|
| files with a duplicated top-level definition | **50** |
| of which in the runtime's `ba_*` family | **50** |
| of which elsewhere in the repository | **0** |
| duplicates whose bodies are byte-identical | **50** |
| duplicates whose bodies **differ** | **0** |

That last row is the reason the guard has to catch both kinds. A duplicate
whose bodies differ is not untidy -- it is a live definition silently
shadowed by a *different* one, which is the failure a reader cannot see.
The repository contains no such case today; a guard that only handled the
identical case would be one line short of the rule.

### 1.3 How it got in

The files were doubled **from birth**. The commit that added them shipped
each one already doubled:

```
$ git log --diff-filter=A --format='%h %ad %s' --date=short \
    -- components/northstar-agent-runtime/ba_01.py
ada8c1e6 2026-10-09 ba modules

$ git show ada8c1e6:components/northstar-agent-runtime/ba_01.py | cat -n
    13  def _tests():          <-- already doubled in the first commit
```

So no later edit introduced it. Whatever produced these files appended the
self-test block instead of writing it once.

### 1.4 Why it survived

**There is no guard, anywhere, against a duplicated top-level definition.**

The repository has guards for the neighbouring packaging facts:

| guard | where |
|---|---|
| a module declared but absent from disk | `test_every_declared_module_exists_on_disk` |
| a module on disk but not declared | `test_every_component_declares_every_module_it_has` |
| a `py-modules` list that is unsorted or has duplicates | `test_the_py_modules_list_is_sorted_and_deduplicated` |
| the CI compile list and the CI install list disagreeing | `test_the_ci_compile_list_and_the_install_list_agree` |

Every one of them is about a module as a **name in a list**. None of them
is about a module's **contents**. A file can be perfectly declared,
perfectly installed and perfectly documented, and still contain a
definition that can never run.

And the "sorted and deduplicated" guard is worth a note: it applies to the
**interop** component only. The runtime's own `py-modules` list has 50
duplicate entries of its own, and no guard covers it. That list is a
separate defect and is not touched here (see §5).

## 2. The fix

### 2.1 Remove the later duplicate

For each `ba_*.py`, the **second** occurrence of the duplicated top-level
definition is removed, together with the `if __name__ == "__main__":` block
that follows it (that block belongs to the duplicated region -- it calls
the function that was just redefined).

The **first** occurrence is kept, so the live definition is exactly the one
that was live before. The two are byte-identical, so the change is a pure
deletion:

```
$ git diff --stat
 ... ba_50.py | 7 -------
 50 files changed, 352 deletions(-)
```

**352 deletions, 0 insertions.** Nothing was rewritten, reordered or
reformatted.

The removal was done **mechanically**, by a script that parses each file
with `ast`, computes the line ranges to delete from the AST's own line
numbers, re-parses the result, and checks that the module's set of
top-level names is exactly the set it had before. A file is only written
if it parses afterwards and carries no duplicate.

### 2.2 The guard

`tests/test_duplicate_definitions.py` adds a repository-wide check:

> **No module in the repository defines the same top-level name twice.**

It is at the **repository level** (`tests/`), not in a component, because
the rule is about the whole repository: a duplicate in a component's
`tests/` directory is just as invisible as one in a shipped module, and a
guard that only looked at the shipped modules would miss half the
surface.

The check parses each file with `ast`, collects the names of the
top-level `FunctionDef` / `AsyncFunctionDef` / `ClassDef` nodes, and
reports any name that appears more than once -- **naming the file and the
name**:

```
components/northstar-agent-runtime/ba_01.py: defines '_tests' 2 times (identical bodies)
```

Two design points:

* **It is not a rubber stamp.** The test file carries its own tests for
  the detector: an identical duplicate is reported; a duplicate whose
  bodies differ is reported *as differing*; a module without duplicates
  reports nothing; two methods with the same name in two different classes
  is not a duplicate. Each was watched fail before the fix.
* **A scan that finds nothing must not pass vacuously.** A separate test
  asserts that the scan really reaches the repository: more than 1000
  files, including `ba_01.py` and the repository's own test files.

### 2.3 The guard proves the repair, not just the absence

The first version of the test read the modules as **text**. The mutant
probe found the gap immediately -- it mutates the module under test and
runs the test file, and a test that never imports the module cannot
detect anything:

```
MUTANT eq@7 SURVIVED (== -> !=)
MUTANT eq@8 SURVIVED (== -> !=)
MUTANT eq@10 SURVIVED (== -> !=)
MUTANT RESULT: killed 0/3
```

So three more tests were added, and they **import and run** the repaired
modules:

* each still exposes exactly one public callable;
* each still passes its own `_tests()`;
* running each as a script prints exactly **one** `ok` -- the observable
  defect, pinned.

With them the probe kills the mutant in the slice's own code:

```
MUTANT eq@7 KILLED (== -> !=)
MUTANT RESULT: killed 1/1
```

## 3. What did NOT change

The `ba_*` modules are **deliberate**. `docs/design/exclusion-reasons.md`
says so:

> `ba_*` and `sm2_*` are the same kind of thing -- scratch utility modules
> from the mock batches (`ba_01` is `add_two`; `sm2_01` is `reverse_str`).

Nothing here removes them, renames them, changes their public function, or
changes what they compute. Measured for all 50 modules, before against
after:

* the **set** of top-level names is identical;
* every public function returns the same value for the same input;
* every module's own `_tests()` still passes.

The only difference is that the self-test now runs once instead of twice.

The `sm2_*` family -- the other scratch-utility family -- was already
clean and is untouched.

## 4. Verification

See the slice report for the full-suite, bench, mutant and fresh-clone
numbers.

## 5. What this slice does not do

* **It does not remove the 50 duplicate entries from the runtime's
  `py-modules` list.** That tail (`ba_01`..`ba_50` appearing twice in the
  array) is pre-existing, harmless to packaging -- setuptools deduplicates,
  measured: the wheel carries 1636 distinct `.py` entries and no duplicate
  -- and the slice before last
  (`runtime-registration-closure`) explicitly declined to touch it as out
  of scope. Removing it is a `pyproject.toml` change, and this slice does
  not authorise one.
* **It does not add a sorted-and-deduplicated guard for the runtime's
  `py-modules` list.** The interop component has one; the runtime does not.
  That is a real gap and it is a separate defect.
* **It does not lint for anything else.** The rule here is one rule:
  a top-level name is defined twice. It is not a style checker and does
  not pretend to be.
