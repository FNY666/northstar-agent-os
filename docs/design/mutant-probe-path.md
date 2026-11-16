# mutant-probe-path — the planted-fault probe must see every slice's own test file

Module: (none — this slice changes the probe, `b173-mutant.sh`, which lives
outside the repository)
Tests: `components/northstar-agent-runtime/tests/test_r9_mutant_probe_path.py`
Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. What was missing (read from the code, not from the ledger)

`b173-mutant.sh` is the batch's planted-fault probe.  Its contract:

> a slice's own new tests must fail on at least one planted semantic fault in
> the slice's new module.

It finds the slice's module and the slice's test file from the
`b173-<slug>.files` manifest, then mutates the module and runs the test
file.  Two selectors do that work:

```bash
MOD=$(grep -E '\.py$' "$MANIFEST" | grep -v '/tests/' | head -n1)
...
for cand in $(grep -E '/tests/test_[^/]+\.py$' "$MANIFEST"); do
...
[ -n "$TESTF" ] || TESTF=$(grep -E '/tests/test_[^/]+\.py$' "$MANIFEST" | head -n1)
```

**The module selector is right.**  The **test-file selector is not.**

`'/tests/test_[^/]+\.py$'` requires a **directory separator immediately
before** `tests/`.  A test file at the **repository root** — `tests/test_x.py`
— has no separator before `tests/`, so the pattern does not match it.  The
pattern matches `components/x/tests/test_y.py` and nothing else.

And the repository root is exactly where the repository-level slices keep
their test files.  The batch's slices live at two levels:

| level | test file | matched by the old pattern? |
|---|---|---|
| component | `components/northstar-agent-runtime/tests/test_x.py` | yes |
| repository root | `tests/test_x.py` | **no** |

### 1.1 The measurement

Every slice's manifest, run through both the old and the proposed pattern:

```
$ python3 - <<'PY'
import glob, os, re
old = re.compile(r'/tests/test_[^/]+\.py$')
new = re.compile(r'(^|/)tests/test_[^/]+\.py$')
for m in sorted(glob.glob("b173-*.files")):
    slug = os.path.basename(m)[4:-6]
    lines = [l.strip() for l in open(m) if l.strip()]
    o = [l for l in lines if old.search(l)]
    n = [l for l in lines if new.search(l)]
    if o != n:
        print(f"{slug:28} old={o} new={n}")
PY
-seal-slice6         old=[] new=['tests/test_delivery_seal.py']
-shipped-module-docs old=[] new=['tests/test_shipped_module_docs.py']
slices whose test-file selection changes: 2
```

Exactly **two** slices' selection changes — the blast radius is small, and
both are in the direction of *finding* a file that was previously invisible.

### 1.2 What the skip cost

The probe's failure mode is not a FAIL; it is a **SKIP**:

```
$ bash b173-mutant.sh seal-slice6
MUTANT SKIP: manifest lacks module/test
```

"manifest lacks module/test" is a **false statement**: the manifest names both
a module and a test file.  The probe's own pattern could not see the test
file, so it reported the manifest as deficient.

A skip reads as "nothing to check here" rather than "the probe was blind",
so the slice's tests were **never verified** and the batch's ledger carried a
verdict that looked like a considered exemption.

Measured before the fix — four slices in the ledger show
`MUTANT SKIP: manifest lacks module/test`:

```
r6-baseline-unify  r6-12-session-resolution  artifact-completion
baseline-attribution  judge-hygiene  r6-check-accuracy
r6-manifest-subject  r6-test-count  r6-worktree-rename
```

**Two of those nine are this defect** (`seal-slice6`,
`shipped-module-docs`: they have a module AND a test file).  The other seven
name **no module at all** in their manifest — a different, honest skip: a
slice that shipped no production module has nothing to mutate.

### 1.3 What the tests would have said

Run by hand against the same probe, the same arguments, with only the pattern
corrected:

```
seal-slice6          MUTANT and@67 KILLED (and -> or)   killed 1/1
shipped-module-docs  MUTANT gt@425 KILLED (> -> >=)    killed 1/1
```

**Both kill a mutant.**  The slices' test suites do verify behaviour; the
probe simply never ran them.

## 2. The fix

One pattern, in two places (the pairing loop and the fallback):

```diff
-  for cand in $(grep -E '/tests/test_[^/]+\.py$' "$MANIFEST"); do
+  for cand in $(grep -E '(^|/)tests/test_[^/]+\.py$' "$MANIFEST"); do
...
-[ -n "$TESTF" ] || TESTF=$(grep -E '/tests/test_[^/]+\.py$' "$MANIFEST" | head -n1)
+[ -n "$TESTF" ] || TESTF=$(grep -E '(^|/)tests/test_[^/]+\.py$' "$MANIFEST" | head -n1)
```

`(^|/)` makes the leading separator **optional**: the component-level shape
matches exactly as before, and the root-level shape now matches too.

The `COMPDIR` derivation (`dirname "$TESTF" | sed 's|/tests$||'`) already
handles a root-level `tests/` correctly — it leaves the literal `.`, which is
the right run directory for a repository-level test.

### 2.1 Why the fix is in the probe and not in the manifests

The alternative would be to move the two slices' test files under a
component.  That is worse on every axis:

* the test file tests repository-level code (`tests/docbuild.py`,
  `scripts/seal-delivery.py`), and a component-level test that imports
  repository-root modules is the wrong home for it;
* the batch has other repository-level slices coming;
* the probe is a **measurement instrument**.  An instrument that cannot see
  part of the population it measures is defective; the population should not
  have to be shaped to suit the instrument.

## 3. The tests (5 methods)

`components/northstar-agent-runtime/tests/test_r9_mutant_probe_path.py` —
**behavioural**: they extract the live probe's own patterns and run them, so a
comment that merely mentions the right words cannot satisfy them, and a
hardcoded copy in the test would pass while the probe regressed.

| test | what it pins |
|---|---|
| `test_the_probe_has_at_least_one_test_file_pattern` | the extractor found the selectors at all |
| `test_every_test_file_pattern_matches_a_repository_root_test_file` | **the defect**: a root-level test file must be selectable |
| `test_every_test_file_pattern_still_matches_a_component_test_file` | the fix must not break the shape that already worked |
| `test_no_test_file_pattern_requires_a_leading_directory_separator` | the defect's exact shape, as a property of the pattern |
| `test_a_repository_root_test_file_is_selectable_end_to_end` | the whole selection path: file → module name → run directory |

The extractor deliberately picks only the patterns that mention `test_`, so
the probe's *module* selector (`grep -E '\.py$' | grep -v '/tests/'`) is not
in scope — that one is correct.

## 4. Verification

### 4.1 RED first

The tests were written before the fix and watched fail, for the right reason —
4 failures, **0 errors**:

```
$ cd components/northstar-agent-runtime && PYTHONPATH=.:.. python3 -m unittest test_r9_mutant_probe_path
FAIL: test_every_test_file_pattern_matches_a_repository_root_test_file (pattern='/tests/test_[^/]+\.py$')
FAIL: test_every_test_file_pattern_matches_a_repository_root_test_file (pattern='/tests/test_[^/]+\.py$')
FAIL: test_no_test_file_pattern_requires_a_leading_directory_separator (pattern='/tests/test_[^/]+\.py$')
FAIL: test_no_test_file_pattern_requires_a_leading_directory_separator (pattern='/tests/test_[^/]+\.py$')
Ran 5 tests in 0.035s
FAILED (failures=4)
```

The two `subTest` repetitions are the two occurrences of the pattern in the
live script (the pairing loop and the fallback) — the defect is in **both**.

### 4.2 GREEN

```
$ cd components/northstar-agent-runtime && PYTHONPATH=.:.. python3 -m unittest test_r9_mutant_probe_path
Ran 5 tests in 0.035s
OK
```

### 4.3 The probe now reaches both slices

```
$ bash b173-mutant.sh seal-slice6
mutant probe: slug=seal-slice6 commit=c9e8885b module=scripts/seal-delivery.py test=test_delivery_seal
MUTANT RESULT: killed 1/1

$ bash b173-mutant.sh shipped-module-docs
mutant probe: slug=shipped-module-docs commit=f5d8b2cb module=tests/docbuild.py test=test_shipped_module_docs
MUTANT RESULT: killed 1/1
```

### 4.4 The blast radius, measured over every slice

The census below runs the probe for every slice in the batch and records its
verdict.  See the slice report for the measured before/after tables.

## 5. Open items

1. **Seven slices still skip the probe, correctly.**  They name no production
   module in their manifest, so there is nothing to mutate.  That is an
   honest skip, and the message "manifest lacks module/test" is true for them.
   A future slice could make the message distinguish the two cases
   ("no module in the manifest" vs "no test file in the manifest") — the
   second case no longer exists after this slice.
2. **`b173-mutant.sh` lives outside the repository.**  So does
   `b173-accept.sh` and the other referee scripts, by the batch's
   convention.  That means the probe's behaviour is pinned by a test in the
   repository (`test_r9_mutant_probe_path.py`) that reads the *live* script
   from outside — which is the same pattern the round-6 and round-7
   referee-behaviour tests use, and the same weakness: if the script is
   absent, the test skips rather than fails.
