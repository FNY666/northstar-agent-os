# judge-hygiene — why the mutant probe's verdicts were not evidence

> B173 slice `judge-hygiene`.
>
> **This slice does not edit the probe.**  `b173-mutant.py` and
> `b173-mutant.sh` live outside the repository and are the referee's
> tools.  This document, the patch file
> `/home/muse-newapi/b173-judge-hygiene-fix.patch` and the read-only
> conformance test are what this slice produces; the coordinator applies
> the patch to the live scripts.
>
> Two defects were found in the planted-fault probe that decides the
> `MUTANT` acceptance item:
>
> * **D-22 — the verdict depended on the Python bytecode cache.**
> * **D-23 — the worktree was pinned to the slice's own last commit.**
>
> Both were measured, reproduced here, and fixed in the patch.

## 1. What the probe does

`b173-mutant.sh <slug>`:

1. finds the slice's commit (`git log --grep="^B173 <slug>:"`),
2. finds the slice's module and test file in `/home/muse-newapi/b173-<slug>.files`,
3. creates a throwaway `git worktree` at that commit,
4. runs `b173-mutant.py --file <module> --test-module <test>`.

`b173-mutant.py` parses the module's AST, picks up to three mutable
constructs (`==`, `>`, `<`, `return True/False`, `and`/`or`) in source
order, and for each one rewrites **that source line** in the worktree,
runs the slice's test module, and records the mutant as

```
MUTANT <kind>@<line> KILLED|SURVIVED|SKIP (<what was changed>)
```

then restores the original file.  The exit code is the referee signal
that `b173-accept.sh` reads: **0** = at least one mutant killed (the
tests verify behaviour), **1** = every applied mutant survived (the tests
do not verify behaviour), **2** = the probe could not run.

The `MUTANT` item in `b173-accept.sh` is therefore the batch's only
question of the form *"does this slice's own test suite actually pin the
behaviour of this slice's own module?"*.

## 2. Defect D-22: the verdict depended on the bytecode cache

### 2.1 Mechanism

Python caches compiled modules in `__pycache__/<mod>.cpython-3xx.pyc`.
With the default timestamp invalidation mode (`flags=0`) a cache entry is
considered valid when **both** the source's mtime *in whole seconds* and
its **byte size** match the values recorded in the `.pyc` header.

The probe rewrites a module in place, three times in a row.  Two of its
mutations are **same-length** rewrites:

| mutation | before | after | length change |
|---|---|---|---|
| `or -> and` | ` or ` | ` and ` | 0 (3 chars → 3 chars) |
| `> -> >=` | `>` | `>=` | +1, same on some lines when the operator is padded |
| `< -> <=` | `<` | `<=` | +1 |

When two same-length rewrites land inside **the same second** — and the
probe's test runs take only tens of milliseconds, so this happens
routinely — the rewritten source has **the same size** and **the same
mtime** as the previous round's source.  The cache criterion is then
*identical*, Python **re-uses the previous round's bytecode**, never
compiles the rewritten source, and the probe silently runs the
**previous** round's code and reports the **previous** round's verdict.

### 2.2 Reproduction (runnable as written)

```bash
REPO=/home/muse-newapi/northstar-agent-os
SLUG=refusal-row
HASH=$(git -C "$REPO" log --format=%H --grep="^B173 ${SLUG}:" -i -1)
git -C "$REPO" worktree add --detach /tmp/jh-repro "$HASH"

# default run -- writable .pyc
python3 /home/muse-newapi/b173-mutant.py \
  --file /tmp/jh-repro/components/northstar-agent-runtime/refusal_row.py \
  --test-module test_refusal_row \
  --workdir /tmp/jh-repro/components/northstar-agent-runtime

# cache-free run
PYTHONDONTWRITEBYTECODE=1 python3 /home/muse-newapi/b173-mutant.py \
  --file /tmp/jh-repro/components/northstar-agent-runtime/refusal_row.py \
  --test-module test_refusal_row \
  --workdir /tmp/jh-repro/components/northstar-agent-runtime
```

**Measured here** (pinned commit `190d9198`, module `refusal_row.py`):

| run | result |
|---|---|
| default, 1st time | `MUTANT RESULT: killed 1/3` |
| default, 2nd time | `MUTANT RESULT: killed 0/3` |
| `PYTHONDONTWRITEBYTECODE=1`, 1st time | `MUTANT RESULT: killed 1/3` |
| `PYTHONDONTWRITEBYTECODE=1`, 2nd time | `MUTANT RESULT: killed 1/3` |

The two *default* runs disagree — the probe's verdict is a function of
where the second boundary falls, not of the code.  The cache-free runs
agree.  **A number that is not reproducible cannot be evidence.**

### 2.3 Reading the cache criterion out

```bash
python3 - <<'EOF'
import os, struct, importlib.util
src = "refusal_row.py"
pyc = importlib.util.cache_from_source(src)
import py_compile; py_compile.compile(src, cfile=pyc)
with open(pyc, "rb") as f:
    magic, flags, mtime, size = struct.unpack("<4sIII", f.read(16))
st = os.stat(src)
print("pyc: flags=%d mtime=%d size=%d" % (flags, mtime, size))
print("src:      mtime=%d size=%d" % (int(st.st_mtime), st.st_size))
print("CRITERIA MATCH:", mtime == int(st.st_mtime) and size == st.st_size)
EOF
```

**Measured here:**

```
pyc: flags=0 mtime=1794641141 size=18931
src:       mtime=1794641141 size=18931
CRITERIA MATCH: True
```

`flags=0` is the timestamp invalidation mode; the criterion matches
exactly, so the cached bytecode is reused.

### 2.4 Why the failure mode is inflation, not deflation

The strategy brain verified the *false KILLED* mechanism separately: with
`or@83` (`math.isnan(rate) or math.isinf(rate)` → `and`) mutated, the
mutant **should survive** — no test covers that branch — but because
`or@80`'s bytecode was reused, the probe actually ran the `or@80`
variant, the test failed, and the probe reported **KILLED**.

So the cache defect inflates the KILLED count.  **Inflated KILLED is
false evidence**, which is worse than a deflated count: it certifies
"the tests verify the behaviour" when they do not.

### 2.5 The fix

Two changes in `b173-mutant.py`, both necessary:

1. `run_tests()` sets `env["PYTHONDONTWRITEBYTECODE"] = "1"`.
   This stops the probe's test runs from **writing** cache entries.
2. A new `purge_bytecode(path)` helper deletes the module's `.pyc` from
   `__pycache__` **before every source rewrite** and again before the
   source is restored.

**Both are required.**  `PYTHONDONTWRITEBYTECODE=1` alone is not enough:
it only stops *writing* a `.pyc`; it does not stop *reading* a `.pyc`
that a previous round left behind — and that previous round's entry has
exactly the same `(mtime, size)` criterion as the current rewrite.

## 3. Defect D-23: the worktree was pinned to the slice's own last commit

### 3.1 Mechanism

`b173-mutant.sh` pinned the worktree with

```bash
HASH=$(git -C "$REPO" log --format=%H --grep="^B173 ${SLUG}:" -i -1)
git -C "$REPO" worktree add --detach "$WT" "$HASH"
```

so the probe ran the code and the tests of **that one commit**, not HEAD.
If a fix for the slice's mutant was committed under a **different slug
prefix** — for example `B173 vina-mutant-blindspots:` instead of
`B173 vina:` — the probe's `grep` never finds it, the fix is not in the
worktree, and the probe reports "all mutants survived" forever.

### 3.2 Reproduction (runnable as written)

```bash
REPO=/home/muse-newapi/northstar-agent-os
for spec in "vina:artifact_authority:test_artifact_authority:831b0312" \
            "tombstone:cancellation_tombstone:test_cancellation_tombstone:695a25b7"; do
  IFS=: read slug mod tmod sha <<< "$spec"
  for target in "$sha" HEAD; do
    git -C "$REPO" worktree add --detach /tmp/jh-$slug "$target"
    python3 /home/muse-newapi/b173-mutant.py \
      --file /tmp/jh-$slug/components/northstar-agent-runtime/$mod.py \
      --test-module $tmod \
      --workdir /tmp/jh-$slug/components/northstar-agent-runtime
  done
done
```

**Measured here** (with `PYTHONDONTWRITEBYTECODE=1`, so the cache defect
does not confound the measurement):

| slice | module | pinned commit | HEAD |
|---|---|---|---|
| `vina` | `artifact_authority.py` | `831b0312` → **killed 0/3** | **killed 3/3** |
| `tombstone` | `cancellation_tombstone.py` | `695a25b7` → **killed 0/3** | **killed 3/3** |

The fixes do exist — under prefixes `B173 vina-mutant-blindspots:`
(`2f89b154`) and `B173 tombstone-mutant-blindspots:` (`f8562b87`):

```bash
git -C "$REPO" log --format="%H %s" 831b0312..HEAD -- \
  components/northstar-agent-runtime/artifact_authority.py \
  components/northstar-agent-runtime/tests/test_artifact_authority.py
# 2f89b154bb8065c5b30f754f532eac9c96b924c5 B173 vina-mutant-blindspots: kill or@150, or@184, gt@186 ...
```

### 3.3 The fix (conservative version)

The worktree stays pinned to the slice's own last commit **unless** a
later commit actually touched **that slice's module or test file**.  In
that case the probe runs at that later commit and prints

```
MUTANT NOTE: pinned at <sha> but the module/test changed later in <sha>
```

Otherwise the behaviour is byte-for-byte unchanged.

## 4. Tradeoff: why the conservative version, not "pin HEAD"

Two candidate fixes for D-23:

| | conservative version (adopted) | pin HEAD (not adopted) |
|---|---|---|
| worktree commit | the slice's last commit, or the later commit that touched *this slice's* module/test | HEAD, unconditionally |
| tests run | the slice's own test module | the slice's own test module |
| what the verdict means | "this slice's own tests pin this slice's own module" | the same, but the *code* is HEAD's |
| risk | a fix that touched neither the module nor the test file is still invisible | other slices' commits change the code under test; the probe's verdict stops being about *this* slice and starts being about the merged tree |
| reproducibility | the commit is a function of the slice's files only | the commit is a function of everything that ever landed |

**"Pin HEAD" is recorded here as the alternative, not adopted.**  The
probe's question is narrow: *does this slice's own test suite catch a
semantic fault in this slice's own module?*  Pinning HEAD lets unrelated
slices' work testify for this one — which is precisely the class of
false evidence this slice exists to remove.  The conservative version
moves the worktree only when there is a concrete, file-scoped reason to
do so, so the verdict stays attributable.

The known cost of the conservative version: a fix that lands under a
different slug prefix and touches **neither** the module nor the test
file of the slice stays invisible.  That case is out of scope for a
mutant probe (a fix that changes neither the code nor the test cannot
change a mutant's verdict).

## 4b. Defect D-24: a killed probe left the module mutated

Found 2026-11-22, while re-verifying the `merged_tree_review` census.

### 4b.1 Mechanism

The probe's round is: **write a mutant into the module → run the suite →
restore the original**.  The restore is an ordinary statement at the end
of the loop body, so it runs on a normal return — and on **nothing else**.
If the process dies inside that window (a wall-clock timeout, a SIGTERM
from a batch runner, an OOM kill), the module is left holding the
mutant.

The next run then measures a tree that is already broken, and every
verdict after that point is about the leftover, not about the mutant
under test.

### 4b.2 What it produced

A census run against `merged_tree_review.py` was killed mid-flight.  It
left two mutations behind:

```diff
-            if len(holders[word]) < 2:
+            if len(holders[word]) <= 2:
...
-                if left_module == right_module:
+                if left_module != right_module:
```

The **next** run reported:

```
MUTANT RESULT: killed 37/37
```

with **zero survivors**.  The committed record said `killed 37/39`, with
`gt@451` and `eq@494` surviving — and both of those are *provably*
equivalent mutants (`span.split(".")` always yields at least two parts
when `"." in span`, which is checked two lines above, so `len(parts) > 1`
and `len(parts) >= 1` cannot disagree; and `len(parts) == 2` is
reachable only after `len(parts) < 2` has already returned).

The two leftover mutants broke four **unrelated** tests, so the suite
failed for reasons that had nothing to do with the mutant being
measured:

```
FAIL: test_positive_two_modules_mint_the_same_verdict_word
FAIL: test_positive_enum_members_are_part_of_the_vocabulary
FAIL: test_positive_records_with_unjoinable_fields_conflict
FAIL: test_and_at_850_a_record_that_is_a_superset_still_conflicts
```

A clean re-run measured on a pristine tree confirms the committed
number: `killed 37/39`, with exactly `gt@451` and `eq@494` surviving.

### 4b.3 Why this is a false kill, not a dirty tree

D-22 is a false kill in one direction: the probe reported a mutant as
**surviving** when the tests had actually noticed it.  D-24 is a false
kill in the other: the probe reported a mutant as **killed** when the
tests had failed for a reason unrelated to it.  Both make the census
number mean something other than what it says.

The asymmetry matters for how the record is read.  A census that
over-reports kills looks *stronger* than it is, so it invites belief
rather than scrutiny; and it does so on the exact slice the record
already claimed had two honest survivors.  A survivor that was
documented as a genuine equivalent mutant is evidence; a kill that was
manufactured by a leftover is not.

### 4b.4 The fix

The restore is registered three ways, so it survives any exit:

* `atexit` — covers a normal return **and** an unhandled exception;
* a `SIGTERM` / `SIGINT` / `SIGHUP` handler — a signal raises
  `SystemExit`, which `atexit` then sees, and the handler re-raises
  with the default disposition so the process still dies the way it was
  asked to;
* a pre-flight check that the file under test still reads as the
  original it was read as, so a probe that starts against a tree another
  process is mutating refuses to run rather than report nonsense.

Measured 2026-11-22, both directions:

| probe | after `SIGTERM` mid-round | module |
|---|---|---|
| before the fix | left mutated | `flag or other` → `flag and other` |
| after the fix | restored byte-identical | unchanged |

### 4b.5 The census script had a second, independent defect

`b173-census-all.sh` passed `--test-module test_cancellation_gate` for
**every** module it was pointed at.  A module that suite does not
exercise is therefore measured with the wrong tests, and every mutant in
it "survives":

```
=== MODULE merged_tree_review.py ===
MUTANT and@156 SURVIVED (and -> or)
...
MUTANT RESULT: killed 0/8
```

That is a false accusation of a weak test suite, and it is the *same*
shape of error as D-23 in a different place: the probe was pointed at
the wrong tests.  The script now pairs each module with the test file
that actually mentions it, the same rule `b173-mutant.sh` already used.
With the pairing fixed, the same census reports `killed 37/39` and names
`test_merged_tree_review` as the suite it ran.

The script also restores the module from the pristine source after each
module's census, so one interrupted census cannot contaminate the next.

### 4b.6 The first-mention rule still lost to a file that only mentioned the module

§4b.5 fixed the *hardcoded* suite.  The rule it left behind -- take the
first test file that **mentions** the module -- is still wrong, and it is
wrong at scale.

A test file that merely **imports one constant** from a module satisfies
the "mentions it" test.  Because the scan is alphabetical, such a file
often wins the race against the module's *own* suite:

```
$ grep -l 'a2a_gates' tests/test_*.py
tests/test_a2a_budget_combo.py     # imports three constants
tests/test_a2a_gates.py            # the module's own suite
```

Measured 2026-11-22, the same module censused with each suite:

| suite | verdict |
|---|---|
| `test_a2a_budget_combo.py` (first mention) | `killed 10/43` |
| `test_a2a_gates.py` (its own) | `killed 37/43` |

The first number is a **false accusation of a weak test suite** -- the
same shape as §4b.5, one level down: the probe was pointed at the wrong
tests, and the wrong tests reported "the mutant survived".

**Scale.**  A scan of the runtime component's 320+ modules against
their own `tests/test_<module>.py` found **144 modules** whose
first-mention file is not their own file.  Every one of them was a
candidate for the same false accusation.

**The fix.**  The module's **own** test file wins outright; the
first-mention scan is only the fallback for a module that has no file of
its own.  The rule is now: *the module's own suite, if it has one*.

**What this does NOT change.**  Nothing about the probe, the mutants,
or the accept thresholds.  It changes only **which suite is asked**, so
the census measures the module rather than a bystander.

### 4b.7 The runner could not SEE the suite it was asked to run

§4b.5 and §4b.6 both fixed **which suite** the probe was given.  They
missed the more basic question: **could the runner see that suite at
all?**

The probe ran:

```python
subprocess.run([sys.executable, "-m", "unittest", test_module], ...)
```

`unittest`'s discovery collects only test **METHODS** inside `TestCase`
classes.  The component's suite is mostly the other shape -- standalone
module-level `test_*` **FUNCTIONS**:

```
1,545 test files
  812 have ONLY standalone functions  (unittest sees 0 of them)
  730 have only TestCase classes
    0 have both
  815 files where unittest collects ZERO tests, holding 9,815 test
  functions in total
```

For those 815 suites `unittest` exits **5** (`NO TESTS RAN`), and the
probe read **any non-zero exit** as "the mutant was KILLED":

```python
elif rc != 0:
    killed += 1
```

So every mutant in the module was reported **killed by a suite that ran
no tests at all**.

**Measured 2026-11-22**, `agents.py` paired with `test_agent_handoff.py`
(40 standalone functions, 0 discoverable by unittest):

| suite | verdict | what actually happened |
|---|---|---|
| `test_agent_handoff.py` | `killed 31/31` | **0 tests ran**; every "kill" was the exit code |
| `test_agents.py` | `killed 14/31` | 45 tests ran; 17 genuine survivors |

This is the **most consequential** of the four defects, and the reason is
directional.  The stale-bytecode false kill (D-22) made a mutant look
*surviving* when the tests had caught it -- over-reporting weakness.
D-24 made a mutant look *killed* when the tests had failed for an
unrelated reason.  This one makes a mutant look *killed* when **no test
ran**: it manufactures evidence of coverage where there is none, and it
points the *stronger* way, so no other check would have caught it.

**The fix.**  Two parts.

1. **The runner.**  The probe runs `pytest`, which collects both test
   shapes -- and is the runner CI already uses
   (`python -m pytest -q tests`).
2. **"Collected nothing" is not a kill.**  Even under pytest, a suite
   that cannot be imported exits 5.  The probe therefore checks the
   output for pytest's own wording (`no tests ran`, `error during
   collection`, `collected 0 items`) and reports **SKIP**, not KILLED.

The probe also accepts **several** test modules, because a module's real
coverage is the **union** of the suites that reference it:
`agents.py` is exercised by `test_agents.py` (773 lines) *and*
`test_agent_handoff.py` (601 lines).

## 5. What is deliberately **not** changed
* `b173-accept.sh` is **not modified by a single character** — it is the
  referee for the twelve acceptance items; changing it changes the
  standard.
* The `MUTANT` threshold stays at ">= 1 mutant killed" (D-21).
* Exit-code semantics stay: 0 = ≥1 killed, 1 = all survived, 2 = the
  probe could not run.
* The output line format stays:
  `MUTANT <kind>@<line> KILLED|SURVIVED|SKIP (...)` and
  `MUTANT RESULT: killed k/n`.  The new `MUTANT NOTE:` line is
  *additional*; `b173-accept.sh` reads only the last four lines and the
  exit code, so it is unaffected.
* `b173-report-numbers.py` is untouched.
* "Just re-run it" is not a fix: D-22 is second-boundary dependent, so
  the results are not reproducible in the first place.

## 6. Precise change specification

The coordinator applies `/home/muse-newapi/b173-judge-hygiene-fix.patch`:

```bash
cd /home/muse-newapi && patch -p1 < b173-judge-hygiene-fix.patch
```

The patch was verified to apply cleanly (`patch -p1 --dry-run`) against
copies of the live scripts, and the result is byte-identical to the
patched copies the tests were run against.

### 6.0 State of the two halves at the time of writing

While this slice was working, the round-5 flow optimisation
(`/home/muse-newapi/b173-flow-optimization-round5-2026-11-14.md`,
"Fix J") applied the **D-22** half to the live `b173-mutant.py` — the
`PYTHONDONTWRITEBYTECODE=1` line plus a `drop_cached_bytecode()` helper
called around every rewrite.  That fix is **equivalent** to the D-22 fix
specified below (same two mechanisms, same necessity of doing both), so
this slice's patch carries only the **D-23** half, which was still
missing.  The D-22 change specification is kept here for the record and
for the case where the round-5 fix is rolled back.

Measured on the live probe **after** the round-5 fix landed, three
consecutive runs on each of the five cache-dependent slices:

```
anthropic-effort-scaling: killed 1/3 killed 1/3 killed 1/3
refusal-row:                killed 1/3 killed 1/3 killed 1/3
jido-statebudget:           killed 2/3 killed 2/3 killed 2/3
dynamiq:                    killed 1/3 killed 1/3 killed 1/3
deterministic-gate-score:   killed 1/3 killed 1/3 killed 1/3
```

These are the values the before/after table in §7 reports as "after",
and they are identical to the values this slice measured with its own
patched copy of the probe.

### 6.1 `/home/muse-newapi/b173-mutant.py` (D-22 — **already applied upstream**)

> These four changes were specified by this slice and are the changes the
> round-5 flow optimisation applied to the live script under the name
> `drop_cached_bytecode()`.  They are **not** part of
> `b173-judge-hygiene-fix.patch` any more, because the live script
> already carries them and the hunks would no longer apply.  They are
> kept here as the authoritative specification of the D-22 fix.

**Change 1 — new helper (inserted between `mutate_line()` and
`run_tests()`, i.e. after line 62 of the original file).**

Old text: the file ends `mutate_line()` with

```python
    if kind == "or":
        return line.replace(" or ", " and ", 1), "or -> and"
    return line, "?"

def run_tests(workdir, test_module, timeout=180):
```

New text:

```python
    if kind == "or":
        return line.replace(" or ", " and ", 1), "or -> and"
    return line, "?"

def purge_bytecode(path):
    """Remove any cached bytecode for `path` so a rewritten source is
    recompiled. PYTHONDONTWRITEBYTECODE only stops *writing* a .pyc; an
    existing .pyc whose (mtime, size) criteria still match the rewritten
    source would still be *read* and the previous round's code would run."""
    cache = os.path.join(os.path.dirname(os.path.abspath(path)), "__pycache__")
    if not os.path.isdir(cache):
        return
    stem = os.path.splitext(os.path.basename(path))[0]
    for name in os.listdir(cache):
        if name.startswith(stem + ".") and name.endswith(".pyc"):
            try:
                os.remove(os.path.join(cache, name))
            except OSError:
                pass

def run_tests(workdir, test_module, timeout=180):
```

**Change 2 — `run_tests()`, line 66 of the original file.**

Old text:

```python
    env = dict(os.environ)
    env["PYTHONPATH"] = ".:tests"
    try:
```

New text:

```python
    env = dict(os.environ)
    env["PYTHONPATH"] = ".:tests"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
```

**Change 3 — `main()`, before the mutant source is written (line 105 of
the original file).**

Old text:

```python
        with open(a.file, "w", encoding="utf-8") as f:
            f.write(trial_src)
```

New text:

```python
        purge_bytecode(a.file)
        with open(a.file, "w", encoding="utf-8") as f:
            f.write(trial_src)
```

**Change 4 — `main()`, before the original source is restored (line 116
of the original file).**

Old text:

```python
        with open(a.file, "w", encoding="utf-8") as f:
            f.write(orig)
```

New text:

```python
        purge_bytecode(a.file)
        with open(a.file, "w", encoding="utf-8") as f:
            f.write(orig)
```

### 6.2 `/home/muse-newapi/b173-mutant.sh` (D-23 — **in the patch**)

> **Line numbers.**  The line numbers below refer to the *original*
> `b173-mutant.sh` (37 lines), which is what the live script still is:
> `COMPDIR=` on line 28, `WT=` on line 29, the `mutant probe:` echo on
> line 34.  The live `b173-mutant.py` has meanwhile grown the round-5
> D-22 helper, so its line numbers have shifted (`drop_cached_bytecode`
> on line 64, `run_tests` on line 88, `PYTHONPATH` on line 90,
> `PYTHONDONTWRITEBYTECODE` on line 94, the two
> `drop_cached_bytecode(a.file)` calls on lines 137 and 149).  The D-22
> change specification below is written against the *original* file, which
> is what it was measured against.

**Change 5 — after `COMPDIR=` (line 28 of the original file) and before
`WT=` (line 29).**

Old text:

```bash
COMPDIR=$(dirname "$TESTF" | sed 's|/tests$||')
WT="/tmp/b173-mutant-$SLUG"
```

New text:

```bash
COMPDIR=$(dirname "$TESTF" | sed 's|/tests$||')
# A fix for this slice's module/test may have landed under a *different* slug
# prefix, so the slice's own last commit does not contain it and the probe
# would report 0/3 forever.  Stay conservative: only move the worktree when a
# later commit actually touched THIS slice's module or test file; otherwise
# behaviour is unchanged.
PINNED="$HASH"
NOTE=""
HEAD_HASH=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || true)
if [ -n "$HEAD_HASH" ] && [ "$HASH" != "$HEAD_HASH" ]; then
  LATER=$(git -C "$REPO" log --full-history --format=%H "$HASH..$HEAD_HASH" -- "$MOD" "$TESTF" 2>/dev/null | head -n1)
  if [ -n "$LATER" ]; then
    HASH="$LATER"
    NOTE="MUTANT NOTE: pinned at ${PINNED:0:8} but the module/test changed later in ${LATER:0:8}"
  fi
fi
WT="/tmp/b173-mutant-$SLUG"
```

**Change 6 — after the `mutant probe:` echo (line 34 of the original
file).**

Old text:

```bash
echo "mutant probe: slug=$SLUG commit=${HASH:0:8} module=$MOD test=$TMOD"
python3 "$HOME_DIR/b173-mutant.py" --file "$WT/$MOD" --test-module "$TMOD" --workdir "$WT/$COMPDIR"
```

New text:

```bash
echo "mutant probe: slug=$SLUG commit=${HASH:0:8} module=$MOD test=$TMOD"
[ -n "$NOTE" ] && echo "$NOTE"
python3 "$HOME_DIR/b173-mutant.py" --file "$WT/$MOD" --test-module "$TMOD" --workdir "$WT/$COMPDIR"
```

Nothing else in either file changes: the exit codes, the output format
and the `MUTANT RESULT:` line are untouched.

## 7. Before/after table — every slice with a manifest

**Method.**  For every `/home/muse-newapi/b173-<slug>.files` manifest:
the probe is run at the slice's pinned commit, twice with the
**original** probe (default environment and with
`PYTHONDONTWRITEBYTECODE=1`) and twice with the **patched** probe.  The
`__pycache__` directory is removed before *every* run, so the "no-cache"
column is genuinely cache-free and the "default" column always starts
from a cold cache.

Columns:

* `before (default)` / `before (no-cache)` — the **original** probe.
* `after (default)` / `after (no-cache)` — the **patched** probe, still
  at the pinned commit.  These two must be equal for every slice.
* `after+pin-fix` — the patched probe at the commit the patched
  `b173-mutant.sh` actually selects (the pinned commit, or the later
  commit that touched this slice's module/test).

A slice's `MUTANT` verdict is `PASS` when at least one mutant is
killed.  The verdict therefore flips only where the killed count
crosses zero.
| slice | before (default) | before (no-cache) | after (default) | after (no-cache) | after + pin-fix | verdict change |
|---|---|---|---|---|---|---|
| `acceptance-conformance` | 0/3 | 1/3 | 1/3 | 1/3 | 1/3 | **FAIL -> PASS** |
| `actionable-digest` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `agent-handoff` | 3/3 | 3/3 | 3/3 | 3/3 | **3/3** | AMENDED 2026-11-22 -- the runner saw no tests; the gap was closed with new tests |
| `ageofagents` | 1/3 | 1/3 | 1/3 | 1/3 | 1/3 | - |
| `anthropic-effort-scaling` | 1/3 | 1/3 | 1/3 | 1/3 | 1/3 | - |
| `artifact-completion` | - | - | - | - | - | - |
| `asinhhc` | 1/3 | 1/3 | 1/3 | 1/3 | 1/3 | - |
| `autogen-speaker-selector` | 3/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `baseline-attribution` | - | - | - | - | - | - |
| `capability-ceiling-probe` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `cost-per-delivery` | 3/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `cwl-episode-eviction` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `deterministic-gate-score` | 0/3 | 1/3 | 1/3 | 1/3 | 1/3 | **FAIL -> PASS** |
| `dynamiq` | 1/3 | 1/3 | 1/3 | 1/3 | 1/3 | - |
| `effect-directive` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `event-condenser` | 0/3 | 1/3 | 1/3 | 1/3 | 1/3 | **FAIL -> PASS** |
| `evidence-independence` | 1/3 | 1/3 | 1/3 | 1/3 | 1/3 | - |
| `false-green-detector` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `fieldnotes` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `horizon-gate` | 3/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `intent-bound-retry` | 2/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `jido-statebudget` | 3/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `judge-hygiene` | - | - | - | - | - | - |
| `langgraph-durability` | 1/3 | 1/3 | 1/3 | 1/3 | 1/3 | - |
| `langgraph-retry-clears-writes` | 2/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `leased-task-claim` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `lightningzero` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | AMENDED 2026-11-22 -- blind suite, but the fixed probe confirms the three constructs |
| `merged-tree-review` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `msaf-lineage` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `mutant-evidence-closure` | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | - |
| `neo-konsi-s2bw` | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | - |
| `openhands-stuck-detector` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `orphan-adoption` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `outsideloop` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `refusal-hold-wiring` | ? | ? | ? | ? | ? | - |
| `refusal-hold` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `refusal-row` | 3/3 | 1/3 | 1/3 | 1/3 | 1/3 | - |
| `resume-validation` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `reversible-compaction` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `revision-checked-tool-results` | 3/3 | 1/3 | 1/3 | 1/3 | 1/3 | - |
| `runtime-registration-closure` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `scope-verbatim-compaction` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `scorer-disagreement` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `session-memory` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `silent-failure-detector` | 2/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `stale-checkpoint-gate` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `step-reliability-budget` | 3/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `strands` | 2/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `swe-failure-modes` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `tombstone-mutant-blindspots` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `tombstone` | 0/3 | 0/3 | 0/3 | 0/3 | 3/3 | **FAIL -> PASS** |
| `tool-output-filter` | 2/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `toolfail` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | AMENDED 2026-11-22 -- blind suite, but the fixed probe confirms the three constructs |
| `turn-truncation` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `verifiability-tier` | 2/3 | 2/3 | 2/3 | 2/3 | 2/3 | - |
| `vina-mutant-blindspots` | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | - |
| `vina-receipt-signing` | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | - |
| `vina` | 0/3 | 0/3 | 0/3 | 0/3 | 3/3 | **FAIL -> PASS** |

**Rows with no numbers** (`-`): no commit found for the slice at census time; `?`: the manifest names a module that does not exist in the tree, so the probe cannot run (exit 2, `MUTANT` SKIP).

## 8. Impact on the batch's `MUTANT` verdicts

The `MUTANT` acceptance item is PASS when at least one mutant is killed.
The verdict therefore only flips where the killed count crosses zero.

### 8.1 Flips FAIL -> PASS

| slice | before | after | why |
|---|---|---|---|
| `vina` | 0/3 | **3/3** | D-23: the fix lives in `2f89b154` (`B173 vina-mutant-blindspots:`), which the pinned grep could not find |
| `tombstone` | 0/3 | **3/3** | D-23: the fix lives in `f8562b87` (`B173 tombstone-mutant-blindspots:`), same cause |
| `acceptance-conformance` | 0/3 | **1/3** | D-22: the default run reused a stale `.pyc` and reported a false 0/3 |
| `deterministic-gate-score` | 0/3 | **1/3** | D-22, same cause |
| `event-condenser` | 0/3 | **1/3** | D-22, same cause |

### 8.2 Flips PASS -> FAIL (none so far)

**No slice flips from PASS to FAIL.**  The five slices whose killed count
changes but stays above zero (`autogen-speaker-selector`, `cost-per-delivery`,
`horizon-gate`, `jido-statebudget`, `revision-checked-tool-results`,
`refusal-row`, `step-reliability-budget`) keep a non-zero count, so their
`MUTANT` item stays PASS — but the *number* they report changes, and the
number is now the true one.

Note that the strategy brain's prediction that four slices would drop to
1/3, 1/3, 2/3 and 1/3 was measured at a different wall-clock moment than
this census; the **slices** are the same, the **numbers** differ because
the strategy brain's own numbers were themselves cache-dependent.  This
census is the reproducible one: every "after" cell was produced twice
(default and no-cache) with a cold `__pycache__` before each run, and the
two agree on all 58 rows.

### 8.3 Slices that stay FAIL

These are **true gaps** — the slice's own tests do not kill any mutant in
the slice's own module, on HEAD as well as on the pinned commit:

* `mutant-evidence-closure` — 0/3
* `neo-konsi-s2bw` — 0/3
* `vina-receipt-signing` — 0/3
* `refusal-hold-wiring` — the probe cannot run at all (the manifest names
  `refusal_hold_wiring.py`, which does not exist in the tree), so the
  item is SKIP, not FAIL.

These need real tests, not a probe fix.  They are **not** in this slice's
scope and are listed here so the coordinator does not read them as
regressions.

### 8.4 The batch-wide effect

Before the patch, 10 of 58 slices gave **different** numbers for the
default and the cache-free run of the *same* code.  After the patch,
**0 of 58** do.  That is this slice's real output: not a better number,
but a number that is the same every time it is measured.

### 8.5 AMENDED 2026-11-22 -- this table's runner was ALSO wrong

§4b.7 above fixed the probe's **cache** dependence.  It did not fix the
probe's **runner**: at the time this table was measured, the probe ran
`python -m unittest <module>`, and unittest collects only test methods
inside `TestCase` classes.

Three rows in this table are measured against a suite unittest could
**not see at all**:

| slice | suite | unittest collects | this table says | fixed probe (pytest) |
|---|---|---|---|---|
| `agent-handoff` | `test_agent_handoff.py` | **0** of 40 | 3/3 | **3/3** (first three), **38/38** whole-file |
| `lightningzero` | `test_coverage_manifest.py` | **0** of 24 | 3/3 | 3/3 (first three), **24/24** whole-file |
| `toolfail` | `test_tool_failure.py` | **0** of 19 | 3/3 | 3/3 (first three), **11/11** whole-file |

Those suites are pytest-style -- standalone module-level `test_*`
functions and no `TestCase` class -- so unittest's loader collected
**zero** tests, exited 5 ("NO TESTS RAN"), and the probe read the
non-zero exit as "the mutant was KILLED".  The 3/3 in those three rows
was the exit code, not a measurement.

For `agent-handoff` that was a **total** false kill: all three of its
listed constructs (`gt@214 gt@226 gt@236`) SURVIVED, both at HEAD and at
the slice's own pinned commit `249f9a5c`.  It measured **0/3**, and the
gap has since been closed with nine new test methods -- so its row above
reads **3/3** again, now on a measurement rather than on an exit code.

**AMENDED 2026-11-22 (b) -- the thirteen survivors behind that row are
now closed too.**  Closing the three *listed* constructs was one step;
the whole-file measurement then read **25/38**, and the other thirteen
survivors had neither a killer nor an equivalence proof.  All thirteen
now have a killer test, named for the mutant it kills, and the module
reads **38/38** at HEAD **and** at the pinned commit `249f9a5c`.  The
module body has zero diff -- the survivors were killed by tests, not by
changing the source.

For `lightningzero` and `toolfail` the listed three constructs do die
under the fixed probe, so their 3/3 stands -- but it now rests on a
measurement rather than on an exit code, and the whole-file counts
show the suite does not cover the whole file.

**AMENDED 2026-11-22 (c) -- `lightningzero` is closed too.**  Its
whole-file count read **12/24**: twelve survivors, nine of them inside
`stdlib_only()` and `main()`, which a test that merely *imports* the
module cannot reach.  The killers drive the module as a **script** and
assert on the module's own output.  The row now reads **24/24** at
HEAD, with the module body unchanged.

**`toolfail` is now closed as well: 11/11** (was 10/11).  Its
`from_provider_fault` had **no test at all** -- the suite covered
`provider_retry.fault_to_failure`, which delegates to it -- and the one
survivor was `or@340`, the `getattr(fault, "detail", "") or ""`
fallback, whose mutant silently drops the detail.  `slice4` is closed
the same way: **4/4** (was 3/4), `or@45` being a genuine double guard
that needed **both** wrong ways.

**Two more rows of the same shape are not in this table at all**,
because this table's slice set is not the census's: `c58` and
`slice3` (both `test_bash_parser.py`, 0 of 42) are in
`docs/design/mutant-evidence-closure.md` §2.  They also measured 0/3
and have since been closed the same way; see that doc's §8.

**AMENDED 2026-11-22 (d) -- `c58` and `slice3` are closed to 106/115.**
Their whole-file count read 73/115, i.e. **42 survivors**.  33 of those
are now killed by named killer tests, one per site; the remaining **9**
are the `lt` sites, and they are **equivalent** rather than untested --
each is a "did I find the closing delimiter?" comparison written
`< 0`, and the value it compares can never be 0 at those call sites, so
the `<= 0` mutant is indistinguishable.  Each of the nine carries a
differential proof with a **non-vacuity control** (the same bound turned
the other way, which IS observable).  So the row reads **106/115**, with
the module body unchanged.

**What this means for the numbers in this table.**  Every row whose
suite unittest can see is unaffected -- the runner change only moves
the rows above.  And the direction is fixed: the false kills all
pointed the *stronger* way, so a corrected number can only be LOWER
than the one here.

The suite-blindness is now measured by **unittest's own loader**, and
the check lives in
`components/northstar-agent-runtime/tests/test_unittest_blind_slices.py`.

## 9. The conformance test

`components/northstar-agent-runtime/tests/test_judge_hygiene.py` is
**read-only** with respect to the repository: it builds throwaway
directories under `tempfile.mkdtemp()`, runs the probe in them and
removes them with `shutil.rmtree()`.  It asserts tool *behaviour*, not
tool source text:

* the probe observes the **second** of two same-length mutants written
  in the same second, rather than replaying the first one's verdict;
* the probe leaves **no bytecode cache** next to the module it rewrote,
  and does not reuse a stale one;
* the reported `killed k/n` is **identical** across two runs on the same
  code, and identical with and without a writable bytecode cache;
* the output format and the exit-code semantics are unchanged
  (`0` = >=1 killed, `1` = all survived, `2` = the probe could not run),
  and the probe restores the original source after every round;
* the probe **also** restores the original source when it is **killed**
  mid-round (D-24) — a SIGTERM is sent while the fixture's deliberately
  slow suite is running, and the module must be byte-identical
  afterwards.  The fixture's suite sleeps for 20 seconds so the probe is
  provably still inside a round when the signal lands; a test that could
  only pass by racing would prove nothing;
* this slice's patch applies cleanly to the installed probe and touches
  **only** `b173-mutant.py` and `b173-mutant.sh`.

The behavioural tests run against a **copy** of the installed probe to
which this slice's D-22 fix is applied (as exact old -> new text
replacements, so the tests work whether or not the coordinator has
applied the live patch yet); if the probe is not installed at all (clean
clone) they skip, and the in-repository tests (the design doc) still
run.  The live probe is never modified by this slice.
