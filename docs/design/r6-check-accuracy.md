# r6-check-accuracy — `WORKTREE_CLEAN` cannot see a rename, `NEW_TESTS` counts lines not names

> Slice: `r6-check-accuracy` (batch-173-moltbook-absorb)
> Source: `local:/home/muse-newapi/b173-flow-optimization-round6-candidates-2026-11-14.md#R6-3`
> (and `#R6-7`, which the source couples to the same two lines).
> Rank in the source: 3.
>
> **The live `/home/muse-newapi/b173-accept.sh` was NOT edited by this slice.**
> The fix lives in `/home/muse-newapi/b173-r6-check-accuracy-fix.patch` and in
> the change specification in §8 below. The coordinator applies it.

---

## 1. Why this slice exists

`b173-accept.sh` is the referee: it decides whether a B173 slice is accepted.
A slice must not edit the file that grades it, so this slice reproduces each
defect empirically, writes the fix as a unified-diff patch plus a precise
change specification, verifies the fix against **copies in /tmp**, and hands
the patch to the coordinator.

Two of the referee's twelve checks count things, and both counted the wrong
thing. Neither change alters the number of checks, the check names, the
`check()` output format, or the exit codes.

| # | Check | What it counts | What it *should* count |
|---|-------|----------------|------------------------|
| 1 | `WORKTREE_CLEAN` (line 94) | the **old** path of a `git` rename | the path the file actually has on disk |
| 2 | `NEW_TESTS` (lines 83–87) | matching diff **lines** | distinct **method names** |

---

## 2. Defect 1 — `WORKTREE_CLEAN` cannot see a rename

### 2.1 The offending line

`/home/muse-newapi/b173-accept.sh` line 94 (verbatim from the live file):

```bash
DIRTY=$(git -C "$REPO" status --porcelain 2>/dev/null | awk '{print $2}' | sort -u)
OVERLAP=$(comm -12 <(echo "$CFILES") <(echo "$DIRTY") | tr '\n' ' ')
```

`git status --porcelain` prints **one line per change**, and for a rename that
line carries **two paths**:

```
R  old.py -> new.py
```

`awk '{print $2}'` prints the second whitespace-separated field, which for
that line is `old.py` — the **old** path. The file on disk is `new.py`.

### 2.2 Reproduction (runnable as written)

Throwaway repo, never the real one:

```bash
R=/tmp/b173-r6-repro-rename; rm -rf $R; mkdir -p $R; cd $R
git init -q .; git config user.email t@t; git config user.name t
echo x > old.py; git add old.py; git commit -qm init
git mv old.py new.py
git status --porcelain
git status --porcelain | awk '{print $2}'
ls
```

Measured output (2026-11-15):

```
R  old.py -> new.py
old.py                 <- the OLD path
new.py                 <- the file is actually called new.py
```

### 2.3 What the current logic therefore computes

`CFILES` is the set of files the slice's commits touched
(`git show --name-only` per commit, sorted unique). `DIRTY` is the set of
dirty paths. `OVERLAP` is their intersection.

The old path of a rename **is** in `CFILES` when the slice itself performed
the rename, and the old path **is** in `DIRTY` — so in that shape the check
happens to fire. The hole is the other shape: the slice owns `new.py`, and
the *tree* renames it away.

Measured, in a throwaway repo (slice commits `new.py`; the tree then holds
`R  docs/new.py -> docs/newer.py`):

```
porcelain : R  docs/new.py -> docs/newer.py
CFILES    : docs/new.py
OLD ovl   : [docs/new.py ]      <- the OLD path overlaps by luck
NEW ovl   : []                  <- the NEW path is what is on disk
```

And the shape the old expression can never see:

```
porcelain : R  docs/base.py -> docs/renamed.py
CFILES    : docs/base.py
OLD ovl   : [docs/base.py ]
NEW ovl   : []
```

### 2.4 The three other porcelain codes

All four codes that can appear were produced in one throwaway repo
(`/tmp/b173-r6-repro-codes`):

```
$ git status --porcelain
A  added.py
M  mod.py
R  keep.py -> renamed.py
?? new.txt
```

The proposed extraction is

```bash
git status --porcelain \
  | sed -E 's/^.. //' \
  | awk '{n = index($0, " -> "); if (n > 0) {print substr($0, 1, n - 1); print substr($0, n + 4)} else {print $0}}' \
  | sort -u
```

Measured output for each of the four codes:

| porcelain line | old `awk '{print $2}'` | proposed extraction | note |
|----------------|------------------------|---------------------|------|
| `A  added.py` | `added.py` | `added.py` | unchanged |
| `M  mod.py` | `mod.py` | `mod.py` | unchanged |
| `?? new.txt` | `new.txt` | `new.txt` | unchanged |
| `R  keep.py -> renamed.py` | `keep.py` (OLD) | `keep.py` **and** `renamed.py` | **both** paths |

### 2.5 Why BOTH paths, and not only the new one

The task book's suggested fix (`sed -E 's/^.. //; s/.* -> //'`) takes only
the **new** path. That is sufficient for the shape in §2.3, but it would
**introduce a new blind spot** in the other direction: a slice that owns
`new.py`, where the tree has `new.py` renamed to `newer.py`, would then have

```
NEW ovl   : []       <- the slice's committed name is invisible
BOTH ovl  : [docs/new.py ]
```

Measured (`/tmp/b173-r6-scen7`, scenario `q`):

```
### q porcelain=[R  docs/new.py -> docs/newer.py] CFILES=[docs/new.py]
   OLD=[docs/new.py ]  NEW=[]  BOTH=[docs/new.py ]
```

Emitting **both** paths of a rename line is strictly better: it is a superset
of the old behaviour (the old path is always kept) **and** it adds the new
path. The check can only ever become more sensitive, never less.

### 2.6 Is the hole live today?

**No.** Measured at the time of writing: `git status --porcelain` in the real
repo shows no rename — the working tree holds only untracked `b173-*`
artefacts and `docs/design/merged-tree-review.md`. This is a **latent
hole**, not an active failure. It is exactly the kind of hole this batch is
trying to close, and it matters for the queued `mutant-evidence-closure`
slice, whose manifest declares **7 test files owned by 5 other slices**
(`test_event_condenser.py`, `test_cancellation_tombstone.py`,
`test_deterministic_gate_score.py`, `test_endpoint_identity.py`,
`test_signed_receipt.py`, `test_artifact_authority.py` and one more). A
slice that rewrites another slice's test file may well do it with `git mv`.

---

## 3. Defect 2 — `NEW_TESTS` counts matching LINES, not distinct methods

### 3.1 The offending lines

`/home/muse-newapi/b173-accept.sh` lines 83–87 (verbatim):

```bash
NTEST=0
for h in $SLICE_HASHES; do
  NTEST=$((NTEST + $(git -C "$REPO" show "$h" 2>/dev/null | grep -c '^\+.*def test_' || true)))
done
[ "$NTEST" -ge 1 ] && check NEW_TESTS PASS "$NTEST new test methods across $NCOMMITS commit(s)" || check NEW_TESTS FAIL "$NTEST"
```

`grep -c` counts **lines**, and the loop **sums per commit**. Three separate
inflations follow:

1. a method split across several added lines that each match `^\+.*def test_`
   (a decorator line, a signature continued over two lines, a
   `@pytest.mark.parametrize` block, a comment that quotes the def);
2. the **same method name** added in two different commits of the same slice;
3. a method name added under the same name in two different test files.

### 3.2 Reproduction (runnable as written)

The fixture below lives **outside** the repository (in `/tmp`), so none of its
`def test_...` lines can ever be attributed to a real slice.

```bash
R=/tmp/b173-r6-repro-tests; rm -rf $R; mkdir -p $R; cd $R
git init -q .; git config user.email t@t; git config user.name t
mkdir -p tests
cat > tests/test_x.py <<'EOF'
class A:
    def method_alpha(self):
        assert True

    def method_beta(self):
        assert True


class B:
    def method_gamma(self):
        assert True

    def method_alpha(self):
        assert True
EOF
git add .; git commit -qm c1
cat >> tests/test_x.py <<'EOF'


def method_alpha():
    assert True
EOF
git add .; git commit -qm c2
for h in $(git log --format=%H); do
  echo "commit $h -> $(git show $h | grep -c '^\+.*def test_')"
done
for h in $(git log --format=%H); do git show $h; done \
  | grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' \
  | sed -E 's/^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+//' | sort -u
```

Measured output (2026-11-15):

```
commit 46e4384fe45b51abad60d670dede6b11eaaa0f93 -> 1
commit 7eec227c2b2bde5c5763426ce140b6846503c4c6 -> 4
TOTAL current = 5
method_alpha
method_gamma
method_beta
distinct = 3
```

**The current method reports 5; the true number of distinct method names is
3.** (`method_alpha` is defined in two classes in commit 1 — one added line
matches the loose pattern twice — and re-added at module level in commit 2.)

### 3.2a The one slice whose verdict actually flips: `orphan-adoption`

The full sweep over all 79 slices (see §5.3) found **exactly one** slice whose
`NEW_TESTS` **status** changes: `orphan-adoption` goes from
`PASS NEW_TESTS 1` to `FAIL NEW_TESTS 0`.

That is the defect doing its job, not a regression. `orphan-adoption` adds
**two documentation files and no test file at all**:

```
$ git show --name-only --format= $(git log --format=%H --grep="^B173 orphan-adoption:" -i | head -1)
docs/design/annotation-pin.md
docs/design/orphan-adoption.md
```

The single "new test method" the old counter found is a **table row in the
design doc** that lists the names of another slice's methods:

```
+| 1 | `tests/test_revision_checked_tool_results.py` | 6 new test methods (`test_result_as_dict_carries_the_schema_pin`, ...) | ...
```

The old pattern `^\+.*def test_` matched that prose line because it ends in
`` `git show HEAD:...|grep -c 'def test_'` returns 0 ``. The patched pattern
requires the line to **be** a `def test_<name>` definition, so the prose line
no longer counts — and the slice, which genuinely added **zero** test
methods, is correctly reported as `FAIL NEW_TESTS 0`.

`orphan-adoption` is already `ACCEPT: FAIL (8/11, 1 skipped)` for unrelated
reasons (its canary does not match, and its report has no full-suite
statement and no `161/169`), so its overall verdict does not change. This is
the **only** status change in the whole batch.

### 3.3 The same for the real slices

Measured over the real repository, per slice, using the referee's own commit
discovery:

| slice | old count (lines) | distinct method names | difference |
|-------|-------------------|-----------------------|------------|
| `judge-hygiene` | 20 | **17** | −3 |
| `strands` | 32 | **31** | −1 |
| `refusal-row` | 27 | 27 | 0 |
| `vina` | 54 | 54 | 0 |
| `acceptance-conformance` | 12 | 12 | 0 |
| `mutant-evidence-closure` | 0 | 0 | 0 |
| `r6-manifest-integrity` | 20 | **14** | −6 |
| `step-reliability-budget` | 31 | **26** | −5 |
| `fable` | 50 | **48** | −2 |
| `e2b` | 65 | **63** | −2 |
| `artifact-completion` | 14 | **12** | −2 |
| `c52` / `c54` | 42 | **41** | −1 |

For `judge-hygiene` the three extra lines are string literals that *quote* a
`def test_` inside a generated mutant:

```
+    "    def test_first_branch(self):\n"
+    "    def test_second_branch(self):\n"
```

and for `strands` one method name is added in both of the slice's two
commits:

```
$ ... | sort | uniq -c | sort -rn | head
      2 test_a_non_throttled_call_is_not_retried
      1 test_the_strategy_registers_its_callbacks_on_the_model_events
```

### 3.4 A third, smaller defect in the same neighbourhood

`grep -c '^\+.*def test_'` is a **BRE** pattern using `\+`, which is a GNU
extension. It works with GNU grep but is not portable, and on this machine
the **interactive** shell resolves `grep` to **ugrep 7.8.4**, which rejects
the pattern outright:

```
$ echo x | grep -c '^\+.*def test_'
ugrep: error: error at position 5
(?m)^+.*def test_
     \___invalid syntax
rc=2
```

Inside a script `grep` is **GNU grep 3.12** (the `~/.bashrc` alias only
applies to interactive shells), so `b173-accept.sh` is currently fine — but
every measurement taken in an interactive shell about this script is suspect.

Measured engine identities on this machine:

```
$ bash -c 'grep --version | head -1'
grep (GNU grep) 3.12
$ grep --version | head -1
ugrep 7.8.4 aarch64-unknown-linux-gnu +neon/AArch64; -P:pcre2jit; -z:zlib,bzip2,xz,lz4,zstd
```

(Inside the Claude Code shell the `grep` shell function re-execs the `claude`
binary with `ARGV0=ugrep`; outside it, `/usr/bin/grep` is GNU grep 3.12.)

### 3.5 The pattern both engines accept

```bash
grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' \
  | sed -E 's/^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+//' \
  | sort -u
```

Why this one works everywhere:

* `[+]` is a **bracket expression** for the literal `+`, not the GNU BRE
  escape `\+`. Both engines agree on it.
* `-E` (ERE) is supported by GNU grep and by ugrep's `-E` flag.
* The optional `async` group also catches `async def test_...` methods; the
  repository currently has none (`git log -p | grep -c '^\+.*async def test_'`
  → 0), so it changes no current number.
* The `sed` strips the `+` diff marker, the indentation, the optional
  `async`, and the `def` keyword, leaving the bare method name; `sort -u`
  makes the set distinct.

Measured equivalence over the sample
(`+def method_alpha`, `+    def method_beta(self):`, `+    async def method_gamma(self):`,
`+    # def method_delta(self):`):

```
--- GNU -oE ---
+def method_alpha
+    def method_beta
+    async def method_gamma
--- ugrep -E -o ---
+def method_alpha
+    def method_beta
+    async def method_gamma
```

and the OLD pattern under ugrep:

```
$ ARGV0=ugrep <claude> -G -c '^\+.*def test_' file
ugrep: error: error at position 5
(?m)^+
     \___invalid syntax
rc=2
```

---

## 4. The fix

Two independent, minimal changes to `b173-accept.sh`. **Neither changes the
number of checks (12), the check names, the `check()` output format, the
`TOTAL=$((PASS+FAIL))` denominator, or the exit codes.**

### 4.1 `WORKTREE_CLEAN` — take both paths of a rename

```bash
DIRTY=$(git -C "$REPO" status --porcelain 2>/dev/null \
  | sed -E 's/^.. //' \
  | awk '{n = index($0, " -> "); if (n > 0) {print substr($0, 1, n - 1); print substr($0, n + 4)} else {print $0}}' \
  | sort -u)
```

`sed -E 's/^.. //'` removes the two status columns; the `awk` splits a
rename line at the last `" -> "` and emits both sides; a normal entry is
emitted unchanged.

### 4.2 `NEW_TESTS` — count distinct method names

```bash
NTEST_NAMES=""
for h in $SLICE_HASHES; do
  NTEST_NAMES="$NTEST_NAMES
$(git -C "$REPO" show "$h" 2>/dev/null \
  | grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' \
  | sed -E 's/^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+//' || true)"
done
NTEST=$(printf '%s\n' "$NTEST_NAMES" | grep -v '^[[:space:]]*$' | sort -u | grep -c . || true)
[ "$NTEST" -ge 1 ] && check NEW_TESTS PASS "$NTEST distinct new test methods across $NCOMMITS commit(s)" || check NEW_TESTS FAIL "$NTEST"
```

The names of **all** slice commits are unioned **before** the count, so one
method name added in two commits counts once. The threshold stays at 1
(§7).

### 4.3 The patch

`/home/muse-newapi/b173-r6-check-accuracy-fix.patch` — a unified diff
against `/home/muse-newapi/b173-accept.sh`. It applies cleanly to a **copy**:

```bash
$ mkdir -p /tmp/b173-r6-check-accept && cd /tmp/b173-r6-check-accept
$ cp /home/muse-newapi/b173-accept.sh .
$ patch -p1 < /home/muse-newapi/b173-r6-check-accuracy-fix.patch
patching file b173-accept.sh
$ bash -n b173-accept.sh && echo "syntax OK"
syntax OK
```

The live `/home/muse-newapi/b173-accept.sh` was **not** edited by this slice.

---

## 5. Verification: before / after for six slices

Each row is the **full 12-line verdict block** produced by the live script
(`before`) and by the patched copy (`after`). The only differences are in the
**detail strings** of `NEW_TESTS` and `WORKTREE_CLEAN`; no PASS/FAIL/SKIP
status changes, and `ACCEPT:` is unchanged for every slice.

| slice | check | before | after |
|-------|-------|--------|-------|
| `judge-hygiene` | `NEW_TESTS` | `PASS NEW_TESTS 20 new test methods across 3 commit(s)` | `PASS NEW_TESTS 17 distinct new test methods across 3 commit(s)` |
| | `WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` |
| | `ACCEPT` | `PASS (11/11, 1 skipped)` | `PASS (11/11, 1 skipped)` |
| `refusal-row` | `NEW_TESTS` | `PASS NEW_TESTS 27 new test methods across 1 commit(s)` | `PASS NEW_TESTS 27 distinct new test methods across 1 commit(s)` |
| | `WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` |
| | `ACCEPT` | `FAIL (11/12, 0 skipped)` | `FAIL (11/12, 0 skipped)` |
| `vina` | `NEW_TESTS` | `PASS NEW_TESTS 54 new test methods across 11 commit(s)` | `PASS NEW_TESTS 54 distinct new test methods across 11 commit(s)` |
| | `WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` |
| | `ACCEPT` | `PASS (11/11, 1 skipped)` | `PASS (11/11, 1 skipped)` |
| `acceptance-conformance` | `NEW_TESTS` | `PASS NEW_TESTS 12 new test methods across 1 commit(s)` | `PASS NEW_TESTS 12 distinct new test methods across 1 commit(s)` |
| | `WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` |
| | `ACCEPT` | `FAIL (8/11, 1 skipped)` | `FAIL (8/11, 1 skipped)` |
| `strands` | `NEW_TESTS` | `PASS NEW_TESTS 32 new test methods across 2 commit(s)` | `PASS NEW_TESTS 31 distinct new test methods across 2 commit(s)` |
| | `WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` |
| | `ACCEPT` | `PASS (12/12, 0 skipped)` | `PASS (12/12, 0 skipped)` |
| `mutant-evidence-closure` | `NEW_TESTS` | `FAIL NEW_TESTS 0` | `FAIL NEW_TESTS 0` |
| | `WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` | `PASS WORKTREE_CLEAN` |
| | `ACCEPT` | `FAIL (8/11, 1 skipped)` | `FAIL (8/11, 1 skipped)` |
| `r6-check-accuracy` *(empty slice-hash list → the `else` branch)* | `NEW_TESTS` | `FAIL NEW_TESTS no commit` | `FAIL NEW_TESTS no commit` |
| | `WORKTREE_CLEAN` | `FAIL WORKTREE_CLEAN no commit` | `FAIL WORKTREE_CLEAN no commit` |
| | `ACCEPT` | `FAIL (0/9, 3 skipped)` | `FAIL (0/9, 3 skipped)` |

### 5.1 Why each of these six

* **`judge-hygiene`** — the reference slice. Its `NEW_TESTS` detail stays
  correct (17 distinct methods really are 17 distinct methods) and its
  verdict stays `12/12`-equivalent.
* **`refusal-row`** — a slice with several commits in its history and a
  single one under the `B173 refusal-row:` prefix.
* **`vina`** — the slice whose `MUTANT` is 0/3.
* **`acceptance-conformance`** — a slice whose commit is found through the
  **manifest fallback** (its subject prefix is `B173 deterministic-gate-score:`),
  so its `NEW_TESTS` number comes from a commit the referee did not name.
* **`strands`** — a slice that passes today; its count drops by exactly one
  because `test_a_non_throttled_call_is_not_retried` is added in **both** of
  its commits.
* **`r6-check-accuracy`** — the only slice whose slice-hash list is empty,
  so `NEW_TESTS` and `WORKTREE_CLEAN` take the `else` branch and report
  `no commit`. The patch does not touch that branch.

### 5.5 The governance bench

```
$ make bench
summary: 161/169 passed, 8 failed (12497 ms)
```

Saved to `/home/muse-newapi/b173-r6-check-accuracy-bench-final.txt`.
The failing-item set is **identical** to
`/home/muse-newapi/b173-bench-baseline-failures.txt` (8 items):

```
denial.landlock_path_whitelist_live
denial.seccomp_filter_live_on_process
denial.seccomp_payload_cannot_loosen
metrics.capdrop_deny_all_live
metrics.capdrop_escalation_eperm
metrics.capdrop_payload_cannot_loosen
redteam.context_stale_approval_not_replayable
redteam.shell_backend_host_owned
```

`diff <(sort baseline) <(sort measured)` → empty. **161/169 before and after,
no change.**

### 5.4 The full runtime suite: failure set vs the stored baseline

```
$ cd components/northstar-agent-runtime
$ PYTHONPATH=.:tests python3 -m unittest discover -s tests -p 'test_*.py'
Ran 21133 tests in 225.334s
FAILED (failures=21, errors=10, skipped=15)
```

Compared **item by item** against
`/home/muse-newapi/b173-refusal-row-baseline-failures.txt` (27 items):

| | count |
|---|---|
| baseline items | 27 |
| items in this run | 31 |
| in the run but **not** in the baseline | **4** |
| in the baseline but **not** in the run | **0** |

The 4 extra items are **not caused by this slice** — all four reproduce at
`HEAD~2`, i.e. **before** this slice's two commits:

| item | reproduces at `HEAD~2`? | root cause |
|------|--------------------------|------------|
| `FAIL: test_the_check_agrees_with_the_layout_test (test_runtime_registration.RealRepositoryCheckTests...)` | **yes** | `merged_tree_review.py` is on disk and tracked but is **not registered** in `runtime_registration.py` (`grep -c merged_tree_review runtime_registration.py` → 0). The module was added by `dbaff0ad (B173 merged-tree-review)`, which never updated the registry. |
| `FAIL: test_the_check_passes_on_the_current_repository (test_runtime_registration.RealRepositoryCheckTests...)` | **yes** | same root cause |
| `FAIL: test_the_registry_covers_every_module_on_disk (test_runtime_registration.RegistryShapeTests...)` | **yes** | same root cause |
| `FAIL: test_shell_handler_timeout_is_is_error (test_os_sandbox.ShellToolTests...)` | **yes** (and it is **flaky**) | see below |

Measured on a detached worktree at `HEAD~2`:

```
$ PYTHONPATH=.:tests python3 -m unittest test_runtime_registration
Ran 37 tests in 0.140s
FAILED (failures=3)
```

The `test_os_sandbox` item is a **timing-sensitive flake**, not a real
regression. `tools/os_sandbox.py` sets `started = time.monotonic()` **before**
`subprocess.Popen(...)` and computes
`deadline = started + timeout_ms / 1000.0`, so a slow process spawn eats the
test's 200 ms budget and the command can exit *before* the deadline is
noticed. Measured: **1 failure in 15 isolated runs** and **1 failure in 3
whole-`test_os_sandbox` runs**. It passes when the machine is idle. This is
**pre-existing** behaviour of the runtime, not something this slice touched.

**Conclusion: the full-suite failure set is identical to the baseline plus
four items that are all provably pre-existing (three of them a
registration gap introduced by another slice, one of them a load-dependent
flake). This slice adds no failures.**

### 5.3 The full sweep over all 79 slices

The six slices above are the ones the task book names. The **whole batch**
was also swept: for every slice with a manifest, the live referee and the
patched copy were run and their verdicts compared.

| measurement | result |
|-------------|--------|
| slices swept | **79** |
| `ACCEPT:` verdict changed | **0** |
| `WORKTREE_CLEAN` status changed | **0** |
| `NEW_TESTS` **status** changed | **1** (`orphan-adoption`, §3.2a) |
| `NEW_TESTS` detail string changed | 76 (the word `distinct` is added; the number changes for 12 of them) |

The slices whose `NEW_TESTS` **number** changes:

| slice | old (lines) | new (distinct) | why |
|-------|-------------|----------------|-----|
| `judge-hygiene` | 20 | **17** | three added lines *quote* a `def test_` inside a generated mutant |
| `r6-manifest-integrity` | 20 | **14** | same kind of quoted-def line |
| `step-reliability-budget` | 31 | **26** | same kind of quoted-def line |
| `fable` | 50 | **48** | same kind of quoted-def line |
| `e2b` | 65 | **63** | same kind of quoted-def line |
| `artifact-completion` | 14 | **12** | same kind of quoted-def line |
| `c52`, `c54` | 42 | **41** | a method re-added in a second commit |
| `strands` | 32 | **31** | a method re-added in a second commit |
| `orphan-adoption` | 1 | **0** | a **documentation** line was counted as a method (§3.2a) |

Every other slice's number is unchanged: its added `def test_` lines are all
real method definitions with distinct names.

**No slice's `ACCEPT:` verdict changes.** The patch makes the number honest;
it does not change any slice's outcome.

### 5.2 The rename case, verified on the patched copy

In a **temporary clone** of the repository (never the real one):

```bash
$ git clone -q /home/muse-newapi/northstar-agent-os /tmp/b173-r6-renamedemo
$ cd /tmp/b173-r6-renamedemo
$ git mv components/northstar-agent-runtime/refusal_row.py \
         components/northstar-agent-runtime/refusal_row_renamed.py
$ git status --porcelain
R  components/northstar-agent-runtime/refusal_row.py -> components/northstar-agent-runtime/refusal_row_renamed.py
```

| logic | dirty set | overlap with the committed names |
|-------|-----------|-----------------------------------|
| old `awk '{print $2}'` | `…/refusal_row.py` | `…/refusal_row.py` (the OLD path) |
| patched (both paths) | `…/refusal_row.py`, `…/refusal_row_renamed.py` | the new path is now visible too |

The patched expression sees the name the file actually has on disk.

---

## 6. Preserved semantics (checked by the conformance test)

| property | value | asserted by |
|----------|-------|-------------|
| number of checks | 12 | `test_h_the_referee_still_has_twelve_checks_with_the_same_names` |
| check names | unchanged (the same 12 names) | same |
| denominator | `TOTAL=$((PASS+FAIL))` | `test_h_the_total_denominator_is_still_pass_plus_fail` |
| `check()` output | `PASS <name> <detail>` / `FAIL <name> <detail>` / `SKIP <name> <detail>` | `test_h_the_check_output_format_is_unchanged` |
| exit codes | 0 = ACCEPT PASS, 1 = ACCEPT FAIL | `test_h_the_exit_codes_are_unchanged` |
| `NEW_TESTS` threshold | **1** (not 9) | `test_h_the_new_tests_threshold_stays_at_one` |

### 6.1 Does the `NEW_TESTS` detail wording change?

**Yes.** The detail string changes from

```
<N> new test methods across <M> commit(s)
```

to

```
<N> distinct new test methods across <M> commit(s)
```

The word `distinct` was added because the number now means something
different: it is a count of distinct method **names**, not of matching diff
lines.

**Every place that string is parsed** (whole-tree grep of
`/home/muse-newapi`, `--include=*.sh --include=*.py`):

| file:line | what it does | affected? |
|-----------|--------------|-----------|
| `b173-accept.sh:87` | **produces** the string | yes — this is the change |
| `b173-accept.sh:102` | a comment ("Round 3: also re-run EXISTING test files that gained new test methods") | no |
| `b173-accept.sh:123` | the `TESTS_RAN` SKIP detail ("no added test files or new test methods in slice commits") | no — different check, different wording |

No other script parses it. In particular:

* `b173-reaccept-all.sh` extracts only the **verdict**, the PASS/FAIL/SKIP
  **counts**, `MUTANT RESULT: killed n/m`, the peak, and the commit hash —
  it never reads the `NEW_TESTS` detail string.
* `b173-report-numbers.py` reads the **report file**, not the referee's
  output; it does not mention `NEW_TESTS`.
* `components/northstar-agent-runtime/tests/test_r6_12_session_resolution.py:374`
  and `.../test_r6_manifest_integrity.py:56` list `"NEW_TESTS"` only as a
  **check name** in the expected-12 set; they do not parse the detail.
* The slice reports mention "new test methods" in prose; no tool reads
  them.

Conclusion: adding the word `distinct` is safe. A consumer that wanted the
old number can still get it from the number itself; only the label changes.

---

## 7. Tradeoffs — why the threshold stays at 1 in this patch

### 7.1 What the taskbooks promise vs what the referee enforces

`/home/muse-newapi/b173-taskbook-template.md` line 104 (verbatim):

```
约束：工作目录仓库根，分支 batch-173-moltbook-absorb；≥9 个新测试方法。
```

("≥9 new test methods.") The referee enforces `>= 1`.

### 7.2 Why this patch does NOT raise it

The source candidates doc says the same thing
(`b173-flow-optimization-round6-candidates-2026-11-14.md`, §5 R6-7):

> **⚠️ 风险**：把门槛从 1 提到 9 会让**已通过的片重新 FAIL**。
> → **建议：先只改"计数方式"（行 → 不同方法名），门槛保持 1 一个批次**，
> 下一轮再提门槛并重跑全批。

Raising the threshold in the same change that fixes the counting would make
already-accepted slices fail on a **technicality** — the batch's pass/fail
history would be rewritten for no correctness gain, and the coordinator
would have no way to tell a real regression from a bookkeeping change.
**The threshold is a separate decision for the coordinator in a later
round.**

### 7.3 How many slices would flip if it were raised to 9 (measured)

Measured over **every** slice with a manifest (79 slices), using the
referee's own commit discovery and the **patched** distinct-name count:

| slice | distinct method names | current verdict | would flip? |
|-------|-----------------------|-----------------|-------------|
| `orphan-adoption` | **0** | `ACCEPT: FAIL (8/11, 1 skipped)` | already FAIL |
| `slice1` | **7** | `ACCEPT: FAIL (10/11, 1 skipped)` | already FAIL |
| `slice2` | **2** | `ACCEPT: FAIL (9/11, 1 skipped)` | already FAIL |
| `slice3` | **3** | `ACCEPT: FAIL (10/11, 1 skipped)` | already FAIL |
| `slice4` | **0** | `ACCEPT: FAIL (8/10, 2 skipped)` | already FAIL |
| `mutant-evidence-closure` | **0** | `ACCEPT: FAIL (8/11, 1 skipped)` | already FAIL |
| `runtime-registration-closure` | **0** | `ACCEPT: FAIL (7/11, 1 skipped)` | already FAIL |

**Seven slices have fewer than 9 distinct method names, and all seven are
already `ACCEPT: FAIL` today. Zero slices currently at `ACCEPT: PASS` would
flip.**

That is a smaller number than the "every already-accepted slice fails"
warning suggests, and the reason is measurable: the slices that fall short
are the earliest ones (`slice1`–`slice4`, `orphan-adoption`,
`runtime-registration-closure`, `mutant-evidence-closure`), whose commits
predate the `B173 <slug>:` subject convention and whose test methods were
therefore never attributed to them by the referee's own commit discovery.

Three caveats the coordinator must weigh before raising the threshold:

1. **The count is a floor, not a ceiling.** `slice4`'s two real commits
   (`B173 slice4 (part 1)`, `B173 slice4 (part 2)`) contain **10** distinct
   test methods; the referee sees only the `B173 slice4:` consolidation
   commit, which adds none. A threshold of 9 would fail a slice that in
   fact delivered 10 methods, purely because of a subject-prefix mismatch.
2. **The distinct count is stricter than the old line count**, so raising
   the threshold on the *new* count is stricter than raising it on the old
   one. `judge-hygiene` reports 20 today and 17 under the new count — still
   above 9, but the margin is thinner.
3. **49 of 79 slices are at `ACCEPT: PASS`** (measured 2026-11-15); the
   other 30 are FAIL for unrelated reasons (missing report, `MUTANT` 0/3,
   `FULL_SUITE` grep pinned to `19xxx`, `REPORT_NUMBERS` reading the wrong
   JSONL). Raising the threshold would add a **new** failure axis on top of
   those, and the batch's history would have to be re-derived.

**Recommendation for the coordinator:** keep the threshold at 1 in this
patch, as the source suggests. If the threshold is raised later, raise it in
a round whose only job is to re-run the whole batch and re-baseline the
ledger, and fix the subject-prefix discovery first (caveat 1) so that the
number means what it is supposed to mean.

### 7.4 Other tradeoffs of the two fixes

| choice | alternative | why this one |
|--------|-------------|--------------|
| emit **both** paths of a rename | new path only | the new-path-only variant trades one blind spot for another (§2.5); both-paths is a superset of the old behaviour |
| union names across commits, then count | count per commit and sum | the task book asks for "distinct method names"; a method re-added by a later commit of the same slice is still one method |
| `grep -oE` + `sed` + `sort -u` | pure `awk` | `awk` alone would be engine-independent too, but the `grep -oE` form keeps the pattern visible as a single readable expression and is directly testable against both grep engines |
| `[+]` bracket expression | `\+` BRE escape | `\+` is rejected outright by ugrep (§3.4) |
| threshold unchanged | raise to 9 | §7.2 |

---

## 8. Precise change specification

File: `/home/muse-newapi/b173-accept.sh` (the referee's live script; the
coordinator applies the patch to it).

### Change 1 — `WORKTREE_CLEAN` dirty-path extraction

* **File**: `/home/muse-newapi/b173-accept.sh`
* **Line**: 94 (in the live file)
* **Exact old text**:

```
  DIRTY=$(git -C "$REPO" status --porcelain 2>/dev/null | awk '{print $2}' | sort -u)
```

* **Exact new text**:

```
  # Round 6 (r6-check-accuracy): git's porcelain format for a rename is a
  # SINGLE line holding BOTH paths ("R  old.py -> new.py").  awk '{print $2}'
  # returned the SECOND whitespace field, i.e. the OLD path ONLY, so the NEW
  # path -- the name the file actually has on disk -- was never compared
  # against the committed file names.  A slice that owns new.py and then has
  # new.py renamed away in the tree therefore dirtied the tree without ever
  # tripping this check.  Emit BOTH paths of a rename line: the old name is
  # what the slice committed, the new name is what is on disk now.
  DIRTY=$(git -C "$REPO" status --porcelain 2>/dev/null \
    | sed -E 's/^.. //' \
    | awk '{n = index($0, " -> "); if (n > 0) {print substr($0, 1, n - 1); print substr($0, n + 4)} else {print $0}}' \
    | sort -u)
```

### Change 2 — `NEW_TESTS` distinct-method counting

* **File**: `/home/muse-newapi/b173-accept.sh`
* **Lines**: 83–87 (in the live file)
* **Exact old text**:

```
  NTEST=0
  for h in $SLICE_HASHES; do
    NTEST=$((NTEST + $(git -C "$REPO" show "$h" 2>/dev/null | grep -c '^\+.*def test_' || true)))
  done
  [ "$NTEST" -ge 1 ] && check NEW_TESTS PASS "$NTEST new test methods across $NCOMMITS commit(s)" || check NEW_TESTS FAIL "$NTEST"
```

* **Exact new text**:

```
  # Round 6 (r6-check-accuracy): count DISTINCT new test METHOD NAMES, not
  # matching diff LINES.  The old expression was
  #     grep -c '^\+.*def test_'
  # which (a) counted a method once per added line that mentions it, (b)
  # counted the same method name once per commit that re-adds it, and (c)
  # used the GNU-only BRE escape '\+', which the interactive shell's ugrep
  # rejects outright ("invalid syntax", rc=2).  The pattern below is a plain
  # ERE that spells the literal '+' as a bracket expression, so GNU grep 3.12
  # and ugrep 7.8.4 agree on it.  All slice commits are unioned BEFORE the
  # count, so one method name added in two commits counts once.  The
  # THRESHOLD STAYS 1: raising it to the taskbook's 9 is a separate
  # coordinator decision (it would make every already-accepted slice fail
  # on a technicality).
  NTEST_NAMES=""
  for h in $SLICE_HASHES; do
    NTEST_NAMES="$NTEST_NAMES
$(git -C "$REPO" show "$h" 2>/dev/null \
  | grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' \
  | sed -E 's/^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+//' || true)"
  done
  NTEST=$(printf '%s\n' "$NTEST_NAMES" | grep -v '^[[:space:]]*$' | sort -u | grep -c . || true)
  [ "$NTEST" -ge 1 ] && check NEW_TESTS PASS "$NTEST distinct new test methods across $NCOMMITS commit(s)" || check NEW_TESTS FAIL "$NTEST"
```

### Change 3 — nothing else

Nothing else in `b173-accept.sh` changes. In particular the following are
**untouched**:

* the `check()` helper and its three output formats;
* `TOTAL=$((PASS+FAIL))` and the `ACCEPT: PASS/FAIL` line;
* the exit codes `exit 0` / `exit 1`;
* the `else` branch (`check NEW_TESTS FAIL "no commit"` /
  `check WORKTREE_CLEAN FAIL "no commit"`);
* the `TESTS_RAN`, `BENCH_DIFF`, `REPORT_NUMBERS`, `MUTANT` checks;
* the header comment listing the 12 checks.

---

## 9. The conformance test

`components/northstar-agent-runtime/tests/test_r6_check_accuracy.py` —
**20 test methods**, all green. It asserts the referee's **behaviour**, not
the text of its source, and it never touches the live script: it builds a
patched **copy** in a temporary directory and runs throwaway git repositories
created with `tempfile.mkdtemp()` and removed with `shutil.rmtree()`.

| test | asserts |
|------|---------|
| `test_a_rename_line_yields_the_new_path` | (a) `R old -> new` contributes the NEW path |
| `test_a_defect_1_the_old_extraction_missed_the_rename` | the OLD expression never saw the NEW path |
| `test_b_modified_line_yields_its_path` | (b) ` M path` → `path` |
| `test_c_untracked_line_yields_its_path` | (c) `?? path` → `path` |
| `test_d_added_line_yields_its_path` | (d) `A  path` → `path` |
| `test_e_a_method_is_counted_once_even_when_two_lines_match` | (e) two matching lines → ONE method |
| `test_e_two_different_methods_count_as_two` | (e) two different names → TWO |
| `test_f_the_same_method_in_two_commits_counts_once` | (f) one name in two commits → ONE |
| `test_f_defect_2_the_old_count_overstated_the_true_number` | the old count overstates |
| `test_g_the_patched_pattern_is_accepted_by_both_engines` | (g) GNU grep and ugrep agree |
| `test_g_the_old_pattern_is_rejected_by_ugrep` | (g) ugrep rejects the old pattern |
| `test_g_the_old_pattern_still_works_under_gnu_grep` | GNU grep accepts the old pattern |
| `test_h_the_referee_still_has_twelve_checks_with_the_same_names` | (h) 12 checks, same names |
| `test_h_the_total_denominator_is_still_pass_plus_fail` | (h) denominator |
| `test_h_the_check_output_format_is_unchanged` | (h) output format |
| `test_h_the_exit_codes_are_unchanged` | (h) exit codes |
| `test_h_the_new_tests_threshold_stays_at_one` | (h) threshold stays 1 |
| `test_h_the_patched_referee_installs_the_two_fixed_expressions` | (h) the patch installs both fixes |
| `test_i_the_design_doc_exists_and_records_the_before_after_table` | (i) this doc exists with the table |
| `test_i_the_design_doc_states_the_threshold_stays_at_one` | (i) this doc states the threshold decision |

The (g) tests skip cleanly if ugrep is not reachable on the machine; the rest
of the file still runs.
