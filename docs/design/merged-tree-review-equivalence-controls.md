# Merged-tree review: two equivalence proofs that could not fail

**Status:** landed. **Module:** `components/northstar-agent-runtime/merged_tree_review.py` (unchanged).
**Test file:** `components/northstar-agent-runtime/tests/test_merged_tree_review.py`.

This slice adds **tests only**. The module's diff is **zero**.

It closes a gap in `docs/design/mutant-evidence-closure.md` §9, which
recorded that every surviving mutant in the batch's census is an
**equivalent** mutant with a recorded proof, and that every one of those
proofs now has a **non-vacuity control**. Measured: **that claim was
one proof short, and the one it was short by was this file's.**

---

## 1. The gap

§9.1 lists eleven slices with a control mutation, and names two that
already had one (`cancellation-gate`'s `or@504` and `durable-resume`'s
`lt@701`). That is thirteen recorded equivalence proofs.

The whole-batch census
(`/home/muse-newapi/census-parallel.txt`, 104 slices, the same probe with
`--tries 64 --no-early-stop`) reports **fifteen distinct survivor
sites** across **18 survivor instances** — three of the names survived
twice, because their slices were censused under two names:

```
eq@387  gt@304  gt@533  gt@640  gt@669 (x2)  gt@681  gt@741
lt@152  lt@390 (x2)  lt@579  lt@667 (x2)  lt@701  lt@928
or@504  or@527
```

Fifteen sites across fifteen proofs — and `merged_tree_review`'s two
(`gt@451` and `eq@494`) were **not among them**. They were recorded in
`test_merged_tree_review.py::MutantEquivalentTests`, but they had
**neither** of the two shapes §9 requires:

* **no control mutation** -- nothing showed that the harness could
  detect a comparison that really changes the answer; and
* **no skipped-inputs control** -- nothing showed that the inputs the
  proof skips are where the two spellings disagree.

So the two proofs were exactly what §9 called a *false comfort*: they
pinned the premise their argument rests on, and showed nothing about
what a broken premise would do.

**The count in §9 was 13; the number of recorded equivalence proofs was
15.** §9.1's table listed eleven with a control, and named two more that
already had one — thirteen — but two more existed and had none.

> **Why the two sites were missing from the census.** The census
> reported this slice as `ERROR`, not as a count. A slice with no
> census number contributes no site, so it contributes no row in any
> table derived from it — the two proofs were invisible in the count for
> the same reason they were invisible in the census. §5.1 has the
> re-measurement.

## 2. The worse defect: the proofs were ASYMMETRIC

Before fixing the missing control, the proofs themselves had to be
measured, because a control on top of a broken proof measures nothing.

`MutantEquivalentTests._mutated_module` was:

```python
source = Path(mtr.__file__).read_text(encoding="utf-8")
self.assertIn(old, source)          # <-- a fingerprint on ONE spelling
...
compile(source.replace(old, new, 1), ...)
```

`assertIn(old, source)` requires the **original** spelling to be on
disk. The moment the mutation probe plants the other spelling, the
assertion fails — and the failure is a difference in the **FILE**, not
in the **BEHAVIOUR**.

That is precisely the pitfall §9.2 measured on
`scope-verbatim-compaction`:

| control | census verdict |
|---|---|
| asymmetric (asserts one spelling) | `killed 33/33` — `lt@390` reported killed |
| symmetric (rewrites whichever spelling is present) | `killed 32/33` — `lt@390` survives, honestly equivalent |

Measured here, the same shape, on this file: with the `gt@451` mutant
planted, the suite failed with

```
AssertionError: 'parts[-1] == "py" and len(parts) > 1' not found in ...
```

— a **textual** failure, in a suite whose claim was a behavioural one.

**Consequence:** `gt@451` was a **false kill**. The census could have
reported `merged_tree_review` as fully killed at a site that no test
can kill, and the batch's "every survivor is a recorded equivalent"
claim would have been resting on a proof that does not hold.

## 3. The fix: a symmetric rewrite

The rewrite now:

* locates the site by **the comparison's own AST**, accepting **either**
  of its two spellings — so it lands whichever one the source carries;
* replaces the comparison by its **own source position**, taken from the
  AST, so it cannot reach a neighbouring comparison on the same line
  (`if parts and parts[-1] == "py" and len(parts) > 1:` carries two);
* asserts that the rewritten source really carries the requested
  comparison, located by its normalized source.

Two implementation notes, both measured rather than assumed:

* **`ast.unparse` on an operator node returns the empty string.** It
  only unparses an expression. The operator text is therefore mapped
  from the AST operator class through an explicit table.
* **the longer spelling is tried first.** Replacing `>` with `>=` inside
  an existing `>=` would leave `>==`, which is not Python. The rewrite
  looks for `>=` before `>`.

The proof now compares **the two spellings against each other**, so it
is symmetric by construction: the pair is `(original, mutant)` when the
source carries the first spelling and `(mutant, original)` when it
carries the second.

Measured, on the pristine tree and on a tree with each mutant planted:

| tree | result |
|---|---|
| pristine | `Ran 72 tests — OK` |
| `gt@451` planted (`len(parts) > 1` → `>= 1`) | `Ran 66 tests — OK` |
| `eq@494` planted (`len(parts) == 2` → `!= 2`) | `Ran 66 tests — OK` |

Before this slice, the second and third rows **FAILED**.

## 4. The non-vacuity control

`MutantEquivalentHarnessControlTests` gives the proofs the two controls
§9.1 requires.

**A control mutation.** The same harness, pointed at a comparison that
really changes the answer, must detect it.

The control was chosen by **measurement, not by guessing** — and the
first two candidates were **no-ops**:

| candidate control | differing spans |
|---|---|
| `len(parts) != 1` | 0 |
| `len(parts) >= 2` | 0 |
| `len(parts) > 2` | **1** (`"a.py"`) |

`len(parts) > 2` is the control: on `"a.py"` the parts are
`["a", "py"]`, so the original trims the `"py"` and the control does
not. This is the pitfall §9.2 measured on `fable` — *"a control
mutation must be OBSERVABLE"* — caught by writing the test and letting
it fail.

**The skipped inputs.** The proof's argument rests on the two spellings
being reached only when the two target sets already agree. The
**skipped** inputs are where they disagree. The control runs the same
comparison over the equal lengths and requires a difference there:
`len(parts) > 1` and `len(parts) >= 1` disagree **exactly** at length
1, and agree everywhere else. If they did not, the skip would be doing
no work and the agreement over the different lengths would be
vacuous.

A third control checks that the proof's corpus is substantial and that
it contains spans that **reach** the comparison at all — a sweep that
compared zero spans would reach the same conclusion and mean nothing.

## 5. The measurement, after

| metric | before | after |
|---|---|---|
| census, `merged_tree_review` | **no number at all** (the run died) | **`killed 37/39`** — see §5.1 |
| `gt@451` with the mutant planted | FAIL (textual) | **OK** |
| `eq@494` with the mutant planted | FAIL (textual) | **OK** |
| equivalence proofs with a non-vacuity control | 13 of 15 | **15 of 15** |

### 5.1 The census had NO number for this slice — and now has one

The whole-batch census reported this slice as `ERROR` — not a count.
Two causes, both measured:

1. **The suite is slow.** Two of its tests analyze the **real
   repository** (`test_analyze_on_the_real_tree_is_read_only` and
   `test_the_real_tree_review_finds_the_four_groups`), and each takes
   **~9.5 s**. The suite is 20 s in total, so a 64-site census at
   180 s per mutant is near the probe's timeout ceiling for a *single*
   mutant that trips the whole suite.
2. **The proof was asymmetric**, so the mutant form of the file failed
   the suite — which the probe counts as a **kill**.

So the slice had **no census number**, and §9's claim that "every
surviving mutant in the batch's census is an equivalent mutant" was
made without a number for this slice. The same lesson as
`cwl-episode-eviction`: **a number that is missing is a finding**.

**Re-measured after this slice**, with the same probe
(`--tries 64 --no-early-stop`) against a copy of the tree:

```
MUTANT RESULT: killed 37/39
```

with exactly two survivors:

```
MUTANT gt@451 SURVIVED (> -> >=)
MUTANT eq@494 SURVIVED (== -> !=)
```

Those are the two sites this slice's equivalence proofs cover — so the
slice now contributes **two sites to the census and two rows to §9.1's
table**, which is what it could not do while it read `ERROR`.

**One probe change was needed to get this number, and it is worth
recording.** The probe collected every verdict in memory and printed
them all at the end, so a run that hit the wall clock produced **no
output at all** — and "no output" and "no mutants survived" look
identical to whatever reads the file. That is the same shape as
`b173-a-timeout-is-not-a-verdict`: a missing number is not a verdict.
The probe now prints each verdict **as it is measured**, so a killed run
still reports the sites it reached.

## 6. What this does NOT change

* The module's diff is **zero**. Nothing about the runtime's behaviour
  changed; what changed is the suite's ability to *see* the behaviour,
  and the honesty of the record.
* No mutant was killed. `gt@451` and `eq@494` were equivalent before
  this slice and they are equivalent after it. What changed is that the
  record now says so **with a proof that can fail**.
* The other thirteen proofs are **untouched**.
* The two real-tree tests are **not** made faster here. The slow suite
  is a fact about this slice, recorded rather than hidden.

## 7. Regression evidence

* Focused suite: `Ran 72 tests — OK` (was 66; +6).
* Module diff: **zero** (`git diff` on `merged_tree_review.py` empty).
* Whole-file census for the slice: **`killed 37/39`**, with exactly
  `gt@451` and `eq@494` surviving (§5.1). The slice no longer reads
  `ERROR` in the census.
* Repo-level suite: `426 passed, 1 failed` — the failure is
  `test_code_task_pack.py::CodeTaskPackTests::test_northstar_delivered_patch_passes_clean_fixture_evaluation`,
  the known Node 24 vs 22 baseline failure, byte-identical to the
  baseline.

## 8. The lesson

**A count is a claim too.** §9 said "13 equivalence proofs, all with a
control" and the census said "15 sites, 13 proofs". Both numbers were
locally correct and **they did not agree**, and the gap was two proofs
that had neither a control nor a symmetry.

The generalisable form: when a document counts things, the count is
only as good as the **enumeration** behind it. The census enumerated
**sites**; the document enumerated **proofs**; and the two sets differ
by exactly the proofs that the census's own failure mode had hidden —
a slice with **no number** cannot contribute a site to the census, so
the site cannot appear in the document's table.

So the ordering matters: **measure the census first, then enumerate the
records against it.** A record written from memory of the proofs misses
whatever the census could not reach.
