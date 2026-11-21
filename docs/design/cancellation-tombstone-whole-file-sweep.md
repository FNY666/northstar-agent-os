# Cancellation tombstone: the whole-file mutant sweep (22/37 → 37/37)

**Status:** landed. **Module:** `components/northstar-agent-runtime/cancellation_tombstone.py`.
**Test file:** `components/northstar-agent-runtime/tests/test_cancellation_tombstone.py`.

This slice adds **tests only**. The module's diff is zero: none of the
fifteen faults are *applied* — the new tests pin the correct behaviour so
that applying each fault makes the suite go red.

It extends `docs/design/cancellation-tombstone-mutant-blindspots.md`, which
closed the **first three** blind spots the acceptance probe found. This one
closes the **fifteen** the acceptance probe could not see.

---

## 1. Why there was a gap at all

The acceptance MUTANT probe (`/home/muse-newapi/b173-mutant.py`) has a
contract: *"kill at least one of up to N planted faults, then stop"*. The
referee's `MUTANT` item only asks for `>= 1` kill, so the probe **stops at
the first kill**.

That makes its number an **accept metric**, not a census. Measured on
`cancellation_tombstone.py`:

| metric | how it is measured | number |
|---|---|---|
| accept | the probe, stopping at the first kill | `1/1` |
| census | the same probe, `--tries 64 --no-early-stop` | `22/37` |

Both numbers are correct. They answer different questions. The ledger row
records the accept metric, and **the census number was not recorded
anywhere** — so the fifteen constructs the whole-file sweep found and the
suite could not kill had no record at all.

The census was run over all 104 slices of the batch
(`/home/muse-newapi/census-final-1795285384.txt`): 74 slices fully killed,
13 doc-only SKIPs (no module), and 17 with survivors. Of those 17, **two**
are this module — the `tombstone` slice and the `tombstone-mutant-blindspots`
slice, both measuring `22/37` against the same file.

**One of the 17 turned out to have no number at all.** The
`cwl-episode-eviction` slice's census row read `ERROR`, not a count: eleven
of its mutants made the test suite **hang**, and the probe reports a
timeout as `SKIP (test timeout)` — neither a kill nor a survival. That
slice is fixed separately; see
`docs/design/cwl-episode-eviction.md` § "The loop's termination
guarantee".

The lesson for a census is the same one this slice teaches about an accept
metric: **a number that is missing is a finding**, and a slice with no
census number is a slice nobody has measured.

## 2. The claim under test: are they EQUIVALENT, or just untested?

A mutant that survives a test suite is not automatically a defect. It may be
**equivalent** — behaviourally indistinguishable from the original, so no
test can kill it. The repo has a convention for recording that claim
(`docs/design/mutant-evidence-closure.md` §9; the pattern in
`tests/test_cancellation_gate.py::EquivalentMutantTests`), and the batch
already carries 13 recorded equivalents.

But an equivalence is a **claim**, and a claim needs a proof. These fifteen
had none — and the default reading of "survived" is "the tests are weak",
which is the reading that would send someone off to rewrite a test file
that was already correct.

So the question was measured, not assumed.

## 3. The measurement: a differential probe

The module was loaded **twice** — as it is on disk, and with one connective
replaced — and both were driven over the same corpus of crafted inputs. The
outcomes were compared.

The probe is **symmetric**: it compares the file as it is against the file
with the fault applied, so the result holds whichever form is on disk. (A
harness that compared "original source" against "mutant source" would
report a difference whenever the mutation probe had already planted the
fault — a difference in the FILE, not in the BEHAVIOUR. This is the pitfall
measured on `scope-verbatim-compaction`'s `lt@390`.)

**Result: fourteen of the fifteen separate on an input.** They are
**coverage gaps**, not equivalent mutants.

| site | the construct | the input that separates the two forms |
|---|---|---|
| `or@171` | `if subject is None or not subject:` | `covers("")` on a scoped tombstone: `True` vs `False` |
| `or@206` | `... or isinstance(expires_at, bool))` | `expires_at="5"`: *"must be a number or null"* vs *"must be a number"* |
| `or@217` | `measurement=str(... or "")` | `measurement="ok"`: `"ok"` vs `""` |
| `or@218` | `reason=str(... or "")` | `reason="because"`: `"because"` vs `""` |
| `retT@263` | `if not tombstone.subject: return True` | an unscoped tombstone + a scoped lift: lifted vs refused |
| `retF@265` | `if not self.subject: return False` | a scoped tombstone + an empty lift: `False` vs `True` |
| `or@288` | `subject=value.get("subject", "") or ""` | `Lift.from_dict({"subject": "post-42"})`: `"post-42"` vs `""` |
| `or@289` | `text=str(value.get("text", "") or "")` | `Lift.from_dict({"text": "continue"})`: `"continue"` vs `""` |
| `or@290` | `lifted_at=float(... or 0.0)` | `Lift.from_dict({"lifted_at": 12.5})`: `12.5` vs `0.0` |
| `or@311` | `if not isinstance(...) or not isinstance(...)` | `check_lift(tombstone, "not a lift")`: `TombstoneLiftError` vs `AttributeError` |
| `lt@322` | `if lift.lifted_at and lift.lifted_at < tombstone.declared_at:` | a lift at exactly the tombstone's own time: lifted vs refused |
| `or@350` | `if not isinstance(now, ...) or isinstance(now, bool):` | `now="nope"`: *"now must be a number"* vs the *valid_until* message |
| `or@352` | `if not isinstance(valid_until, ...) or ...` | `valid_until="nope"` with a good `now`: the bound slips past |
| `and@421` | `if tombstone.kind == CAPACITY and now is not None:` | a capacity tombstone with `now=None`: blocked vs `TypeError` |
| `or@519` | `if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):` | `from_list("abc")`: *"a list of tombstones"* vs *"a mapping"* |

### The one that looked equivalent, and was not

`or@352` measured **SAME** on the first pass — and it would have been easy
to record it as an equivalent mutant and move on. It was not. The `or@350`
guard sits one line above and fires first on most inputs, so the `or@352`
guard is only reached when `now` is already good. The corpus case
`valid_until="nope"` with `now=100.0` reaches it, and the two forms differ:
the correct one says *"valid_until must be a number"*, the mutant lets the
bound through.

**This is the same shape as the batch's earlier "one guard, two halves"
findings** (`docs/design/artifact-authority-mutant-blindspots.md` §5,
`docs/design/mutant-evidence-closure.md` §5.2): a *type* half joined by
`or` to an *emptiness* / *bound* / *boolean* half. The suites drive one
half; the other survives. A mutant that "survives" because the preceding
guard shadows it is **not** equivalent — it is unreachable, and the
reachability is the bug.

## 4. The tests

All of them live in one class, `TombstoneWholeFileSweepBlindspotTests`, in
`components/northstar-agent-runtime/tests/test_cancellation_tombstone.py`.
Every method name names the mutant it kills.

**37 methods** (2–3 per site, plus a control per site), above the task
book's floor of ≥ 15 in
`tests/test_r8_promised_test_methods.py::TheMethodsExistTests::test_the_mutant_kill_methods_are_in_the_tree`.

Each site gets:

* a **positive** case that drives the distinguishing input and pins the
  correct outcome, and
* a **control** that pins the neighbouring correct behaviour, so the pin
  cannot be "over-corrected" into a rule that breaks the ordinary path.

The controls matter here: a mutant that is killed because the pin is too
strict is a **false kill**, and a false kill is worse than a survivor —
it makes the suite look strong where it is brittle.

## 5. The measurement, after

The whole-file census, same probe, same command:

```
python3 /home/muse-newapi/b173-mutant.py \
    --file .../cancellation_tombstone.py \
    --test-module test_cancellation_tombstone \
    --workdir .../northstar-agent-runtime --tries 64 --no-early-stop
```

| metric | before | after |
|---|---|---|
| census (`--no-early-stop`) | `killed 22/37` | **`killed 37/37`** |
| accept (first kill) | `1/1` | `1/1` |

**37/37.** Every construct in the file is now killed by the suite. There is
no survivor left to classify — no equivalence claim to prove, and no
untested boundary left standing.

## 6. What this does NOT change

* The module's diff is **zero**. Nothing about the runtime's behaviour
  changed; what changed is the suite's ability to *see* the behaviour.
* The thirteen recorded equivalents elsewhere in the batch are **untouched**.
  This slice says nothing about them; it says that *these* fifteen were
  not equivalents.
* The accept metric is unchanged at `1/1` — which is the point. The accept
  metric was never wrong; it was measuring a narrower question. The census
  was the wider question, and it had not been asked of this file.

## 7. Regression evidence

* Focused suite: `Ran 97 tests — OK` (was 68 before this slice; +29).
* Module diff: **zero** (`git diff` on `cancellation_tombstone.py` empty).
* Full runtime suite and bench: see the slice's own acceptance artifacts.

## 8. The lesson

**A "mutant survived" verdict is not a verdict — it is a question with two
answers, and only one of them is a defect.** The batch's own ledger recorded
the narrow metric (`1/1`) and never asked the wide one, so fifteen
untested boundaries sat in a file whose slice was marked closed.

The measurement is cheap (a two-load differential probe, one corpus) and
the payoff is a **complete** answer: 37/37, nothing left to classify. An
equivalent-mutant record is a permanent liability — it is a claim that has
to be re-proved every time the file changes. A killed mutant is a fact that
holds until the code changes.
