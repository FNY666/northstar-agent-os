# Cancellation tombstone: mutant blind spots (or@87, gt@89, retF@101)

**Status:** landed. **Module:** `components/northstar-agent-runtime/cancellation_tombstone.py`.
**Test file:** `components/northstar-agent-runtime/tests/test_cancellation_tombstone.py`.

This slice adds **tests only**. The module's diff is zero: the three faults
the acceptance MUTANT probe found are *not* applied — the new tests pin the
correct behaviour so that applying each fault makes the suite go red.

---

## 1. What the probe found

The acceptance v2.1 MUTANT probe (`/home/muse-newapi/b173-mutant.py`) parses
the module's AST, collects mutable constructs in source order (`==`, `>`, `<`,
`return True/False`, `and`/`or`), and tries the first three of them. On the
landed tombstone slice it reported **0/3 killed** — every applied mutant
survived.

The three constructs it reaches first are, verbatim from the module source:

* **or@87** — `cancellation_tombstone.py:87`
  ```python
  if not isinstance(value, str) or not value.strip():
  ```
  in `_require_text(value, name, *, limit=MAX_ID_CHARS)`.

* **gt@89** — `cancellation_tombstone.py:89`
  ```python
  if len(value) > limit:
  ```
  in the same function, with `limit` defaulting to `MAX_ID_CHARS = 128`
  (`cancellation_tombstone.py:70`).

* **retF@101** — `cancellation_tombstone.py:101`
  ```python
  return False
  ```
  in `_is_generic_continuation(text)`, the early return for a non-string.

(The probe's own candidate order was confirmed against the current file: its
first three candidates are exactly `('or', 87)`, `('gt', 89)`,
`('retF', 101)`.)

---

## 2. Why each mutant survived

Each fault sits on a boundary the landed suite never drove.

### or@87 — `or` → `and`

The guard becomes:

```python
if not isinstance(value, str) and not value.strip():
```

The `and` short-circuits: for a non-string the left operand is `True`, so
the right operand is never evaluated, the guard does not fire, and the
non-string value falls through to `value.strip()` — an `AttributeError`
rather than the fail-closed `TombstoneError` the guard exists to raise.

For an empty string the left operand is `False`, so the right operand is
never evaluated either; `""` passes the guard untouched.

The landed suite passed only well-formed strings to `_require_text`, so
neither path was ever taken and the mutant was invisible.

**What the new tests pin:** the guard must *reject* — with
`TombstoneError`, not `AttributeError` — an empty string, a whitespace-only
string, and a non-string (`123`, `None`, `["x"]`). `TombstoneError` is the
fail-closed contract; an `AttributeError` escaping `_require_text` would be
a crash, not a refusal.

### gt@89 — `>` → `>=`

The bound becomes:

```python
if len(value) >= limit:
```

A value of *exactly* `limit` characters (exactly `MAX_ID_CHARS = 128`) is
now wrongly refused. The landed suite used only short identifiers, so the
boundary was never reached and the mutant was invisible.

**What the new tests pin:** the bound is inclusive on the accepted side —
128 characters is accepted, 127 characters is accepted, 129 characters
raises `TombstoneError`. Two of the tests drive the same boundary through
the public constructor (`Tombstone(grant_id=...)`) so the bound is pinned on
the real path, not only on the private helper.

### retF@101 — `return False` → `return True`

The non-string early return becomes `return True`. A non-string `text` is
then classified as a *generic continuation* — a phrase that never lifts
anything. A lift whose text is not a string (and which otherwise names the
revoked action exactly) would be refused on the generic-continuation
ground: the stop stays standing when the declarer did in fact re-authorize.

The landed suite only passed strings to `_is_generic_continuation`, so the
non-string branch was never taken and the mutant was invisible.

**What the new tests pin:** a non-string (`123`, `None`, `["continue"]`,
`b"continue"`) is **not** a generic continuation — the function returns
`False`. The control is pinned in the other direction too: a known generic
continuation (`continue`, `resume`, `carry on`, `go on`) still returns
`True` and still lifts nothing, so pinning the type guard cannot be
"over-corrected" into a rule that makes the phrase list dead.

---

## 3. The new tests

All of them live in one class, `TombstoneMutantBlindspotTests`, in
`components/northstar-agent-runtime/tests/test_cancellation_tombstone.py`.
Every method name names the mutant it kills.

| mutant | methods |
|---|---|
| `or@87` | `test_or_87_require_text_refuses_an_empty_string`, `test_or_87_require_text_refuses_a_whitespace_only_string`, `test_or_87_require_text_refuses_a_non_string_as_a_tombstone_error`, `test_or_87_a_tombstone_with_an_empty_grant_id_is_refused`, `test_or_87_a_tombstone_with_a_non_string_declarer_is_refused` |
| `gt@89` | `test_gt_89_require_text_accepts_a_value_exactly_at_the_limit`, `test_gt_89_require_text_refuses_a_value_one_over_the_limit`, `test_gt_89_require_text_accepts_a_value_one_under_the_limit`, `test_gt_89_a_tombstone_with_a_grant_id_at_the_limit_is_accepted`, `test_gt_89_a_tombstone_with_a_grant_id_over_the_limit_is_refused` |
| `retF@101` | `test_retF_101_a_non_string_continuation_is_not_a_generic_continuation`, `test_retF_101_a_non_string_continuation_does_not_refuse_the_lift`, `test_retF_101_a_known_generic_continuation_is_still_generic`, `test_retF_101_a_generic_continuation_still_lifts_nothing`, `test_retF_101_a_named_lift_with_a_non_string_text_is_still_refused_when_it_names_nothing` |

15 new methods (5 per mutant), above the task book's floor of ≥ 9 with ≥ 3
per mutant.

---

## 4. Re-run of the probe

`/home/muse-newapi/b173-mutant.sh tombstone-mutant-blindspots` (worktree at
the slice commit) — **3/3 KILLED**, against the 0/3 the probe reported on the
landed slice.

Each mutant was also applied one at a time to the working tree, with the
module restored afterwards, to confirm the kill is attributable to the
intended mutant and not to a side effect:

| mutant | applied fault | focused suite result |
|---|---|---|
| `or@87` | `or` → `and` | `Ran 52 tests — FAILED (failures=3, errors=4)` |
| `gt@89` | `>` → `>=` | `Ran 52 tests — FAILED (failures=3, errors=4)` |
| `retF@101` | `return False` → `return True` | `Ran 52 tests — FAILED (failures=4, errors=1)` |

The module's diff after all three trials was **zero** (`git diff` on
`cancellation_tombstone.py` empty).

---

## 5. Regression evidence

* Focused suite: `Ran 52 tests — OK` (was 37 before this slice; +15).
* Adjacent suites: `tests.test_cancellation_tombstone`,
  `tests.test_forward_seal_ledger`, `tests.test_ledger` — all OK.
* Full runtime suite: `Ran 20165 tests — FAILED (failures=17, errors=10,
  skipped=13)` = 27 failing items, **identical item for item** to the
  baseline recorded before this slice (`/home/muse-newapi/b173-tombstone-mutant-blindspots-baseline-failures.txt`,
  28 lines counting the `FAILED` summary line). No new failure.
* Bench: `summary: 161/169 passed, 8 failed` — the same 8 live-leg items as
  the stored baseline (`/home/muse-newapi/b173-bench-baseline-failures.txt`).
  Bench output: `/home/muse-newapi/b173-tombstone-mutant-blindspots-bench-final.txt`.
