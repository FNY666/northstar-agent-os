# Artifact authority: mutant blind spots (or@150, or@184, gt@186)

**Status:** landed. **Module:** `components/northstar-agent-runtime/artifact_authority.py`.
**Test file:** `components/northstar-agent-runtime/tests/test_artifact_authority.py`.

This slice adds **tests only**. The module's diff is zero: the three faults
the acceptance MUTANT probe found are *not* applied — the new tests pin the
correct behaviour so that applying each fault makes the suite go red.

---

## 1. What the probe found

The acceptance v2.1 MUTANT probe (`/home/muse-newapi/b173-mutant.py`) parses
the module's AST, collects mutable constructs in source order (`==`, `>`, `<`,
`return True/False`, `and`/`or`), and tries the first three of them. On the
landed *vina* slice it reported **0/3 killed** — every applied mutant
survived, i.e. the landed suite did not verify those behaviours.

The three constructs it reaches first are, verbatim from the module source:

* **or@150** — `artifact_authority.py:150`
  ```python
  if spec is None or spec.loader is None:  # pragma: no cover - defensive
  ```
  in `_load_grant_pin_ledger()`.

* **or@184** — `artifact_authority.py:184`
  ```python
  if not isinstance(value, str) or not value.strip():
  ```
  in `_require_text(value, name, *, limit=_MAX_ID_CHARS)`.

* **gt@186** — `artifact_authority.py:186`
  ```python
  if len(value) > limit:
  ```
  in the same function, with `limit` defaulting to `_MAX_ID_CHARS = 256`
  (`artifact_authority.py:113`).

(The probe's own candidate order was confirmed against the current file: its
first three candidates are exactly `('or', 150)`, `('or', 184)`,
`('gt', 186)`.)

---

## 2. Why each mutant survived

Each fault sits on a boundary the landed suite never drove.

### or@150 — `or` → `and`

The guard becomes:

```python
if spec is None and spec.loader is None:
```

The `and` short-circuits on the first operand. If only the *spec* is
`None`, the guard does not fire and execution continues into
`spec.loader` — an `AttributeError` on `None`. If the spec exists but its
*loader* is `None`, the first operand is `False`, so the guard does not fire
either, and the module proceeds to `importlib.util.module_from_spec(spec)`
and `spec.loader.exec_module(module)` with a broken spec.

The landed suite never reached line 150 at all: `_load_grant_pin_ledger()`
short-circuits on `sys.modules.get("grant_pin_ledger")`, and the sibling
`grant_pin_ledger` module is imported by the test file itself, so the cache
entry is always warm. The line even carries `# pragma: no cover - defensive`
— it was never executed, let alone verified.

**What the new tests pin:** the loader must raise `ImportError` when the
spec is `None`, and `ImportError` when the spec has no loader. A control
test pins the happy path (a loadable spec still yields the module with
`GrantPin` and `resolve_seal_outcome`) so the fix cannot be "refuse
everything".

### or@184 — `or` → `and`

The guard becomes:

```python
if not isinstance(value, str) and not value.strip():
```

The `and` short-circuits: for a non-string the left operand is `True`, so
the right operand is never evaluated, the guard does not fire, and the
non-string value falls through to `value.strip()` — an `AttributeError`
rather than the fail-closed `ArtifactAuthorityError` the guard exists to
raise.

For an empty string the left operand is `False`, so the right operand is
never evaluated either; `""` passes the guard untouched.

The landed suite passed only well-formed strings to `_require_text`, so
neither path was ever taken and the mutant was invisible.

**What the new tests pin:** the guard must *reject* — with
`ArtifactAuthorityError`, not `AttributeError` — an empty string, a
whitespace-only string, and a non-string (`123`, `None`, `["x"]`).
`ArtifactAuthorityError` is the fail-closed contract; an `AttributeError`
escaping `_require_text` would be a crash, not a refusal.

### gt@186 — `>` → `>=`

The bound becomes:

```python
if len(value) >= limit:
```

A value of *exactly* `limit` characters is now rejected even though the rule
allows it (`> limit` refuses only what is longer). The landed suite never
used a value at the limit, so the off-by-one was invisible.

**What the new tests pin:** exactly `_MAX_ID_CHARS` (256) characters is
accepted, one over (257) is refused with `ArtifactAuthorityError`, and one
under (255) is accepted.

---

## 3. The new tests

All nine live in `components/northstar-agent-runtime/tests/test_artifact_authority.py`,
in three classes. Each method name names the mutant it kills.

| Class | Method | Kills |
|---|---|---|
| `MutantOrAt150LoaderTests` | `test_or150_a_none_spec_is_refused_with_an_import_error` | or@150 |
| | `test_or150_a_spec_without_a_loader_is_refused_with_an_import_error` | or@150 |
| | `test_or150_a_loadable_spec_still_loads_the_module` | or@150 (control) |
| `MutantOrAt184RequireTextTests` | `test_or184_an_empty_string_is_refused` | or@184 |
| | `test_or184_a_whitespace_only_string_is_refused` | or@184 |
| | `test_or184_a_non_string_is_refused_with_the_module_error` | or@184 |
| `MutantGtAt186RequireTextTests` | `test_gt186_a_value_of_exactly_the_limit_is_accepted` | gt@186 |
| | `test_gt186_a_value_one_over_the_limit_is_refused` | gt@186 |
| | `test_gt186_a_value_one_under_the_limit_is_accepted` | gt@186 |

The loader tests use a context manager (`_ledger_not_in_sys_modules`) that
pops `grant_pin_ledger` out of `sys.modules` for the duration of the call
and restores it afterwards, so the `sys.modules` short-circuit at
`artifact_authority.py:145` cannot mask the guard at line 150.

---

## 4. Re-running the probe

`b173-mutant.sh vina-mutant-blindspots` (which drives `b173-mutant.py`
against a throwaway worktree of the slice commit) now reports:

```
MUTANT or@150 KILLED (or -> and)
MUTANT or@184 KILLED (or -> and)
MUTANT gt@186 KILLED (> -> >=)
MUTANT RESULT: killed 3/3
```

**3/3 killed** — up from the acceptance run's 0/3.

---

## 5. Relationship to the cancellation-tombstone blind spots

This is the **same class of gap** as the tombstone slice
(`docs/design/cancellation-tombstone-mutant-blindspots.md`), but a
**different finding**: the two modules each carry their *own* copy of a
`_require_text` helper, so the same fault pattern had to be killed twice, in
two separate files.

| | cancellation_tombstone.py | artifact_authority.py |
|---|---|---|
| empty / non-string guard | `or@87` | `or@184` |
| length bound | `gt@89` | `gt@186` |
| limit constant | `MAX_ID_CHARS = 128` (line 70) | `_MAX_ID_CHARS = 256` (line 113) |
| error type raised | `TombstoneError` | `ArtifactAuthorityError` |

The two slices are **not** the same discovery: the tombstone slice killed
`or@87`, `gt@89` and `retF@101` in `cancellation_tombstone.py`; this slice
kills `or@150`, `or@184` and `gt@186` in `artifact_authority.py`. The
tombstone module's `retF@101` has no counterpart here, and the artifact
authority module's loader guard (`or@150`) has no counterpart there. The
shared *pattern* is the duplicated `_require_text` helper — a private
helper duplicated across two modules, whose edges no suite drove. The two
limit constants also differ (128 vs 256), so the boundary tests are not
interchangeable between the modules.

Northstar extension beyond the source: the artifact authority copy of
`_require_text` also rejects `;` and newline separators
(`artifact_authority.py:188-191`) because the receipt format uses those
characters as field separators. The tombstone copy has no such rule — it
ends at the length bound. That asymmetry is why the two helpers are two
findings, not one: the artifact authority module's text rule is stricter
than the tombstone module's.

---

## 6. Scope

* `artifact_authority.py` — **zero diff**. No behaviour changed.
* `tests/test_artifact_authority.py` — nine new test methods added to the
  existing file.
* `docs/design/artifact-authority-mutant-blindspots.md` — this document.
