# scope-qualifier: the whole-file mutation census, and what it found

**Slice:** `scope-verb-canonical` (the slice that owns `scope_qualifier.py`).
**Measured:** 2026-11-25, on `submission-window/b173-refusal-gate-landing`.

## 1. The measurement

The whole-file mutation census plants a small semantic fault at every
comparison, boolean connective and constant-boolean return in the module,
and runs the module's own suites against each.  Coverage is execution proof;
mutation is verification proof.  A site that survives is a site where the
fault changed the code and **no test could tell the difference**.

The census was run as:

```
python3 scripts/b173-mutant.py \
    --file "$PWD/components/northstar-agent-runtime/scope_qualifier.py" \
    --test-module test_scope_qualifier,test_scope_qualifier_dispatch,test_scope_verb_canonical \
    --workdir "$PWD/components/northstar-agent-runtime" \
    --tries 200 --no-early-stop
```

**The `--test-module` argument takes the module name WITHOUT the `tests.`
prefix.**  With the prefix the probe reports `MUTANT SKIP: the suite
collected no tests`, which reads like a pass and measures nothing.

The first run reported **65/73 killed, 8 survivors**.

## 2. The eight survivors, and what each one turned out to be

| site | the site | what it was |
|---|---|---|
| `lt@667` | `if presented_targets < source_targets:` | a **registered equivalent** |
| `gt@669` | `if presented_targets > source_targets:` | a **registered equivalent** |
| `retF@1775` | `return False` (the `ast.Import` arm) | a **real gap** -- unreachable branch |
| `retF@1778` | `return False` (the `ast.ImportFrom` arm) | a **real gap** -- unreachable branch |
| `eq@1805` | `assert check.outcome == OUTCOME_MATCH` | a **real gap** -- `main()` runs under no test |
| `and@1805` | `... and not check.blocked` | a **real gap** -- the same, and a weakened assert does not raise |
| `eq@1810` | `assert check.outcome == OUTCOME_MISMATCH` | a **real gap** -- the same |
| `eq@1819` | `if __name__ == "__main__":` | a **real gap** -- the entry point runs under no test |

### 2.1 The two equivalents (`lt@667`, `gt@669`)

Both are registered in `mutant-evidence-closure.md` §9.1's table, in the row
`diviner / scope-verb-canonical`, with a control:

> the same comparison, over the EQUAL target sets the sweep skips

They are equivalent because the equality test at `eq@661` comes FIRST, so
the subset and superset comparisons are reached only when the two target
sets are already known to be DIFFERENT -- and for two different sets `P < S`
and `P <= S` agree.  `tests/test_scope_qualifier.py` carries the proof
(`ScopeRelationEquivalenceTests`) and its non-vacuity control
(`ScopeRelationEquivalenceHarnessControlTests`).

**A survivor is not automatically a gap.**  Their survival IS the evidence
that they are equivalent, and the differential harness that proves it loads
the module twice -- once with the connective flipped -- so it needs the
sites to exist.  Removing them would delete the proof's subject.

### 2.2 The unreachable stdlib guard (`retF@1775`, `retF@1778`)

`stdlib_only()` read **only its own module's source**:

```python
tree = ast.parse(Path(__file__).read_text(encoding="utf-8"), filename=__file__)
```

Every import in the module is in the allowed set, so the guard's two
`return False` branches were **unreachable from any test**.  A guard whose
branches cannot be reached cannot be told apart from a guard that always
says "yes", so a planted fault in it (``return False`` -> ``return True``)
survived every test.

The fix is the repo's own pattern -- `deny_hotpath.stdlib_only(source=None)`
already does it, and so does `config_management`'s path-taking check.  The
guard now takes the source to check, defaulting to its own:

```python
def stdlib_only(source: Optional[str] = None) -> bool:
```

Every existing caller passes no argument, so nothing else changes, and the
guard's branches become reachable: a crafted source with a foreign import,
a dotted foreign package, or a **relative** import is refused, and an
allowed import is accepted.

**The crafted input found a real hole.**  A relative import
(`from . import sibling`) parses with `module=None`, so the guard's "not in
allowed" test never ran on it and the import **passed** the stdlib-only
check.  A relative import reaches outside the stdlib exactly as a foreign
one does, so the guard now refuses it:

```python
elif isinstance(node, ast.ImportFrom):
    if node.level:
        return False
    if node.module and node.module.split(".")[0] not in allowed:
        return False
```

### 2.3 The self-check that ran under no test (`eq@1805`, `and@1805`, `eq@1810`, `eq@1819`)

The module's `main()` is a self-check that the design doc quotes, and **no
test ran it**.  So a weakened assertion inside it survived.

Running `main()` is not enough either: it only proves the self-check does
not raise, and a weakened assertion (``and`` -> ``or``) does not raise.  So
three things were done:

1. **the `and` assertion was split** -- `assert check.outcome == OUTCOME_MATCH
   and not check.blocked` became two separate assertions, the same fix
   `agent_boundary`'s self-check got;
2. **`main()` is executed by the suite**, both directly and as a subprocess
   (`python3 -m scope_qualifier`), so the `__name__ == "__main__"` guard at
   `eq@1819` is reached;
3. **the self-check's claims are re-derived from outside it**, so a
   weakened assertion inside it is caught even though `main()` still passes.

## 3. The measurement after

    killed 71/73

The two survivors are the registered equivalents of §2.1.  Every site that
was a real gap is now killed, each verified by planting the fault alone and
watching the suite go red:

| planted fault | the test that killed it |
|---|---|
| `retF`@1791 (the `ast.Import` arm) | `test_a_foreign_import_is_refused` |
| `retF`@1799 (the `ast.ImportFrom` arm) | `test_a_foreign_from_import_is_refused` |
| `eq`@1826 (the MATCH assertion) | `test_the_module_self_check_runs` |
| `eq`@1832 (the MISMATCH assertion) | `test_the_module_self_check_runs` |
| `eq`@1841 (the `__main__` guard) | `test_the_self_check_entry_point_is_the_main_guard` |

## 4. What did NOT change

* The scope algebra is untouched.  A dropped fence still blocks; a widened
  fence still blocks; a narrowed fence still falls back to the narrower
  scope under a clock.
* The gate's fail-closed semantics are untouched.
* No new module: the pinned module counts do not move.
* The `stdlib_only()` default argument still checks THIS module, and
  `test_the_module_itself_is_stdlib_only` pins that.

## 5. Open items

1. **The other modules in the census have the same shape.**  The whole-file
   census was measured over the whole candidate set on 2026-11-25; the
   modules that carry a `stdlib_only()`-style guard of their own are
   `agent_boundary`, `deny_hotpath`, `long_horizon`, `sessions`,
   `code_task` and the rest.  `deny_hotpath` has already been converted to
   the `source=` parameter; the others have not, and each is a slice of its
   own because the guard is a module-body change.
2. **`code_task.py` was UNMEASURED at the first census**, because the census
   timed out on it -- and a timeout is a SKIP, not a kill.  It is being
   re-measured with a longer per-mutant budget.
