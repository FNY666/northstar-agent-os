# exclusion-reasons — 519 exclusions, 9 reasons

Module: (none — this slice changes the documentation generator's data model, not
a runtime module)
Tests: `tests/test_exclusion_reasons.py`
Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. What was wrong

`tests/docbuild.py` builds the API reference from an explicit manifest. A
module that ships but is not published must appear in
`MANIFEST_EXCLUSIONS` — that is the "recorded decision" the coverage test
enforces.

Before this slice, the runtime's exclusion list was one flat `frozenset` of
**519 bare module names**.  Nothing recorded *why* any given name was
excluded.  The list was therefore not reviewable by eye: the only way to check
it was to check all 519 names.

This was already an open item in the previous slice's report
(`docs/design/shipped-module-docs.md` §"Open items" 2):

> **`MANIFEST_EXCLUSIONS` now holds 519 entries for the runtime alone.**  A
> list that long is not reviewable by eye.  A future slice should group the
> entries by reason, so a reviewer can check the reason rather than 519
> names.

### 1.1 The tempting answers, and why they are wrong

The obvious implementation is to replace the flat set with a dict of
`reason -> {names}`.  That is not a fix: it is the same 519 names with a
label attached, in a second list that must be kept in step with the first.
The slice would have added a maintenance burden rather than removed one.

The other obvious answer is to find a *mechanical* property that separates the
excluded modules from the published ones.  That was measured and rejected.
Every candidate property was measured over both populations:

| property | excluded (519) | published (1117) |
|---|---|---|
| has an `if __name__ == "__main__"` guard | 97.3 % | 78.7 % |
| defines `stdlib_only()` | 81.3 % | 22.6 % |
| defines a class | 74.2 % | 95.5 % |
| defines `VERSION =` | 16.6 % | 6.0 % |
| docstring contains `Simulated` | 74.0 % | 24.0 % |

No property separates them.  `Simulated` is the closest, and it is still
wrong: **268 published modules also carry the marker**.  The tag means "this
is a simulation of a defence", not "this is not published".

So the axis cannot be a property of the module's *code*.  It has to be a
**declared reason**, and the module's name or family has to be what lets the
reason be *derived*.

## 2. The fix

### 2.1 A reason is a kind, not a module

`docbuild.EXCLUSION_REASON_KINDS` names nine kinds.  Every excluded module
lands under exactly one of them, and the landing is **derived** from the
module — its name, its family stem, or the design tag in its own docstring —
rather than declared beside it.

A reviewer now checks **9 reasons**, not 519 names:

| reason | modules | what the rule is |
|---|---|---|
| `numbered-probe-family` | 385 | the module is a member of a declared numbered family |
| `guard-detector` | 49 | the module's docstring carries a `(D-IN-nnn)`/`(D-OUT-nnn)` tag |
| `probe-corpus` | 35 | the module's name ends in `_probe`/`_probes` |
| `policy-mechanism` | 19 | named: the module implements a mechanism documented elsewhere |
| `ops-bookkeeping` | 12 | named: the module is operations bookkeeping |
| `sandbox-config` | 10 | the module's name starts with `sandbox_` |
| `mock-stand-in` | 7 | the module's name ends in `_mock` |
| `shared-internal-base` | 1 | named: the shared base of the published domain packs |
| `generated-artifact` | 1 | named: generated at build time |

**486 of the 519 names are covered by a rule.**  Only **33** must be read
individually, and those are the ones where the decision genuinely *is* about
that particular module.

### 2.2 The families

385 of the 519 are the numbered sibling families.  Each is declared once, as
a stem and an index range:

```python
ExclusionFamily("out_def", "out_def", 31, 50, "numbered-probe-family",
                 "Output-side defences: exfiltration and steganography checks.")
```

and the members are **derived**:

```python
def member_names(self) -> tuple[str, ...]:
    return tuple(f"{self.stem}_{index:02d}" for index in range(self.first, self.last + 1))
```

A module that follows an existing pattern is therefore classified without
anybody adding its name.  This is the property the slice exists to have.

The 15 families, all measured against the filesystem:

| family | index range | members |
|---|---|---|
| `attack_extra` | 01..20 | 20 |
| `ba` | 01..50 | 50 |
| `crypto_defense` | 01..30 | 30 |
| `def_extra` | 01..20 | 20 |
| `inj_variant` | 01..20 | 20 |
| `input_defense` | 01..30 | 30 |
| `model_attack` | 01..20 | 20 |
| `multi_attack` | 01..20 | 20 |
| `out_def` | 31..50 | 20 |
| `output_defense` | 08..22 | 15 |
| `priv_esc` | 01..20 | 20 |
| `runtime_defense` | 01..30 | 30 |
| `sm2` | 01..30 | 30 |
| `state_mgmt` | 01..30 | 30 |
| `tool_system` | 01..30 | 30 |

Two of these ranges are **not** 1..n, and both are exactly what is on disk:
`out_def` starts at 31 (01..30 belong to `output_defense`'s numbering
scheme) and `output_defense` starts at 08.  Every family was checked against
the filesystem: for each, the set of files matching its stem-and-index
pattern is **equal** to its declared member set, and **no** family member is
published.

`ba_*` and `sm2_*` are the same kind of thing — scratch utility modules from
the mock batches (`ba_01` is `add_two`; `sm2_01` is `reverse_str`).  They are
kept as two families because they are two generators, and the description
says so.

### 2.3 The precedence, and why it had to exist

Two rules can match the same module, and both overlaps are real:

* five `out_def_*` family members also carry a `(D-OUT-nnn)` tag —
  `out_def_36` is `Homoglyph exfiltration defense (D-OUT-036)`;
* seven `*_mock` modules also carry a design tag — `bias_mock` is
  `Bias detection mock (D-OUT-010)`.

Both were resolved by making the rules **mutually exclusive**, with the
exclusion stated in the rule itself:

> * five `out_def_*` family members also carry a `(D-OUT-nnn)` tag.  The
> family is their reason — they are siblings in a numbered defence series —
> so the tag rule excludes family members.
> * seven `*_mock` modules also carry a `(D-IN-nnn)`/`(D-OUT-nnn)` tag.  Their
> reason is the mock — they stand in for a classifier that does not exist
> here — so the tag rule excludes mocks.

The disjointness is a property of the *classification*, not of today's
exclusion list, so the test that pins it runs over the **whole public
surface** (1636 modules), not just the exclusions.  Measured over that
surface: **0 modules match more than one kind**.

`EXCLUSION_REASON_PRECEDENCE` states the order the kinds are considered in,
so the resolution never depends on dict or set iteration order.  The test
pins that a module's recorded reason is the *first* kind in that order whose
rule matches it.

### 2.4 The exclusion set did not change

The slice adds the reasons; it does not change the decision.  The
`MANIFEST_EXCLUSIONS` set is **byte-identical** to its state before the
slice:

```
old: 519   new: 519   identical: True
added: []
removed: []
```

This was checked by extracting the literal from `git show HEAD:tests/docbuild.py`
and comparing it to the new one, rather than by trusting the edit.

### 2.5 The set stays explicit; the reason is derived

The exclusion **set** is still spelled out, because the exclusion is the
*decision* and a decision must be loud.  What is derived is the *reason*.

This distinction matters, and it was measured.  If the predicates defined
the set, `probe-corpus` would pull **11 published modules** into the
exclusions:

```
a2abreak_probes, asi04_probes, asi08_probes, asi09_probes,
capability_ceiling_probe, drift_probe, injection_probe,
interpretability_probe, pocketos_probe, rule_of_two_probe,
temporal_decoupling_probe
```

Those are *supported* probes — published precisely because they are the ones
the API reference should carry.  A rule cannot both classify and decide.

## 3. The tests (18 methods)

`tests/test_exclusion_reasons.py`:

| test | what it pins |
|---|---|
| `test_every_exclusion_carries_exactly_one_reason` | every exclusion is classified, and no reason is recorded for a module that is not excluded |
| `test_every_reason_is_a_declared_kind` | no reason outside the nine declared kinds |
| `test_the_reason_kinds_are_disjoint` | over the **whole** public surface, no module matches two kinds |
| `test_the_resolution_is_by_a_stated_precedence_not_by_accident` | the precedence names every kind once, and the recorded reason is the first match |
| `test_the_grouping_is_derived_not_declared` | the recorded reason is one the module *derives* — no hand-maintained second list |
| `test_a_new_module_in_a_family_is_grouped_without_being_named` | a family member derives its family's reason |
| `test_the_derived_grouping_covers_every_exclusion_exactly_once` | no exclusion is left unclassified |
| `test_the_runtime_exclusions_are_reviewable_at_the_reason_level` | every declared kind is used, and the counts add up |
| `test_every_family_matches_the_filesystem_exactly` | each family's declared range is exactly the set of files matching its stem — in both directions |
| `test_every_family_member_is_excluded_and_nothing_else_is` | a family member is excluded, and is *not* published |
| `test_the_families_cover_every_numbered_probe_family_on_disk` | no numbered family on disk is left uncovered by the family declarations |
| `test_the_exclusions_still_decide_the_published_surface` | the exclusions still decide what is published: no gap, no ghost, no exclusion of a module that is not on disk |
| `test_a_family_can_be_addressed_by_name_or_by_object` | `family_members` accepts both forms and they agree; a wrong name is an error |
| `test_a_module_with_no_docstring_has_no_design_tag` | a module with no docstring has no tag, and is not misread as having one |
| `test_the_renderer_that_consumes_the_exclusions_still_behaves` | the summary cap is exclusive at the boundary and truncates with an ellipsis above it |
| `test_a_rendered_page_lists_the_public_members_and_nothing_private` | a public method is listed with its parameters, a private one is not, `self` is dropped |
| `test_a_rendered_page_hides_the_underscored_members` | no heading names an underscore-prefixed member |
| `test_a_rendered_page_has_exactly_one_trailing_newline` | every page ends in exactly one newline |

The first eight were written before the implementation and watched fail, for
the right reason — `AttributeError: module 'docbuild' has no attribute
'exclusion_reason_kinds'` — not a typo.

The last three were written **after** the implementation, and their RED was
established differently and honestly: they were run against the pre-slice
commit (`32d4b02c~1`), where all **11** methods error with
`AttributeError` — the machinery they test does not exist there.  Running a
test against the tree it was written for proves nothing; running it against
the tree the slice replaces proves the feature was absent.

Two of the failures during the cycle were **real defects the tests caught**:

1. the disjointness test found the five `out_def_*` × `guard-detector`
   overlap and the seven `*_mock` × `guard-detector` overlap (§2.3);
2. the derived-vs-declared test found that `exclusion_reason` was returning
   module *names* where the test (and the name) said it returns *reasons*.

A third was a defect in a test rather than in the code:
`test_the_families_cover_every_numbered_probe_family_on_disk` initially
split a multi-word stem (`attack_extra`) at its first underscore, so it
reported 305 covered modules as uncovered.  The stem is the whole prefix.

## 4. Verification

See the slice report (`b173-exclusion-reasons-cc-final.txt`) for the full
numbers: RED/GREEN, the repo suite against the baseline commit, the runtime
suite against the stored baseline, the bench, and the referee's verdict.

## 5. Open items

1. **The `policy-mechanism` group is the least mechanical.**  Its 19 members
   are named rather than derived, because "this module implements a mechanism
   whose reference lives elsewhere" is not readable off the module.  A future
   slice could give each of them a `docs/design/` page and derive the reason
   from the *presence* of that page, which would move 19 names into the
   rule-covered set.

2. **The `ops-bookkeeping` group is similarly named.**  The same treatment —
   a page per module, or a shared marker — would move another 12.

3. **The exclusion set is still 519 names.**  This slice made it
   *reviewable*, not smaller.  A module that should not be excluded at all is
   still only discoverable by reading the reasons and agreeing with them.

4. **Only the runtime has exclusions.**  The other seven components have
   none, so the reason machinery is exercised by one component.  If a second
   component ever needs exclusions, the precedence and the named-group
   structure are already per-component.

5. **The mutant probe cannot see a slice's own code when the slice appends
   to an existing module.**  `b173-mutant.py` takes its candidate sites in
   *source order* and stops after 12.  This slice appended to
   `tests/docbuild.py`, whose first 14 mutable sites are in the
   pre-existing renderer; the slice's own code begins at line 546.  The
   probe therefore never planted a fault in the new code at all, and
   reported `killed 0/12` — a verdict about the *renderer's* coverage, not
   about the new code.

   The fix belongs in the referee: take the candidates from the slice's
   **diff** rather than from the whole file.  That is outside this slice's
   scope, so it is recorded here rather than done.  What this slice did do
   was close the underlying gap — its own evidence now covers the renderer
   it depends on, so the probe kills `gt@426` on its first candidate.
