# shipped-module-docs — every shipped module carries a documentation decision

Module: (none — this slice changes `tests/docbuild.py`, the generator, and the
generated pages)
Tests: `tests/test_shipped_module_docs.py`
Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. What was missing (read from the code, not from the ledger)

The API reference is built from an **explicit manifest**:

```python
# tests/docbuild.py
MANIFEST: dict[str, tuple[str, ...]] = {
    ...
    "northstar-agent-runtime": ( ... 1064 module names ... ),
}
```

and the generator refuses to be quiet about a module it does not know:

```python
def undocumented_modules() -> list[str]:
    """``component: module`` pairs that are on disk but in neither manifest nor exclusions."""
```

`tests/test_docbuild.py` asserts that list is empty.  So the *intent* was
already right: an added public module must be consciously exposed in the API
reference, and the freshness check then keeps it there.

**What was missing was the link between "shipped" and "documented".**

`MANIFEST` is keyed on *the module's file being on disk*.  `public_modules()`
globs `components/<c>/*.py`.  But a module being on disk is not the same as a
module being **shipped**: `pyproject.toml`'s `[tool.setuptools] py-modules`
is the array `pip install .` puts on the path.  A module on disk but absent
from `py-modules` is a checkout-only file; a module in `py-modules` is
installed and importable by anyone who installs the package.

The batch added **53 runtime modules**, every one of them registered in
`py-modules`, and **none** of them recorded in the manifest or in the
exclusions.  So:

* the API reference silently shrank while the shipped surface grew by 53
  modules — every one of them a real feature (232 to 1474 lines, each with a
  module docstring);
* `undocumented_modules()` **did not fire**, because it counts modules that are
  on disk but undecided, and the check never asked whether a module was
  shipped at all;
* `tests/test_docbuild.py` failed anyway, on the *stale page* check, because
  `handoff.py` grew a `tombstones` parameter that the committed
  `docs/api/northstar-agent-interop.md` did not have.

That is the shape of the defect: **the coverage check was blind to the
shipped surface, so the batch grew the package by 53 modules and the API
reference did not notice.**

### 1.1 The measurement, before any change

```
$ cd tests && PYTHONPATH=..:. python3 -m unittest test_docbuild
FAIL: test_committed_api_pages_match_docstring_generation
  stale: northstar-agent-interop
FAIL: test_every_public_module_is_documented_or_deliberately_excluded
  53 modules missing from the API reference

$ python3 - <<'PY'
import sys, tomllib; sys.path.insert(0,'tests'); import docbuild
d = tomllib.load(open("components/northstar-agent-runtime/pyproject.toml","rb"))
py = set(d["tool"]["setuptools"]["py-modules"])
man = set(docbuild.MANIFEST["northstar-agent-runtime"])
exc = set(docbuild.MANIFEST_EXCLUSIONS["northstar-agent-runtime"])
print(len(py), len(man), len(exc))
print("shipped but undecided:", len(py - (man | exc)))
PY
1613 1064 519
shipped but undecided: 53
```

All 53 are registered in `py-modules` **and** carry a registry record in
`runtime_registration.py` (`REGISTRY`, 1613 entries) — so the runtime's own
registration machinery already treats them as shipped, and the documentation
machinery was the only place that had not caught up.

The 53 are not one-off probes.  They are the batch's feature modules:
`actionable_digest`, `agent_handoff`, `annotation_pin`, `approval_rules`,
`artifact_authority`, `cancellation_tombstone`, `capability_ceiling_probe`,
`checkpoint_durability`, `checkpoint_store`, `cost_per_delivery`,
`coverage_manifest`, `deterministic_gate_score`, `durable_resume`,
`effect_directive`, `effort_scaling`, `endpoint_identity`, `episode_eviction`,
`event_condenser`, `evidence_independence`, `false_green_detector`,
`horizon_gate`, `intent_bound_retry`, `key_custody`, `leased_task_claim`,
`ledger_concurrency`, `merged_tree_review`, `refusal_hold`,
`refusal_hold_wiring`, `refusal_row`, `resume_validation`,
`retry_clears_writes`, `retry_config`, `reversible_compaction`,
`revision_checked_tool_results`, `runtime_registration`, `scope_qualifier`,
`scope_verbatim_compaction`, `scorer_disagreement`, `session_memory`,
`shutdown_unwind`, `signed_receipt`, `silent_failure_detector`,
`speaker_selector`, `stale_checkpoint_gate`, `state_budget`,
`step_reliability_budget`, `strands_checkpoint`, `stuck_detector`,
`swe_failure_modes`, `tool_failure`, `tool_output_filter`, `turn_truncation`,
`verifiability_tier`.

### 1.2 The other direction, measured

23 modules are on disk and in the manifest/exclusions but **not** in
`py-modules`:

```
providers.__init__, providers.anthropic, providers.base,
providers.http_response_limits, providers.openai_compat, providers.scripted,
tools.__init__, tools.capdrop, tools.code, tools.effect_envelope,
tools.fetch, tools.os_sandbox, tools.parallel, tools.path_integrity,
tools.pledge, tools.resource_limits, tools.sandbox, tools.seccomp,
tools.shell, tools.skill_scripts, tools.systemd_scope,
tools.verify_invariants, test_runner
```

These are **packages** (`providers.*`, `tools.*`) — `py-modules` lists flat
module names only, so a package's members cannot appear there.  `test_runner`
is the component's own entry point.  None of them is a gap in the shipped
surface, and none of them is a gap in the documentation: all 23 are already
in the manifest or the exclusions.

## 2. The rule this slice pins

> **A module that ships must carry a documentation decision.**

Concretely, for every component with a `pyproject.toml`:

```
py-modules  ⊆  MANIFEST  ∪  MANIFEST_EXCLUSIONS
```

and the two sets are disjoint, so every shipped module is either published in
the API reference or explicitly recorded as not published, and never both.

The invariant is *shipped surface*, not *files on disk*.  That distinction is
the whole point: a checkout-only file is not a documentation obligation, and
a shipped module is.

### 2.1 Why the existing check did not catch it

`undocumented_modules()` computed `public_modules(component) - MANIFEST -
MANIFEST_EXCLUSIONS` — i.e. it asked "which files on disk are undecided?" and
the answer was 53.  The check **did** find them.  What it did not do was
*fail* on them in a way anyone acted on, because:

* `test_every_public_module_is_documented_or_deliberately_excluded` had been
  failing since the batch's first runtime slice, alongside a stale page and
  two other repo-level failures, so it was part of the standing noise rather
  than a signal;
* the failure message said "add them to docbuild.MANIFEST or record an
  exclusion" but did not say **which shipped modules** were at stake, so the
  reader could not tell a feature module from a probe without going and
  looking.

The slice therefore does two things: it makes the shipped surface the
**subject** of the check (so the message names shipped modules, and a
checkout-only file can never be the subject of a documentation obligation),
and it closes the gap itself.

## 3. What changed

### 3.1 `tests/docbuild.py` — publish the 53

The 53 shipped modules are added to `MANIFEST["northstar-agent-runtime"]`,
in their own block with a comment naming the provenance.  They are **not**
excluded: each is a registered, documented feature module, and the exclusion
list exists for "benchmark probes, one-off detectors, fixtures, or standalone
experiments rather than supported entry points" — none of which applies.

### 3.2 The generated pages — regenerate

```
$ cd tests && PYTHONPATH=..:. python3 docbuild.py build
wrote docs/api/northstar-run-contract.md
wrote docs/api/northstar-run-evidence.md
wrote docs/api/northstar-host.md
wrote docs/api/northstar-durable-run.md
wrote docs/api/northstar-agent-interop.md
wrote docs/api/northstar-codex-sidecar.md
wrote docs/api/northstar-egress-sidecar.md
wrote docs/api/northstar-agent-runtime.md
```

`docs/api/northstar-agent-runtime.md` grows by **4168 lines** (the 53 modules
rendered).  `docs/api/northstar-agent-interop.md` changes by **4 lines**:
`authorize_handoff` gains `tombstones: Any=None` in its published signature,
and the generator now also emits the function's one-line summary, which the
stale page had lost.

The other six pages are byte-identical — they were already fresh.

### 3.3 `tests/test_shipped_module_docs.py` — the new tests (8 methods)

| test | what it pins |
|---|---|
| `test_every_shipped_runtime_module_is_published_or_explicitly_excluded` | the invariant, over `py-modules` |
| `test_the_batch_modules_that_escaped_the_decision_are_all_accounted_for` | the 53, named explicitly, so the fix cannot be a widening that hides a *different* escape |
| `test_the_manifest_and_the_exclusions_never_overlap` | one module, one decision |
| `test_the_exclusions_only_name_modules_that_exist_on_disk` | an exclusion cannot outlive its module |
| `test_a_published_module_is_present_on_disk` | the manifest cannot name a ghost |
| `test_no_api_page_is_stale` | the freshness check, restated |
| `test_the_interop_page_documents_the_handoff_tombstones_parameter` | the specific staleness, so a future signature change cannot silently drop a parameter |
| `test_the_generation_is_reproducible` | the generator is deterministic |

The tests read `tests/docbuild.py` — the generator itself — not a copy of its
rules.  A future change to the manifest that reintroduces the gap fails them.

### 3.4 What was deliberately NOT changed

* **`docbuild.py`'s `undocumented_modules()`** was left alone.  It is correct
  as the *on-disk* check, and `tests/test_docbuild.py` still uses it.  The
  new test adds the *shipped* check on top; removing the on-disk check would
  weaken a rule that predates this slice.
* **The exclusion list was not pruned.**  The 23 package members and
  `test_runner` are excluded on purpose and stay excluded.
* **No `docbuild.py` module was moved, renamed, or re-registered.**  The
  slice adds documentation decisions; it does not change what ships.

## 4. Verification

### 4.1 RED first

The tests were written before the fix and watched fail, for the right reason:

```
$ cd tests && PYTHONPATH=..:. python3 -m unittest test_shipped_module_docs
FAIL: test_no_api_page_is_stale
FAIL: test_the_interop_page_documents_the_handoff_tombstones_parameter
FAIL: test_every_shipped_runtime_module_is_published_or_explicitly_excluded
FAIL: test_the_batch_modules_that_escaped_the_decision_are_all_accounted_for
Ran 8 tests in 17.877s
FAILED (failures=4)
```

All four failed on the *missing decision* / *stale page*, not on a typo or an
import error.

### 4.2 GREEN

```
$ cd tests && PYTHONPATH=..:. python3 -m unittest test_shipped_module_docs test_docbuild
Ran 21 tests in 24.853s
OK
```

### 4.3 The whole repository-level suite

```
$ cd tests && python3 -m unittest discover -s . -p 'test_*.py'
FAIL: test_northstar_delivered_patch_passes_clean_fixture_evaluation (test_code_task_pack...)
FAIL: test_panel_renders_the_full_record_vocabulary (test_observability_examples...) (kind='cancellation')
Ran 146 tests in 29.323s
FAILED (failures=2)
```

Both failures are **pre-existing**: with the slice's changes stashed, the same
two fail at the same place:

```
$ git stash -u && cd tests && python3 -m unittest test_code_task_pack test_observability_examples
FAIL: test_northstar_delivered_patch_passes_clean_fixture_evaluation
FAIL: test_panel_renders_the_full_record_vocabulary (kind='cancellation')
Ran 32 tests in 2.365s
FAILED (failures=2)
```

They are in the batch's standing baseline failure set (`/tmp/b173-r13-failures.txt`).
This slice **fixes two** of the batch's baseline failures (`test_docbuild`'s
two) and **adds none**.

### 4.4 The runtime suite and the bench

See the slice report (`b173-shipped-module-docs-cc-final.txt`) for the
full-suite and bench numbers, measured on the branch as it stands and
re-measured in a fresh clone.

## 5. Open items

* The 23 package members (`providers.*`, `tools.*`) are excluded from the API
  reference as a class.  They are real shipped surface — `tools.shell` is
  installed and importable — and the exclusion is a blanket decision recorded
  once for the whole class rather than per module.  That is defensible, but
  it is a decision someone should make deliberately rather than inherit.
* `MANIFEST_EXCLUSIONS` now has **519** entries for the runtime alone.  A
  list that long is not reviewable by eye; a future slice should group them
  by reason, so that a reviewer can check the reason rather than 519 names.
