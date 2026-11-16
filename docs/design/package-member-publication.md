# package-member-publication — a package member is published surface, and the docs must say so

Module: (none — this slice changes `tests/docbuild.py`, the generator, and
`docs/design/shipped-module-docs.md`)
Tests: `tests/test_package_member_publication.py`
Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. What was missing (read from the code, not from the ledger)

The previous slice (`shipped-module-docs`) established the rule:

> **A module that ships must carry a documentation decision.**

and implemented the coverage check over `py-modules`.  It then wrote, in two
places, that the runtime's package members were **excluded**:

* `docs/design/shipped-module-docs.md` §3.4:

  > The 23 package members and `test_runner` are excluded on purpose and stay
  > excluded.

* `docs/design/shipped-module-docs.md` §5 (an open item):

  > The 23 package members (`providers.*`, `tools.*`) are excluded from the
  > API reference as a class.  They are real shipped surface — `tools.shell`
  > is installed and importable — and the exclusion is a blanket decision
  > recorded once for the whole class rather than per module.

**Both statements were false, and the count was wrong too.**

### 1.1 The measurement

```
$ python3 - <<'PY'
import sys; sys.path.insert(0, 'tests'); import docbuild
exc = docbuild.MANIFEST_EXCLUSIONS['northstar-agent-runtime']
man = docbuild.MANIFEST['northstar-agent-runtime']
members = sorted(n for n in docbuild.public_modules('northstar-agent-runtime') if '.' in n)
print('exclusions containing a dot:', sorted(n for n in exc if '.' in n))
print('package members:', len(members))
print('all PUBLISHED:', all(m in man for m in members))
print('any EXCLUDED :', any(m in exc for m in members))
PY
exclusions containing a dot: []
package members: 22   all PUBLISHED: True   any EXCLUDED: False
```

Not one exclusion contains a dot.  All 22 package members are published; none
is excluded.

The count was wrong as well: there are **22** package members, not 23.  The
23rd number came from counting `test_runner` — the runtime's own entry point —
which is a **flat** module, not a package member.  It is published too.

### 1.2 Why the false claim was possible

The coverage check the previous slice added reads `py-modules`:

```python
def _pyproject_modules(component: str) -> set[str]:
    return set(data["tool"]["setuptools"]["py-modules"])
```

`py-modules` lists **flat** module names only.  A package's members cannot
appear there — setuptools installs them through a second mechanism:

```toml
[tool.setuptools.packages.find]
where = ["."]
include = ["providers*", "tools*"]
```

So the check was **blind to 22 installed modules**: the ones that are the most
obviously *shipped* (`tools.shell` is the sandboxed shell executor, one of the
runtime's headline features).  The check did not fail on them because it never
asked about them.

That is the real defect, and it is worse than the false sentence.  The false
sentence is a documentation error; the blind check is a **coverage hole**: the
invariant "an installed module carries a documentation decision" was enforced
over 1613 of 1635 installed modules.

### 1.3 Why the false claim was believable

The previous slice's own report listed all 23 modules under the heading "23
modules are on disk and in the manifest/exclusions but **not** in
`py-modules`", and then concluded they were "excluded".  The list mixed two
different things — 22 package members and the flat `test_runner` — under a
single count, and read "not in `py-modules`" as "not published".

The generator's data says the opposite, and it says it in one line:

```
MANIFEST["northstar-agent-runtime"] contains 'tools.shell'
MANIFEST_EXCLUSIONS["northstar-agent-runtime"] does not
```

## 2. The rule this slice pins

> **An installed module carries a documentation decision — and a package
> member is installed surface, not an exception to it.**

Concretely, the installed surface of a component is the union of two
installation mechanisms:

```
installed  =  py-modules  ∪  members of packages found by setuptools
```

and the coverage invariant is over that union:

```
installed  ⊆  MANIFEST  ∪  MANIFEST_EXCLUSIONS
```

## 3. What changed

### 3.1 `tests/docbuild.py` — the generator can now name the installed surface

Five new functions, all reading the packaging configuration rather than a
hand-maintained list:

| function | what it answers |
|---|---|
| `_packaging(component)` | the parsed `pyproject.toml` (cached) |
| `flat_modules(component)` | the `py-modules` entries — the flat half |
| `_package_patterns(component)` | the `packages.find` `include` patterns |
| `package_members(component)` | the installed members of those packages — the dotted half |
| `installed_modules(component)` | the union — what `pip install .` puts on the path |
| `undecided_installed_modules(component)` | the installed modules with no decision |

`package_members()` reads the `include` patterns from the packaging
configuration, so a package added to the configuration is part of the
installed surface **automatically**.  There is no second list to keep in
step — which was the shape of the previous slice's own defect (a 519-name
exclusion list with no reason attached).

`undecided_installed_modules()` is the installed-surface counterpart of the
existing `undocumented_modules()`, which asks about *files on disk*.  The two
answer different questions and both are needed: a checkout-only file is not a
documentation obligation, and an installed module is.

### 3.2 `docs/design/shipped-module-docs.md` — the two false statements corrected

§3.4 now reads:

> **The exclusion list was not pruned.**  The 22 package members and
> `test_runner` are *published*, not excluded, and stay published.

§5's open item is replaced by a **CLOSED** block that quotes the old wording
in a blockquote, records the measurement, and states that the count was 22
rather than 23.

### 3.3 `tests/test_package_member_publication.py` — the new tests (17 methods)

| test | what it pins |
|---|---|
| `test_no_package_member_is_excluded` | the truth: no exclusion carries a dotted name |
| `test_every_package_member_on_disk_is_published` | the other direction: no package member escapes the decision |
| `test_the_runtime_package_members_are_the_measured_twenty_two` | the count, so a change to it is a visible event |
| `test_the_component_entry_point_is_published` | `test_runner` is published too |
| `test_a_package_member_appears_in_the_rendered_api_page` | published means *on the page* |
| `test_the_installed_surface_is_covered_not_just_the_flat_one` | the invariant over the union, computed in the test as well as in the generator |
| `test_the_generator_knows_the_installed_surface` | the generator's own answer: 1613 flat + 22 package = 1635 installed, disjoint |
| `test_the_generator_sees_no_installed_module_without_a_decision` | the generator's coverage check over the installed surface is empty |
| `test_the_installed_surface_includes_the_packages_setuptools_finds` | the package members come from the packaging configuration, and every one is covered by an `include` pattern |
| `test_the_renderer_that_produces_the_page_still_behaves` | `_summary`: the empty case, the whitespace case, the first-paragraph case, the exclusive cap |
| `test_the_renderer_recognises_property_decorators` | `_is_property`: both branches, and a decorator that is not a property |
| `test_a_rendered_page_names_the_package_members` | a package member's heading keeps the package prefix and drops `.__init__` |
| `test_a_rendered_page_lists_the_public_members_and_nothing_private` | the member filter and the `self`-dropping |
| `test_a_rendered_page_hides_the_underscored_members` | no heading names an underscore-prefixed member |
| `test_a_rendered_page_has_exactly_one_trailing_newline` | the page contract |
| `test_the_surface_document_states_that_package_members_are_published` | the document must *state the truth* |
| `test_no_document_asserts_a_package_member_is_excluded` | the document must not *assert the falsehood* |

### 3.4 The negative check is the interesting one

The obvious way to pin "no document says a package member is excluded" is to
search for the sentence "the package members are excluded".  That was tried
first and it **over-fires**: the corrective prose this slice itself wrote
("…which now fails if any document says a package member is excluded") is a
*meta-sentence* about the claim, not an assertion of it.  A pattern that
cannot tell those apart forbids the document from explaining its own
correction.

The check therefore has two halves:

* a **positive** check — the document must state that the package members are
  published.  Stating the truth is a better rule than enumerating every way
  of mis-stating it: it cannot be defeated by a sentence shape nobody
  anticipated;
* a **narrower** negative check, which skips three shapes that do not assert
  the claim: a **blockquote** (which quotes the old wording in order to
  correct it), a **meta-sentence** (which reports the claim), and a sentence
  that **denies** it ("…are *published*, not excluded, and stay published").

The false sentence has none of the three markers, so it is still caught.  The
check runs over **sentences**, not lines: the original false statement spanned
two lines, so a line-based pattern would have missed it.

This was measured, not assumed.  The first version of the pattern fired on
three sentences that all assert the *truth*:

```
OFFENDER: 'A reader who believed the false claim would have gone and excluded
           the published package members, or would have inherited a decision
           nobody made.  The slice corrected both statements in this document
           and pinned the truth with `tests/test_package_member_publication.py`,
           which now fails if any document says a package member is excluded.'
```

### 3.5 What was deliberately NOT changed

* **No API page was regenerated.**  No module's published/excluded status
  changed — the set of published modules is the same 1064 (+ the 53 the
  previous slice added), and the exclusion set is byte-identical.  The slice
  corrects a *document* and closes a *check*; it changes no decision.
* **`docbuild.py`'s `undocumented_modules()`** was left alone.  It answers the
  on-disk question, and `tests/test_docbuild.py` uses it.  The installed
  question is a separate question, and gets its own function.
* **No `pyproject.toml` was touched.**  The packaging configuration is the
  *input* to the new check, not something the check should reshape.

## 4. Verification

See the slice report (`b173-package-member-publication-cc-final.txt`) for the
full-suite, bench, mutant and fresh-clone numbers.

### 4.1 RED, then GREEN

The three methods that exercise the new generator API were written before the
implementation and watched fail for the right reason — the API was missing,
not a typo:

```
ERROR: test_the_generator_knows_the_installed_surface
ERROR: test_the_generator_sees_no_installed_module_without_a_decision
ERROR: test_the_installed_surface_includes_the_packages_setuptools_finds
Ran 11 tests ... FAILED (errors=3)
```

The two document methods were established against the **pre-slice** document —
the version with the false claims — and failed there:

```
FAIL: test_no_document_asserts_a_package_member_is_excluded
  Lists differ: ['* **The exclusion list was not pruned.**[185 chars]ss.'] != []
FAIL: test_the_surface_document_states_that_package_members_are_published
  ... must state that the package members are published
Ran 8 tests ... FAILED (failures=2)
```

Running a test against the tree it was written for proves nothing; running it
against the tree the slice replaces proves the defect was there.

### 4.2 The mutant probe

The referee plants small semantic faults in the module the slice changed
(`tests/docbuild.py`) and runs the slice's own tests against them.  **At least
one mutant must be killed.**

The probe takes its candidate sites in **source order** and stops at the
first kill.  `tests/docbuild.py`'s first mutable sites are in the
**pre-existing** renderer — the slice's own new code starts at line 945 — so
the first attempt was:

```
MUTANT gt@427 SURVIVED (> -> >=)
MUTANT and@438 SURVIVED (and -> or)
...
MUTANT RESULT: killed 0/12
```

That is a real gap, not a probe artefact: the slice's evidence did not cover
the module it changed.  Six methods were added covering the renderer's
behaviour (`_summary`, `_is_property`, the member filter, the page
contract), and with that coverage:

```
MUTANT gt@427 KILLED (> -> >=)
MUTANT RESULT: killed 1/1
```

The probe's own finding, already recorded by the `exclusion-reasons` slice,
still stands: **`b173-mutant.py` takes the first N candidate sites in the
file, so a slice that appends to an existing module is never probed in its own
code.**  Run deeper (`--tries 80 --no-early-stop`), the probe reaches the
slice's new code and reports `killed 13/23` — the surviving ten are in the
*previous* slice's reason machinery (lines 678, 753–754, 806, 810) and in
`stale_pages`/`broken_links`/`verify`/`main` (lines 1075–1151), none of which
this slice touched.  The proper fix is to take the candidates from the
slice's **diff** rather than from the whole file; that changes the referee,
which is outside this slice's scope.
