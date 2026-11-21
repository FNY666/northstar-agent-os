"""Every exclusion must carry a *reason*, and the reasons must be checkable.

An exclusion is a recorded decision: "this module ships, and we are not
publishing it in the API reference."  The decision is only reviewable if the
reviewer can read *why* without reading hundreds of names.

Before this slice, ``docbuild.MANIFEST_EXCLUSIONS`` for the runtime held 519
bare module names in one flat ``frozenset``.  Nothing recorded why any given
name was excluded, so the list could not be reviewed by eye -- the only way to
check it was to check all 519 names.

This slice groups the exclusions by reason.  The tests below pin:

* every exclusion carries exactly one reason, and every reason is one of the
  declared kinds;
* the declared kinds are **disjoint** -- a module lands in exactly one;
* the grouping is **total** -- no exclusion is left ungrouped;
* the grouping is **derived**, not a second hand-maintained list: the kind a
  module lands in is computed from the module itself (its name, its family
  stem, or its design tag), so a new module cannot drift into the wrong
  group;
* the derived grouping agrees with the flat exclusion set -- adding a module
  to a kind without adding it to the flat set, or the reverse, fails.

They are written against ``tests/docbuild.py`` -- the generator itself -- so
they fail when the invariant is broken, not when a copy of it is.
"""
from __future__ import annotations

import ast
import contextlib
import io
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import docbuild

RUNTIME = "northstar-agent-runtime"


class ExclusionReasonTests(unittest.TestCase):
    """The invariant: an exclusion names its reason, and the reason is checkable."""

    def test_every_exclusion_carries_exactly_one_reason(self):
        for component in docbuild.MANIFEST_EXCLUSIONS:
            names = set(docbuild.MANIFEST_EXCLUSIONS[component])
            reasons = docbuild.exclusion_reason(component)
            ungrouped = sorted(names - set(reasons))
            self.assertEqual(
                ungrouped,
                [],
                f"{component}: exclusions with no recorded reason:\n  " + "\n  ".join(ungrouped),
            )
            extra = sorted(set(reasons) - names)
            self.assertEqual(
                extra,
                [],
                f"{component}: reasons recorded for modules that are not excluded:\n  "
                + "\n  ".join(extra),
            )

    def test_every_reason_is_a_declared_kind(self):
        declared = set(docbuild.EXCLUSION_REASON_KINDS)
        self.assertTrue(declared, "the reason kinds must be declared, not implied")
        for component in docbuild.MANIFEST_EXCLUSIONS:
            reasons = docbuild.exclusion_reason(component)
            unknown = sorted(set(reasons.values()) - declared)
            self.assertEqual(
                unknown,
                [],
                f"{component}: reasons outside the declared kinds:\n  " + "\n  ".join(unknown),
            )

    def test_the_reason_kinds_are_disjoint(self):
        # A module that lands in two kinds is a module with two reasons, and a
        # reviewer cannot check a reason that is ambiguous.  This is checked
        # over the *whole* shipped runtime surface, not just the exclusions,
        # so the disjointness is a property of the classification rather than
        # of today's exclusion list.
        seen: dict[str, list[str]] = {}
        for component in docbuild.MANIFEST:
            for name in docbuild.public_modules(component):
                kinds = docbuild.exclusion_reason_kinds(component, name)
                if len(kinds) > 1:
                    seen.setdefault(component, []).append(f"{name}: {kinds}")
        self.assertEqual(
            seen,
            {},
            "modules classified under more than one exclusion reason:\n  "
            + "\n  ".join(sum(seen.values(), [])),
        )

    def test_the_resolution_is_by_a_stated_precedence_not_by_accident(self):
        # Two rules may in principle match the same module; the resolution
        # must then be the *first* rule in a declared order, so the answer
        # never depends on dict or set iteration order.
        order = docbuild.EXCLUSION_REASON_PRECEDENCE
        self.assertTrue(order, "the precedence must be declared")
        self.assertEqual(
            sorted(order),
            sorted(docbuild.EXCLUSION_REASON_KINDS),
            "the precedence must name every declared kind exactly once",
        )
        for component in docbuild.MANIFEST_EXCLUSIONS:
            for name, reason in sorted(docbuild.exclusion_reason(component).items()):
                with self.subTest(component=component, name=name):
                    kinds = docbuild.exclusion_reason_kinds(component, name)
                    self.assertEqual(
                        reason,
                        kinds[0],
                        f"{component}: {name} resolves to {reason!r} but the first "
                        f"matching kind is {kinds[0]!r}",
                    )

    def test_the_grouping_is_derived_not_declared(self):
        # The reason a module gets must come from the module itself.  If the
        # classification were a hand-maintained list of names, this slice
        # would have added a second 519-name list to keep in step with the
        # first -- the defect, not the fix.
        for component in docbuild.MANIFEST_EXCLUSIONS:
            reasons = docbuild.exclusion_reason(component)
            for name, reason in sorted(reasons.items()):
                with self.subTest(component=component, name=name):
                    kinds = docbuild.exclusion_reason_kinds(component, name)
                    self.assertIn(
                        reason,
                        kinds,
                        f"{component}: {name} is recorded as {reason!r} but derives {kinds}",
                    )

    def test_a_new_module_in_a_family_is_grouped_without_being_named(self):
        # The point of the slice: a module that follows an existing pattern
        # must be classified by the pattern, so nobody has to add its name.
        families = docbuild.EXCLUSION_FAMILIES
        self.assertTrue(families, "the numbered families must be declared")
        for family in families:
            for name in docbuild.family_members(family):
                with self.subTest(family=family, name=name):
                    kinds = docbuild.exclusion_reason_kinds(RUNTIME, name)
                    self.assertIn(
                        family.reason,
                        kinds,
                        f"{name} follows family {family.name!r} but does not derive its reason",
                    )

    def test_the_derived_grouping_covers_every_exclusion_exactly_once(self):
        for component in docbuild.MANIFEST_EXCLUSIONS:
            names = set(docbuild.MANIFEST_EXCLUSIONS[component])
            derived: dict[str, list[str]] = {}
            for name in names:
                derived[name] = docbuild.exclusion_reason_kinds(component, name)
            empty = sorted(name for name, kinds in derived.items() if not kinds)
            self.assertEqual(
                empty,
                [],
                f"{component}: exclusions the rules do not classify:\n  " + "\n  ".join(empty),
            )

    def test_the_runtime_exclusions_are_reviewable_at_the_reason_level(self):
        # The measurable outcome: a reviewer checks a handful of reasons, not
        # 519 names.  If the number of names a reviewer must read ever grows
        # back to the size of the list, the slice has stopped working.
        reasons = docbuild.exclusion_reason(RUNTIME)
        kinds = docbuild.EXCLUSION_REASON_KINDS
        self.assertTrue(kinds)
        by_kind: dict[str, int] = {}
        for reason in reasons.values():
            by_kind[reason] = by_kind.get(reason, 0) + 1
        for kind in kinds:
            self.assertIn(kind, by_kind, f"reason {kind!r} is declared but unused")
        # The whole list is explained by the declared kinds.
        self.assertEqual(sum(by_kind.values()), len(reasons))

    def test_every_family_matches_the_filesystem_exactly(self):
        # A family is a claim about the filesystem: "these files are siblings
        # with this reason".  The claim must be exact in both directions --
        # every declared member is a file, and every file matching the
        # family's stem-and-index pattern is a member.  A family whose range
        # was mis-stated would quietly classify a module wrongly.
        root = docbuild.ROOT / "components" / RUNTIME
        for family in docbuild.EXCLUSION_FAMILIES:
            with self.subTest(family=family.name):
                on_disk = {
                    path.stem
                    for path in root.glob(f"{family.stem}_*.py")
                    if path.stem[len(family.stem) + 1:].isdigit()
                }
                self.assertEqual(
                    on_disk,
                    set(family.member_names()),
                    f"family {family.name!r} does not match the files on disk",
                )

    def test_every_family_member_is_excluded_and_nothing_else_is(self):
        # A family member that is published would mean the family reason is
        # being applied to a module that was not excluded -- the two lists
        # have drifted apart.
        excluded = set(docbuild.MANIFEST_EXCLUSIONS[RUNTIME])
        published = set(docbuild.MANIFEST[RUNTIME])
        for family in docbuild.EXCLUSION_FAMILIES:
            for name in family.member_names():
                with self.subTest(family=family.name, name=name):
                    self.assertIn(name, excluded)
                    self.assertNotIn(name, published)

    def test_the_families_cover_every_numbered_probe_family_on_disk(self):
        # The families are the derived half of the classification.  If a
        # numbered family appeared on disk that no family covered, its members
        # would fall through to the singleton rules -- or to nothing at all.
        root = docbuild.ROOT / "components" / RUNTIME
        covered = {
            name for family in docbuild.EXCLUSION_FAMILIES for name in family.member_names()
        }
        stems = {family.stem for family in docbuild.EXCLUSION_FAMILIES}
        uncovered = sorted(
            path.stem
            for path in root.glob("*.py")
            if re.fullmatch(r"[a-z][a-z0-9_]*_\d+", path.stem)
            and not any(path.stem.startswith(f"{stem}_") for stem in stems)
        )
        self.assertEqual(
            uncovered,
            [],
            "numbered modules on disk that no family covers:\n  " + "\n  ".join(uncovered),
        )
        self.assertTrue(covered)

    def test_the_exclusions_still_decide_the_published_surface(self):
        # The exclusion set is the input to the coverage decision, so the
        # decision is what must be pinned -- not just the names.  A module
        # that is neither published nor excluded is a gap; a module that is
        # both is a contradiction; and an exclusion that names a module that
        # is not on disk is a lie about a decision.
        gaps = docbuild.undocumented_modules()
        self.assertEqual(
            gaps,
            [],
            "public modules missing from the API reference:\n  " + "\n  ".join(gaps),
        )
        ghosts = docbuild.documented_but_absent()
        self.assertEqual(
            ghosts,
            [],
            "manifest lists modules with no file:\n  " + "\n  ".join(ghosts),
        )
        on_disk = docbuild.public_modules(RUNTIME)
        for name in docbuild.MANIFEST_EXCLUSIONS[RUNTIME]:
            with self.subTest(name=name):
                self.assertIn(name, on_disk)

    def test_a_family_can_be_addressed_by_name_or_by_object(self):
        # ``family_members`` takes either the family's name or the family
        # itself, and the two must agree.  A caller that passes the wrong one
        # must get an error, not an empty answer.
        for family in docbuild.EXCLUSION_FAMILIES:
            with self.subTest(family=family.name):
                self.assertEqual(
                    docbuild.family_members(family.name),
                    docbuild.family_members(family),
                )
                self.assertTrue(docbuild.family_members(family))
        with self.assertRaises(KeyError):
            docbuild.family_members("no-such-family")

    def test_a_module_with_no_docstring_has_no_design_tag(self):
        # The design tag is read from the module's docstring.  A module
        # without one has no tag, and must not be misread as having one --
        # which would put it under the guard-detector reason by accident.
        self.assertFalse(docbuild._has_design_tag(RUNTIME, "no_such_module_at_all"))
        self.assertEqual(
            docbuild.exclusion_reason_kinds(RUNTIME, "no_such_module_at_all"),
            [],
        )

    def test_the_renderer_that_consumes_the_exclusions_still_behaves(self):
        # The exclusion set is the input to the renderer: it decides which
        # modules reach a page.  This slice changed that input, so the
        # renderer's own behaviour is part of the slice's evidence -- a
        # change to the renderer that truncated, filtered, or mis-rendered a
        # page must fail *here*, not only in the generator's own test file.
        self.assertEqual(docbuild._summary(None), "")
        self.assertEqual(docbuild._summary("  one   two  "), "one two")
        # The cap is exclusive: a docstring exactly at the cap is not cut.
        at_cap = "x" * 300
        self.assertEqual(docbuild._summary(at_cap), at_cap)
        over_cap = "x" * 301
        self.assertTrue(docbuild._summary(over_cap).endswith("…"))
        self.assertLessEqual(len(docbuild._summary(over_cap)), 300)

    def test_a_rendered_page_lists_the_public_members_and_nothing_private(self):
        # The renderer drops private members (those whose name starts with an
        # underscore) and drops a leading self/cls from a method signature.
        # Both are load-bearing for the reference page, and both are
        # observable from the slice's own evidence.
        source = docbuild.ROOT / "components" / RUNTIME / "allowlist.py"
        text = "\n".join(docbuild._render_module(RUNTIME, "allowlist", source))
        self.assertIn("### `allowlist`", text)
        self.assertIn("#### `Allowlist`", text)
        # A public method is listed, with its parameter list.
        self.assertIn("- `check(value: str)`", text)
        # A public module-level function is listed.
        self.assertIn("#### `stdlib_only()`", text)
        # A method's signature drops the leading self.
        self.assertNotIn("self", text)
        # The module's own docstring becomes the page's summary.
        self.assertIn("Allowlist validation", text)

    def test_a_rendered_page_hides_the_underscored_members(self):
        # A module with a private helper must not advertise it.  This is the
        # other half of the rule above, and it is the half a truncation or a
        # prefix test would get wrong.
        source = docbuild.ROOT / "components" / RUNTIME / "budget.py"
        text = "\n".join(docbuild._render_module(RUNTIME, "budget", source))
        self.assertIn("#### `ModelPricing`", text)
        self.assertNotIn("_private", text)
        # Every heading is a public name: no heading may start with "_".
        for line in text.splitlines():
            if line.startswith("#### `") or line.startswith("### `"):
                name = line.split("`")[1]
                with self.subTest(heading=name):
                    self.assertFalse(name.startswith("_"))

    def test_a_rendered_page_has_exactly_one_trailing_newline(self):
        # The generator promises the page ends in exactly one newline; a
        # trailing-blank-line regression would show up in every committed
        # page, so it is pinned here rather than only in the generator's own
        # test file.
        for component in docbuild.MANIFEST:
            with self.subTest(component=component):
                page = docbuild.render_page(component)
                self.assertTrue(page.endswith("\n"))
                self.assertFalse(page.endswith("\n\n"))


class ExclusionReasonsGuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of every guard in ``tests/docbuild.py``.

    These four slices SHARE one module -- ``tests/docbuild.py`` -- and the
    batch's planted-fault probe plants a fault in it and then runs EACH
    slice's OWN test file against it.  A killer test placed in one test
    file kills the mutant for that slice ONLY, so the same technique has to
    be applied in every one of the four files.

    The mutants that survived, per slice, measured with the batch's own
    probe (``b173-mutant.py --tries 64 --no-early-stop``, run against a
    copy of the tree with the unmutated module):

      exclusion-reasons           14 of 27 survived
      component-packaging-closure 20 of 27
      package-member-publication  13 of 27
      shipped-module-docs         12 of 27

    The union of the four survivor sets is the seventeen sites below.  Each
    one is a DOUBLE guard -- a type half joined to a second half by
    ``and``/``or``, or a bound compared against a constant -- and the
    existing suite drove only ONE half of each.  Under a planted fault the
    half that was never driven changes the answer, and the suite passes
    anyway.

      and@464   the ``@property`` decorator, Name form
      retT@465   its return
      retT@467   the ``@x.property`` decorator, Attribute form, its return
      eq@680     the exclusion-family lookup
      lt@755     the docstring-tag split
      retF@756   its "no tag" return
      or@808     the probe-corpus name test
      and@812    the guard-detector rule
      eq@1059    the runtime-module suffix
      and@1073   the wheel component sweep
      or@1151    the data-file scan
      eq@1157    the ``pyproject.toml`` exclusion
      or@1234    the staleness check
      or@1272    the external-link skip
      or@1298    the verify verdict
      or@1307    the argument check
      eq@1310    the build/verify dispatch

    Every test below fails when its own planted fault is applied alone.
    """

    # --- and@464 / retT@465: the Name-form property decorator ----------
    def test_a_name_decorator_that_is_not_a_property_is_not_a_property(self):
        """`and@464`: the second half of the Name-form guard.

        The guard is ``isinstance(decorator, ast.Name) AND decorator.id in
        {"property", "cached_property"}``.  The "is a known name" half
        never fires on ``@staticmethod`` -- only the type half does, and
        the type half is satisfied.  Under the mutant (``and`` -> ``or``)
        the guard would fire on ANY name decorator, and the reference
        page would drop the parentheses from a method that has arguments.
        """
        node = ast.parse("@staticmethod\ndef value(self):\n    pass\n").body[0]
        self.assertFalse(docbuild._is_property(node))

    def test_the_name_form_property_decorator_is_recognised(self):
        """`retT@465`: the return of the Name-form branch.

        A bare ``@property`` must still be recognised.  Under the mutant
        (``return True`` -> ``return False``) it would be reported as an
        ordinary method, so the page would show ``value()`` for a
        property.
        """
        node = ast.parse("@property\ndef value(self):\n    pass\n").body[0]
        self.assertTrue(docbuild._is_property(node))

    # --- retT@467: the Attribute-form property decorator ----------------
    def test_the_attribute_form_property_decorator_is_recognised(self):
        """`retT@467`: the return of the Attribute-form branch.

        ``@functools.cached_property`` is a property reached through an
        attribute, so it is this branch's own case.  Under the mutant
        (``return True`` -> ``return False``) it would lose its
        ``(property)`` marker on the reference page.
        """
        node = ast.parse(
            "@functools.cached_property\ndef value(self):\n    pass\n"
        ).body[0]
        self.assertTrue(docbuild._is_property(node))

    # --- eq@680: the exclusion-family lookup ----------------------------
    def test_a_family_lookup_returns_that_familys_members(self):
        """`eq@680`: the family that carries the requested name.

        ``family_members("ba")`` must return the ``ba`` family's members.
        Under the mutant (``==`` -> ``!=``) the lookup would accept the
        FIRST family whose name does NOT match, so a module would be
        classified under a family it does not belong to.
        """
        declared = docbuild.EXCLUSION_FAMILIES[1]
        self.assertEqual(
            docbuild.family_members(declared.name), declared.member_names()
        )
        self.assertNotEqual(
            docbuild.family_members(declared.name),
            docbuild.EXCLUSION_FAMILIES[0].member_names(),
        )

    # --- lt@755: the docstring split is strict --------------------------
    def test_a_single_docstring_marker_still_yields_the_tag(self):
        """`lt@755`: the bound, from the side that shows it is strict.

        The guard is ``if len(parts) < 2: return False``.  A source whose
        docstring marker has no closing marker splits into exactly TWO
        parts, and the second still carries the tag -- so the tag must be
        found.  With the bound weakened to ``<= 2`` the guard would
        return False and the tag would be missed.
        """
        source = '"""Module docstring carrying (D-OUT-123) and no closing marker'
        with mock.patch.object(docbuild, "_module_source", return_value=source):
            self.assertTrue(docbuild._has_design_tag(RUNTIME, "any"))

    # --- retF@756: the "no docstring at all" answer --------------------
    def test_a_source_with_no_docstring_marker_has_no_tag(self):
        """`retF@756`: the "there is no docstring" answer.

        A source with no ``\"\"\"`` marker at all splits into exactly ONE
        part, so there is nothing to scan and the answer must be False.
        Under the mutant (``return False`` -> ``return True``) every such
        module would be reported as carrying a design tag, and the
        guard-detector rule would claim modules that carry none.
        """
        with mock.patch.object(docbuild, "_module_source", return_value="x = 1\n"):
            self.assertFalse(docbuild._has_design_tag(RUNTIME, "any"))

    # --- or@808: the probe-corpus name test -----------------------------
    def test_the_probe_suffix_alone_makes_a_probe_corpus(self):
        """`or@808`: the ``_probe`` suffix -- the first half.

        The two halves are the two spellings -- ``_probe`` and
        ``_probes``.  Under the mutant (``or`` -> ``and``) a module ending
        in ``_probe`` would no longer be a probe corpus, so its exclusion
        would fall to a different reason kind.
        """
        kinds = docbuild.exclusion_reason_kinds(RUNTIME, "asi02_probe")
        self.assertIn("probe-corpus", kinds)

    # --- and@812: the guard-detector rule -------------------------------
    def test_an_untagged_module_is_not_a_guard_detector(self):
        """`and@812`: the half that has to be FALSE.

        ``egress_client`` carries no design tag, is in no family and is
        not a mock, so the tag rule must not claim it.  Under the mutant
        (``and`` -> ``or``) the second half -- ``"numbered-probe-family"
        not in kinds`` -- is true for every module, so EVERY module would
        be reported as a guard detector.
        """
        kinds = docbuild.exclusion_reason_kinds(RUNTIME, "egress_client")
        self.assertNotIn("guard-detector", kinds)

    # --- eq@1059: the runtime-module suffix ----------------------------
    def test_a_non_python_file_is_not_a_runtime_module(self):
        """`eq@1059`: the suffix half of the guard.

        The guard is ``path.is_file() AND path.suffix == ".py" AND ...``.
        A README is a file that is not Python, so it must not be counted
        as a runtime module.  Under the mutant (``==`` -> ``!=``) every
        non-Python file in a component directory would be counted, and
        the component's flat-module list would gain a name that is not a
        module at all.
        """
        readme = docbuild.ROOT / "components" / RUNTIME / "README.md"
        self.assertTrue(readme.is_file())
        self.assertFalse(docbuild.is_runtime_module(readme))

    # --- and@1073: the wheel component sweep ---------------------------
    def test_a_directory_without_a_pyproject_builds_no_wheel(self):
        """`and@1073`: the second half of the wheel sweep.

        A component directory with no ``pyproject.toml`` builds no wheel,
        so it must not be reported as shipping one.  Under the mutant
        (``and`` -> ``or``) the type half -- "it is a directory" -- would
        be enough, and every component directory would be reported.
        """
        wheels = docbuild.components_that_ship_a_wheel()
        self.assertIn(RUNTIME, wheels)
        self.assertNotIn("northstar-codex-sidecar", wheels)
        self.assertNotIn("northstar-egress-sidecar", wheels)

    # --- or@1151: the data-file scan -----------------------------------
    def test_only_data_suffixes_are_reported_as_data_files(self):
        """`or@1151`: the suffix half of the scan's skip rule.

        The rule is ``not path.is_file() OR path.suffix not in
        DATA_SUFFIXES`` -- skip anything that is not a data file.  A
        module's ``.py`` source is installed by ``py-modules`` and is not
        runtime data, so it must not be reported as one.  Under the mutant
        (``or`` -> ``and``) every file that EXISTS but is not a data file
        would be reported instead.
        """
        for name in docbuild.data_files_on_disk(RUNTIME):
            with self.subTest(name=name):
                self.assertTrue(name.endswith((".json", ".toml")), name)

    # --- eq@1157: the pyproject.toml exclusion -------------------------
    def test_the_pyproject_is_not_counted_as_a_data_file(self):
        """`eq@1157`: the packaging-configuration exclusion.

        A ``pyproject.toml`` is packaging configuration, not a file a
        module reads at runtime, so it must not be reported as a data
        file -- and the two files that ARE data files must still be
        reported.  Under the mutant (``==`` -> ``!=``) the exclusion
        would fire on every other file, and the two real data files
        would be reported INSTEAD.
        """
        found = docbuild.data_files_on_disk(RUNTIME)
        self.assertNotIn("pyproject.toml", found)
        self.assertIn("policy/dataflow.toml", found)
        self.assertIn("policy/deny_monotonicity_baseline.json", found)

    # --- or@1234: the staleness check ----------------------------------
    def test_a_stale_page_is_named_as_stale(self):
        """`or@1234`: the content half of the staleness rule.

        A committed page whose bytes differ from a fresh generation is
        stale and must be named.  Under the mutant (``or`` -> ``and``)
        the rule would only fire for a page that does not EXIST, so a
        page that is present but out of date would be reported as fresh
        -- which is exactly the drift the check exists to catch.
        """
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            (api / "northstar-run-contract.md").write_text("stale", encoding="utf-8")
            with mock.patch.object(docbuild, "API_DIR", api), mock.patch.object(
                docbuild,
                "build_all",
                return_value={"northstar-run-contract": "fresh"},
            ):
                self.assertEqual(docbuild.stale_pages(), ["northstar-run-contract"])

    # --- or@1272: the external-link skip -------------------------------
    def test_an_external_link_is_not_a_broken_link(self):
        """`or@1272`: the first half of the skip rule.

        An ``http(s)`` or ``mailto:`` link points off-site, so it is not
        an internal link and must not be reported as broken.  Under the
        mutant (``or`` -> ``and``) the emptiness half would be the only
        one left, so every external link would be resolved against the
        local tree and reported as broken.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "doc.md").write_text(
                "[site](https://example.com/page)\n\n[mail](mailto:someone@example.com)\n",
                encoding="utf-8",
            )
            with mock.patch.object(docbuild, "ROOT", root):
                self.assertEqual(docbuild.broken_links(), [])

    # --- or@1298: the verify verdict -----------------------------------
    def test_stale_pages_alone_make_verify_fail(self):
        """`or@1298`: the two halves of the verdict.

        Stale pages and broken links are two independent failures, and
        EITHER one must fail the check.  Under the mutant (``or`` ->
        ``and``) a run with stale pages but no broken links would be
        reported as OK -- and the stale pages would go unnoticed.
        """
        with mock.patch.object(
            docbuild, "stale_pages", return_value=["northstar-run-contract"]
        ), mock.patch.object(docbuild, "broken_links", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(docbuild.verify(), 1)

    # --- or@1307: the argument check -----------------------------------
    def test_running_with_no_argument_prints_the_usage(self):
        """`or@1307`: the emptiness half of the argument rule.

        With no argument at all there is no command, so the usage must
        be printed and the exit code must be 2.  Under the mutant
        (``or`` -> ``and``) the second half would be evaluated on an
        empty list and the guard would raise instead of refusing.
        """
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(docbuild.main([]), 2)

    def test_running_with_an_unknown_argument_prints_the_usage(self):
        """`or@1307`: the membership half of the argument rule.

        A command that is neither ``build`` nor ``verify`` must be
        refused with exit code 2.  Under the mutant (``or`` -> ``and``)
        an unknown command would fall through to the verify path.
        """
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
            docbuild, "verify", return_value=0
        ):
            self.assertEqual(docbuild.main(["nonsense"]), 2)

    # --- eq@1310: the build/verify dispatch ----------------------------
    def test_the_build_command_writes_the_pages(self):
        """`eq@1310`: the ``build`` half of the dispatch.

        ``build`` WRITES the pages.  Under the mutant (``==`` -> ``!=``)
        ``build`` would fall through to ``verify`` and write nothing, so
        the page would not exist afterwards.
        """
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            with mock.patch.object(docbuild, "API_DIR", api), mock.patch.object(
                docbuild,
                "build_all",
                return_value={"northstar-run-contract": "fresh"},
            ), mock.patch.object(docbuild, "verify", return_value=0), mock.patch.object(
                docbuild, "ROOT", api
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(docbuild.main(["build"]), 0)
            self.assertTrue((api / "northstar-run-contract.md").is_file())

    def test_the_verify_command_writes_nothing(self):
        """`eq@1310`: the ``verify`` half of the dispatch.

        ``verify`` CHECKS the pages and writes none of them.  Under the
        mutant (``==`` -> ``!=``) ``verify`` would regenerate the pages
        instead -- which would hide the very staleness it is meant to
        report.
        """
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            with mock.patch.object(docbuild, "API_DIR", api), mock.patch.object(
                docbuild, "build_all", return_value={"northstar-run-contract": "fresh"}
            ), mock.patch.object(docbuild, "verify", return_value=0), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(docbuild.main(["verify"]), 0)
            self.assertEqual(list(api.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
