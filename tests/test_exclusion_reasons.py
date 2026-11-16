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

import re
import unittest

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


if __name__ == "__main__":
    unittest.main()
