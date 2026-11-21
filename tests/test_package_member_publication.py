"""A package member is published surface, and no document may say otherwise.

A runtime *package* (``providers/``, ``tools/``) is installed by setuptools'
``packages.find`` — its members do not appear in ``py-modules`` at all,
because ``py-modules`` lists flat module names only.

The previous slice (``shipped-module-docs``) measured that all 23 of the
runtime's package members — 22 package members plus ``test_runner`` — carry
a documentation decision.  It then wrote, in **two** places, that those 23
were *excluded*:

* `docs/design/shipped-module-docs.md` §3.4: "The 23 package members and
  `test_runner` are excluded on purpose and stay excluded."
* `docs/design/shipped-module-docs.md` §5: "The 23 package members
  (`providers.*`, `tools.*`) are excluded from the API reference as a
  class... the exclusion is a blanket decision recorded once for the whole
  class."

**Both statements were false**, and the count was wrong too.  All 22 package
members are *published*; not one is excluded:

```
exclusions containing a dot: []
package members: 22   all PUBLISHED: True   any EXCLUDED: False
```

A false claim in a design doc is a live hazard.  A reader who believes it
would go and "fix" the published package members by excluding them, or would
inherit a decision nobody made — and the open item that carried it would keep
the false claim alive in every report that cites it.

So this module pins three things:

* the **truth** — no package member is excluded, every package member on disk
  is published, and each appears in the rendered API page;
* the **positive statement** — the surface document must say that the package
  members are published.  Stating the truth is a better rule than trying to
  enumerate every way of mis-stating it: a document that quotes the old
  wording, explains that the claim was false, or says "not one is excluded"
  would all trip a negation-blind detector of the old sentence, and none of
  them asserts the false claim;
* the **generalisation** — the rule "a shipped module carries a documentation
  decision" must hold for the *installed* surface, which is `py-modules`
  **plus** the package members that `py-modules` cannot name.

The tests are written against ``tests/docbuild.py`` — the generator itself —
so they fail when the invariant is broken, not when a copy of it is.
"""
from __future__ import annotations

import ast
import contextlib
import io
import re
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import docbuild

RUNTIME = "northstar-agent-runtime"

#: The documents that describe the runtime's package surface.
SURFACE_DOCS = ("docs/design/shipped-module-docs.md",)


class PackageMemberPublicationTests(unittest.TestCase):
    """The invariant: a package member is published, not excluded."""

    def test_no_package_member_is_excluded(self):
        # The load-bearing truth.  A package member carries a dotted name;
        # an exclusion with a dotted name would be a package member that was
        # decided against.
        for component, excluded in docbuild.MANIFEST_EXCLUSIONS.items():
            dotted = sorted(name for name in excluded if "." in name)
            self.assertEqual(
                dotted,
                [],
                f"{component}: package members must be published, not excluded:\n  "
                + "\n  ".join(dotted),
            )

    def test_every_package_member_on_disk_is_published(self):
        # The other direction: a package member that is neither published nor
        # excluded is a module that escapes the documentation decision
        # entirely, because ``py-modules`` cannot name it.
        for component in docbuild.MANIFEST:
            on_disk = {
                name for name in docbuild.public_modules(component) if "." in name
            }
            if not on_disk:
                continue
            published = set(docbuild.MANIFEST[component])
            undecided = sorted(on_disk - published)
            self.assertEqual(
                undecided,
                [],
                f"{component}: package members with no documentation decision:\n  "
                + "\n  ".join(undecided),
            )

    def test_the_runtime_package_members_are_the_measured_twenty_three(self):
        # The count is pinned so that a package member being added or removed
        # is a visible event rather than a silent drift.  If the count
        # changes, this test fails and the number in the design doc has to be
        # re-measured -- which is the point.
        #
        # RE-MEASURED 2026-11-16 by the `runtime-data-files` slice: 22 ->
        # 23, because the runtime's data-file directory (`policy/`) became
        # a package so that its data files could ship in the wheel.  A
        # namespace directory would have shipped the files without
        # registering a module -- and an installed module that the registry
        # cannot name is the exact blind spot `installed-surface-registration`
        # closed.
        published = {name for name in docbuild.MANIFEST[RUNTIME] if "." in name}
        self.assertEqual(
            len(published),
            23,
            "the runtime's published package members: " + ", ".join(sorted(published)),
        )
        self.assertIn("providers.__init__", published)
        self.assertIn("policy.__init__", published)
        self.assertIn("tools.__init__", published)
        self.assertIn("tools.shell", published)

    def test_the_component_entry_point_is_published(self):
        # ``test_runner`` is the runtime's own entry point, and the previous
        # slice's report listed it alongside the package members.  It is
        # published, and it must stay published.
        self.assertIn("test_runner", docbuild.MANIFEST[RUNTIME])

    def test_a_package_member_appears_in_the_rendered_api_page(self):
        # Published must mean *published*: the module has to be on the page,
        # not merely in the manifest.
        page = (docbuild.ROOT / "docs" / "api" / f"{RUNTIME}.md").read_text(
            encoding="utf-8"
        )
        for name in sorted(n for n in docbuild.MANIFEST[RUNTIME] if "." in n):
            with self.subTest(name=name):
                self.assertIn(f"### `{name.replace('.__init__', '')}`", page)

    def test_the_installed_surface_is_covered_not_just_the_flat_one(self):
        # The rule this slice generalises: every INSTALLED module carries a
        # documentation decision.  The installed surface is ``py-modules``
        # *plus* the package members that ``py-modules`` cannot name --
        # 22 modules that a ``py-modules``-only check never sees.
        root = docbuild.ROOT / "components" / RUNTIME
        with (root / "pyproject.toml").open("rb") as handle:
            data = tomllib.load(handle)
        flat = set(data["tool"]["setuptools"]["py-modules"])
        package_members = {
            name for name in docbuild.public_modules(RUNTIME) if "." in name
        }
        installed = flat | package_members
        self.assertEqual(
            len(package_members),
            23,
            "the package members py-modules cannot name",
        )
        self.assertEqual(
            len(installed),
            len(flat) + len(package_members),
            "the installed surface is the flat modules plus the package members",
        )
        decided = set(docbuild.MANIFEST[RUNTIME]) | set(
            docbuild.MANIFEST_EXCLUSIONS[RUNTIME]
        )
        undecided = sorted(installed - decided)
        self.assertEqual(
            undecided,
            [],
            "installed modules with no documentation decision:\n  "
            + "\n  ".join(undecided),
        )

    def test_the_generator_knows_the_installed_surface(self):
        # The generator must be able to answer "what does ``pip install .``
        # put on the path?" *without* the test re-deriving it.  If the
        # installed surface is only computed in the test, the generator's own
        # coverage check stays blind to the 23 package members -- which is
        # the hole the previous slice left open.
        installed = docbuild.installed_modules(RUNTIME)
        self.assertEqual(
            installed,
            docbuild.flat_modules(RUNTIME) | docbuild.package_members(RUNTIME),
            "the installed surface is the flat modules plus the package members",
        )
        self.assertEqual(len(docbuild.package_members(RUNTIME)), 23)
        self.assertEqual(len(docbuild.flat_modules(RUNTIME)), 1614)
        self.assertEqual(len(installed), 1637)
        # A package member is in the installed surface and is not a flat
        # module -- that is the whole reason it needs a separate path.
        self.assertNotIn("tools.shell", docbuild.flat_modules(RUNTIME))
        self.assertIn("tools.shell", installed)
        # The flat and package surfaces are disjoint, so the union is a count,
        # not a guess.
        self.assertEqual(
            docbuild.flat_modules(RUNTIME) & docbuild.package_members(RUNTIME),
            set(),
        )

    def test_the_generator_sees_no_installed_module_without_a_decision(self):
        # The generator's own coverage check, run over the INSTALLED surface.
        # ``undocumented_modules()`` asks about files on disk; this asks about
        # what is installed.  The answer must be empty, and the message must
        # name the surface it checked.
        undecided = docbuild.undecided_installed_modules(RUNTIME)
        self.assertEqual(
            undecided,
            [],
            "installed runtime modules with no documentation decision:\n  "
            + "\n  ".join(undecided),
        )

    def test_the_installed_surface_includes_the_packages_setuptools_finds(self):
        # The package members are installed because ``packages.find`` picks
        # them up -- not because the generator guessed.  The generator reads
        # the packaging configuration, so a package added to ``include`` is
        # part of the installed surface automatically.
        #
        # The include list is NOT frozen here: it is the packaging
        # configuration's business, and a slice that adds a package to it
        # must not have to edit this test to be accepted.  What this test
        # pins is the RULE -- every named pattern has modules on disk, and
        # every package member is covered by a pattern -- not the current
        # contents of the list.
        #
        # MEASURED 2026-11-16: the `runtime-data-files` slice added
        # ``policy*`` to the include list (the runtime's data-file
        # directory, so its ``package-data`` globs are reachable), and this
        # assertion -- which froze the list to two entries -- failed.  The
        # freeze was the defect: it made an unrelated packaging change
        # look like a regression.
        with (docbuild.ROOT / "components" / RUNTIME / "pyproject.toml").open(
            "rb"
        ) as handle:
            data = tomllib.load(handle)
        include = data["tool"]["setuptools"]["packages"]["find"]["include"]
        self.assertTrue(include, "the packaging configuration names no package")
        self.assertEqual(len(include), len(set(include)), "duplicate patterns")
        for pattern in include:
            stem = pattern.rstrip("*")
            on_disk = {
                path.stem
                for path in (docbuild.ROOT / "components" / RUNTIME / stem).glob("*.py")
            }
            self.assertTrue(on_disk, f"packaging names {pattern!r} but nothing is on disk")
            expected = {
                name
                for name in docbuild.package_members(RUNTIME)
                if name.split(".")[0] == stem
            }
            self.assertTrue(expected, f"no package member found for {pattern!r}")
        # Every package member is covered by one of the include patterns.
        patterns = [
            pattern.rstrip("*")
            for pattern in data["tool"]["setuptools"]["packages"]["find"]["include"]
        ]
        uncovered = sorted(
            name
            for name in docbuild.package_members(RUNTIME)
            if name.split(".")[0] not in patterns
        )
        self.assertEqual(
            uncovered,
            [],
            "package members not covered by the packaging include patterns:\n  "
            + "\n  ".join(uncovered),
        )

    def test_the_renderer_that_produces_the_page_still_behaves(self):
        # This slice changed ``tests/docbuild.py`` -- the generator.  The
        # referee plants small semantic faults in the module a slice changed
        # and runs the slice's own tests against them, so the generator's
        # behaviour must be covered *here*, not only in the generator's own
        # test file.  Without this coverage a fault in the renderer would
        # survive, and the verdict would say nothing about the slice.
        #
        # ``_summary`` -- the docstring cleaner the page is built from.
        self.assertEqual(docbuild._summary(None), "")
        self.assertEqual(docbuild._summary("  one   two  "), "one two")
        # Only the FIRST paragraph is used.
        self.assertEqual(docbuild._summary("para one\n\npara two"), "para one")
        # The cap is exclusive: a summary exactly at the cap is not cut, and
        # one character more is cut and marked with an ellipsis.
        at_cap = "x" * 300
        self.assertEqual(docbuild._summary(at_cap), at_cap)
        over_cap = docbuild._summary("x" * 301)
        self.assertTrue(over_cap.endswith("…"))
        self.assertLessEqual(len(over_cap), 300)

    def test_the_renderer_recognises_property_decorators(self):
        # ``_is_property`` decides whether a member is rendered as
        # ``name`` or ``name()``.  A fault in either branch changes the
        # rendered page, so both branches are pinned.
        source = (
            "class C:\n"
            "    @property\n"
            "    def a(self): ...\n"
            "    @x.cached_property\n"
            "    def b(self): ...\n"
            "    @staticmethod\n"
            "    def c(self): ...\n"
        )
        tree = ast.parse(source)
        members = tree.body[0].body
        self.assertTrue(docbuild._is_property(members[0]))
        self.assertTrue(docbuild._is_property(members[1]))
        self.assertFalse(docbuild._is_property(members[2]))

    def test_a_rendered_page_names_the_package_members(self):
        # The renderer is what turns a manifest entry into a page heading.
        # A package member's heading drops the ``.__init__`` suffix but keeps
        # the package prefix -- that is how a reader tells ``tools.shell``
        # from a flat ``shell``.
        root = docbuild.ROOT / "components" / RUNTIME
        source = root / "tools" / "shell.py"
        text = "\n".join(docbuild._render_module(RUNTIME, "tools.shell", source))
        self.assertIn("### `tools.shell`", text)
        self.assertNotIn("tools.shell.__init__", text)
        package_source = root / "tools" / "__init__.py"
        package_text = "\n".join(
            docbuild._render_module(RUNTIME, "tools.__init__", package_source)
        )
        self.assertIn("### `tools`", package_text)

    def test_the_rendered_page_lists_the_public_members_and_nothing_private(self):
        # The renderer's member filter: a public member is listed, a private
        # one is not, and a leading ``self`` is dropped from the signature.
        source = docbuild.ROOT / "components" / RUNTIME / "allowlist.py"
        text = "\n".join(docbuild._render_module(RUNTIME, "allowlist", source))
        self.assertIn("### `allowlist`", text)
        self.assertIn("#### `Allowlist`", text)
        self.assertIn("- `check(value: str)`", text)
        self.assertIn("#### `stdlib_only()`", text)
        self.assertNotIn("self", text)
        self.assertIn("Allowlist validation", text)

    def test_a_rendered_page_hides_the_underscored_members(self):
        source = docbuild.ROOT / "components" / RUNTIME / "budget.py"
        text = "\n".join(docbuild._render_module(RUNTIME, "budget", source))
        self.assertIn("#### `ModelPricing`", text)
        self.assertNotIn("_private", text)
        for line in text.splitlines():
            if line.startswith("#### `") or line.startswith("### `"):
                name = line.split("`")[1]
                with self.subTest(heading=name):
                    self.assertFalse(name.startswith("_"))

    def test_a_rendered_page_has_exactly_one_trailing_newline(self):
        for component in docbuild.MANIFEST:
            with self.subTest(component=component):
                page = docbuild.render_page(component)
                self.assertTrue(page.endswith("\n"))
                self.assertFalse(page.endswith("\n\n"))

    def test_the_surface_document_states_that_package_members_are_published(self):
        # The positive form of the truth, pinned in the document itself.
        #
        # The alternative -- catching the sentence "the package members are
        # excluded" -- was the wrong shape.  A document that quotes the old
        # wording, that explains the claim was false, or that says "not one
        # is excluded", all trip a negation-blind pattern, and none of them
        # asserts the false claim.  Stating the truth is both more reliable
        # and a better rule.
        for relative in SURFACE_DOCS:
            path = docbuild.ROOT / relative
            self.assertTrue(path.exists(), f"missing document: {relative}")
            text = path.read_text(encoding="utf-8")
            with self.subTest(document=relative):
                self.assertRegex(
                    text,
                    # The document may emphasis the word with * or **.
                    r"package members?[^\n]{0,200}?\b(?:are|were)\s+(?:\*{1,2})?published",
                    f"{relative} must state that the package members are published",
                )

    def test_no_document_asserts_a_package_member_is_excluded(self):
        # The false claim, pinned.  A document that says a package member is
        # excluded is describing a decision nobody made, and a reader who
        # believes it would act on it.
        #
        # The check runs over **sentences**, not lines: the original false
        # statement spanned two lines ("The 23 package members and
        # `test_runner` are excluded on purpose and stay excluded."), so a
        # line-based pattern would miss it.
        #
        # Three shapes are deliberately allowed, because none of them *asserts*
        # the claim:
        #
        # * a blockquote, which quotes the old wording in order to correct it;
        # * a **meta-sentence** — one that reports the claim instead of making
        #   it ("...which now fails if any document says a package member is
        #   excluded").  This is the shape the slice's own corrective prose
        #   takes, and a naive pattern catches it;
        # * a sentence that **denies** the claim ("...are *published*, not
        #   excluded, and stay published").
        #
        # The false sentence has none of those three markers, so it is still
        # caught.
        mention = r"(?:package members?|\bproviders\.\*|\btools\.\*|\btest_runner\b)"
        asserted = re.compile(
            rf"{mention}[^.\n]{{0,120}}?\b(?:are|is|were|was)\s+(?:\*{1,2})?excluded",
            re.IGNORECASE,
        )
        denied = re.compile(
            r"\bnot\s+(?:\*{0,2})?(?:one\s+is\s+)?excluded\b"
            r"|(?:excluded|published),\s*not\b"
            r"|\b(?:are|were|is)\s+(?:\*{0,2})?published\b",
            re.IGNORECASE,
        )
        meta = re.compile(
            r"\b(?:says?|said|state[sd]?|claims?|claimed|mentions?|mentioned"
            r"|writes?|wrote|notes?|noted|reports?|reported|reads?"
            r"|if\s+any\s+document|would\s+have|previously)\b",
            re.IGNORECASE,
        )
        for relative in SURFACE_DOCS:
            path = docbuild.ROOT / relative
            self.assertTrue(path.exists(), f"missing document: {relative}")
            text = path.read_text(encoding="utf-8")
            offenders: list[str] = []
            for block in re.split(r"\n\s*\n", text):
                lines = [line.strip() for line in block.splitlines()]
                # A blockquote quotes a claim; it does not assert one.
                if any(line.startswith(">") for line in lines):
                    continue
                prose = " ".join(line for line in lines if line)
                for sentence in re.split(r"(?<=[.!?:])\s+", prose):
                    sentence = sentence.strip()
                    if not sentence:
                        continue
                    if meta.search(sentence) or denied.search(sentence):
                        continue
                    if asserted.search(sentence):
                        offenders.append(sentence)
            self.assertEqual(
                offenders,
                [],
                f"{relative} claims a package member is excluded, but every "
                "package member is published:\n  " + "\n  ".join(offenders),
            )


class PackageMemberPublicationGuardSecondHalfTests(unittest.TestCase):
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
