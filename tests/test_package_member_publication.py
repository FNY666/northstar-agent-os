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
import re
import tomllib
import unittest

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


if __name__ == "__main__":
    unittest.main()
