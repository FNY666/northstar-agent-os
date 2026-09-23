"""Repository-level documentation checks: structure, build freshness, links.

These are the tests behind the CI documentation job's three concerns:

* structure  - every component README exposes the "Concepts, guides and API
               reference" link targets; the examples index covers every example;
* build      - docs/api/*.md are byte-identical to what tests/docbuild.py
               generates from docstrings (a stale page fails CI);
* links      - every internal markdown link in the repository resolves.

The generator/checker itself lives in docbuild.py (pure standard library).
"""
import unittest
import unittest.mock
from pathlib import Path
import tempfile

import docbuild

ROOT = docbuild.ROOT
SECTION_HEADING = "## Concepts, guides and API reference"


class ComponentReadmeLinkTargetTests(unittest.TestCase):
    def test_every_component_readme_offers_concept_guide_and_api_targets(self):
        for component in docbuild.MANIFEST:
            with self.subTest(component=component):
                readme = ROOT / "components" / component / "README.md"
                self.assertTrue(readme.is_file(), f"missing README: {readme}")
                text = readme.read_text(encoding="utf-8")
                self.assertEqual(
                    text.count(SECTION_HEADING),
                    1,
                    f"{component} README must contain exactly one {SECTION_HEADING!r} section",
                )
                # The four-layer structure: README (quick start) links onward to
                # at least one concepts page, one guides page, and its own API page.
                self.assertIn("../../docs/concepts/", text, f"{component}: no concepts link target")
                self.assertIn("../../docs/guides/", text, f"{component}: no guides link target")
                self.assertIn(
                    f"../../docs/api/{component}.md",
                    text,
                    f"{component}: no API reference link target",
                )
                self.assertTrue(
                    (ROOT / "docs" / "api" / f"{component}.md").is_file(),
                    f"missing generated API page for {component}",
                )


class ExamplesIndexTests(unittest.TestCase):
    def test_examples_index_covers_every_example(self):
        examples = ROOT / "examples"
        index = examples / "README.md"
        self.assertTrue(index.is_file(), "missing examples/README.md index page")
        text = index.read_text(encoding="utf-8")
        example_dirs = sorted(
            path.name for path in examples.iterdir() if path.is_dir() and (path / "README.md").is_file()
        )
        self.assertGreaterEqual(len(example_dirs), 1, "no example directories found")
        for name in example_dirs:
            with self.subTest(example=name):
                self.assertIn(f"{name}/README.md", text, f"examples index does not link {name!r}")
        self.assertIn("Structure expectation", text, "index should state the index rule")


class GeneratedApiFreshnessTests(unittest.TestCase):
    def test_committed_api_pages_match_docstring_generation(self):
        stale = docbuild.stale_pages()
        self.assertEqual(
            stale,
            [],
            "docs/api pages are stale; run `python3 tests/docbuild.py build` "
            f"and commit the regeneration (stale: {', '.join(stale) or 'none'})",
        )

    def test_every_public_module_is_documented_or_deliberately_excluded(self):
        # The manifest is explicit so that publishing a module is a decision; that only
        # holds if *omitting* one is an error. Without this test, adding a module and
        # forgetting the manifest silently shrinks the API reference forever.
        gaps = docbuild.undocumented_modules()
        self.assertEqual(
            gaps,
            [],
            "public modules missing from the API reference (add them to docbuild.MANIFEST "
            "or record an exclusion in MANIFEST_EXCLUSIONS):\n  " + "\n  ".join(gaps),
        )

    def test_no_api_page_documents_a_module_that_does_not_exist(self):
        ghosts = docbuild.documented_but_absent()
        self.assertEqual(ghosts, [], "manifest lists modules with no file:\n  " + "\n  ".join(ghosts))

    def test_exclusions_are_only_for_modules_that_exist(self):
        # An exclusion that outlives its module is a lie about a decision.
        for component, excluded in docbuild.MANIFEST_EXCLUSIONS.items():
            names = docbuild.public_modules(component)
            for name in sorted(excluded):
                with self.subTest(component=component, name=name):
                    self.assertIn(name, names, f"{component}: {name} excluded but not on disk")

    def test_api_pages_carry_generated_header_and_module_headings(self):
        # A page that silently lost its provenance header or its module list
        # must fail loudly, not just drift byte-wise against itself.
        for component, modules in docbuild.MANIFEST.items():
            with self.subTest(component=component):
                page = (ROOT / "docs" / "api" / f"{component}.md").read_text(encoding="utf-8")
                self.assertIn(docbuild.GENERATED_HEADER, page)
                for module in modules:
                    heading = f"### `{module.replace('.__init__', '')}`"
                    self.assertIn(heading, page, f"missing module heading {heading!r}")


class MarkdownLinkTests(unittest.TestCase):
    def test_all_internal_markdown_links_resolve(self):
        broken = docbuild.broken_links()
        self.assertEqual(broken, [], "broken internal markdown links:\n  " + "\n  ".join(broken))

    def test_only_third_party_captures_are_excluded_from_the_link_check(self):
        checked = {path.relative_to(docbuild.ROOT).as_posix() for path in docbuild.markdown_files()}
        self.assertFalse(any(name.startswith("research/") for name in checked))
        # The exclusion must stay narrow: the project's own documentation is still checked.
        self.assertIn("README.md", checked)
        self.assertTrue(any(name.startswith("docs/") for name in checked))
        self.assertTrue(any(name.startswith("components/") for name in checked))


class LinkCheckExclusionBoundaryTests(unittest.TestCase):
    """Isolated fixtures (not the real repository tree) that pin down the exact shape of
    the research/ exclusion: it drops *source files* under the top-level research/
    directory from the scan, nothing else. A link check that instead excluded *targets*
    under research/, or matched research/ by prefix, would pass the tests above (which
    only look at the real tree) while silently widening the exclusion."""

    def _build_tree(self, root: Path, files: dict[str, str]) -> None:
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def test_a_non_research_document_linking_into_research_still_fails(self):
        # The exclusion drops research/ *source* files from the scan; it must not become a
        # blanket allowance for any link that merely points *at* something under research/.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._build_tree(root, {
                "docs/guide.md": "See the [capture](../research/missing.md) for details.\n",
            })
            with unittest.mock.patch.object(docbuild, "ROOT", root):
                broken = docbuild.broken_links()
            self.assertEqual(
                broken,
                ["docs/guide.md:1: ../research/missing.md"],
                "a non-research document's link to a missing research/ target must still be reported",
            )

    def test_a_look_alike_top_level_directory_is_not_swept_into_the_exclusion(self):
        # Only the exact top-level name "research" is excluded. A directory whose name
        # merely starts with it (or contains it) must keep being checked, which would fail
        # a naive str.startswith("research") check but passes the parts[0]-equality check.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._build_tree(root, {
                "research-old/broken.md": "[dangling](./nowhere.md)\n",
                "not-research/broken.md": "[dangling](./nowhere.md)\n",
            })
            with unittest.mock.patch.object(docbuild, "ROOT", root):
                checked = {path.relative_to(root).as_posix() for path in docbuild.markdown_files()}
                broken = {entry.split(":", 1)[0] for entry in docbuild.broken_links()}
            self.assertIn("research-old/broken.md", checked)
            self.assertIn("not-research/broken.md", checked)
            self.assertIn("research-old/broken.md", broken)
            self.assertIn("not-research/broken.md", broken)

    def test_the_exclusion_only_matches_the_exact_top_level_research_directory(self):
        # A file literally named "research.md" at the root is not the research/ directory
        # and must still be checked; nested "research" directories below the top level are
        # not the excluded root either.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._build_tree(root, {
                "research.md": "[dangling](./nowhere.md)\n",
                "docs/research/broken.md": "[dangling](./nowhere.md)\n",
            })
            with unittest.mock.patch.object(docbuild, "ROOT", root):
                checked = {path.relative_to(root).as_posix() for path in docbuild.markdown_files()}
            self.assertIn("research.md", checked)
            self.assertIn("docs/research/broken.md", checked)


if __name__ == "__main__":
    unittest.main()
