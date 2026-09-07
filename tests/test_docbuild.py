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
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
