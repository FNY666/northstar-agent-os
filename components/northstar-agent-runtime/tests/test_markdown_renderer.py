"""Targeted tests for the markdown renderer interface."""

import ast
import unittest
from pathlib import Path

from markdown_renderer import (
    MarkdownRenderer,
    MarkdownError,
    InvalidInputError,
    SeqOrderError,
    RenderedDocument,
    TocDocument,
    SanitizedOutput,
    TocEntry,
    markdown_renderer_audit_event,
    MARKDOWN_RENDERER_VERSION,
    MARKDOWN_RENDERER_SCHEMA,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "markdown_renderer.py"


def fresh():
    return MarkdownRenderer()


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(MARKDOWN_RENDERER_VERSION, "markdown-renderer.v1")
        self.assertEqual(MARKDOWN_RENDERER_SCHEMA,
                         "northstar.markdown-renderer.v1")

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "html", "re", "threading",
            "dataclasses", "typing", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRender(unittest.TestCase):
    def test_heading_render(self):
        doc = fresh().render("# Hello World\n", seq=1)
        self.assertIn('<h1 id="hello-world">Hello World</h1>', doc.html)
        self.assertTrue(doc.digest.startswith("sha256:"))
        self.assertEqual(doc.block_count, 1)
        self.assertIsInstance(doc, RenderedDocument)

    def test_heading_levels_and_slug_dedupe(self):
        doc = fresh().render("## A\n\n### A\n\n## A\n", seq=1)
        anchors = [e.anchor for e in doc.toc]
        self.assertEqual(anchors, ["a", "a-1", "a-2"])
        self.assertIn('<h2 id="a">', doc.html)
        self.assertIn('<h3 id="a-1">', doc.html)

    def test_level7_is_paragraph(self):
        doc = fresh().render("####### not a heading\n", seq=1)
        self.assertIn("<p>####### not a heading</p>", doc.html)
        self.assertEqual(len(doc.toc), 0)

    def test_inline_strong_em_code(self):
        doc = fresh().render("**b** *i* `c` __s__ _e_\n", seq=1)
        self.assertIn("<strong>b</strong>", doc.html)
        self.assertIn("<em>i</em>", doc.html)
        self.assertIn("<code>c</code>", doc.html)
        self.assertIn("<strong>s</strong>", doc.html)
        self.assertIn("<em>e</em>", doc.html)

    def test_underscore_inside_word_is_literal(self):
        doc = fresh().render("snake_case stays\n", seq=1)
        self.assertIn("snake_case", doc.html)
        self.assertNotIn("<em>", doc.html)

    def test_link_and_image(self):
        doc = fresh().render(
            '[t](https://x.example "T") ![a](https://x.example/i.png)\n', seq=1)
        self.assertIn('<a href="https://x.example" title="T">t</a>', doc.html)
        self.assertIn('<img src="https://x.example/i.png" alt="a" />', doc.html)

    def test_unsafe_link_url_degrades_to_text(self):
        doc = fresh().render("[click](javascript:alert(1))\n", seq=1)
        self.assertNotIn("javascript:", doc.html)
        self.assertNotIn("<a", doc.html)
        self.assertIn("click", doc.html)

    def test_code_block_with_language(self):
        doc = fresh().render("```python\nprint(1)\n```\n", seq=1)
        self.assertIn('<pre><code class="language-python">', doc.html)
        self.assertIn("print(1)", doc.html)

    def test_unclosed_fence_runs_to_end(self):
        doc = fresh().render("```\nline1\nline2\n", seq=1)
        self.assertIn("<pre><code>line1\nline2\n</code></pre>", doc.html)

    def test_unordered_and_ordered_lists(self):
        doc = fresh().render("- a\n- b\n\n1. x\n2. y\n", seq=1)
        self.assertIn("<ul><li>a</li><li>b</li></ul>", doc.html)
        self.assertIn("<ol><li>x</li><li>y</li></ol>", doc.html)

    def test_blockquote(self):
        doc = fresh().render("> quoted **text**\n", seq=1)
        self.assertIn("<blockquote>", doc.html)
        self.assertIn("<strong>text</strong>", doc.html)

    def test_hr_and_paragraph_join(self):
        doc = fresh().render("one\ntwo\n\n---\n", seq=1)
        self.assertIn("<p>one\ntwo</p>", doc.html)
        self.assertIn("<hr />", doc.html)

    def test_html_escaping(self):
        doc = fresh().render("<b>raw</b> & \"q\"\n", seq=1)
        self.assertNotIn("<b>raw</b>", doc.html)
        self.assertIn("&lt;b&gt;raw&lt;/b&gt;", doc.html)
        self.assertIn("&amp;", doc.html)

    def test_digest_deterministic(self):
        a = fresh().render("# T\n\n- x\n", seq=1)
        b = fresh().render("# T\n\n- x\n", seq=1)
        self.assertEqual(a.digest, b.digest)
        c = fresh().render("# T\n\n- y\n", seq=1)
        self.assertNotEqual(a.digest, c.digest)


class TestToc(unittest.TestCase):
    def test_toc_entries(self):
        doc = fresh().toc("# A\n\ntext\n\n### B\n", seq=1)
        self.assertIsInstance(doc, TocDocument)
        self.assertEqual(
            [(e.level, e.text, e.anchor) for e in doc.entries],
            [(1, "A", "a"), (3, "B", "b")])
        self.assertTrue(doc.digest.startswith("sha256:"))


class TestSanitize(unittest.TestCase):
    def test_strips_script_and_content(self):
        out = fresh().sanitize("<p>ok</p><script>alert(1)</script>", seq=1)
        self.assertIsInstance(out, SanitizedOutput)
        self.assertEqual(out.html, "<p>ok</p>")
        self.assertIn("script", out.stripped_tags)

    def test_strips_event_handlers(self):
        out = fresh().sanitize('<p onclick="x()" title="t">hi</p>', seq=1)
        self.assertEqual(out.html, "<p>hi</p>")

    def test_strips_javascript_href(self):
        out = fresh().sanitize('<a href="javascript:x">y</a>', seq=1)
        self.assertEqual(out.html, "<a>y</a>")
        self.assertNotIn("javascript:", out.html)

    def test_disallowed_tag_keeps_text(self):
        out = fresh().sanitize("<div>keep <span>me</span></div>", seq=1)
        self.assertEqual(out.html, "keep me")
        self.assertIn("div", out.stripped_tags)

    def test_allowed_markup_survives(self):
        src = '<h1>t</h1><p><strong>b</strong> <a href="https://a.b">l</a></p>'
        out = fresh().sanitize(src, seq=1)
        self.assertEqual(out.html, src)


class TestSeqAndInput(unittest.TestCase):
    def test_seq_strictly_increasing(self):
        r = fresh()
        r.render("a\n", seq=1)
        with self.assertRaises(SeqOrderError):
            r.render("a\n", seq=1)
        with self.assertRaises(SeqOrderError):
            r.toc("a\n", seq=0)
        r.sanitize("<p>x</p>", seq=2)  # higher seq works

    def test_seq_bool_and_negative_rejected(self):
        r = fresh()
        with self.assertRaises(SeqOrderError):
            r.render("a\n", seq=True)
        with self.assertRaises(SeqOrderError):
            r.render("a\n", seq=-1)
        with self.assertRaises(SeqOrderError):
            r.render("a\n", seq="1")

    def test_non_string_source_rejected(self):
        r = fresh()
        with self.assertRaises(InvalidInputError):
            r.render(None, seq=1)
        with self.assertRaises(InvalidInputError):
            r.sanitize(123, seq=1)


class TestAudit(unittest.TestCase):
    def test_audit_event_shape(self):
        ev = markdown_renderer_audit_event("rendered", seq=3,
                                           detail={"blocks": 2})
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["component"], "markdown-renderer")
        self.assertEqual(ev["kind"], "rendered")
        self.assertEqual(ev["seq"], 3)
        with self.assertRaises(MarkdownError):
            markdown_renderer_audit_event("nope", seq=1)

    def test_main_runs(self):
        import markdown_renderer as m
        m.main()


if __name__ == "__main__":
    unittest.main()
