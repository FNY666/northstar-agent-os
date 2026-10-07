"""Tests for template_engine (Mustache/Jinja rendering discipline)."""

import ast
import math
import threading
import unittest

from template_engine import (
    TEMPLATE_ENGINE_SCHEMA,
    TEMPLATE_ENGINE_VERSION,
    MAX_PARTIAL_DEPTH,
    BadContextError,
    BadValueError,
    DuplicateTemplateError,
    RecursionDepthError,
    RenderedTemplate,
    SeqOrderError,
    TemplateEngine,
    TemplateError,
    TemplateRecord,
    TemplateSyntaxError,
    UnknownPartialError,
    UnknownTemplateError,
    escape,
    template_engine_audit_event,
)


def _engine():
    return TemplateEngine()


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(TEMPLATE_ENGINE_VERSION, "template-engine.v1")
        self.assertEqual(TEMPLATE_ENGINE_SCHEMA, "northstar.template-engine.v1")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_imports_only(self):
        tree = ast.parse(open("template_engine.py").read())
        allowed = {
            "html", "math", "re", "threading", "dataclasses", "typing",
            "__future__", "hashlib", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed, alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


class TestRegistration(unittest.TestCase):
    def test_register_roundtrip(self):
        e = _engine()
        rec = e.register("hello", "Hi {{name}}", seq=1)
        self.assertIsInstance(rec, TemplateRecord)
        self.assertEqual(rec.name, "hello")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertFalse(rec.is_partial)
        self.assertEqual(e.template("hello").digest, rec.digest)

    def test_digest_deterministic(self):
        e1, e2 = _engine(), _engine()
        r1 = e1.register("t", "x {{y}}", seq=1)
        r2 = e2.register("t", "x {{y}}", seq=1)
        self.assertEqual(r1.digest, r2.digest)

    def test_duplicate_refused(self):
        e = _engine()
        e.register("t", "a", seq=1)
        with self.assertRaises(DuplicateTemplateError):
            e.register("t", "b", seq=2)

    def test_unclosed_section_refused(self):
        e = _engine()
        with self.assertRaises(TemplateSyntaxError):
            e.register("t", "{{#items}}oops", seq=1)

    def test_stray_closing_refused(self):
        e = _engine()
        with self.assertRaises(TemplateSyntaxError):
            e.register("t", "x {{/items}}", seq=1)

    def test_mismatched_section_refused(self):
        e = _engine()
        with self.assertRaises(TemplateSyntaxError):
            e.register("t", "{{#a}}x{{/b}}", seq=1)

    def test_empty_tag_refused(self):
        e = _engine()
        with self.assertRaises(TemplateSyntaxError):
            e.register("t", "x {{}}", seq=1)

    def test_bad_name_refused(self):
        e = _engine()
        with self.assertRaises(TemplateError):
            e.register("", "x", seq=1)

    def test_partial_flag(self):
        e = _engine()
        rec = e.partial("foot", "-- {{org}}", seq=1)
        self.assertTrue(rec.is_partial)

    def test_views(self):
        e = _engine()
        e.register("b", "x", seq=1)
        e.register("a", "y", seq=2)
        self.assertEqual(e.names(), ("a", "b"))
        self.assertEqual(e.template_count(), 2)
        with self.assertRaises(UnknownTemplateError):
            e.template("nope")


class TestRender(unittest.TestCase):
    def test_escaped_interpolation(self):
        e = _engine()
        e.register("t", "Hello, {{name}}!", seq=1)
        r = e.render("t", {"name": "<b>Ada</b>"}, seq=2)
        self.assertIsInstance(r, RenderedTemplate)
        self.assertEqual(r.text, "Hello, &lt;b&gt;Ada&lt;/b&gt;!")

    def test_triple_stache_unescaped(self):
        e = _engine()
        e.register("t", "{{{html}}}", seq=1)
        r = e.render("t", {"html": "<b>x</b>"}, seq=2)
        self.assertEqual(r.text, "<b>x</b>")

    def test_ampersand_unescaped(self):
        e = _engine()
        e.register("t", "{{& html}}", seq=1)
        r = e.render("t", {"html": "<i>y</i>"}, seq=2)
        self.assertEqual(r.text, "<i>y</i>")

    def test_missing_variable_empty(self):
        e = _engine()
        e.register("t", "a{{missing}}b", seq=1)
        r = e.render("t", {}, seq=2)
        self.assertEqual(r.text, "ab")

    def test_dotted_path(self):
        e = _engine()
        e.register("t", "{{user.name}} <{{user.email}}>", seq=1)
        r = e.render("t", {"user": {"name": "Ada", "email": "a@x.y"}}, seq=2)
        self.assertEqual(r.text, "Ada <a@x.y>")

    def test_bool_and_none(self):
        e = _engine()
        e.register("t", "{{flag}}/{{nothing}}", seq=1)
        r = e.render("t", {"flag": True, "nothing": None}, seq=2)
        self.assertEqual(r.text, "true/")

    def test_comment_stripped(self):
        e = _engine()
        e.register("t", "a{{! secret }}b", seq=1)
        r = e.render("t", {}, seq=2)
        self.assertEqual(r.text, "ab")

    def test_render_digest_binds_context(self):
        e = _engine()
        e.register("t", "{{v}}", seq=1)
        r1 = e.render("t", {"v": "a"}, seq=2)
        r2 = e.render("t", {"v": "b"}, seq=3)
        self.assertNotEqual(r1.context_digest, r2.context_digest)
        self.assertNotEqual(r1.digest, r2.digest)
        self.assertTrue(r1.template_digest.startswith("sha256:"))

    def test_unknown_template_raises(self):
        e = _engine()
        with self.assertRaises(UnknownTemplateError):
            e.render("nope", {}, seq=1)

    def test_mapping_interpolation_refused(self):
        e = _engine()
        e.register("t", "{{obj}}", seq=1)
        with self.assertRaises(BadValueError):
            e.render("t", {"obj": {"a": 1}}, seq=2)

    def test_list_interpolation_refused(self):
        e = _engine()
        e.register("t", "{{lst}}", seq=1)
        with self.assertRaises(BadValueError):
            e.render("t", {"lst": [1, 2]}, seq=2)


class TestSections(unittest.TestCase):
    def test_section_iterates_mappings(self):
        e = _engine()
        e.register("t", "{{#users}}{{name}},{{/users}}", seq=1)
        r = e.render("t", {"users": [{"name": "x"}, {"name": "y"}]}, seq=2)
        self.assertEqual(r.text, "x,y,")

    def test_section_dot_scalar(self):
        e = _engine()
        e.register("t", "{{#items}}[{{.}}]{{/items}}", seq=1)
        r = e.render("t", {"items": ["a", "b"]}, seq=2)
        self.assertEqual(r.text, "[a][b]")

    def test_section_truthy_once(self):
        e = _engine()
        e.register("t", "{{#show}}YES{{/show}}", seq=1)
        r = e.render("t", {"show": True}, seq=2)
        self.assertEqual(r.text, "YES")

    def test_section_falsy_skips(self):
        e = _engine()
        e.register("t", "a{{#x}}B{{/x}}c", seq=1)
        for i, falsy in enumerate((None, False, "", [], {}, 0)):
            r = e.render("t", {"x": falsy}, seq=2 + i)
            self.assertEqual(r.text, "ac", falsy)

    def test_inverted_section(self):
        e = _engine()
        e.register("t", "{{^items}}empty{{/items}}", seq=1)
        r = e.render("t", {"items": []}, seq=2)
        self.assertEqual(r.text, "empty")
        r2 = e.render("t", {"items": [1]}, seq=3)
        self.assertEqual(r2.text, "")

    def test_section_falls_back_to_parent_scope(self):
        e = _engine()
        e.register("t", "{{#users}}{{greet}} {{name}};{{/users}}", seq=1)
        r = e.render(
            "t", {"greet": "hi", "users": [{"name": "a"}]}, seq=2
        )
        self.assertEqual(r.text, "hi a;")


class TestPartials(unittest.TestCase):
    def test_partial_include(self):
        e = _engine()
        e.partial("footer", "-- {{org}}", seq=1)
        e.register("page", "<h1>{{t}}</h1>{{> footer}}", seq=2)
        r = e.render("page", {"t": "Hi", "org": "ACME"}, seq=3)
        self.assertEqual(r.text, "<h1>Hi</h1>-- ACME")

    def test_partial_sees_caller_context(self):
        e = _engine()
        e.partial("who", "{{name}}!", seq=1)
        e.register("t", "hi {{> who}}", seq=2)
        r = e.render("t", {"name": "Ada"}, seq=3)
        self.assertEqual(r.text, "hi Ada!")

    def test_unknown_partial_raises(self):
        e = _engine()
        e.register("t", "{{> ghost}}", seq=1)
        with self.assertRaises(UnknownPartialError):
            e.render("t", {}, seq=2)

    def test_partial_recursion_refused(self):
        e = _engine()
        e.partial("loop", "{{> loop}}", seq=1)
        e.register("t", "{{> loop}}", seq=2)
        with self.assertRaises(RecursionDepthError):
            e.render("t", {}, seq=3)


class TestEscape(unittest.TestCase):
    def test_escape_quotes(self):
        self.assertEqual(escape('"a<b>&'), "&quot;a&lt;b&gt;&amp;")

    def test_escape_none(self):
        self.assertEqual(escape(None), "")

    def test_engine_escape_same(self):
        self.assertEqual(TemplateEngine.escape("<x>"), escape("<x>"))


class TestContextValidation(unittest.TestCase):
    def test_nan_refused(self):
        e = _engine()
        e.register("t", "{{v}}", seq=1)
        with self.assertRaises(BadContextError):
            e.render("t", {"v": math.nan}, seq=2)

    def test_inf_refused(self):
        e = _engine()
        e.register("t", "{{v}}", seq=1)
        with self.assertRaises(BadContextError):
            e.render("t", {"v": math.inf}, seq=2)

    def test_big_int_refused(self):
        e = _engine()
        e.register("t", "{{v}}", seq=1)
        with self.assertRaises(BadContextError):
            e.render("t", {"v": 2 ** 53}, seq=2)

    def test_integral_float_refused(self):
        e = _engine()
        e.register("t", "{{v}}", seq=1)
        with self.assertRaises(BadContextError):
            e.render("t", {"v": 3.0}, seq=2)

    def test_non_mapping_context_refused(self):
        e = _engine()
        e.register("t", "{{v}}", seq=1)
        with self.assertRaises(BadContextError):
            e.render("t", [("v", 1)], seq=2)

    def test_non_str_key_refused(self):
        e = _engine()
        e.register("t", "{{v}}", seq=1)
        with self.assertRaises(BadContextError):
            e.render("t", {1: "x"}, seq=2)


class TestSeqOrder(unittest.TestCase):
    def test_rewind_refused(self):
        e = _engine()
        e.register("t", "x", seq=5)
        with self.assertRaises(SeqOrderError):
            e.register("u", "y", seq=5)
        with self.assertRaises(SeqOrderError):
            e.render("t", {}, seq=1)

    def test_bool_seq_refused(self):
        e = _engine()
        with self.assertRaises(TemplateError):
            e.register("t", "x", seq=True)


class TestAudit(unittest.TestCase):
    def test_kinds(self):
        for kind in ("template-registered", "partial-registered", "rendered", "rejected"):
            ev = template_engine_audit_event(kind, 1, name="t")
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["module"], "template_engine")
            self.assertEqual(ev["module_version"], TEMPLATE_ENGINE_VERSION)

    def test_unknown_kind_refused(self):
        with self.assertRaises(TemplateError):
            template_engine_audit_event("nope", 1)


class TestConcurrency(unittest.TestCase):
    def test_concurrent_renders(self):
        e = _engine()
        e.register("t", "{{v}}", seq=1)
        results = []
        errors = []

        def work(i):
            try:
                r = e.render("t", {"v": i}, seq=2 + i)
                results.append(r.text)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), [str(i) for i in range(8)])


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import template_engine as m

        m.main()


if __name__ == "__main__":
    unittest.main()
