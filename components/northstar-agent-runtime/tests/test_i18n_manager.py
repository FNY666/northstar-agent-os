"""Tests for i18n_manager: locales, catalogs, ICU messages, plural rules."""

import ast
import unittest

from i18n_manager import (
    VERSION,
    SCHEMA,
    PLURAL_LOCALES,
    I18nError,
    InvalidTagError,
    UnknownLocaleError,
    DuplicateLocaleError,
    InvalidCatalogError,
    MissingMessageError,
    MessageFormatError,
    InvalidCountError,
    SequenceError,
    I18nManager,
    i18n_manager_audit_event,
)


def make_manager():
    m = I18nManager(default_locale="en")
    m.add_locale("en", 1, display_name="English")
    m.add_messages("en", {"hello": "Hello, {name}!"}, 2)
    return m


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(VERSION, "i18n-manager.v1")
        self.assertEqual(SCHEMA, "northstar.i18n-manager.v1")

    def test_stdlib_only(self):
        with open("i18n_manager.py") as f:
            tree = ast.parse(f.read())
        allowed = {"hashlib", "re", "threading", "dataclasses", "typing",
                   "__future__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestLocales(unittest.TestCase):
    def test_add_and_list(self):
        m = make_manager()
        m.add_locale("de", 3, display_name="Deutsch")
        self.assertEqual(m.locales(), ("de", "en"))

    def test_duplicate_locale(self):
        m = make_manager()
        with self.assertRaises(DuplicateLocaleError):
            m.add_locale("en", 3)

    def test_bad_tag(self):
        m = make_manager()
        with self.assertRaises(InvalidTagError):
            m.add_locale("e", 3)
        with self.assertRaises(InvalidTagError):
            m.add_locale("", 4)

    def test_tag_normalization(self):
        m = make_manager()
        rec = m.add_locale("en-us", 3)
        self.assertEqual(rec.tag, "en-US")
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_set_and_get_locale(self):
        m = make_manager()
        m.add_locale("fr", 3, display_name="Français")
        self.assertEqual(m.locale("fr", 4), "fr")
        self.assertEqual(m.locale(), "fr")

    def test_set_unknown_locale(self):
        m = make_manager()
        with self.assertRaises(UnknownLocaleError):
            m.locale("xx", 3)

    def test_seq_monotonic(self):
        m = make_manager()
        with self.assertRaises(SequenceError):
            m.add_locale("de", 2)  # rewind
        with self.assertRaises(SequenceError):
            m.add_locale("de", True)


class TestCatalogs(unittest.TestCase):
    def test_resolve_and_fallback_chain(self):
        m = make_manager()
        m.add_locale("pt", 3, display_name="Português")
        m.add_locale("pt-BR", 4, display_name="Português (BR)")
        m.add_messages("pt", {"regional": "Olá (pt)!"}, 5)
        m.add_messages("pt-BR", {"hello": "Olá!"}, 6)
        # exact locale wins
        self.assertEqual(m.translate("hello", 7, locale="pt-BR"), "Olá!")
        # pt-BR region falls back to pt base for a pt-only key
        self.assertEqual(m.translate("regional", 8, locale="pt-BR"), "Olá (pt)!")
        # es has no catalog: falls back through the default en; {name}
        # unbound -> fail-closed
        m.add_locale("es", 9)
        with self.assertRaises(MessageFormatError):
            m.translate("hello", 10, locale="es")

    def test_missing_key_everywhere(self):
        m = make_manager()
        with self.assertRaises(MissingMessageError):
            m.translate("nope", 3)

    def test_catalog_for_unknown_locale(self):
        m = make_manager()
        with self.assertRaises(UnknownLocaleError):
            m.add_messages("xx", {"a": "b"}, 3)

    def test_bad_catalog(self):
        m = make_manager()
        with self.assertRaises(InvalidCatalogError):
            m.add_messages("en", {}, 3)
        with self.assertRaises(InvalidCatalogError):
            m.add_messages("en", {"": "x"}, 4)


class TestMessages(unittest.TestCase):
    def setUp(self):
        self.m = make_manager()
        self.m.add_messages("en", {
            "items": "{n, plural, one {# item} other {# items}}",
            "cart": "{n, plural, =0 {empty} one {# thing} other {# things}}",
            "greet": "{g, select, male {He} female {She} other {They}} came",
            "quoted": "it''s {x}",
            "num": "total {v, number}",
        }, 3)

    def test_simple_arg(self):
        self.assertEqual(
            self.m.translate("hello", 4, args={"name": "Ada"}), "Hello, Ada!")

    def test_missing_arg(self):
        with self.assertRaises(MessageFormatError):
            self.m.translate("hello", 4)

    def test_plural_en(self):
        self.assertEqual(self.m.translate("items", 4, args={"n": 1}), "1 item")
        self.assertEqual(self.m.translate("items", 5, args={"n": 0}), "0 items")
        self.assertEqual(self.m.translate("items", 6, args={"n": 7}), "7 items")

    def test_plural_explicit(self):
        self.assertEqual(self.m.translate("cart", 4, args={"n": 0}), "empty")
        self.assertEqual(self.m.translate("cart", 5, args={"n": 1}), "1 thing")
        self.assertEqual(self.m.translate("cart", 6, args={"n": 2}), "2 things")

    def test_select(self):
        self.assertEqual(
            self.m.translate("greet", 4, args={"g": "male"}), "He came")
        self.assertEqual(
            self.m.translate("greet", 5, args={"g": "x"}), "They came")

    def test_apostrophe(self):
        self.assertEqual(
            self.m.translate("quoted", 4, args={"x": 1}), "it's 1")

    def test_number(self):
        self.assertEqual(self.m.translate("num", 4, args={"v": 42}), "total 42")
        with self.assertRaises(MessageFormatError):
            self.m.translate("num", 5, args={"v": "x"})

    def test_unbalanced(self):
        self.m.add_messages("en", {"bad": "oops {"}, 4)
        with self.assertRaises(MessageFormatError):
            self.m.translate("bad", 5)

    def test_bad_count_types(self):
        for i, bad in enumerate((True, 1.5, -1, "2", None)):
            with self.assertRaises((InvalidCountError, MessageFormatError)):
                self.m.translate("items", 4 + i, args={"n": bad})


class TestPluralRules(unittest.TestCase):
    def setUp(self):
        self.m = make_manager()
        self.m.add_locale("ru", 3, display_name="Русский")
        self.m.add_locale("ar", 4, display_name="العربية")
        self.m.add_locale("fr", 5, display_name="Français")
        self.m.add_locale("ja", 6, display_name="日本語")

    def test_en(self):
        self.assertEqual(self.m.plural(1, 7).category, "one")
        self.assertEqual(self.m.plural(0, 8).category, "other")
        self.assertEqual(self.m.plural(2, 9).category, "other")

    def test_fr_zero_singular(self):
        self.assertEqual(self.m.plural(0, 7, locale="fr").category, "one")
        self.assertEqual(self.m.plural(1, 8, locale="fr").category, "one")
        self.assertEqual(self.m.plural(2, 9, locale="fr").category, "other")

    def test_ru(self):
        cases = {1: "one", 2: "few", 5: "many", 11: "many",
                 21: "one", 22: "few", 25: "many", 111: "many", 121: "one"}
        for i, (n, want) in enumerate(cases.items()):
            self.assertEqual(
                self.m.plural(n, 7 + i, locale="ru").category, want,
                f"ru n={n}")

    def test_ar(self):
        cases = {0: "zero", 1: "one", 2: "two", 5: "few",
                 15: "many", 100: "other"}
        for i, (n, want) in enumerate(cases.items()):
            self.assertEqual(
                self.m.plural(n, 7 + i, locale="ar").category, want,
                f"ar n={n}")

    def test_ja_other_only(self):
        for i, n in enumerate((0, 1, 2, 100)):
            self.assertEqual(
                self.m.plural(n, 7 + i, locale="ja").category, "other")

    def test_ru_message(self):
        self.m.add_messages("ru", {
            "apples": "{n, plural, one {# яблоко} few {# яблока} many {# яблок} other {# яблока}}",
        }, 7)
        self.assertEqual(
            self.m.translate("apples", 8, locale="ru", args={"n": 1}), "1 яблоко")
        self.assertEqual(
            self.m.translate("apples", 9, locale="ru", args={"n": 3}), "3 яблока")
        self.assertEqual(
            self.m.translate("apples", 10, locale="ru", args={"n": 5}), "5 яблок")

    def test_bad_counts(self):
        for i, bad in enumerate((True, -1, 1.5, "3")):
            with self.assertRaises(InvalidCountError):
                self.m.plural(bad, 7 + i)


class TestAudit(unittest.TestCase):
    def test_event_shapes(self):
        ev = i18n_manager_audit_event("locale-added", 1, "en", "sha256:x")
        self.assertEqual(ev["kind"], "i18n.locale-added")
        self.assertEqual(ev["schema"], SCHEMA)
        with self.assertRaises(I18nError):
            i18n_manager_audit_event("bogus", 1)
        with self.assertRaises(I18nError):
            i18n_manager_audit_event("locale-added", True)

    def test_manager_audit_log(self):
        m = make_manager()
        log = m.audit_log()
        kinds = [e["kind"] for e in log]
        self.assertIn("locale-added", kinds)
        self.assertIn("catalog-added", kinds)

    def test_plural_locales_registry(self):
        self.assertIn("en", PLURAL_LOCALES)
        self.assertIn("ru", PLURAL_LOCALES)
        self.assertIn("ar", PLURAL_LOCALES)
        self.assertIn("zh", PLURAL_LOCALES)


if __name__ == "__main__":
    unittest.main()
