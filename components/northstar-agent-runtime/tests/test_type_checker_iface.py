"""Targeted tests for type_checker_iface (batch 26)."""

import ast
import unittest
from pathlib import Path

from type_checker_iface import (
    SCHEMA_PIN,
    TYPE_CHECKER_IFACE_VERSION,
    BadArgumentError,
    BadSignatureError,
    BadTypeError,
    CheckReport,
    DuplicateSignatureError,
    SeqOrderError,
    StrictRecord,
    TypeCheckerIface,
    TypeDiagnostic,
    TypeIfaceError,
    UnknownSignatureError,
    type_checker_iface_audit_event,
    type_to_str,
)

MODULE_PATH = Path(__file__).parent.parent / "type_checker_iface.py"


class TestVersionPins(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(TYPE_CHECKER_IFACE_VERSION, "type-checker-iface.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.type-checker-iface.v1")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestDeclare(unittest.TestCase):
    def test_declare_roundtrip(self):
        tc = TypeCheckerIface()
        rec = tc.declare_signature(
            "sig-1", "greet", (("name", "str"), ("count", "int")), "str", 1
        )
        self.assertEqual(rec.sig_id, "sig-1")
        self.assertEqual(rec.func_name, "greet")
        self.assertTrue(rec.pin.startswith("sha256:"))
        self.assertEqual(tc.signature("sig-1").pin, rec.pin)
        self.assertEqual(tc.signature_ids(), ("sig-1",))
        self.assertEqual(type_to_str(rec.params[0][1]), "str")

    def test_declare_pin_determinism(self):
        t1, t2 = TypeCheckerIface(), TypeCheckerIface()
        r1 = t1.declare_signature("s", "f", (("x", "int"),), "None", 1)
        r2 = t2.declare_signature("s", "f", (("x", "int"),), "None", 1)
        self.assertEqual(r1.pin, r2.pin)

    def test_declare_containers(self):
        tc = TypeCheckerIface()
        rec = tc.declare_signature(
            "s",
            "f",
            (
                ("a", ("List", "int")),
                ("b", ("Dict", "str", "int")),
                ("c", ("Optional", "str")),
                ("d", ("Union", "int", "str")),
                ("e", ("Tuple", "int", "str")),
            ),
            ("List", "str"),
            1,
        )
        self.assertEqual(type_to_str(rec.params[0][1]), "List[int]")
        self.assertEqual(type_to_str(rec.params[1][1]), "Dict[str, int]")
        self.assertEqual(type_to_str(rec.params[2][1]), "Optional[str]")
        self.assertEqual(type_to_str(rec.params[3][1]), "Union[int, str]")
        self.assertEqual(type_to_str(rec.params[4][1]), "Tuple[int, str]")
        self.assertEqual(type_to_str(rec.returns), "List[str]")

    def test_declare_duplicate_refused(self):
        tc = TypeCheckerIface()
        tc.declare_signature("s", "f", (), "None", 1)
        with self.assertRaises(DuplicateSignatureError):
            tc.declare_signature("s", "f", (), "None", 2)

    def test_declare_bad_types_refused(self):
        tc = TypeCheckerIface()
        bad = [
            "Integer",  # unknown primitive
            ("Set", "int"),  # unknown head
            ("List",),  # wrong arity
            ("List", "int", "str"),  # wrong arity
            ("Dict", "str"),  # wrong arity
            ("Optional", "None"),  # Optional[None]
            ("Union", "int"),  # arity < 2
            ("Union", "int", "int"),  # duplicates
            ("Union", "Any", "int"),  # Any in union
            ("Tuple",),  # empty tuple
            ["int"],  # list is not a type expression
            42,  # not str/tuple
        ]
        for i, texpr in enumerate(bad):
            with self.assertRaises(BadTypeError, msg=f"case {i}: {texpr!r}"):
                tc.declare_signature(
                    f"s-{i}", "f", (("x", texpr),), "None", i + 1
                )

    def test_declare_duplicate_param_refused(self):
        tc = TypeCheckerIface()
        with self.assertRaises(BadSignatureError):
            tc.declare_signature(
                "s", "f", (("x", "int"), ("x", "str")), "None", 1
            )

    def test_declare_unknown_sig(self):
        tc = TypeCheckerIface()
        with self.assertRaises(UnknownSignatureError):
            tc.signature("nope")

    def test_declare_seq_order(self):
        tc = TypeCheckerIface()
        tc.declare_signature("s", "f", (), "None", 1)
        with self.assertRaises(SeqOrderError):
            tc.declare_signature("t", "f", (), "None", 1)
        with self.assertRaises(SeqOrderError):
            tc.declare_signature("t", "f", (), "None", True)


class TestCheck(unittest.TestCase):
    def _tc(self):
        tc = TypeCheckerIface()
        tc.declare_signature(
            "sig-1",
            "greet",
            (("name", "str"), ("count", "int")),
            "str",
            1,
        )
        return tc

    def test_check_ok(self):
        tc = self._tc()
        rep = tc.check("sig-1", {"name": "str", "count": "int"}, 2)
        self.assertIsInstance(rep, CheckReport)
        self.assertTrue(rep.ok)
        self.assertEqual(rep.diagnostics, ())
        self.assertTrue(rep.pin.startswith("sha256:"))
        self.assertEqual(tc.errors(), ())

    def test_check_arg_type_mismatch_is_data(self):
        tc = self._tc()
        rep = tc.check("sig-1", {"name": "int", "count": "int"}, 2)
        self.assertFalse(rep.ok)
        self.assertEqual(len(rep.diagnostics), 1)
        d = rep.diagnostics[0]
        self.assertIsInstance(d, TypeDiagnostic)
        self.assertEqual(d.code, "arg-type")
        self.assertEqual(d.param, "name")
        self.assertEqual(d.expected, "str")
        self.assertEqual(d.got, "int")
        self.assertTrue(d.pin.startswith("sha256:"))
        # ledgers the diagnostic
        self.assertEqual(len(tc.errors()), 1)
        self.assertEqual(tc.errors()[0].pin, d.pin)

    def test_check_missing_arg(self):
        tc = self._tc()
        rep = tc.check("sig-1", {"name": "str"}, 2)
        self.assertFalse(rep.ok)
        self.assertEqual(rep.diagnostics[0].code, "call-arg")
        self.assertIn("count", rep.diagnostics[0].message)

    def test_check_unexpected_arg(self):
        tc = self._tc()
        rep = tc.check("sig-1", {"name": "str", "count": "int", "x": "str"}, 2)
        self.assertFalse(rep.ok)
        self.assertEqual(rep.diagnostics[0].code, "call-arg")
        self.assertIn("x", rep.diagnostics[0].message)

    def test_check_numeric_tower(self):
        tc = TypeCheckerIface()
        tc.declare_signature("s", "f", (("x", "int"), ("y", "float")), "None", 1)
        rep = tc.check("s", {"x": "bool", "y": "int"}, 2)
        self.assertTrue(rep.ok)  # bool <: int, int <: float

    def test_check_any_silent_non_strict(self):
        tc = self._tc()
        rep = tc.check("sig-1", {"name": "Any", "count": "int"}, 2)
        self.assertTrue(rep.ok)

    def test_check_optional_union(self):
        tc = TypeCheckerIface()
        tc.declare_signature(
            "s", "f", (("a", ("Optional", "str")), ("b", ("Union", "int", "str"))), "None", 1
        )
        rep = tc.check("s", {"a": "None", "b": "int"}, 2)
        self.assertTrue(rep.ok)
        rep2 = tc.check("s", {"a": "bytes", "b": "float"}, 3)
        self.assertFalse(rep2.ok)
        self.assertEqual(len(rep2.diagnostics), 2)

    def test_check_list_invariant(self):
        tc = TypeCheckerIface()
        tc.declare_signature("s", "f", (("xs", ("List", "int")),), "None", 1)
        ok = tc.check("s", {"xs": ("List", "int")}, 2)
        self.assertTrue(ok.ok)
        bad = tc.check("s", {"xs": ("List", "str")}, 3)
        self.assertFalse(bad.ok)
        any_ok = tc.check("s", {"xs": ("List", "Any")}, 4)
        self.assertTrue(any_ok.ok)  # Any matches under invariance

    def test_check_tuple_positional(self):
        tc = TypeCheckerIface()
        tc.declare_signature(
            "s", "f", (("t", ("Tuple", "int", "str")),), "None", 1
        )
        ok = tc.check("s", {"t": ("Tuple", "bool", "str")}, 2)
        self.assertTrue(ok.ok)  # bool <: int per-position
        bad = tc.check("s", {"t": ("Tuple", "int",)}, 3)
        self.assertFalse(bad.ok)  # arity mismatch
        bad2 = tc.check("s", {"t": ("Tuple", "str", "int")}, 4)
        self.assertFalse(bad2.ok)

    def test_check_report_pin_determinism(self):
        t1 = self._tc()
        t2 = self._tc()
        r1 = t1.check("sig-1", {"name": "str", "count": "int"}, 2)
        r2 = t2.check("sig-1", {"name": "str", "count": "int"}, 2)
        self.assertEqual(r1.pin, r2.pin)

    def test_check_bad_args_refused(self):
        tc = self._tc()
        with self.assertRaises(BadArgumentError):
            tc.check("sig-1", [("name", "str")], 2)  # not a mapping
        with self.assertRaises(BadTypeError):
            tc.check("sig-1", {"name": "Integer", "count": "int"}, 3)
        with self.assertRaises(UnknownSignatureError):
            tc.check("nope", {"name": "str"}, 4)

    def test_check_seq_order_and_failed_consumes(self):
        tc = self._tc()
        with self.assertRaises(SeqOrderError):
            tc.check("sig-1", {"name": "str", "count": "int"}, 1)
        # failed mutation consumed seq 1... last claimed is 1, so seq 1 refused again
        with self.assertRaises(SeqOrderError):
            tc.check("sig-1", {"name": "str", "count": "int"}, 1)
        rep = tc.check("sig-1", {"name": "str", "count": "int"}, 2)
        self.assertTrue(rep.ok)


class TestStrict(unittest.TestCase):
    def test_strict_any_diagnostic(self):
        tc = TypeCheckerIface()
        tc.declare_signature("s", "f", (("v", "str"),), "None", 1)
        rec = tc.strict(2)
        self.assertIsInstance(rec, StrictRecord)
        self.assertTrue(rec.enabled)
        self.assertTrue(tc.is_strict())
        self.assertTrue(rec.pin.startswith("sha256:"))
        rep = tc.check("s", {"v": "Any"}, 3)
        self.assertFalse(rep.ok)
        self.assertEqual(rep.diagnostics[0].code, "any-expr")

    def test_strict_relax(self):
        tc = TypeCheckerIface()
        tc.declare_signature("s", "f", (("v", "str"),), "None", 1)
        tc.strict(2)
        tc.strict(3, enabled=False)
        self.assertFalse(tc.is_strict())
        rep = tc.check("s", {"v": "Any"}, 4)
        self.assertTrue(rep.ok)

    def test_strict_default_off(self):
        tc = TypeCheckerIface()
        self.assertFalse(tc.is_strict())

    def test_strict_bad_enabled(self):
        tc = TypeCheckerIface()
        with self.assertRaises(TypeIfaceError):
            tc.strict(1, enabled="yes")


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("declared", "checked", "errors-read", "strict-set", "rejected"):
            evt = type_checker_iface_audit_event(kind, 1, detail="d")
            self.assertEqual(evt["kind"], kind)
            self.assertEqual(evt["seq"], 1)
            self.assertEqual(evt["module"], TYPE_CHECKER_IFACE_VERSION)
            self.assertEqual(evt["schema"], SCHEMA_PIN)

    def test_audit_bad_kind(self):
        with self.assertRaises(TypeIfaceError):
            type_checker_iface_audit_event("nope", 1)

    def test_audit_bad_seq(self):
        with self.assertRaises(TypeIfaceError):
            type_checker_iface_audit_event("checked", 0)


class TestMain(unittest.TestCase):
    def test_main(self):
        import type_checker_iface as m

        m.main()


if __name__ == "__main__":
    unittest.main()
