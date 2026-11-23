"""Tests for conformity.py: register/assess/declare/affix decision ledger (simulated)."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "conformity.py"


def _load():
    spec = importlib.util.spec_from_file_location("conformity", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["conformity"] = module  # frozen dataclasses need a registered module
    spec.loader.exec_module(module)
    return module


cf = _load()

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32
BAD_DIGESTS = ["sha256:xyz", "ab" * 32, "sha256:" + "zz" * 32, "SHA256:" + "ab" * 32, None, 123]


def _fresh():
    return cf.Conformity()


# 1 -- pins ---------------------------------------------------------------


def test_version_and_schema_pins():
    assert cf.CONFORMITY_VERSION == "conformity.v1"
    assert cf.CONFORMITY_SCHEMA == "northstar.conformity.v1"
    assert cf.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(cf.PRODUCT_CLASSES) == {
        "general", "machinery", "electrical", "radio", "medical-device",
        "toy", "pressure-equipment", "construction",
    }
    assert set(cf.ASSESSMENT_MODULES) == {
        "a", "a1", "a2", "b", "c", "c1", "c2", "d", "d1", "e", "e1",
        "f", "f1", "g", "h", "h1",
    }
    assert set(cf.VERDICTS) == {"conformant", "non-conformant", "conditional"}
    assert set(cf.MARKS) == {"ce", "ukca", "ce-ukca"}


# 2 -- stdlib only --------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "__future__",
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            assert mod in allowed or mod == "canonical_json", node.module


# 3 -- register roundtrip --------------------------------------------------


def test_register_product_roundtrip():
    c = _fresh()
    rec = c.register_product("p1", 1, product_class="machinery", product_digest=DIGEST)
    assert rec.product_id == "p1"
    assert rec.product_class == "machinery"
    assert rec.verify()
    assert rec.as_dict()["version"] == "conformity.v1"
    assert c.product_record("p1", 2) is rec
    assert c.product_ids(3) == ("p1",)


def test_register_duplicate_and_bad_inputs():
    c = _fresh()
    c.register_product("p1", 1)
    n_rejected = 0
    with pytest.raises(cf.DuplicateProductError):
        c.register_product("p1", 2)
    n_rejected += 1
    cases = [
        ("", 3), ("  ", 4), ("a b", 5), (None, 6), (123, 7),
        ("x" * 129, 8),
    ]
    for pid, sq in cases:
        with pytest.raises(cf.BadIdError):
            c.register_product(pid, sq)
        n_rejected += 1
    for sq, (kwargs) in enumerate(
        ({"product_class": "spaceship"}, {"product_digest": "nope"}, {"product_digest": "sha256:zz" + "00" * 31}), start=9
    ):
        with pytest.raises(cf.ConformityError):
            c.register_product(f"px{sq}", sq, **kwargs)
        n_rejected += 1
    assert c.stats(100)["rejected"] == n_rejected


# 4 -- assess roundtrip + vocabulary ---------------------------------------


def test_assess_roundtrip_and_minted_ids():
    c = _fresh()
    c.register_product("p1", 1)
    a1 = c.assess("p1", 2, module="b", verdict="conformant", standard_digest=DIGEST)
    a2 = c.assess("p1", 3, module="c2", verdict="non-conformant")
    assert a1.assessment_id == "asm-1"
    assert a2.assessment_id == "asm-2"
    assert a1.verify() and a2.verify()
    assert c.assessments_for("p1", 4) == ("asm-1", "asm-2")
    assert c.assessment_record("asm-1", 5) is a1


def test_assess_bad_inputs_seq_burn():
    c = _fresh()
    c.register_product("p1", 1)
    n_rejected = 0
    with pytest.raises(cf.UnknownProductError):
        c.assess("ghost", 2)
    n_rejected += 1
    for kw, sq in (
        ({"module": "z"}, 3),
        ({"verdict": "maybe"}, 4),
        ({"standard_digest": "nope"}, 5),
    ):
        with pytest.raises(cf.ConformityError):
            c.assess("p1", sq, **kw)
        n_rejected += 1
    assert c.stats(100)["rejected"] == n_rejected
    # seq was consumed by each failure (claim-then-burn): next valid call must use 6
    a = c.assess("p1", 6, module="a", verdict="conditional")
    assert a.assessment_id == "asm-1"


def test_assess_full_vocabulary():
    c = _fresh()
    c.register_product("p1", 1)
    sq = 2
    for mod in cf.ASSESSMENT_MODULES:
        for verdict in cf.VERDICTS:
            c.assess("p1", sq, module=mod, verdict=verdict)
            sq += 1
    assert c.stats(sq)["assessments"] == len(cf.ASSESSMENT_MODULES) * len(cf.VERDICTS)


# 5 -- declare gating ------------------------------------------------------


def test_declare_roundtrip():
    c = _fresh()
    c.register_product("p1", 1)
    c.assess("p1", 2, module="a", verdict="conformant")
    d = c.declare("p1", 3, declaration_digest=DIGEST)
    assert d.declaration_id == "doc-1"
    assert d.verify()
    assert c.declaration_record("doc-1", 4) is d
    assert c.declared_ids(5) == ("p1",)


def test_declare_gating_failures():
    c = _fresh()
    c.register_product("p1", 1)
    n_rejected = 0
    with pytest.raises(cf.UnknownProductError):
        c.declare("ghost", 2)
    n_rejected += 1
    # non-conformant only -> refused
    c.assess("p1", 3, module="a", verdict="non-conformant")
    with pytest.raises(cf.NotConformantError):
        c.declare("p1", 4)
    n_rejected += 1
    # conditional only -> refused
    c.assess("p1", 5, module="b", verdict="conditional")
    with pytest.raises(cf.NotConformantError):
        c.declare("p1", 6)
    n_rejected += 1
    # once conformant -> ok, twice -> refused
    c.assess("p1", 7, module="c", verdict="conformant")
    c.declare("p1", 8)
    with pytest.raises(cf.AlreadyDeclaredError):
        c.declare("p1", 9)
    n_rejected += 1
    # bad digest on a conformant, undeclared product
    c.register_product("p2", 10)
    c.assess("p2", 11, module="a", verdict="conformant")
    with pytest.raises(cf.BadDigestError):
        c.declare("p2", 12, declaration_digest="nope")
    n_rejected += 1
    assert c.stats(100)["rejected"] == n_rejected


# 6 -- affix gating --------------------------------------------------------


def test_affix_roundtrip_and_marks():
    c = _fresh()
    c.register_product("p1", 1)
    c.assess("p1", 2, module="g", verdict="conformant")
    c.declare("p1", 3)
    a = c.affix("p1", 4, mark="ce-ukca")
    assert a.affix_id == "aff-1"
    assert a.mark == "ce-ukca"
    assert a.verify()
    assert c.affix_record("aff-1", 5) is a
    assert c.affixed_ids(6) == ("p1",)


def test_affix_gating_failures():
    c = _fresh()
    c.register_product("p1", 1)
    c.register_product("p2", 2)
    c.assess("p1", 3, module="a", verdict="conformant")
    c.assess("p2", 4, module="a", verdict="conformant")
    c.declare("p2", 5)
    n_rejected = 0
    # no declaration -> refused
    with pytest.raises(cf.NotDeclaredError):
        c.affix("p1", 6)
    n_rejected += 1
    # ok on declared product
    c.affix("p2", 7, mark="ce")
    with pytest.raises(cf.AlreadyAffixedError):
        c.affix("p2", 8)
    n_rejected += 1
    # bad mark on a declared, unaffixed product
    c.register_product("p3", 9)
    c.assess("p3", 10, module="a", verdict="conformant")
    c.declare("p3", 11)
    with pytest.raises(cf.BadMarkError):
        c.affix("p3", 12, mark="ce-plus")
    n_rejected += 1
    with pytest.raises(cf.UnknownProductError):
        c.affix("ghost", 13)
    n_rejected += 1
    assert c.stats(100)["rejected"] == n_rejected


# 7 -- seq discipline -------------------------------------------------------


def test_seq_discipline_rewind_bare():
    c = _fresh()
    c.register_product("p1", 1)
    with pytest.raises(cf.SeqOrderError):
        c.register_product("p2", 1)  # rewind: bare, no rejected row
    with pytest.raises(cf.SeqOrderError):
        c.assess("p1", 1)
    for bad in (0, -1, True, "2", 2.0, None):
        with pytest.raises(cf.SeqOrderError):
            c.register_product("p3", bad)
    assert c.stats(100)["rejected"] == 0
    # seq 1 still claimed; seq 2 is free
    c.register_product("p2", 2)
    assert c.stats(100)["products"] == 2


# 8 -- view read purity -----------------------------------------------------


def test_view_read_purity():
    c = _fresh()
    c.register_product("p1", 1)
    c.assess("p1", 2, module="a", verdict="conformant")
    c.declare("p1", 3)
    c.affix("p1", 4, mark="ce")
    n_audit = len(c.audit_log(5))
    # same-seq reads: no seq consumption, no audit rows
    for _ in range(3):
        assert c.stats(5)["products"] == 1
        assert c.product_ids(5) == ("p1",)
        assert c.assessments_for("p1", 5) == ("asm-1",)
        assert c.declared_ids(5) == ("p1",)
        assert c.affixed_ids(5) == ("p1",)
    assert len(c.audit_log(5)) == n_audit
    assert c.stats(5)["rejected"] == 0
    # unknown lookups raise (they validate first, never mutate)
    with pytest.raises(cf.UnknownProductError):
        c.product_record("ghost", 5)
    with pytest.raises(cf.UnknownAssessmentError):
        c.assessment_record("asm-99", 5)


# 9 -- audit shapes + leak ban + bad-kind -----------------------------------


def test_audit_shapes_leak_ban_bad_kind():
    c = _fresh()
    c.register_product("p1", 1, product_digest=DIGEST)
    c.assess("p1", 2, module="b", verdict="conformant", standard_digest=DIGEST2)
    c.declare("p1", 3, declaration_digest=DIGEST)
    c.affix("p1", 4, mark="ukca")
    log = c.audit_log(5)
    kinds = [e["kind"] for e in log]
    assert kinds == [
        "conformity.product-registered",
        "conformity.assessed",
        "conformity.declared",
        "conformity.affixed",
    ]
    for e in log:
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "northstar.conformity.v1"
        # raw material never crosses the audit boundary
        for key in e["detail"]:
            assert key not in (
                "declaration", "product", "description", "serial",
                "notified-body", "report", "certificate", "text",
            )
    # leak ban enforced at the builder level
    with pytest.raises(cf.AuditKindError):
        cf.conformity_audit_event("conformity.declared", 6, declaration="secret text")
    with pytest.raises(cf.AuditKindError):
        cf.conformity_audit_event("bogus.kind", 6)


# 10 -- cross-instance determinism + tamper ----------------------------------


def test_cross_instance_digest_determinism_and_tamper():
    c1, c2 = _fresh(), _fresh()
    r1 = c1.register_product("p1", 1, product_class="radio", product_digest=DIGEST)
    r2 = c2.register_product("p1", 1, product_class="radio", product_digest=DIGEST)
    assert r1.digest == r2.digest
    a1 = c1.assess("p1", 2, module="h", verdict="conformant")
    a2 = c2.assess("p1", 2, module="h", verdict="conformant")
    assert a1.digest == a2.digest
    # tamper is reported as data, never raised
    object.__setattr__(r1, "product_class", "toy")
    assert r1.verify() is False


# 11 -- frozen-ness + concurrency smoke --------------------------------------


def test_frozen_records_and_thread_reads():
    c = _fresh()
    rec = c.register_product("p1", 1)
    with pytest.raises(Exception):
        rec.product_id = "evil"  # frozen dataclass
    c.assess("p1", 2, module="a", verdict="conformant")
    c.declare("p1", 3)
    c.affix("p1", 4, mark="ce")
    errors = []

    def reader():
        try:
            for _ in range(50):
                c.stats(4)
                c.product_ids(4)
                c.assessments_for("p1", 4)
                c.declared_ids(4)
                c.affixed_ids(4)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 12 -- stats ----------------------------------------------------------------


def test_stats_counts():
    c = _fresh()
    c.register_product("p1", 1)
    c.register_product("p2", 2)
    c.assess("p1", 3, module="a", verdict="conformant")
    c.assess("p1", 4, module="b", verdict="non-conformant")
    c.declare("p1", 5)
    c.affix("p1", 6, mark="ce")
    assert c.stats(7) == {
        "products": 2,
        "assessments": 2,
        "declarations": 1,
        "affixes": 1,
        "rejected": 0,
    }


# 13 -- end-to-end lifecycle --------------------------------------------------


def test_end_to_end_lifecycle():
    c = _fresh()
    for i, pclass in enumerate(("machinery", "toy", "electrical")):
        pid = f"p{i}"
        sq = i * 5 + 1
        c.register_product(pid, sq, product_class=pclass)
        c.assess(pid, sq + 1, module="b", verdict="conformant")
        c.declare(pid, sq + 2)
        c.affix(pid, sq + 3, mark="ce")
    assert c.stats(i * 5 + 5)["products"] == 3
    assert c.stats(i * 5 + 5)["affixes"] == 3


# 14 -- all marks + product classes --------------------------------------------


def test_all_marks_and_classes():
    c = _fresh()
    sq = 1
    for pclass in cf.PRODUCT_CLASSES:
        pid = f"p-{pclass}"
        c.register_product(pid, sq, product_class=pclass)
        sq += 1
        c.assess(pid, sq, module="d", verdict="conformant")
        sq += 1
        c.declare(pid, sq)
        sq += 1
        mark = cf.MARKS[sq % len(cf.MARKS)]
        c.affix(pid, sq, mark=mark)
        sq += 1
        assert c.affix_record(f"aff-{len(c.affixed_ids(1))}", 1).mark == mark


# 15 -- main() self-check ------------------------------------------------------


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        cwd=str(HERE.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert "conformity OK: register, assess, declare, affix, pins, audit" in proc.stdout
