"""Targeted tests for the provenance attestation ledger."""

import ast
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

MODULE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(MODULE_DIR))

import provenance as prov_mod  # noqa: E402
from provenance import Provenance  # noqa: E402


def _digest(text):
    return prov_mod._digest_pin({"t": text})


def test_version_and_schema_pins():
    assert prov_mod.VERSION == "provenance.v1"
    assert prov_mod.SCHEMA == "northstar.provenance.v1"


def test_stdlib_only_ast():
    src = (MODULE_DIR / "provenance.py").read_text()
    tree = ast.parse(src)
    allowed = {"__future__", "dataclasses", "hashlib", "json", "re",
               "threading", "typing", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_attest_roundtrip_and_verify_record():
    p = Provenance()
    d = _digest("asset-a")
    rec = p.attest("asset-a", d, 0, generator="capture-tool")
    assert rec.content_id == "asset-a"
    assert rec.subject_digest == d
    assert rec.generator == "capture-tool"
    assert rec.ingredients == ()
    assert rec.verify()
    assert rec.as_dict()["schema"] == prov_mod.SCHEMA
    assert p.attestation_record("asset-a", 1) is rec


def test_attest_duplicate_and_bad_inputs_seq_burn():
    p = Provenance()
    p.attest("ok", _digest("x"), 0)
    bad = [
        ("ok", _digest("y")),  # duplicate
        ("", _digest("y")),  # empty id
        ("bad id", _digest("y")),  # whitespace
        ("a" * 257, _digest("y")),  # too long
        (123, _digest("y")),  # non-str id
        (True, _digest("y")),  # bool id
        ("x1", "not-a-digest"),  # bad digest
        ("x2", "md5:" + "ab" * 16),  # bad digest scheme
        ("x3", None),  # non-str digest
    ]
    seq = 1
    for cid, digest in bad:
        with pytest.raises(prov_mod.ProvenanceError):
            p.attest(cid, digest, seq)
        seq += 1
    # failed mutations burned their seqs: rejected rows booked
    audit = p.audit_log(seq)
    rejected = [r for r in audit if r["kind"] == "provenance.rejected"]
    assert len(rejected) == len(bad)
    # next seq continues after the burns
    rec = p.attest("fresh", _digest("z"), seq)
    assert rec.content_id == "fresh"


def test_attest_unknown_ingredient_refused():
    p = Provenance()
    p.attest("base", _digest("b"), 0)
    with pytest.raises(prov_mod.UnknownIngredientError):
        p.attest("child", _digest("c"), 1, ingredients=("ghost",))
    # base alone was attested, ghost never was
    assert p.content_ids(2) == ("base",)


def test_attest_self_and_duplicate_ingredients_refused():
    p = Provenance()
    p.attest("a", _digest("a"), 0)
    with pytest.raises(prov_mod.BadIngredientError):
        p.attest("b", _digest("b"), 1, ingredients=("a", "a"))
    with pytest.raises(prov_mod.BadIngredientError):
        p.attest("self", _digest("s"), 2, ingredients=("self",))
    with pytest.raises(prov_mod.BadIngredientError):
        p.attest("c", _digest("c"), 3, ingredients="a")


def test_verify_ok_and_determinism():
    p = Provenance()
    p.attest("base", _digest("b"), 0, generator="cap")
    p.attest("mid", _digest("m"), 1, generator="edit",
             ingredients=("base",))
    r1 = p.verify("mid", 2)
    assert r1.ok is True
    assert r1.problems == ()
    assert r1.as_dict()["schema"] == prov_mod.SCHEMA
    # cross-instance determinism
    q = Provenance()
    q.attest("base", _digest("b"), 0, generator="cap")
    q.attest("mid", _digest("m"), 1, generator="edit",
             ingredients=("base",))
    r2 = q.verify("mid", 2)
    assert r1.digest == r2.digest


def test_verify_tamper_is_data():
    p = Provenance()
    p.attest("base", _digest("b"), 0)
    p.attest("mid", _digest("m"), 1, ingredients=("base",))
    rec = p.attestation_record("mid", 2)
    object.__setattr__(rec, "digest", "sha256:" + "0" * 64)
    report = p.verify("mid", 3)
    assert report.ok is False
    assert "tamper:mid" in report.problems


def test_verify_unknown_refused():
    p = Provenance()
    with pytest.raises(prov_mod.UnknownContentError):
        p.verify("nope", 0)
    # unknown read consumes nothing
    p.attest("a", _digest("a"), 0)


def test_trace_closure_and_max_depth():
    p = Provenance()
    p.attest("a", _digest("a"), 0)
    p.attest("b", _digest("b"), 1, ingredients=("a",))
    p.attest("c", _digest("c"), 2, ingredients=("b",))
    t = p.trace("c", 3)
    assert t.ancestors == ("a", "b")
    assert t.depth_reached == 2
    assert t.as_dict()["schema"] == prov_mod.SCHEMA
    shallow = p.trace("c", 4, max_depth=1)
    assert shallow.ancestors == ("b",)
    assert shallow.depth_reached == 1


def test_trace_unknown_as_data_and_bad_depth():
    p = Provenance()
    t = p.trace("ghost", 0)
    assert t.ancestors == ()
    assert t.depth_reached == 0
    with pytest.raises(prov_mod.BadDepthError):
        p.trace("ghost", 1, max_depth=0)
    with pytest.raises(prov_mod.BadDepthError):
        p.trace("ghost", 1, max_depth=True)


def test_seq_discipline():
    p = Provenance()
    p.attest("a", _digest("a"), 0)
    # rewind raises bare without consuming
    with pytest.raises(prov_mod.SeqOrderError):
        p.attest("b", _digest("b"), 0)
    p.attest("b", _digest("b"), 1)
    # malformed seqs
    for bad in (True, "1", 1.5, None, -1):
        with pytest.raises(prov_mod.SeqOrderError):
            p.trace("a", bad)
    # failed mutation consumes seq
    with pytest.raises(prov_mod.BadDigestError):
        p.attest("c", "junk", 2)
    with pytest.raises(prov_mod.SeqOrderError):
        p.attest("c", _digest("c"), 2)
    p.attest("c", _digest("c"), 3)


def test_view_read_purity():
    p = Provenance()
    p.attest("a", _digest("a"), 0)
    before = p.audit_log(1)
    t1 = p.trace("a", 1)
    t2 = p.trace("a", 1)  # same seq reuse is legal for reads
    v = p.verify("a", 1)
    assert t1.digest == t2.digest
    assert v.ok
    assert p.audit_log(2) == before  # no audit rows from reads
    assert p.stats(3)["audit_count"] == 1
    assert p.content_ids(4) == ("a",)


def test_audit_shapes_leak_ban_bad_kind():
    p = Provenance()
    p.attest("a", _digest("a"), 0, generator="gen")
    audit = p.audit_log(1)
    assert len(audit) == 1
    row = audit[0]
    assert row["audit_version"] == "audit.ndjson/1"
    assert row["kind"] == "provenance.attested"
    assert row["detail"]["content_id"] == "a"
    assert row["seq"] == 0
    # banned keys cannot cross the audit boundary
    with pytest.raises(prov_mod.AuditKindError):
        prov_mod.provenance_audit_event("attested", {"subject": "x"}, 5)
    with pytest.raises(prov_mod.AuditKindError):
        prov_mod.provenance_audit_event("attested", {"text": "x"}, 5)
    # unknown kind
    with pytest.raises(prov_mod.AuditKindError):
        prov_mod.provenance_audit_event("bogus", {}, 5)


def test_main_subprocess_and_concurrency():
    result = subprocess.run(
        [sys.executable, str(MODULE_DIR / "provenance.py")],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "provenance OK: attest, verify, trace, pins, audit" in result.stdout
    # standalone import from a bare temp dir (no repo on sys.path)
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy(str(MODULE_DIR / "provenance.py"), tmp)
        code = ("import sys; sys.path.insert(0, %r);"
                " import provenance as m;"
                " p = m.Provenance();"
                " d = m._digest_pin({'t': 'x'});"
                " p.attest('x', d, 0);"
                " assert p.verify('x', 1).ok;"
                " print('standalone OK')" % tmp)
        r2 = subprocess.run([sys.executable, "-c", code],
                            capture_output=True, text=True, timeout=60)
        assert r2.returncode == 0, r2.stderr
        assert "standalone OK" in r2.stdout
    # concurrent reads stay deterministic
    p = Provenance()
    p.attest("a", _digest("a"), 0)
    p.attest("b", _digest("b"), 1, ingredients=("a",))
    digests = []
    def reader():
        digests.append(p.trace("b", 2).digest)
    threads = [threading.Thread(target=reader) for _ in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert len(set(digests)) == 1
    # frozen records
    rec = p.attestation_record("a", 3)
    with pytest.raises(Exception):
        rec.digest = "sha256:" + "1" * 64
