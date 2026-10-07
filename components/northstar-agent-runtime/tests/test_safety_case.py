"""Tests for safety_case: claim/evidence/argument decision ledger."""

import ast
import subprocess
import sys

import pytest

import safety_case as scm
from safety_case import SafetyCase


def _module_path():
    return scm.__file__


def _digest(tag):
    return "sha256:" + tag * 64


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert scm.SAFETY_CASE_VERSION == "safety-case.v1"
    assert scm.SAFETY_CASE_SCHEMA == "northstar.safety-case.v1"
    assert scm.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "__future__",
        "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# claim
# ---------------------------------------------------------------------------


def test_claim_roundtrip_and_digest():
    sc = SafetyCase()
    rec = sc.claim("top", _digest("a"), 1)
    assert rec.claim_id == "top"
    assert rec.parent_id == ""
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("top", "", _digest("a"))
    assert not rec.verify("top", "", _digest("b"))
    assert sc.claim_record("top") == rec
    assert sc.claim_record("nope") is None
    assert sc.claim_ids() == ("top",)
    # frozen records
    with pytest.raises(Exception):
        rec.claim_id = "x"


def test_claim_duplicate_and_bad_inputs_consume_seq_and_audit_rejected():
    sc = SafetyCase()
    sc.claim("a1", _digest("a"), 1)
    with pytest.raises(scm.DuplicateClaimError):
        sc.claim("a1", _digest("a"), 2)
    with pytest.raises(scm.BadClaimError):
        sc.claim("", _digest("a"), 3)
    with pytest.raises(scm.BadClaimError):
        sc.claim("has space", _digest("a"), 4)
    with pytest.raises(scm.BadClaimError):
        sc.claim("x" * 257, _digest("a"), 5)
    with pytest.raises(scm.BadDigestError):
        sc.claim("a2", "not-a-pin", 6)
    with pytest.raises(scm.SeqOrderError):
        sc.claim("a3", _digest("a"), 6)  # rewind: bare
    kinds = [r["kind"] for r in sc.audit_log()]
    assert kinds.count("rejected") == 5
    assert len(sc.audit_log()) == 1 + 5


def test_claim_decomposition_tree_and_parent_rules():
    sc = SafetyCase()
    sc.claim("top", _digest("a"), 1)
    sc.claim("c1", _digest("b"), 2, parent_id="top")
    sc.claim("c2", _digest("b"), 3, parent_id="top")
    assert sc.children_of("top") == ("c1", "c2")
    assert sc.children_of("c1") == ()
    # unknown parent refused, consumes seq
    with pytest.raises(scm.UnknownClaimError):
        sc.claim("c3", _digest("b"), 4, parent_id="ghost")
    # retired parent refused
    sc.retire("c1", 5)
    with pytest.raises(scm.RetiredClaimError):
        sc.claim("c4", _digest("b"), 6, parent_id="c1")
    # parent cannot be itself (not yet declared -> unknown)
    with pytest.raises(scm.UnknownClaimError):
        sc.claim("c5", _digest("b"), 7, parent_id="c5")


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------


def test_evidence_roundtrip_and_digest():
    sc = SafetyCase()
    sc.claim("top", _digest("a"), 1)
    rec = sc.evidence("top", "test-1", 2, evidence_digest=_digest("c"),
                      kind="test")
    assert rec.binding_id == "ev-1"
    assert rec.claim_id == "top"
    assert rec.kind == "test"
    assert rec.verify("ev-1", "top", "test-1", "test", _digest("c"))
    assert not rec.verify("ev-1", "top", "test-1", "test", _digest("d"))
    assert sc.evidence_record("ev-1") == rec
    assert sc.evidence_for("top") == ("ev-1",)
    # empty evidence digest = pending evidence, allowed
    rec2 = sc.evidence("top", "test-2", 3, kind="eval")
    assert rec2.evidence_digest == ""
    assert rec2.verify("ev-2", "top", "test-2", "eval", "")


def test_evidence_bad_inputs_consume_seq_and_audit_rejected():
    sc = SafetyCase()
    sc.claim("top", _digest("a"), 1)
    sc.evidence("top", "t1", 2, evidence_digest=_digest("c"))
    with pytest.raises(scm.DuplicateEvidenceError):
        sc.evidence("top", "t1", 3, evidence_digest=_digest("c"))
    with pytest.raises(scm.UnknownClaimError):
        sc.evidence("ghost", "t2", 4, evidence_digest=_digest("c"))
    with pytest.raises(scm.BadEvidenceError):
        sc.evidence("top", "", 5, evidence_digest=_digest("c"))
    with pytest.raises(scm.BadEvidenceKindError):
        sc.evidence("top", "t3", 6, kind="hallucination")
    with pytest.raises(scm.BadDigestError):
        sc.evidence("top", "t4", 7, evidence_digest="raw-text")
    sc.retire("top", 8)
    with pytest.raises(scm.RetiredClaimError):
        sc.evidence("top", "t5", 9, evidence_digest=_digest("c"))
    kinds = [r["kind"] for r in sc.audit_log()]
    assert kinds.count("rejected") == 6
    assert kinds.count("evidence-bound") == 1


def test_evidence_kinds_accepted():
    sc = SafetyCase()
    sc.claim("top", _digest("a"), 1)
    for i, kind in enumerate(scm.EVIDENCE_KINDS):
        rec = sc.evidence("top", f"e{i}", i + 2,
                          evidence_digest=_digest("c"), kind=kind)
        assert rec.kind == kind
    assert len(sc.evidence_for("top")) == 6


# ---------------------------------------------------------------------------
# retire
# ---------------------------------------------------------------------------


def test_retire_terminality_and_id_non_recycling():
    sc = SafetyCase()
    sc.claim("top", _digest("a"), 1)
    rec = sc.retire("top", 2, reason="invalidated")
    assert rec.verify("top", "invalidated")
    assert sc.retired_ids() == ("top",)
    with pytest.raises(scm.RetiredClaimError):
        sc.retire("top", 3)
    with pytest.raises(scm.RetiredClaimError):
        sc.claim("top", _digest("a"), 4)
    with pytest.raises(scm.BadReasonError):
        sc.retire("top", 5, reason="vibes")  # bad reason also refused
    with pytest.raises(scm.UnknownClaimError):
        sc.retire("ghost", 6)
    st = sc.stats()
    assert (st.claims, st.evidence_bindings, st.retired) == (1, 0, 1)


# ---------------------------------------------------------------------------
# argue
# ---------------------------------------------------------------------------


def test_argue_leaf_supported_and_open():
    sc = SafetyCase()
    sc.claim("leaf-e", _digest("a"), 1)
    sc.claim("leaf-o", _digest("a"), 2)
    sc.evidence("leaf-e", "t1", 3, evidence_digest=_digest("c"))
    rep_e = sc.argue("leaf-e", 3)
    assert rep_e.verdict == "supported"
    assert rep_e.evidence_count == 1
    assert rep_e.child_ids == ()
    assert rep_e.verify("leaf-e", "supported", 1, (), ())
    rep_o = sc.argue("leaf-o", 3)
    assert rep_o.verdict == "open"
    assert rep_o.evidence_count == 0


def test_argue_decomposition_supported_partial():
    sc = SafetyCase()
    sc.claim("top", _digest("a"), 1)
    sc.claim("c1", _digest("b"), 2, parent_id="top")
    sc.claim("c2", _digest("b"), 3, parent_id="top")
    sc.evidence("c1", "t1", 4, evidence_digest=_digest("c"))
    mid = sc.argue("top", 4)
    assert mid.verdict == "partial"
    assert mid.child_ids == ("c1", "c2")
    assert mid.child_verdicts == ("supported", "open")
    assert mid.verify("top", "partial", 0, ("c1", "c2"),
                      ("supported", "open"))
    sc.evidence("c2", "t2", 5, evidence_digest=_digest("c"))
    full = sc.argue("top", 5)
    assert full.verdict == "supported"
    assert not full.verify("top", "supported", 0, ("c1", "c2"),
                           ("supported", "partial"))


def test_argue_pure_read_and_unknown_and_retired():
    sc = SafetyCase()
    sc.claim("top", _digest("a"), 1)
    n_audit = len(sc.audit_log())
    r1 = sc.argue("top", 1)  # same seq as the claim: pure read
    r2 = sc.argue("top", 1)
    assert r1 == r2
    assert len(sc.audit_log()) == n_audit  # no audit rows for reads
    # mutation seqs still advance normally after reads
    sc.evidence("top", "t1", 2, evidence_digest=_digest("c"))
    rep = sc.argue("top", 2)
    assert rep.verdict == "supported"
    with pytest.raises(scm.UnknownClaimError):
        sc.argue("ghost", 2)  # raises, no seq to consume
    sc.retire("top", 3)
    with pytest.raises(scm.RetiredClaimError):
        sc.argue("top", 3)
    with pytest.raises(scm.SeqOrderError):
        sc.argue("top", -1)


def test_argue_cross_instance_digest_determinism():
    def build():
        s = SafetyCase()
        s.claim("top", _digest("a"), 1)
        s.claim("c1", _digest("b"), 2, parent_id="top")
        s.evidence("c1", "t1", 3, evidence_digest=_digest("c"))
        return s.argue("top", 3)

    assert build().digest == build().digest


# ---------------------------------------------------------------------------
# seq discipline, audit boundary, main()
# ---------------------------------------------------------------------------


def test_seq_discipline_rewind_bare_and_malformed():
    sc = SafetyCase()
    sc.claim("a", _digest("a"), 1)
    for bad in (True, "2", 1.5, None):
        with pytest.raises(scm.SeqOrderError):
            sc.claim("b", _digest("a"), bad)
    # malformed seqs consume nothing: next good seq is still 2
    rec = sc.claim("b", _digest("a"), 2)
    assert rec.seq == 2
    kinds = [r["kind"] for r in sc.audit_log()]
    assert "rejected" not in kinds  # rewinds raise bare, no rejected rows


def test_audit_shapes_banned_keys_and_bad_kind():
    sc = SafetyCase()
    sc.claim("top", _digest("a"), 1)
    sc.evidence("top", "t1", 2, evidence_digest=_digest("c"))
    rows = sc.audit_log()
    assert [r["kind"] for r in rows] == ["claim-declared", "evidence-bound"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "safety-case.v1"
    # raw statement/evidence material must stay out of the audit boundary
    with pytest.raises(scm.AuditKindError):
        scm.safety_case_audit_event("claim-declared",
                                    {"statement": "secret"}, 3)
    with pytest.raises(scm.AuditKindError):
        scm.safety_case_audit_event("evidence-bound",
                                    {"evidence": "raw"}, 3)
    with pytest.raises(scm.AuditKindError):
        scm.safety_case_audit_event("nope", {}, 3)


def test_main_subprocess_check():
    proc = subprocess.run(
        [sys.executable, _module_path()],
        capture_output=True, text=True, cwd="/tmp")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == \
        "safety-case OK: claim, evidence, argue, retire"
