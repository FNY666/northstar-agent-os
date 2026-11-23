"""Tests for ai_assurance.py: 15 tests, house style."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ai_assurance as aa

D = "sha256:" + "ab" * 32


def _mod():
    return aa.AIAssurance()


# 1. version / schema / vocabulary pins -------------------------------------

def test_pins_and_vocabulary():
    assert aa.AI_ASSURANCE_VERSION == "ai-assurance.v1"
    assert aa.AI_ASSURANCE_SCHEMA == "northstar.ai-assurance.v1"
    assert aa.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(aa.ASSURANCE_KINDS) == 8
    assert len(aa.FINDINGS) == 5
    assert len(aa.RETIRE_REASONS) == 3
    assert aa.KIND_ASSURED == "assured"
    assert aa.KIND_RETIRED == "retired"
    assert aa.KIND_REJECTED == "rejected"
    # version/schema pins on every record class
    m = _mod()
    rec = m.assure("sys-1", 1)
    assert rec.version == "ai-assurance.v1"
    assert rec.schema == "northstar.ai-assurance.v1"
    rep = m.verify("asr-1", 2)
    assert rep.version == "ai-assurance.v1"
    evl = m.evaluate("sys-1", 3)
    assert evl.schema == "northstar.ai-assurance.v1"
    ret = m.retire("sys-1", 4)
    assert ret.version == "ai-assurance.v1"


# 2. stdlib-only AST check ---------------------------------------------------

def test_stdlib_only_ast():
    assert aa.stdlib_only()
    tree = ast.parse(Path(aa.__file__).read_text())
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or \
                node.module.split(".")[0] in stdlib or \
                node.module.split(".")[0] == "canonical_json"


# 3. assure roundtrip / verify() / frozen-ness --------------------------------

def test_assure_roundtrip_verify_frozen():
    m = _mod()
    rec = m.assure("sys-1", 1,
                   assurance_kind=aa.ASSURANCE_INDEPENDENT_ASSESSMENT,
                   finding=aa.FINDING_ASSURED,
                   assurance_digest=D)
    assert rec.assurance_id == "asr-1"
    assert rec.system_id == "sys-1"
    assert rec.assurance_kind == aa.ASSURANCE_INDEPENDENT_ASSESSMENT
    assert rec.finding == aa.FINDING_ASSURED
    assert rec.assurance_digest == D
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.finding = aa.FINDING_NOT_ASSURED  # type: ignore[misc]
    # defaults
    rec2 = m.assure("sys-2", 2)
    assert rec2.assurance_id == "asr-2"
    assert rec2.assurance_kind == aa.ASSURANCE_SELF_ATTESTATION
    assert rec2.finding == aa.FINDING_NOT_ASSESSED
    assert rec2.assurance_digest == ""
    assert rec2.verify()


# 4. assure bad-input table + seq-burn + rejected-row accounting ---------------

def test_assure_bad_input_seq_burn():
    m = _mod()
    bad_calls = [
        lambda s: m.assure("", s),                                   # bad id
        lambda s: m.assure("has space", s),                           # bad id
        lambda s: m.assure("sys", s, assurance_kind="bogus"),         # bad kind
        lambda s: m.assure("sys", s, finding="bogus"),                # bad finding
        lambda s: m.assure("sys", s, assurance_digest="not-a-digest"),  # bad digest
        lambda s: m.assure("sys", s, assurance_digest="sha256:zzz"),  # bad digest hex
        lambda s: m.assure("x" * 300, s),                             # id too long
    ]
    seq = 1
    for i, call in enumerate(bad_calls):
        with pytest.raises(aa.AIAssuranceError):
            call(seq)
        seq += 1
    # each failed mutation consumed its seq and booked a rejected row
    log = m.audit_log(999)
    rejected = [e for e in log if e["kind"] == "rejected"]
    assert len(rejected) == len(bad_calls)
    assert m.stats(999)["seq"] == len(bad_calls)
    # next good call needs a strictly larger seq
    rec = m.assure("sys-ok", seq)
    assert rec.assurance_id == "asr-1"
    assert rec.verify()


# 5. full 8-kind assurance vocabulary ----------------------------------------

def test_full_assurance_kind_vocabulary():
    m = _mod()
    for i, kind in enumerate(aa.ASSURANCE_KINDS, start=1):
        rec = m.assure(f"sys-{i}", i, assurance_kind=kind,
                       finding=aa.FINDING_ASSURED)
        assert rec.assurance_kind == kind
        assert rec.verify()
    assert m.stats(999)["assurances"] == 8


# 6. full 5-finding vocabulary -------------------------------------------------

def test_full_finding_vocabulary():
    m = _mod()
    for i, finding in enumerate(aa.FINDINGS, start=1):
        rec = m.assure("sys-x", i, finding=finding)
        assert rec.finding == finding
        assert rec.verify()


# 7. verify semantics: tamper-as-data, unknown, read purity --------------------

def test_verify_semantics():
    m = _mod()
    m.assure("sys-1", 1, finding=aa.FINDING_ASSURED)
    rep = m.verify("asr-1", 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # same-seq twice: read purity (no audit rows, no seq consumption)
    before = len(m.audit_log(999))
    rep2 = m.verify("asr-1", 2)
    assert rep2.verdict == "verified"
    assert len(m.audit_log(999)) == before
    # tamper is data, never raised
    rec = m.assurance_record("asr-1", 3)
    object.__setattr__(rec, "finding", aa.FINDING_NOT_ASSURED)
    rep3 = m.verify("asr-1", 4)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    assert rep3.verify()
    # unknown id
    with pytest.raises(aa.UnknownAssuranceError):
        m.verify("asr-999", 5)


# 8. evaluate posture math: all postures + precedence ---------------------------

def test_evaluate_posture_math():
    # unassessed
    m = _mod()
    m.assure("sys-1", 1, finding=aa.FINDING_NOT_ASSESSED)
    rep = m.evaluate("sys-1", 2)
    assert rep.posture == "unassessed"
    assert rep.assurance_count == 1
    assert rep.verify()
    # assured
    m2 = _mod()
    m2.assure("s", 1, finding=aa.FINDING_ASSURED)
    m2.assure("s", 2, finding=aa.FINDING_ASSURED)
    rep2 = m2.evaluate("s", 3)
    assert rep2.posture == "assured"
    assert rep2.assured_count == 2
    # not-assured outranks everything
    m3 = _mod()
    m3.assure("s", 1, finding=aa.FINDING_ASSURED)
    m3.assure("s", 2, finding=aa.FINDING_CONDITIONALLY_ASSURED)
    m3.assure("s", 3, finding=aa.FINDING_INCONCLUSIVE)
    m3.assure("s", 4, finding=aa.FINDING_NOT_ASSURED)
    rep3 = m3.evaluate("s", 5)
    assert rep3.posture == "not-assured"
    assert rep3.not_assured_count == 1
    # inconclusive outranks conditionally-assured
    m4 = _mod()
    m4.assure("s", 1, finding=aa.FINDING_CONDITIONALLY_ASSURED)
    m4.assure("s", 2, finding=aa.FINDING_INCONCLUSIVE)
    rep4 = m4.evaluate("s", 3)
    assert rep4.posture == "inconclusive"
    assert rep4.inconclusive_count == 1
    # conditionally-assured
    m5 = _mod()
    m5.assure("s", 1, finding=aa.FINDING_ASSURED)
    m5.assure("s", 2, finding=aa.FINDING_CONDITIONALLY_ASSURED)
    rep5 = m5.evaluate("s", 3)
    assert rep5.posture == "conditionally-assured"
    assert rep5.conditional_count == 1
    # tallies add up
    assert (rep5.assured_count + rep5.conditional_count
            + rep5.not_assured_count + rep5.inconclusive_count) <= \
        rep5.assurance_count


# 9. evaluate read purity + unknown-system refusal -------------------------------

def test_evaluate_read_purity_unknown():
    m = _mod()
    m.assure("sys-1", 1, finding=aa.FINDING_ASSURED)
    before = len(m.audit_log(999))
    r1 = m.evaluate("sys-1", 2)
    r2 = m.evaluate("sys-1", 2)
    assert r1 == r2
    assert len(m.audit_log(999)) == before
    # read-seq shape validated
    for bad in (True, "2", None, 1.5, -1):
        with pytest.raises(aa.SeqOrderError):
            m.evaluate("sys-1", bad)
    # unknown system
    with pytest.raises(aa.UnknownSystemError):
        m.evaluate("nope", 3)
    # bad system id shape
    with pytest.raises(aa.BadSystemError):
        m.evaluate("", 4)


# 10. retire terminality + id non-recycling + post-retire reads -------------------

def test_retire_terminality():
    m = _mod()
    m.assure("sys-1", 1, finding=aa.FINDING_ASSURED)
    ret = m.retire("sys-1", 2, reason=aa.REASON_SUPERSEDED)
    assert ret.reason == aa.REASON_SUPERSEDED
    assert ret.verify()
    assert m.retired_ids(99) == ("sys-1",)
    # id never recycled
    with pytest.raises(aa.RetiredSystemError):
        m.assure("sys-1", 3)
    # reads still work post-retire
    assert m.assurances_for("sys-1", 4) == ("asr-1",)
    rep = m.evaluate("sys-1", 5)
    assert rep.posture == "assured"
    # double retire refused
    with pytest.raises(aa.RetiredSystemError):
        m.retire("sys-1", 6)
    # unknown system refused
    with pytest.raises(aa.UnknownSystemError):
        m.retire("ghost", 7)
    # bad reason burns seq + rejected row
    m.assure("sys-2", 8)
    with pytest.raises(aa.BadReasonError):
        m.retire("sys-2", 9, reason="bogus")
    assert any(e["kind"] == "rejected" for e in m.audit_log(999))


# 11. seq discipline: rewind bare, malformed, failed-mutation-consumes ----------

def test_seq_discipline():
    m = _mod()
    # rewind raises bare with zero rejected rows
    m.assure("sys-1", 1)
    with pytest.raises(aa.SeqOrderError):
        m.assure("sys-2", 1)
    assert not [e for e in m.audit_log(99) if e["kind"] == "rejected"]
    # malformed seqs
    for bad in (True, "1", None, 1.5, -1, b"1"):
        with pytest.raises(aa.SeqOrderError):
            m.assure("sys-x", bad)
    # failed mutation consumes seq: next good seq must be larger
    with pytest.raises(aa.BadAssuranceKindError):
        m.assure("sys-3", 2, assurance_kind="bogus")
    rec = m.assure("sys-3", 3)
    assert rec.seq == 3
    # seq gap allowed (strictly increasing, not consecutive)
    rec2 = m.assure("sys-4", 100)
    assert rec2.seq == 100


# 12. audit shapes + leak ban + bad-kind ------------------------------------------

def test_audit_shapes_and_leak_ban():
    m = _mod()
    m.assure("sys-1", 1, finding=aa.FINDING_ASSURED)
    m.retire("sys-1", 2)
    log = m.audit_log(999)
    kinds = [e["kind"] for e in log]
    assert kinds == ["assured", "retired"]
    for e in log:
        assert e["schema"] == "audit.ndjson/1"
        assert e["version"] == "ai-assurance.v1"
        assert isinstance(e["audit_seq"], int)
        assert isinstance(e["detail"], dict)
    # raw evidence never crosses the audit boundary
    with pytest.raises(aa.AuditKindError):
        aa.ai_assurance_audit_event("assured", 3, evidence="raw text")
    with pytest.raises(aa.AuditKindError):
        aa.ai_assurance_audit_event("assured", 3, certificate="raw blob")
    with pytest.raises(aa.AuditKindError):
        aa.ai_assurance_audit_event("assured", 3, workpapers={"k": "v"})
    # bad kind
    with pytest.raises(aa.AuditKindError):
        aa.ai_assurance_audit_event("bogus-kind", 3)
    # pinned vocab values remain emittable as declared data
    ev = aa.ai_assurance_audit_event(
        "assured", 3, assurance_id="asr-1",
        assurance_kind=aa.ASSURANCE_CERTIFICATION,
        finding=aa.FINDING_ASSURED)
    assert ev["detail"]["finding"] == aa.FINDING_ASSURED


# 13. cross-instance digest determinism + tamper breaks verify() -----------------

def test_digest_determinism_and_tamper():
    m1, m2 = _mod(), _mod()
    r1 = m1.assure("sys-1", 1,
                   assurance_kind=aa.ASSURANCE_INTERNAL_AUDIT,
                   finding=aa.FINDING_CONDITIONALLY_ASSURED,
                   assurance_digest=D)
    r2 = m2.assure("sys-1", 1,
                   assurance_kind=aa.ASSURANCE_INTERNAL_AUDIT,
                   finding=aa.FINDING_CONDITIONALLY_ASSURED,
                   assurance_digest=D)
    assert r1.digest == r2.digest
    e1 = m1.evaluate("sys-1", 2)
    e2 = m2.evaluate("sys-1", 2)
    assert e1.digest == e2.digest
    assert e1.verify() and e2.verify()
    # tamper breaks verify() and flips integrity_ok as data
    object.__setattr__(r1, "assurance_digest", "sha256:" + "cd" * 32)
    assert not r1.verify()
    e3 = m1.evaluate("sys-1", 3)
    assert e3.integrity_ok is False
    assert e3.verify()


# 14. views/stats + unknown lookups ----------------------------------------------

def test_views_stats_unknown_lookups():
    m = _mod()
    m.assure("sys-1", 1, finding=aa.FINDING_ASSURED)
    m.assure("sys-1", 2, finding=aa.FINDING_INCONCLUSIVE)
    m.assure("sys-2", 3)
    assert m.system_ids(99) == ("sys-1", "sys-2")
    assert m.assurance_ids(99) == ("asr-1", "asr-2", "asr-3")
    assert m.assurances_for("sys-1", 99) == ("asr-1", "asr-2")
    st = m.stats(99)
    assert st == {"systems": 2, "assurances": 3, "retired": 0, "seq": 3}
    rec = m.assurance_record("asr-1", 99)
    assert rec.system_id == "sys-1"
    # unknown lookups
    with pytest.raises(aa.UnknownAssuranceError):
        m.assurance_record("asr-999", 99)
    with pytest.raises(aa.UnknownSystemError):
        m.assurances_for("ghost", 99)
    # views write no audit rows
    before = len(m.audit_log(99))
    m.system_ids(99); m.assurance_ids(99); m.stats(99)
    assert len(m.audit_log(99)) == before


# 15. main() subprocess check + 8-thread read smoke -------------------------------

def test_main_subprocess_and_thread_smoke():
    here = Path(__file__).resolve().parent.parent
    out = subprocess.run([sys.executable, "ai_assurance.py"],
                         capture_output=True, text=True, cwd=str(here),
                         timeout=60)
    assert out.returncode == 0, out.stderr
    assert "ai-assurance OK" in out.stdout
    # 8-thread read smoke over one shared ledger
    m = _mod()
    for i in range(1, 9):
        m.assure("sys-1", i, finding=aa.FINDING_ASSURED)
    errors = []

    def reader():
        try:
            for _ in range(50):
                rep = m.evaluate("sys-1", 999)
                assert rep.posture == "assured"
                assert rep.verify()
                m.system_ids(999)
                m.assurance_ids(999)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
